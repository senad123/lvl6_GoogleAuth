import dotenv from "dotenv";

import express from "express";
import bodyParser from "body-parser";
import pgPromise from "pg-promise";
import session from "express-session";
import passport from "passport";
//import LocalStrategy from 'passport-local';
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
//import bcrypt from 'bcrypt';

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.set("view engine", "ejs");

// Set up session middleware
app.use(
  session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);
// Initialize Passport
app.use(passport.initialize()); //inicializacija passport
app.use(passport.session()); //passport koristi session

// Create an instance of pg-promise
const pgp = pgPromise();
// Connection string with your PostgreSQL database details
// Connection options for PostgreSQL
const connectionOptions = {
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  //app:process.env.APP,
  port: process.env.DB_PORT || 5432,

  ssl: { rejectUnauthorized: false }, // Adjust as needed for your environment
};
// Set up the database connection
const db = pgp({ ...connectionOptions, application_name: "lvl6_GoogleAuth" });

db.connect()
  .then((obj) => {
    obj.done(); // success
  })
  .catch((error) => {
    console.error("Error connecting to the database:", error.message || error);
  });

// // Set the application name
// db.connect({ direct: true, application_name: 'lvl6_GoogleAuth'})
//   .then(obj => {
//     // Your database connection logic here
//     obj.done();
//   })
//   .catch(error => {
//     console.error('Error connecting to the database:', error.message || error);
//   });

// Set up LocalStrategy for passport
passport.use(
  new LocalStrategy((username, password, done) => {
    db.oneOrNone(
      "SELECT * FROM users WHERE email = $1",
      [username],
      (err, result) => {
        if (err) {
          return done(err);
        }

        if (!result.rows[0]) {
          return done(null, false, { message: "Incorrect username." });
        }

        const user = result.rows[0];
        console.log(user);

        //bcrypt.compare(password, user.password_hash, (err, res) => {

        bcrypt.compare(password, user.password, (err, res) => {
          if (res) {
            return done(null, user);
          } else {
            return done(null, false, { message: "Incorrect password." });
          }
        });
      }
    );
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.oneOrNone(
      "SELECT * FROM users WHERE googleId = $1",
      id
    );
    return done(null, user);
  } catch (err) {
    return done(err);
  }
});

//GOOGLE OAUTH
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "https://lvl6-googleauth.onrender.com/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      try {
        // Try to find the user by googleId
        const user = await db.oneOrNone(
          "SELECT * FROM users WHERE googleId = $1",
          [profile.id]
        );

        if (user) {
          // User already exists, return the user
          return cb(null, user);
        } else {
          // User doesn't exist, create a new user
          const newUser = await db.one(
            "INSERT INTO users (googleId) VALUES ($1) RETURNING *",
            [profile.id]
          );
          return cb(null, newUser);
        }
      } catch (err) {
        return cb(err, null);
      }
    }
  )
);

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    return res.render("secrets");
  }
  res.redirect("/login");
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

// app.get("/auth/google", (req,res)=>{
//     passport.authenticate("google", {scope :["profile"]})
// })

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", (req, res) => {
  res.render("login.ejs");
});
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

//Registration route
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    // Check if the username is already taken
    const existingUser = await db.oneOrNone(
      "SELECT * FROM users WHERE (email) = $1",
      username
    );
    if (existingUser) {
      return res.status(400).json({ message: "Email already taken." });
    }

    // When registering a new user
    //const hashedPassword = await bcrypt.hash(userPassword, saltRounds);
    // Store 'hashedPassword' in the database

    // Insert the new user into the database
    const newUser = await db.one(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [username, password]
    );

    // Manually authenticate the user after successful registration
    req.login(newUser, (err) => {
      if (err) {
        return res
          .status(500)
          .json({ message: "Login Internal server error." });
      }
      return passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });

      //res.render("secrets.ejs");
      //res.status(201).json({ message: 'User registered successfully.', username: newUser });
    });
  } catch (err) {
    return res.status(500).json({ message: "Reg Internal server error." });
  }
});

// // Login route
// app.post('/login', passport.authenticate('local'), (req, res) => {
//     res.json({ message: 'Login successful.', user: req.user });
//   });

app.post(
  "/login",
  passport.authenticate("local", { failureRedirect: "/login" }),
  function (req, res) {
    res.redirect("/secrets.ejs");
  }
);

// // Login route using passport.authenticate
// app.post('/secrets', passport.authenticate('local', {
//     successRedirect: '/secrets',
//     failureRedirect: '/login',
//     failureFlash: true
// }));

app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

//from passport
// app.post('/login',
//   passport.authenticate('local', { failureRedirect: '/login' }),
//   function(req, res) {
//     res.redirect('/');
//   });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
