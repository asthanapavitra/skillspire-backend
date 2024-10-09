// Other imports and configurations
import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as GoogleStrategy } from 'passport-google-oauth2';
import session from 'express-session';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const port = 4000;
const saltRounds = 10;
const server = "http://localhost:4000";

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({ origin: "http://localhost:3000", credentials: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

passport.use(new LocalStrategy(
  async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        if (valid) {
          return done(null, user);
        } else {
          return done(null, false);
        }
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${server}/auth/google/dashboard`
},
  async (accessToken, refreshToken, profile, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
      if (result.rows.length === 0) {
        const newUser = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
          [profile.email, "google"]
        );
        return done(null, newUser.rows[0]);
      } else {
        return done(null, result.rows[0]);
      }
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.get("/", (req, res) => {
  res.send("Message from backend");
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"],
}));

app.get("/auth/google/dashboard",
  passport.authenticate("google", {
    failureRedirect: "/login",
  }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

app.post("/login", passport.authenticate("local", {
  successRedirect: "/dashboard",
  failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      const hash = await bcrypt.hash(password, saltRounds);
      const result = await db.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
        [email, hash]
      );
      const user = result.rows[0];
      req.login(user, (err) => {
        if (err) {
          console.error("Login error:", err);
          res.redirect("/login");
        } else {
          res.redirect("/dashboard");
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.redirect("/register");
  }
});

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    res.send("Welcome to your dashboard");
  } else {
    res.redirect("/login");
  }
});

app.listen(port, () => {
  console.log("Listening on port", port);
});
