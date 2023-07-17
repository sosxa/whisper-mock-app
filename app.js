// environment var
require("dotenv").config();
// basic npm
const bodyParser = require("body-parser");
const express = require("express");
const ejs = require("ejs");
const nodemon = require("nodemon");
const mongoose = require("mongoose");
// for cookies and auth
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
// oauth20 from passport with google
const GoogleStrategy = require("passport-google-oauth20").Strategy;
// find or create for google
const findOrCreate = require("mongoose-findorcreate");
// facebook
const FacebookStrategy = require("passport-facebook");

// express
const app = express();
// body parser
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));
app.set("view engine", "ejs");
// using session to make a browser session
app.use(
  session({
    // the key should be more unique but this will do for now
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false,
  })
);
// making passport utilize this session and passport and its extenstions will be the middleware
app.use(passport.initialize());
app.use(passport.session());

// mongoose connection
mongoose
  .connect("mongodb://localhost:27017/userDB")
  .then(console.log("Mongodb is listening"));

// the layout for the data going into the database
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  // google id so it can be something added to the db or else enabling users to login with google is pointless
  googleId: String,
  // facebook id
  facebookId: String,
  secret: String,
});
// pluging for findOrCreate
userSchema.plugin(findOrCreate);

// applying passport-local-mongoose to the mongoosedb schema and it automatically adds additonal methods for authentication
userSchema.plugin(passportLocalMongoose);

// making a folder nammed user in the UserDB
const User = mongoose.model("user", userSchema);

passport.use(User.createStrategy());

// serializing the user with passsport keeps the user logged in throughout the session
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});
// google oauth2.0 these are all the strats google will use to login our users
passport.use(
  new GoogleStrategy(
    {
      // process.env.secret to pull the secret ecryption from the env file
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      // this is what adds the google id to our db
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

// oaurth2.0 with facebook
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.route("/").get(async function (req, res) {
  console.log("User is at the home pg");
  res.render("home");
});

// path for google signin and loggin
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

// redirection to when user clicks to signinto account
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);
// facebook login
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", {
    authType: "reauthenticate",
    scope: ["user_friends", "manage_pages"],
  })
);
app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app
  .route("/secrets")
  .get(async function (req, res) {
    // using passport alongside the home page of the whisper mock app so users cant just access the actual content of the app without logging in
    // making sure cookies is being used with there token and there account is athenticated
    User.find({"secret": {$ne: null}})
    .then(function(foundUsers){
        res.render("secrets", {usersWithSecrets:foundUsers});
    })
    .catch((err)=>{
        console.log(err);
    })
});
app
  .route("/login")
  .get(async function (req, res) {
    res.render("login");
  })
  .post(async function (req, res) {
    // the user will have to log back in if they exit chrome since the cookies will stop once they close chrome
    // asigning the request made by the user to user
    const user = new User({
      username: req.body.username,
      password: req.body.password,
      // getting the request the user has put out by filling out the username and password field
    });

    // using passport to login and authenticate to log the user back in
    req.login(user, function (err) {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    });
  });

app
  .route("/register")
  .get(function (get, res) {
    // using passport local mongoose to register users into db
    res.render("register");
  })
  .post(async function (req, res) {
    User.register(
      { username: req.body.username },
      req.body.password,
      // can use callbacks since it isnt a mongoose attribute, its an attribute from passport
      function (err, user) {
        if (err) {
          // if the authentication fails we will leave them at the register page
          console.log(err);
          res.redirect("/register");
        } else {
          // calling password function athenticate locally and then res.redirecting to secrets which the social media home pg
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

// submitting or making a post
app
  .route("/submit")
  .get(async function (req, res) {
    if(req.isAuthenticated()){
      res.render("submit");
  }
  else{
      res.redirect("/login");
  }
})

  .post(async function (req, res) {
    const submittedSecret= req.body.secret;
 
    User.findById(req.user.id)
        .then(function(founudUser){
            founudUser.secret=submittedSecret;
            founudUser.save()
                .then(()=>{
                    res.redirect("/secrets");
                });
        })
        .catch((err)=>{
            console.log(err);
        })
});

app.route("/logout").get(async function (req, res) {
  // logging user out and ending there session and redirecting them to home
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// port connection
app.listen(3000, function (req, res) {
  console.log("Listening to port 3000");
});
