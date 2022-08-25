require("dotenv").config();
const express = require("express");
const app = express();
const mongoose = require("mongoose");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const flash = require("connect-flash");
const bodyParser = require("body-parser");
const User = require("./models/user");
const bycrypt = require("bcrypt");
const saltRounds = 10;
// 總共執行hash function的次數
// Cost factor 10代表2的10次方

app.set("view engine", "ejs");
// middlewares
app.use(express.static("public"));
app.use(cookieParser(process.env.SECRET));
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(flash());
app.use(bodyParser.urlencoded({ extended: true }));

const requireLogin = (req, res, next) => {
  if (!req.session.isVerified == true) {
    res.redirect("login");
  } else {
    next();
  }
};

mongoose
  .connect("mongodb://localhost:27017/test")
  .then(() => {
    console.log("Connected to mongodb.");
  })
  .catch((e) => {
    console.log(e);
  });

app.get("/secret", requireLogin, (req, res) => {
  res.render("secret");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res, next) => {
  let { username, password } = req.body;
  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      bycrypt.compare(password, foundUser.password, (err, result) => {
        if (err) {
          next(err);
        }
        if (result === true) {
          req.session.isVerified = true;
          res.redirect("secret");
        }
      });
    } else {
      res.send("Username or password not correct!!");
    }
  } catch (err) {
    next(err);
  }
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res, next) => {
  let { username, password } = req.body;
  try {
    let foundUser = await User.findOne({ username });
    if (foundUser) {
      res.send("Username has been used.");
    } else {
      bycrypt.genSalt(saltRounds, (err, salt) => {
        if (err) {
          next(err);
        }
        console.log("this is salt: " + salt);
        bycrypt.hash(password, salt, (err, hash) => {
          if (err) {
            next(err);
          }
          console.log("this is hash: " + hash);
          let newUser = new User({ username, password: hash });
          try {
            newUser
              .save()
              .then(() => {
                res.send("Data has been saved");
              })
              .catch((e) => {
                res.send("Error!!");
              });
          } catch (err) {
            next(err);
          }
        });
      });
    }
  } catch (err) {
    next(err);
  }
});

app.get("/*", (req, res) => {
  res.status(404).send("Page not found");
});

// error handler 放在最後面
app.use((err, req, res, next) => {
  console.log(err);
  res.status(500).send("Something wrong. Gonna fix it soon");
});

app.listen(3000, () => {
  console.log("Server running on port 3000.");
});
