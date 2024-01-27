import express from "express";
import mongoose from "mongoose";
import "dotenv/config";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
import serviceAccountKey from "./firebase-admin.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";

// schema below
import User from "./Schema/User.js";

const server = express();
let PORT = 3000;

// firebase project connection condential from serviceAccountKey
admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

// Email and Password validation keys
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
server.use(cors());

// Mongodb Database connection
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

// User data formate object
const formatDatatoSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

// Get user name from logged user profile email
const generateUsername = async (email) => {
  let username = email.split("@")[0];

  let isUsernameNotUnique = await User.exists({
    "personal_info.username": "username",
  }).then((result) => result);

  isUsernameNotUnique ? (username += nanoid().substring(0, 5)) : "";
  return username;
};

// Create signUp route
server.post("/signup", (req, res) => {
  let { fullname, email, password } = req.body;

  // Validating the data from frontend
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ Error: "Fullname must be at least 3 letter long" });
  }

  if (!email.length) {
    return res.status(403).json({ Error: "Email is required" });
  }

  if (!emailRegex.test(email)) {
    return res.status(403).json({ Error: "Email is invalide" });
  }

  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      Error:
        "Password should contain atleast 1 uppercase, 1 lowercase and 1 number with length between 6 to 20 characters",
    });
  }

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    let username = await generateUsername(email);

    let user = new User({
      personal_info: { fullname, email, password: hashed_password, username },
    });

    user
      .save()
      .then((u) => {
        return res.status(200).json(formatDatatoSend(u));
      })
      .catch((err) => {
        if (err.code == 11000) {
          return res.status(409).json({ Error: "Email already exists" });
        }
        return res.status(500).json({ Error: err.message });
      });
  });
});

// Create signin route
server.post("/signin", (req, res) => {
  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.json({ status: "Email not found" });
      }
      bcrypt.compare(password, user.personal_info.password, (err, result) => {
        if (err) {
          return res
            .status(403)
            .json({ Error: "Error occured while login please try again" });
        }

        if (!result) {
          return res.status(403).json({ Error: "Incorrect password" });
        } else {
          return res.status(200).json(formatDatatoSend(user));
        }
      });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({ Error: err.message });
    });
});

// Google authentication
server.post("/google-auth", async (req, res) => {
  let { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodeduser) => {
      let { email, name, picture } = decodeduser;

      picture = picture.replace("s96-c", "s384-c"); // Picture resolution from the google s96-c is low & s384-c is high resolution

      // Checking if the user is already registered or not
      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json({
            Error: err.message,
          });
        });

      if (user) {
        // logIn
        if (!user.google_auth) {
          return res.status(403).json({
            Error:
              "This email was signed up without google. Please log in with password to access the account",
          });
        }
      } else {
        // signUp
        let username = await generateUsername(email);

        user = new User({
          personal_info: {
            fullname: name,
            email,
            profile_img: picture,
            username,
          },
          google_auth: true,
        });

        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json({
              Error: err.message,
            });
          });
      }

      return res.status(200).json(formatDatatoSend(user));
    })
    .catch((err) => {
      return res.status(500).json({
        Error:
          "Failed to authenticate you with google. Try with some other google account",
      });
    });
});

// Create server port
server.listen(PORT, () => {
  console.log(`listening on port -> ${PORT}`);
});
