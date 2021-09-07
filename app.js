require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const User = require("./model/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const auth = require("./middleware/auth");

const app = express();

app.use(express.json());

app.post("/Welcome", auth, (req, res) => {
  res.status(200).send("Welcome to the website");
});

// Logic goes here
app.post("/register", async (req, res) => {
  // ----- register logic -------
  try {
    // step1: get user input
    const { first_name, last_name, email, password } = req.body;

    // step2: validate the user input
    if (!(email && password && first_name && last_name)) {
      res.status(400).send("All inputs are required!");
    }
    // step3: Check if a user already exists
    const oldUser = await User.findOne({ email });
    if (oldUser) {
      return res
        .status(409)
        .send("User already exists, Please login instead at /login");
    }

    // step4: encrypt the user password to store in the database
    encryptedPassword = await bcrypt.hash(password, 10);
    // step5: Create a new user
    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    // step6: Create a token
    const token = jwt.sign(
      { user_id: user._id, email },
      process.env.TOKEN_KEY,
      {
        expiresIn: "2h",
      }
    );
    // step7: Save the token for current user
    user.token = token;

    return res.status(201).json(user);
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  // login logic
  try {
    const { email, password } = req.body;
    console.log(email, password);
    //   step1:Validate user input
    if (!(email && password)) {
      res.status(400).send("Enter all inputs");
    }
    // step2: check if the user exits
    const user = await User.findOne({ email });
    // step3: check if the password is correct
    encryptedPassword = await bcrypt.hash(password, 10);
    if (user && (await bcrypt.compare(password, user.password))) {
      // Create token
      const token = jwt.sign(
        { user_id: user._id, email },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      // save user token
      user.token = token;

      // user
      res.status(200).json(user);
    } else res.status(400).send("Invalid credentials");
  } catch (err) {
    console.log(err);
  }
});
// app.post("/login", async (req, res) => {
//   // Our login logic starts here
//   try {
//     // Get user input
//     const { email, password } = req.body;

//     // Validate user input
//     if (!(email && password)) {
//       res.status(400).send("All input is required");
//     }
//     // Validate if user exist in our database
//     const user = await User.findOne({ email });

//     if (user && (await bcrypt.compare(password, user.password))) {
//       // Create token
//       const token = jwt.sign(
//         { user_id: user._id, email },
//         process.env.TOKEN_KEY,
//         {
//           expiresIn: "2h",
//         }
//       );

//       // save user token
//       user.token = token;

//       // user
//       res.status(200).json(user);
//     } else res.status(400).send("Invalid Credentials");
//   } catch (err) {
//     console.log(err);
//   }
//   // Our register logic ends here
// });
module.exports = app;
