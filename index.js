const express = require("express");
const cors = require("cors");
const app = express();
const mongodb = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
var nodemailer = require("nodemailer");

const dotenv = require("dotenv").config();
const mongoClient = mongodb.MongoClient;
const URL = process.env.DB_URL;
const DB = process.env.DB;

//middleware
app.use(express.json());
app.use(
  cors({
    origin: "https://kiruba-password-reset.netlify.app",
  })
);

let authenticate = (req, res, next) => {
  console.log(req.headers);
  if (req.headers.authorization) {
    try {
      let decode = jwt.verify(req.headers.authorization, process.env.SECRET);
      if (decode) {
        next();
      }
    } catch (error) {
      res.status(401).json({ message: "Unauthorized" });
    }
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
};

app.get("/allusers", authenticate, async function (req, res) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);
    let reUser = await db.collection("register").find().toArray();
    await connection.close();
    res.json(reUser);
  } catch (error) {
    res.status(500).json({ message: "something went wrong" });
  }
});

app.post("/register", async function (req, res) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db(DB);

    let salt = await bcrypt.genSalt(10);
    let hash = await bcrypt.hash(req.body.password, salt);

    req.body.password = hash;
    await db.collection("register").insertOne(req.body);

    await connection.close();

    res.json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "something went wrong" });
  }
});

app.post("/login", async function (req, res) {
  try {
    let connection = await mongoClient.connect(URL);
    let db = connection.db(DB);

    let user = await db
      .collection("register")
      .findOne({ email: req.body.email });
    if (user) {
      let compare = await bcrypt.compare(req.body.password, user.password);

      if (compare) {
        let token = jwt.sign({ _id: user._id }, process.env.SECRET, {
          expiresIn: "1m",
        });
        res.json({ token });
      } else {
        res.json({ message: "email or Password is wrong" });
      }
    } else {
      res.status(401).json({ message: "User email or password wrong" });
    }
  } catch (error) {
    res.status(500).json({ message: "something went wrong" });
  }
});







app.post("/resetpassword", async function (req, res) {
  

      try {
        let connection = await mongoClient.connect(URL);
        let db = connection.db(DB);

        let id = await db.collection("register").findOne({ email: req.body.email });

        if (id) {
          let mailid = req.body.email;
        let token = jwt.sign({ _id: id._id }, process.env.SECRET, { expiresIn: '2m' });

        let link = `https://kiruba-password-reset.netlify.app/reset-password-page/${id._id}/${token}`;
        console.log(link);
        // res.send(link)



      var transporter = nodemailer.createTransport({
        service: "gmail",
       
        auth: {
          user: "kirubam8878@gmail.com",
          pass: process.env.pass,
        },
      });

      var mailOptions = {
        from: "kirubam8878@gmail.com",
        to: mailid,
        subject: "Password Reset",
        text: ` Click the link to reset password ${link}`,
        html: `<h2>  Click the link to reset password ${link}</h2>`,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
          res.json({
            message: "Email not send",
          });
        } else {
          console.log("Email sent: " + info.response);
          res.json({
            message: "Email Send",
          });
        }
      });
      res.json({
        message: "Email Send",
      });
    } 
    
    
    
    else {
      res.json({
        message: "Email Id not match / User not found",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

 
 app.post("/reset-password-page/:id/:token", async function (req, res) {
  const id = req.params.id
  const token = req.params.token
  try {

      let salt = await bcrypt.genSalt(10);
      let hash = await bcrypt.hash(req.body.password, salt);
      let connection = await mongoClient.connect(URL);
      let db = connection.db(DB);

      let compare =  jwt.verify(token,process.env.SECRET);
      console.log(compare);
      if (compare) {
          let Person = await db.collection("register").findOne({ _id: mongodb.ObjectId(`${id}`) })
          if (!Person) {
              return res.json({ Message: "User Exists!!" });
          }
          await db.collection("register").updateOne({ _id: mongodb.ObjectId(`${id}`) }, { $set: { password: hash } });
          res.json({ message: "Password Updated" });
      } else {
          res.json({ message: "URL TimeOut" })
      }
  } catch (error) {
      res.status(500).json({ message: 'URL TimeOut' });
      console.log(error);
  }
})
 
  
app.listen(process.env.PORT || 7000);
