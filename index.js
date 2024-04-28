const express = require("express");
const app = express();
const path = require("path");
var cors = require("cors");
const bodyParser = require("body-parser");
const fs = require("fs");
const mongoose = require("mongoose");
const multer = require("multer");
var morganLogger = require("morgan");
const port = process.env.PORT || 4000;
require("dotenv").config();

//middleware
app.use(morganLogger("dev"));
app.use(bodyParser.json());
app.set("view engine", "ejs");
app.use(cors());
app.use(express.json());
var jwt = require("jsonwebtoken");
app.use(express.urlencoded({ extended: true }));

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});
const { MongoClient, ServerApiVersion } = require("mongodb");
const { query } = require("express");

const uri = `mongodb+srv://ejournal20:YwM5O1d15Rb92IJb@cluster0.qdbumy3.mongodb.net/?retryWrites=true&w=majority`;

// mongodb+srv://ejournal20:YwM5O1d15Rb92IJb@cluster0.qdbumy3.mongodb.net/?retryWrites=true&w=majority

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverApi: ServerApiVersion.v1,
});

const conn = mongoose.createConnection(uri);

// Api Naming Conversion
const secretKey = "your_secret_key_here"; 

function verifyJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send("unauthorized accesse 401");
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function (err, decoded) {
    if (err) {
      return res.status(403).send({ message: "forbidden access" });
    }
    req.decoded = decoded;
    next();
  });
}

async function run() {
  try {
    await client.connect();
    console.log("DB connected!!!");
    const reviewerCollection = client.db("ejournal20").collection("reviewer");
    const dataCollection = client.db("ejournal20").collection("submittedData");
    const usersCollection = client.db("ejournal20").collection("users");

    app.post("/reviewerLogin", async (req, res) => {
      const { email, password, userType } = req.body;
      try {
        if (userType === "author") {
          const user = await usersCollection.findOne({ email });

          if (!user) {
            return res.status(401).send({
              success: false,
              message: "You are not an Author",
            });
          }
          if (user.role !== "admin") {
            if (!user) {
              return res.status(401).send({
                success: false,
                message: "Invalid email or authoremail password",
              });
            }

            if (user.password !== password) {
              return res.status(401).send({
                success: false,
                message: "Invalid email or authorpasss password",
              });
            }
            return res.send({
              success: true,
              message: "Author Login successful",
              user,
            });
          } else {
            return res.send({
              success: false,
              message: "You are not an Author",
              user,
            });
          }
        } else if (userType === "editor") {
          const user = await usersCollection.findOne({
            email,
          });
          if (!user) {
            return res.status(401).send({
              success: false,
              message: "You are not an Editor",
            });
          }

          if (user.role === "admin") {
            if (!user) {
              return res
                .status(401)
                .send({ success: false, message: "Invalid email or password" });
            }

            if (user.password !== password) {
              return res
                .status(401)
                .send({ success: false, message: "Invalid email or password" });
            }
            return res.send({
              success: true,
              message: "Editor Login successful",
              user,
            });
          } else {
            return res.send({
              success: false,
              message: "You are not an Editor",
              user,
            });
          }
        } else if (userType === "reviewer") {
          const user = await reviewerCollection.findOne({
            email,
          });

          if (!user) {
            return res
              .status(401)
              .send({ success: false, message: "You are not a Reviewer" });
          }

          if (user.password !== password) {
            return res
              .status(401)
              .send({ success: false, message: "Invalid email or password" });
          }
          return res.send({
            success: true,
            message: " Reviewer Login successful",
            user,
          });
        } else {
          return res
            .status(401)
            .json({ success: false, message: "Invalid user type" });
        }
      } catch (error) {
        console.error(error);
        return res
          .status(500)
          .json({ success: false, error: "Internal Server Error" });
      }
    });

    app.post("/addReviewer", async (req, res) => {
      const author = req.body;
      const query = { email: author.email };

      const exists = await reviewerCollection.findOne(query);
      if (exists) {
        return res.send({ success: false, email: exists });
      }
      const result = await reviewerCollection.insertOne(author);
      return res.send({ success: true, author });
    });

    //!verify Email + create user in DB
    app.post("/verify-user", async (req, res) => {
      const { token } = req.body;
      const decoded = jwt.verify(token,secretKey);
      const createdData = decoded.author;
      const result = await usersCollection.insertOne(createdData);
      if (!result) {
        return res.status(404).json({ message: "User not found" });
      }
      return res
        .status(200)
        .json({ message: "User is Verified successfully!" });
    });

    // author Post Coding
    app.post("/author", async (req, res) => {
      const author = req.body;
      const query = { email: author.email };
      const exists = await usersCollection.findOne(query);
      const createdData = { ...author, role: "author" };
      if (exists) {
        return res.send({
          success: false,
          data: exists,
          status: 409,
          message: "Email Already Exist !!",
        });
      }

      try {
        await usersCollection.insertOne(createdData);
        res.json({
          success: true,
          status: 200,
          message: "Account Created Successfully",
        });
      } catch (error) {}
    });

    //!forget Password

    app.post("/forget-password", async (req, res) => {
      const { email } = req.body;
      const isExist = await usersCollection.findOne({ email });
      if (!isExist) {
        res.send({
          success: false,
          status: 404,
          message:
            "Email is Incorrect or You have not verified your Email Address",
        });
      } else {
        const token = jwt.sign({ email }, secretKey, {
          expiresIn: "72h",
        });

        // Send forget Password Email
        try {
          // Create the email message
          const mailOptions = {
            from: process.env.SMTP_USER_NAME, // Sender email address
            to: email, // Recipient email address (assuming email is a string representing the email address)
            subject: "Reset Password Email", // Email subject
            html: `<p>Please Click Here <a href="${process.env.CLIENT_URL}/reset-password/${token}" target="_blank">to reset Your password</a></p>`,
          };

          // Send the email using the transporter
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error(error);
              res
                .status(500)
                .json({ success: false, message: "Error sending email" });
            } else {
              res.json({
                success: true,
                status: 200,
                message: "Please Go to Your Email for reset Your Password",
              });
            }
          });
        } catch (error) {
          // Handle any errors that might occur during email sending or token generation
          console.error(error);
          res
            .status(500)
            .json({ success: false, message: "Error sending email" });
        }
      }
    });

    //!Reset Password

    app.patch("/reset-password", async (req, res) => {
      const { password, token } = req.body;
      const decoded = jwt.verify(token, secretKey);
      const email = decoded.email;
      const result = await usersCollection.findOneAndUpdate(
        { email: email },
        { $set: { password: password } },
        { returnOriginal: false }
      );

      if (!result) {
        return res.status(404).json({ message: "User not found" });
      }
      return res.status(200).json({ message: "Password updated successfully" });
    });

    const upload = multer({ storage: storage });
    app.post("/file", upload.single("file"), function (req, res, next) {
      const file = req.file;
      const fileUrl = `${req.protocol}://${req.get("host")}/uploads/${
        file.filename
      }`;
      res.send(`${fileUrl}`);
    });

    app.post("/submittedData", async (req, res) => {
      try {
        // Get the uploaded file from the request
        const articleType = req.body.articleType;
        const title = req.body.title;
        const email = req.body.email;
        const abstract = req.body.abstract;
        const keyword = req.body.keyword;
        const url = req.body.url;
        const fileName = req.body.fileName;
        const comment = req.body.comment;
        const reviewer = req.body.reviewer;

        const currentDate = new Date();
        const timeOptions = {
          timeZone: "Asia/Dhaka",
          hour12: true,
          hour: "2-digit",
          minute: "2-digit",
        };
        const dateOptions = {
          month: "long",
          day: "numeric",
          year: "numeric",
        };
        const timeFormat = new Intl.DateTimeFormat("en-US", timeOptions);
        const dateFormat = new Intl.DateTimeFormat("en-US", dateOptions);
        const currentTime = timeFormat.format(currentDate);
        const currentDateString = dateFormat.format(currentDate);

        const year = currentDate.getFullYear();
        const month = (currentDate.getMonth() + 1).toString().padStart(2, "0");

        const count = await dataCollection.countDocuments();
        const currentPaperNo = count + 1; //4+1=5
        const paddedPaperNo = currentPaperNo.toString().padStart(3, "0");
        const uniqueID = `${year}-${month}-${paddedPaperNo}`;

        // Store the file in MongoDB
        const db = client.db("ejournal20");
        const collection = db.collection("submittedData");

        const result = await collection.insertOne({
          submissionTime: currentTime,
          submissionDate: currentDateString,
          articleId: uniqueID,
          url: url,
          email: email,
          fileName: fileName,
          title: title,
          articleType: articleType,
          abstract: abstract,
          keyword: keyword,
          reviewer: reviewer,
          comment: comment,
        });

        // Send a success response
        res.send(`File uploaded successfully. ID: ${result.insertedId}`);
      } catch (error) {
        res.status(500).send(error.message);
      }
    });

    app.get("/jwt", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };

      const user = (await usersCollection) || reviewerCollection.findOne(query);

      if (user) {
        const token = jwt.sign({ email }, secretKey, {
          expiresIn: "72h",
        });

        return res.send({ accessToken: token });
      }

      res.status(403).send({ accessToken: "" });
    });

    app.get("/getReviewer", async (req, res) => {
      try {
        const users = await reviewerCollection.find().toArray();
        return res.send(users);
      } catch (error) {
        console.error(error);
        return res
          .status(500)
          .send({ success: false, error: "Internal Server Error" });
      }
    });

    const { ObjectId } = require("mongodb");
    //!!
    app.get("/submittedData/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const objectId = ObjectId(id);
        const user = await dataCollection.findOne({ _id: objectId });
        if (!user) {
          res.status(404).send("Data not found");
          return;
        }
        const fileurl = user.url;

        res.send(user);
      } catch (err) {
        console.error(err);
        res.status(500).send("An error occurred while retrieving data");
      }
    });

    //get data collection
    app.get("/submittedData", verifyJWT, async (req, res) => {
      const decoded = req.decoded;
      if (decoded.email !== req.query.email) {
        return res.status(401).send({ message: "Unauthorized Access" });
      }
      let query = {};

      if (req.query.email) {
        query = {
          email: req.query.email,
        };
      }
      const cursor = dataCollection.find(query);
      const data = await cursor.toArray();
      res.send(data);
    });

    app.get("/adminData", async (req, res) => {
      const query = {};
      const cursor = dataCollection.find(query);
      const data = await cursor.toArray();
      res.send(data);
    });

    app.get("/revData", async (req, res) => {
      const email = req.query.email;

      const cursor = dataCollection.find({ assignReviewerEmail: email });
      const data = await cursor.toArray();
      res.send(data);
    });

    //npm run start-dev

    app.get("/uploads/:filename", (req, res) => {
      const { filename } = req.params;
      const filePath = path.join(__dirname, "uploads", filename);
      res.sendFile(filePath);
    });

    app.get("/uploads", (req, res) => {
      const uploadFolder = path.join(__dirname, "uploads");

      fs.readdir(uploadFolder, (err, files) => {
        if (err) {
          res.status(500).send("Error retrieving files");
        } else {
          res.send(files);
        }
      });
    });

    app.get("/author", async (req, res) => {
      // Get the email parameter from the request query string
      const email = req.query.email;

      try {
        // Execute the queries on both collections asynchronously
        const [usersData, reviewerData] = await Promise.all([
          usersCollection.find({ email: email }).toArray(),
          reviewerCollection.find({ email: email }).toArray(),
        ]);
        const combinedData = [...usersData, ...reviewerData];
        res.send(combinedData);
      } catch (error) {
        res.status(500).send("Internal Server Error");
      }
    });

    app.get("/users/admin", async (req, res) => {
      const query = {};
      const user = await usersCollection.find(query).toArray();
      res.send(user);
    });

    app.get("/allUserData", async (req, res) => {
      const query = {};
      const user = await usersCollection.find(query).toArray();
      res.send(user);
    });
    // Editor GET Coding
    app.get("/reviewer", async (req, res) => {
      const editor = await reviewerCollection.find({ query }).toArray();
      res.send(editor);
    });

    app.get("/users/admin/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email };

      const user = await usersCollection.findOne(query);
      res.send({ isAdmin: user?.role === "admin" });
    });

    //find reviwere
    app.get("/users/reviewer/:email", async (req, res) => {
      try {
        const email = req.params.email;
        const query = { email };

        const user = await reviewerCollection.findOne(query);

        if (user) {
          res.send({ isReviewer: true });
        } else {
          res.send({ isReviewer: false });
        }
      } catch (error) {
        res
          .status(500)
          .send({ error: "An error occurred while fetching the reviewer." });
      }
    });

    app.get("/reviewer/:email", async (req, res) => {
      const email = req.params.email;
      const query = { email };

      const user = await reviewerCollection.findOne(query);
      res.send(user);
      if (!user) {
        return res.status(404).send(`No user found with  ${email}`);
      }
    });

    app.delete("/submittedData/:id", (req, res) => {
      dataCollection
        .deleteOne({ _id: ObjectId(req.params.id) })
        .then((result) => {
          res.send(result.deletedCount > 0);
        });
    });

    //UPDATE PUT Opatation
    app.put("/users/admin/:id", verifyJWT, async (req, res) => {
      const decodedEmail = req.decoded.email;
      const query = { email: decodedEmail };
      const user = await usersCollection.findOne(query);
      if (user?.role !== "admin") {
        return res.status(401).send({ message: "Unauthorized Access" });
      }
      const id = req.params.id;
      const filter = { _id: ObjectId(id) };
      const updateDoc = {
        $set: {
          role: "admin",
        },
      };
      const options = { returnOriginal: false };

      try {
        const result = await usersCollection.findOneAndUpdate(
          filter,
          updateDoc,
          options
        );
        res.send(result);
      } catch (error) {
        console.error(error);
        res.status(500).send(error);
      }
    });

    app.put("/assign/:id", async (req, res) => {
      const id = req.params.id;
      const { assignReviewer, assignReviewerEmail } = req.body;
      const filter = { _id: ObjectId(id) };
      const updateDoc = {
        $set: {
          assignReviewer: assignReviewer,
          assignReviewerEmail: assignReviewerEmail,
        },
      };
      const options = { returnOriginal: false };

      try {
        const result = await dataCollection.findOneAndUpdate(
          filter,
          updateDoc,
          options
        );

        // Check if the document was updated
        if (!result.value) {
          return res.status(404).send({ message: "Document not found" });
        }

        res.send(result);
      } catch (error) {
        res.status(500).send(error);
      }
    });

    app.put("/reviewerComment/:id", async (req, res) => {
      const id = req.params.id;
      const {
        contentAbtract,
        methodOriginality,
        referenceOriginality,
        ethicalConsiderations,
        experimentalResultOriginality,
      } = req.body;
      const filter = { _id: ObjectId(id) };
      const updateDoc = {
        $set: {
          contentAbtract: contentAbtract,
          methodOriginality: methodOriginality,
          referenceOriginality: referenceOriginality,
          ethicalConsiderations: ethicalConsiderations,
          experimentalResultOriginality: experimentalResultOriginality,
        },
      };
      const options = { returnOriginal: false };

      try {
        const result = await dataCollection.findOneAndUpdate(
          filter,
          updateDoc,
          options
        );
        if (!result.value) {
          return res.status(404).send({ message: "Document not found" });
        }

        res.send(result);
      } catch (error) {
        res.status(500).send(error);
      }
    });

    app.put("/editorComment/:id", async (req, res) => {
      const id = req.params.id;
      const { editorComment } = req.body;
      const filter = { _id: ObjectId(id) };
      const updateDoc = {
        $set: {
          editorComment: editorComment,
        },
      };
      const options = { returnOriginal: false };
      try {
        const result = await dataCollection.findOneAndUpdate(
          filter,
          updateDoc,
          options
        );
        if (!result.value) {
          return res.status(404).send({ message: "Document not found" });
        }
        res.send(result);
      } catch (error) {
        res.status(500).send(error);
      }
    });

    app.put("/authorData/:email", async (req, res) => {
      const email = req.params.email;
      const user = req.body;
      const filter = { email: email };
      const options = { upsert: true };
      const updateUser = {};
      if (user.authorName !== null && user.authorName !== undefined) {
        updateUser.authorName = user.authorName;
      }
      if (user.reviewerName !== null && user.reviewerName !== undefined) {
        updateUser.reviewerName = user.reviewerName;
      }

      if (user.phone !== null && user.phone !== undefined) {
        updateUser.phone = user.phone;
      }
      if (user.institutionName !== null && user.institutionName !== undefined) {
        updateUser.institutionName = user.institutionName;
      }
      if (user.department !== null && user.department !== undefined) {
        updateUser.department = user.department;
      }
      if (user.city !== null && user.city !== undefined) {
        updateUser.city = user.city;
      }
      if (user.postalCode !== null && user.postalCode !== undefined) {
        updateUser.postalCode = user.postalCode;
      }
      if (user.imageUrl !== null && user.imageUrl !== undefined) {
        updateUser.profilePic = user.imageUrl;
      }

      const updatedUser = {
        $set: updateUser,
      };

      try {
        let result;
        let collectionName;

        // Check if the email exists in the usersCollection
        const usersDoc = await usersCollection.findOne(filter);
        if (usersDoc) {
          result = await usersCollection.updateOne(
            filter,
            updatedUser,
            options
          );
          collectionName = "usersCollection";
        } else {
          // Check if the email exists in the reviewerCollection
          const reviewerDoc = await reviewerCollection.findOne(filter);
          if (reviewerDoc) {
            result = await reviewerCollection.updateOne(
              filter,
              updatedUser,
              options
            );
            collectionName = "reviewerCollection";
          } else {
            throw new Error("No document found with the provided email");
          }
        }

        const updateResult = {
          collection: collectionName,
          result: result,
        };

        res.send(updateResult);
      } catch (err) {
        console.error(err);
        res.status(500).send(err);
      }
    });
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Welcome to E-journal Server ");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
