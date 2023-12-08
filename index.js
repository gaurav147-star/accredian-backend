const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

dotenv.config();
const app = express();
app.use(express.json()); // to accept json data

app.use(cors());
app.use(cookieParser());
const PORT = process.env.PORT || 8000;

// MySQL Connection
const connection = mysql.createConnection({
  host: "localhost",
  user: "ggdb",
  password: "",
  database: "ggacc",
});

connection.connect((err) => {
  if (err) throw err;
  console.log("Connected to MySQL Database");
});

// Define API endpoints for login and signup
app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  // Check credentials against database
  connection.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    (error, results) => {
      if (error) {
        res.status(500).json({ error: "Internal Server Error" });
      } else {
        if (results.length > 0) {
          const user = results[0];
          // Compare hashed password
          bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) {
              res.status(401).json({ error: "Invalid credentials" });
            } else {
              // Here, you might generate and send a token for authentication
              const payload = { id: user.id, username: user.username }; // Customize payload as needed
              const token = jwt.sign(payload, "jwtToken", {
                expiresIn: "1d",
              });

              res.status(200).json({ message: "Login successful", token });
            }
          });
        } else {
          res.status(404).json({ error: "User not found" });
        }
      }
    }
  );
});

app.post("/api/signup", (req, res) => {
  const { username, email, password } = req.body;
  // Create the users table
  connection.query(
    `
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL
    )
    `,
    (err, result) => {
      if (err) {
        console.error("Error creating table:", err);
        return;
      }
      console.log("Users table created successfully");
    }
  );

  // Hash the password before storing it
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      res.status(500).json({ error: "Internal Server Error" });
    } else {
      // Store user in the database
      connection.query(
        "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
        [username, email, hashedPassword],
        (error, results) => {
          if (error) {
            console.error("User creation error:", error);
            res
              .status(400)
              .json({ error: "User creation failed", details: error.message }); // Send detailed error message
          } else {
            res.status(201).json({ message: "User created successfully" });
          }
        }
      );
    }
  });
});

// Logout route
app.get("/api/logout", (req, res) => {
  // Clear the token stored in the client (cookie in this case)
  res.clearCookie("token"); // Clears the token cookie

  res.status(200).json({ message: "Logout successful" });
});

app.get("/", (req, res) => {
  res.send("API Running!");
});

app.listen(PORT, () => {
  console.log(`Server running on PORT ${PORT}...`);
});
