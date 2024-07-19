const express = require("express");
const path = require("path");
const app = express();
const port = 3000;
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const users = []; // In-memory user storage, replace with database in production

app.use(express.static(path.join(__dirname, "public")));

app.use(bodyParser.json());

// Serve the main HTML file
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Registration route
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  // Simple validation
  if (!name || !email || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  // Check if the user already exists
  const existingUser = users.find((user) => user.email === email);
  if (existingUser) {
    return res.status(400).json({ message: "User already exists" });
  }

  // Save the user
  const newUser = { name, email, password }; // Hash password in production
  users.push(newUser);

  res.status(201).json({ message: "User registered successfully" });
});

// Login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Find the user
  const user = users.find(
    (user) => user.email === email && user.password === password
  );
  if (!user) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  // Generate a token
  const token = jwt.sign({ email: user.email }, "your_jwt_secret", {
    expiresIn: "1h",
  });

  res.json({ token });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
