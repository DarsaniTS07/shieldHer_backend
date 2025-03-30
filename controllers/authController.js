const bcrypt = require("bcryptjs"); // This is the corrected import
const jwt = require("jsonwebtoken");
const User = require("../models/User");
require("dotenv").config();

// Correct Usage
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
};

const authController = {
  async login(req, res) {
    try {
      const { email, password } = req.body;

      console.log("Login request received:", { email, password }); // Debug log

      if (!email || !password) {
        console.log("Missing email or password in request body"); // Debug log
        return res.status(400).json({ message: "Email and password are required" });
      }

      // 1. Check if user exists
      const user = await User.findByEmail(email);
      console.log("User found in database:", user); // Debug log
      if (!user) {
        console.log("No user found with email:", email); // Debug log
        return res.status(401).json({ message: "Invalid credentials (user not found)" });
      }

      // 2. Validate password
      const isMatch = await bcrypt.compare(password, user.password);
      console.log("Password validation result:", isMatch); // Debug log
      if (!isMatch) {
        console.log("Password mismatch for user:", email); // Debug log
        return res.status(401).json({ message: "Invalid credentials (wrong password)" });
      }

      // 3. Create JWT token
      const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      // 4. Send response
      console.log("Login successful for user:", email); // Debug log
      res.json({
        message: "Login successful",
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
        },
      });
    } catch (error) {
      console.error("Error during login:", error); // Log the error
      res.status(500).json({ message: "Server error" });
    }
  },

  async register(req, res) {
    try {
      const { username, email, password } = req.body;

      console.log("Register request received:", { username, email }); // Debug log

      if (!username || !email || !password) {
        console.log("Missing fields in request body"); // Debug log
        return res.status(400).json({ message: "All fields are required" });
      }

      // Check if username already exists
      const existingUsername = await User.findByUsername(username);
      console.log("Existing username check result:", existingUsername); // Debug log
      if (existingUsername) {
        return res.status(400).json({ message: "Username already exists" });
      }

      // Check if email already exists
      const existingUser = await User.findByEmail(email);
      console.log("Existing user check result:", existingUser); // Debug log
      if (existingUser) {
        return res.status(400).json({ message: "Email already exists" });
      }

      // Hash the password
      const hashedPassword = await hashPassword(password);
      console.log("Password hashed successfully"); // Debug log

      // Create the user
      const newUser = await User.create({ username, email, password: hashedPassword });
      console.log("User created successfully:", newUser); // Debug log

      res.status(201).json({
        message: "User registered successfully",
        user: {
          id: newUser.id,
          username: newUser.username,
          email: newUser.email,
        },
      });
    } catch (error) {
      console.error("Error during registration:", error.message, error.stack); // Enhanced error logging
      res.status(500).json({ message: "Server error", error: error.message }); // Include error message in response for debugging
    }
  },
};

module.exports = authController;
