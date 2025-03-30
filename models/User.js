const pool = require('../config/db');

class User {
  static async findByEmail(email) {
    try {
      console.log("Executing query to find user by email:", email); // Debug log
      const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
      console.log("Query result for email:", email, rows); // Debug log
      if (rows.length === 0) {
        console.log("No user found with email:", email); // Debug log
      }
      return rows[0];
    } catch (error) {
      console.error("Error fetching user by email:", error); // Log the error
      throw error;
    }
  }

  static async findByUsername(username) {
    try {
      console.log("Executing query to find user by username:", username); // Debug log
      const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
      console.log("Query result for username:", username, rows); // Debug log
      if (rows.length === 0) {
        console.log("No user found with username:", username); // Debug log
      }
      return rows[0];
    } catch (error) {
      console.error("Error fetching user by username:", error); // Log the error
      throw error;
    }
  }

  static async create(user) {
    try {
      const { username, email, password } = user;
      console.log("Executing query to create user:", user); // Debug log
      const [result] = await pool.query(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, password]
      );
      console.log("User created with ID:", result.insertId); // Debug log
      return { id: result.insertId, username, email };
    } catch (error) {
      console.error("Error creating user:", error.message, error.stack); // Enhanced error logging
      throw error;
    }
  }

  static async findById(id) {
    const [rows] = await pool.query('SELECT id, username, email FROM users WHERE id = ?', [id]);
    return rows[0];
  }
}

module.exports = User;