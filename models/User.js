const pool = require('../config/db');

class User {
  static async findByEmail(email) {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    return rows[0];
  }

  static async create(user) {
    const { username, email, password } = user;
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, password]
    );
    return { id: result.insertId, username, email };
  }

  static async findById(id) {
    const [rows] = await pool.query('SELECT id, username, email FROM users WHERE id = ?', [id]);
    return rows[0];
  }
}

module.exports = User;