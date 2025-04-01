const pool = require('../config/db');

module.exports = {
  async findByEmail(email) {
    const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    return rows[0];
  },

  async findByUsername(username) {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    return rows[0];
  },

  async create({ username, email, password }) {
    const [result] = await pool.query(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, password]
    );
    return { id: result.insertId, username, email };
  },

  async findById(id) {
    const [rows] = await pool.query('SELECT id, username, email FROM users WHERE id = ?', [id]);
    return rows[0];
  },

  async updateResetToken(id, token, expires) {
    await pool.query(
      'UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [token, expires, id]
    );
  },

  async findByResetToken(token) {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE reset_token = ? AND reset_token_expires > ?',
      [token, Date.now()]
    );
    return rows[0];
  },

  async updatePassword(id, password) {
    await pool.query(
      'UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [password, id]
    );
  },

  // Add these methods to your user model
async findByGoogleId(googleId) {
  const [rows] = await pool.query('SELECT * FROM users WHERE google_id = ?', [googleId]);
  return rows[0];
},

async createGoogleUser({ googleId, email, name, picture }) {
  const [result] = await pool.query(
    'INSERT INTO users (google_id, email, username, avatar, is_verified) VALUES (?, ?, ?, ?, ?)',
    [googleId, email, name, picture, true]
  );
  return { id: result.insertId, email, username: name };
},

  async clearResetToken(id) {
    await pool.query(
      'UPDATE users SET reset_token = NULL, reset_token_expires = NULL WHERE id = ?',
      [id]
    );
  }
};