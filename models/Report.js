const pool = require('../config/db');

module.exports = {
  async create({ user_id, incident_type, description, email, contact_number, status = 'received' }) {
    try {
      // Validate status value
      const validStatuses = ['pending', 'received', 'in_progress', 'resolved'];
      if (!validStatuses.includes(status)) {
        throw new Error(`Invalid status value. Must be one of: ${validStatuses.join(', ')}`);
      }

      // Truncate all fields to ensure they fit in the database
      const [result] = await pool.query(
        `INSERT INTO reports 
         (user_id, incident_type, description, email, contact_number, status) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
          user_id,
          incident_type?.substring(0, 100) || null,
          description?.substring(0, 2000) || null,
          email?.substring(0, 100),
          contact_number?.substring(0, 20) || null,
          status.substring(0, 20) // Ensure status fits in the column
        ]
      );
      
      return this.findById(result.insertId);
      
    } catch (error) {
      console.error('Error creating report:', error);
      
      if (error.code === 'ER_DATA_TOO_LONG' || error.errno === 1265) {
        throw new Error('Data too long for one or more fields. Please check your input.');
      }
      
      throw error;
    }
  },


  async findById(id) {
    const [rows] = await pool.query('SELECT * FROM reports WHERE id = ?', [id]);
    return rows[0];
  },

  async findByUserId(user_id) {
    const [rows] = await pool.query('SELECT * FROM reports WHERE user_id = ? ORDER BY created_at DESC', [user_id]);
    return rows;
  },

  async findByEmail(email) {
    const [rows] = await pool.query('SELECT * FROM reports WHERE email = ? ORDER BY created_at DESC', [email]);
    return rows;
  },

  async updateStatus(id, status) {
    await pool.query(
      'UPDATE reports SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [status, id]
    );
    return this.findById(id);
  },

  async getAll(limit = 50, offset = 0) {
    const [rows] = await pool.query(
      'SELECT * FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?',
      [limit, offset]
    );
    return rows;
  },

  async getCount() {
    const [rows] = await pool.query('SELECT COUNT(*) as count FROM reports');
    return rows[0].count;
  },

  async search(query) {
    const searchQuery = `%${query}%`;
    const [rows] = await pool.query(
      `SELECT * FROM reports 
       WHERE incident_type LIKE ? OR description LIKE ? OR email LIKE ?
       ORDER BY created_at DESC`,
      [searchQuery, searchQuery, searchQuery]
    );
    return rows;
  },

  async delete(id) {
    const [result] = await pool.query('DELETE FROM reports WHERE id = ?', [id]);
    return result.affectedRows > 0;
  },

  async getStats() {
    const [rows] = await pool.query(
      `SELECT 
        status, 
        COUNT(*) as count,
        DATE_FORMAT(created_at, '%Y-%m-%d') as date
       FROM reports
       GROUP BY status, date
       ORDER BY date DESC`
    );
    return rows;
  }
};