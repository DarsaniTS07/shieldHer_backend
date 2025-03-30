const mysql = require('mysql2/promise');
require('dotenv').config();

(async () => {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME
    });
    
    console.log('✅ Successfully connected to MySQL!');
    const [rows] = await connection.query('SHOW TABLES LIKE "users"');
    if (rows.length === 0) {
      console.error('❌ Table "users" does not exist in the database.');
    } else {
      console.log('✅ Table "users" exists in the database.');
    }
    await connection.end();
  } catch (error) {
    console.error('❌ Connection failed:', error); // Log the error
  }
})();