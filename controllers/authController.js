const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
require('dotenv').config();

const authController = {
  async login(req, res) {
    try {
      const { email, password } = req.body;
      
      // 1. Check if user exists
      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      // 2. Validate password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
      
      // 3. Create JWT token
      const token = jwt.sign(
        { userId: user.id },
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
      );
      
      // 4. Send response with user data (excluding password)
      const userData = {
        id: user.id,
        username: user.username,
        email: user.email
      };
      
      res.json({ 
        message: 'Login successful', 
        token, 
        user: userData 
      });
      
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  },

  async getUserDashboard(req, res) {
    try {
      // The userId is set by the auth middleware
      const user = await User.findById(req.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
      
      // Here you would typically fetch user-specific dashboard data
      res.json({ 
        message: 'Dashboard data', 
        user,
        dashboardData: {
          // Add user-specific dashboard data here
          stats: { /* ... */ },
          recentActivity: [ /* ... */ ]
        }
      });
      
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  }
};

module.exports = authController;