const jwt = require('jsonwebtoken');
require('dotenv').config();

module.exports = (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        success: false,
        message: 'No token, authorization denied' 
      });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add more user info to the request
    req.user = {
      id: decoded.id,
      email: decoded.email,
      authMethod: decoded.authMethod // Add this to your JWT payload
    };
    
    next();
  } catch (error) {
    console.error('JWT Error:', error);
    res.status(401).json({ 
      success: false,
      message: 'Invalid or expired token' 
    });
  }
};