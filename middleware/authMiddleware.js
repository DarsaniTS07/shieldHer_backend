const jwt = require('jsonwebtoken');
const { promisify } = require('util');
require('dotenv').config();

const verifyToken = promisify(jwt.verify);

module.exports = async (req, res, next) => {
  // Skip authentication for report submission
  if (req.path === '/' && req.method === 'POST') {
    return next();
  }

  // Get token from headers or cookies
  let token;
  if (req.headers.authorization?.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies?.token) {
    token = req.cookies.token;
  }

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required',
      errorCode: 'AUTH_REQUIRED'
    });
  }

  try {
    const decoded = await verifyToken(token, process.env.JWT_SECRET);
    
    req.user = {
      id: decoded.id,
      email: decoded.email,
      role: decoded.role || 'user'
    };

    // Token refresh logic
    const now = Math.floor(Date.now() / 1000);
    if (decoded.exp - now < 600) {
      const newToken = jwt.sign(
        { id: decoded.id, email: decoded.email, role: decoded.role },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRES_IN || '1h' }
      );
      
      res.setHeader('X-Refreshed-Token', newToken);
      res.cookie('token', newToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000
      });
    }

    next();
  } catch (error) {
    // Clear invalid token
    res.clearCookie('token');
    
    const response = {
      success: false,
      message: 'Invalid token',
      errorCode: 'INVALID_TOKEN',
      shouldLogout: true
    };

    if (error.name === 'TokenExpiredError') {
      response.message = 'Session expired';
      response.errorCode = 'TOKEN_EXPIRED';
    }

    return res.status(401).json(response);
  }
};