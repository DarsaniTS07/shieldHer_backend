const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const passwordController = require('../controllers/passwordController');
const rateLimit = require('express-rate-limit');

// Rate limiting for OTP requests
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // Limit each IP to 3 OTP requests per window
  message: 'Too many OTP requests from this IP, please try again later'
});

// Authentication routes
router.post('/login', authController.login);
router.post('/register', authController.register);
// Add this with other authentication routes
router.post('/google-login', authController.googleLogin);

// Password routes with rate limiting
router.post('/send-otp', otpLimiter, passwordController.sendOTP);
router.post('/verify-otp', passwordController.verifyOTP);
router.post('/reset-password', passwordController.resetPassword);
router.post('/forgot-password', otpLimiter, passwordController.forgotPassword);

module.exports = router;