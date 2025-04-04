const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const passwordController = require('../controllers/passwordController');
const reportController = require('../controllers/reportController'); // Make sure this path is correct
const rateLimit = require('express-rate-limit');

// Rate limiting configurations
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  message: 'Too many OTP requests from this IP, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});



// Authentication Routes
router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/google-login', authController.googleLogin);

// Password Recovery Routes
router.post('/send-otp', otpLimiter, passwordController.sendOTP);
router.post('/verify-otp', passwordController.verifyOTP);
router.post('/reset-password', passwordController.resetPassword);
router.post('/forgot-password', otpLimiter, passwordController.forgotPassword);


module.exports = router;