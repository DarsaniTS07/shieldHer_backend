const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const authMiddleware = require('../middlewares/authMiddleware');
// Login route
router.post('/login', authController.login);

// Protected dashboard route
router.get('/dashboard', authMiddleware, authController.getUserDashboard);

module.exports = router;