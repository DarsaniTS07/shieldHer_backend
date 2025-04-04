const express = require('express');
const router = express.Router();
const reportController = require('../controllers/reportController');
const authMiddleware = require('../middleware/authMiddleware');
const rateLimit = require('express-rate-limit');

const reportLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5
});

router.post('/', reportLimiter, authMiddleware, reportController.submitCyberReport);
router.get('/:id', authMiddleware, reportController.getReportById);

module.exports = router;