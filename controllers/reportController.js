const Report = require('../models/Report');
const nodemailer = require('nodemailer');
require('dotenv').config();

// Field length constants
const FIELD_LIMITS = {
  incidentType: 100,
  description: 2000,
  email: 100,
  contactNumber: 20
};

// Improved email sending function
async function sendReportEmail(report) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('Email credentials not configured');
    return;
  }

  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      },
      logger: true,
      debug: true,
      tls: {
        rejectUnauthorized: false
      }
    });

    const mailOptions = {
      from: `${report.email}`,
      to: "darsanits9781@gmail.com",
      subject: `Report #${report.id} Received`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #1a3b5c;">Your Report (#${report.id})</h2>
          <div style="background: #f5f7fa; padding: 20px; border-radius: 8px;">
            <p><strong>Type:</strong> ${report.incident_type}</p>
            <p><strong>Status:</strong> ${report.status}</p>
            ${report.description ? `<p><strong>Description:</strong> ${report.description}</p>` : ''}
          </div>
          <p style="margin-top: 20px;">We'll contact you shortly regarding this matter.</p>
          <p style="font-size: 12px; color: #888; margin-top: 30px;">
            This is an automated message. Please do not reply directly to this email.
          </p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.messageId);
    return info;
  } catch (error) {
    console.error('Error sending email:', error);
    throw error;
  }
}

const submitCyberReport = async (req, res) => {
  try {
    const { incidentType, description, email, contactNumber } = req.body;
    
    // Validate required fields
    if (!incidentType || !email) {
      return res.status(400).json({
        success: false,
        message: 'Incident type and email are required'
      });
    }

    // Validate email format
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({
        success: false,
        message: 'Please provide a valid email address'
      });
    }

    // Create report with explicit status
    const report = await Report.create({
      user_id: req.user?.id || null,
      incident_type: incidentType,
      description: description || null,
      email,
      contact_number: contactNumber || null,
      status: 'received'
    });

    // Send email notification (don't await to not block response)
    sendReportEmail(report)
      .then(() => console.log('Confirmation email sent successfully'))
      .catch(emailError => console.error('Email sending failed:', emailError));

    res.status(201).json({
      success: true,
      message: 'Report submitted successfully',
      data: report
    });

  } catch (error) {
    console.error('Report submission error:', error);
    
    const statusCode = error.message.includes('Invalid status') ? 400 : 500;
    const message = error.message.includes('Invalid status') 
      ? error.message 
      : 'Failed to submit report';

    res.status(statusCode).json({
      success: false,
      message,
      ...(process.env.NODE_ENV === 'development' && { error: error.message })
    });
  }
};

const getReportById = async (req, res) => {
  try {
    const report = await Report.findById(req.params.id);
    
    if (!report) {
      return res.status(404).json({
        success: false,
        message: 'Report not found'
      });
    }

    // Authorization check
    if (req.user && report.user_id !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: 'Unauthorized access'
      });
    }

    res.status(200).json({
      success: true,
      data: report
    });

  } catch (error) {
    console.error('Get report error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

module.exports = {
  submitCyberReport,
  getReportById,
  sendReportEmail
};