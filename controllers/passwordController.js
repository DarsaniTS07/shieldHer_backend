const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../models/User");
const nodemailer = require('nodemailer');
require('dotenv').config();

// Corrected transporter configuration
const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,  // Changed from 25 to 587 (standard TLS port)
  secure: false,  // Uncommented this line
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

// Verify SMTP connection
const verifySMTPConnection = async () => {
  try {
    await transporter.verify();
    console.log('SMTP Server is ready to send messages');
    return true;
  } catch (error) {
    console.error('SMTP Connection Error:', error);
    return false;
  }
};

// Execute verification on module load
verifySMTPConnection();

exports.sendOTP = async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, message: "Email is required" });
  }

  try {
    const user = await User.findByEmail(email);
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = Date.now() + 15 * 60 * 1000; // 15 minutes

    if (user) {
      await User.updateResetToken(user.id, otp, otpExpires);
    }

    const mailOptions = {
      from: `"ShieldHer Support" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your OTP Code',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2563eb;">OTP Verification</h2>
          <p>Your verification code is:</p>
          <div style="background: #f3f4f6; padding: 20px; text-align: center; font-size: 24px; letter-spacing: 2px; margin: 20px 0;">
            <strong>${otp}</strong>
          </div>
          <p>This code will expire in 15 minutes.</p>
        </div>
      `
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.response);
    
    return res.json({
      success: true,
      message: "OTP sent successfully",
      email: email
    });

  } catch (error) {
    console.error("Email sending error:", error);
    return res.status(500).json({
      success: false,
      message: "Failed to send OTP email",
      error: error.message
    });
  }
};

exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;
  
  if (!email || !otp) {
    return res.status(400).json({ 
      success: false,
      message: "Email and OTP are required" 
    });
  }

  try {
    const user = await User.findByEmail(email);
    
    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid OTP" 
      });
    }
    
    console.log(`Verifying OTP for user ${user.id}. Received: ${otp}, Stored: ${user.reset_token}`);
    
    if (!user.reset_token || user.reset_token !== otp) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid OTP" 
      });
    }

    if (Date.now() > user.reset_token_expires) {
      return res.status(400).json({ 
        success: false,
        message: "OTP has expired" 
      });
    }

    return res.json({ 
      success: true,
      message: "OTP verified successfully",
      verified: true
    });

  } catch (error) {
    console.error("OTP verification error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Server error during OTP verification",
      error: error.message 
    });
  }
};

exports.resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  
  if (!email || !otp || !newPassword) {
    return res.status(400).json({ 
      success: false,
      message: "Email, OTP and new password are required" 
    });
  }

  try {
    const user = await User.findByEmail(email);
    
    if (!user || user.reset_token !== otp) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid OTP" 
      });
    }

    if (Date.now() > user.reset_token_expires) {
      return res.status(400).json({ 
        success: false,
        message: "OTP has expired" 
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ 
        success: false,
        message: "Password must be at least 8 characters" 
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.updatePassword(user.id, hashedPassword);
    await User.clearResetToken(user.id);

    return res.json({ 
      success: true,
      message: "Password updated successfully" 
    });

  } catch (error) {
    console.error("Password reset error:", error);
    return res.status(500).json({ 
      success: false,
      message: "Server error during password update",
      error: error.message 
    });
  }
};

// Keep this for compatibility, but will use sendOTP instead
exports.forgotPassword = async (req, res) => {
  exports.forgotPassword = async (req, res, next) => {
    try {
      const { email } = req.body;
      const user = await User.findByEmail(email);
      
      if (!user) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }
      
      // Don't allow password reset for Google-authenticated users
      if (user.google_id) {
        return res.status(400).json({ 
          success: false, 
          message: 'Google-authenticated users must use Google login' 
        });
        return exports.sendOTP(req, res);
      }
    } catch (err) {
      next(err);
    }
  }
};