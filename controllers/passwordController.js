const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const User = require("../models/User");

const passwordController = {
  async forgotPassword(req, res) {
    try {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json({ message: "Email is required" });
      }

      const user = await User.findByEmail(email);
      if (!user) {
        return res.status(404).json({ message: "If this email exists, we've sent a reset link" });
      }

      const resetToken = crypto.randomBytes(20).toString("hex");
      const resetTokenExpires = Date.now() + 3600000; // 1 hour

      await User.updateResetToken(user.id, resetToken, resetTokenExpires);

      // TODO: Implement email sending here
      console.log(`Password reset link: http://localhost:5173/reset-password?token=${resetToken}`);

      res.json({
        message: "If this email exists, we've sent a reset link"
      });

    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).json({ message: "Server error during password reset" });
    }
  },

  async resetPassword(req, res) {
    try {
      const { token, newPassword } = req.body;
      
      if (!token || !newPassword) {
        return res.status(400).json({ message: "Token and new password are required" });
      }

      const user = await User.findByResetToken(token);
      
      if (!user || Date.now() > user.reset_token_expires) {
        return res.status(400).json({ message: "Invalid or expired token" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await User.updatePassword(user.id, hashedPassword);
      await User.clearResetToken(user.id);

      res.json({ message: "Password updated successfully" });

    } catch (error) {
      console.error("Password reset error:", error);
      res.status(500).json({ message: "Server error during password update" });
    }
  }
};

module.exports = passwordController;