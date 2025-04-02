const express = require("express");
const router = express.Router();

router.post("/check-phishing", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    // Call your phishing check logic here
    res.json({ message: "Phishing check successful", isPhishing: false });
  } catch (error) {
    console.error("Backend Error:", error.message);
    res.status(500).json({ error: `Server Error: ${error.message}` });
  }
});

module.exports = router;
