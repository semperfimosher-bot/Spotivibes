const express = require("express");

const router = express.Router();

router.get("/", (req, res) => {
  res.json({
    apiBase: process.env.API_BASE_URL || ""
  });
});

module.exports = router;