const express = require("express");
const pool = require("../database");
const { requireLogin } = require("../middleware/auth.middleware");

const router = express.Router();

router.get("/", requireLogin, async (req, res) => {
  const result = await pool.query(
    `
    SELECT * FROM listening_stats
    WHERE user_id = $1
    `,
    [req.session.user.id]
  );

  res.json({
    stats: result.rows[0]?.data || {}
  });
});

router.post("/play", requireLogin, async (req, res) => {
  const { songId } = req.body;

  await pool.query(
    `
    INSERT INTO listening_history (user_id, song_id)
    VALUES ($1, $2)
    `,
    [req.session.user.id, songId]
  );

  res.json({ success: true });
});

module.exports = router;