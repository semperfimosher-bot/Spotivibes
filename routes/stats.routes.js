const express = require("express");
const pool = require("../database");
const { requireLogin } = require("../middleware/auth.middleware");

const router = express.Router();

router.get("/", requireLogin, async (req, res) => {
  const result = await pool.query(
    `
    SELECT songs.title, songs.artist, COUNT(*)::int AS plays
    FROM listening_history
    JOIN songs ON songs.id = listening_history.song_id
    WHERE listening_history.user_id = $1
    GROUP BY songs.artist, songs.title
    ORDER BY plays DESC
    `,
    [req.session.user.id]
  );

  const stats = {};

  result.rows.forEach(row => {
    if (!stats[row.artist]) stats[row.artist] = {};
    stats[row.artist][row.title] = row.plays;
  });

  res.json({ stats });
});

router.post("/play", requireLogin, async (req, res) => {
  const { songId } = req.body;


  const songCheck = await pool.query(
  "SELECT id FROM songs WHERE id = $1",
  [songId]
);

if (!songCheck.rows.length) {
  return res.status(404).json({
    error: "Song no longer exists"
  });
}

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