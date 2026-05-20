const express = require("express");
const pool = require("../database");
const { requireLogin } = require("../middleware/auth.middleware");
const { getFileUrl } = require("../services/storage.service");

const router = express.Router();

router.get("/", requireLogin, async (req, res) => {
  const result = await pool.query(
    `
    SELECT songs.*
    FROM songs
    JOIN user_library
      ON songs.id = user_library.song_id
    WHERE user_library.user_id = $1
    ORDER BY songs.title ASC
    `,
    [req.session.user.id]
  );

  const songs = await Promise.all(
    result.rows.map(async s => ({
      id: s.id,
      title: s.title,
      artist: s.artist,
      genre: s.genre,
      album: s.album,
      year: s.year,
      lyrics: s.lyrics,
      audioUrl: await getFileUrl(s.audio_url),
      coverUrl: s.cover_url ? await getFileUrl(s.cover_url) : null
    }))
  );

  res.json({ songs });
});

router.post("/add", requireLogin, async (req, res) => {
  const { songId } = req.body;

  await pool.query(
    `
    INSERT INTO user_library (user_id, song_id)
    VALUES ($1, $2)
    ON CONFLICT DO NOTHING
    `,
    [req.session.user.id, songId]
  );

  res.json({ success: true });
});

router.post("/remove", requireLogin, async (req, res) => {
  const { songId } = req.body;

  await pool.query(
    `
    DELETE FROM user_library
    WHERE user_id = $1
    AND song_id = $2
    `,
    [req.session.user.id, songId]
  );

  res.json({ success: true });
});

module.exports = router;