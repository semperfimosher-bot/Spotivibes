const express = require("express");
const pool = require("../database");
const { requireLogin } = require("../middleware/auth.middleware");
const { getFileUrl } = require("../services/storage.service");

const router = express.Router();

router.get("/", requireLogin, async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 100);
  const cursor = Number(req.query.cursor) || null;

  const params = [req.session.user.id, limit];

  let cursorSql = "";
  if (cursor) {
    params.push(cursor);
    cursorSql = "AND songs.id < $3";
  }

  const result = await pool.query(
    `
    SELECT songs.id, songs.title, songs.artist, songs.genre, songs.album,
           songs.year, songs.duration, songs.cover_url
    FROM songs
    JOIN user_library ON songs.id = user_library.song_id
    WHERE user_library.user_id = $1
    ${cursorSql}
    ORDER BY songs.id DESC
    LIMIT $2
    `,
    params
  );

  res.json({
    songs: result.rows.map(s => ({
      id: s.id,
      title: s.title,
      artist: s.artist,
      genre: s.genre,
      album: s.album,
      year: s.year,
      duration: s.duration,
      coverUrl: getPublicCoverUrl(s.cover_url)
    })),
    nextCursor: result.rows.at(-1)?.id || null,
    hasMore: result.rows.length === limit
  });
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

  const result = await pool.query(
    `
    DELETE FROM user_library
    WHERE user_id = $1
    AND song_id = $2
    RETURNING song_id
    `,
    [req.session.user.id, songId]
  );

  if (!result.rows.length) {
    return res.status(404).json({
      error: "Song not found in library"
    });
  }

  res.json({ success: true });
});

module.exports = router;