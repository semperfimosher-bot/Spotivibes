const express = require("express");

const pool = require("../database");

const {
  requireLogin
} = require("../middleware/auth.middleware");

const {
  getFileUrl
} = require("../services/storage.service");

const router = express.Router();

router.post("/custom", requireLogin, async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Missing playlist name"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO playlists
      (user_id, name, query, is_generated)
      VALUES ($1, $2, $3, false)
      RETURNING *
      `,
      [req.session.user.id, name, name]
    );

    res.json({
      success: true,
      playlist: result.rows[0]
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to create playlist"
    });
  }
});

router.post("/remove", requireLogin, async (req, res) => {
  const client = await pool.connect();

  try {
    const { playlistId } = req.body;

    if (!playlistId) {
      return res.status(400).json({ error: "Missing playlistId" });
    }

    await client.query("BEGIN");

    const ownerCheck = await client.query(
      `
      SELECT id
      FROM playlists
      WHERE id = $1
      AND user_id = $2
      `,
      [playlistId, req.session.user.id]
    );

    if (!ownerCheck.rows.length) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Playlist not found or not owned by user"
      });
    }

    await client.query(
      "DELETE FROM playlist_songs WHERE playlist_id = $1",
      [playlistId]
    );

    await client.query(
      "DELETE FROM playlists WHERE id = $1 AND user_id = $2",
      [playlistId, req.session.user.id]
    );

    await client.query("COMMIT");

    res.json({ success: true, deletedId: playlistId });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("REMOVE PLAYLIST ERROR:", err);
    res.status(500).json({ error: "Failed to remove playlist" });
  } finally {
    client.release();
  }
});

router.post("/add-song", requireLogin, async (req, res) => {
  try {

    const {
      playlistId,
      playlistName,
      songId
    } = req.body;

    let playlist;

    if (playlistId) {

      const result = await pool.query(
        `
        SELECT *
        FROM playlists
        WHERE id = $1
        AND user_id = $2
        `,
        [playlistId, req.session.user.id]
      );

      playlist = result.rows[0];

    } else {

      const result = await pool.query(
        `
        SELECT *
        FROM playlists
        WHERE name = $1
        AND user_id = $2
        `,
        [playlistName, req.session.user.id]
      );

      playlist = result.rows[0];
    }

    if (!playlist) {
      return res.status(404).json({
        error: "Playlist not found"
      });
    }

    await pool.query(
      `
      INSERT INTO playlist_songs
      (playlist_id, song_id)
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
      `,
      [playlist.id, songId]
    );

    res.json({ success: true });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Failed to add song"
    });
  }
});

/* ---------------- PLAYLIST BUILDER HELPER ---------------- */

async function buildGeneratedPlaylist(userId, query, songs) {
  const name = `Created for ${query}`;

  const playlistResult = await pool.query(
    `
    INSERT INTO playlists (user_id, name, query, is_generated)
    VALUES ($1, $2, $3, true)
    RETURNING id
    `,
    [userId, name, query]
  );

  const playlistId = playlistResult.rows[0].id;

  for (const song of songs) {
    await pool.query(
      `
      INSERT INTO playlist_songs (playlist_id, song_id)
      VALUES ($1, $2)
      ON CONFLICT DO NOTHING
      `,
      [playlistId, song.id]
    );
  }

  return playlistId;
}

/* ---------------- SAVE PLAYLIST ---------------- */

router.post("/save", requireLogin, async (req, res) => {
  try {
    const { name, query, songs } = req.body;

    if (!name || !Array.isArray(songs)) {
      return res.status(400).json({
        error: "Missing playlist name or songs"
      });
    }

    const playlistResult = await pool.query(
      `
      INSERT INTO playlists (user_id, name, query, is_generated)
      VALUES ($1, $2, $3, true)
      RETURNING id
      `,
      [req.session.user.id, name, query || name]
    );

    const playlistId = playlistResult.rows[0].id;

    for (const song of songs) {
      if (!song.id) continue;

      await pool.query(
        `
        INSERT INTO playlist_songs (playlist_id, song_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [playlistId, song.id]
      );
    }

    res.json({
      success: true,
      playlistId
    });

  } catch (err) {
    console.error("SAVE PLAYLIST ERROR:", err);

    res.status(500).json({
      error: "Failed to save playlist"
    });
  }
});

/* ---------------- GET USER PLAYLISTS ---------------- */

router.get("/", requireLogin, async (req, res) => {
  try {
    const playlists = await pool.query(
      `
      SELECT *
      FROM playlists
      WHERE user_id = $1
      ORDER BY created_at DESC
      `,
      [req.session.user.id]
    );

    res.json({
      playlists: playlists.rows || []
    });

  } catch (err) {
    console.error("GET PLAYLISTS ERROR:", err);

    res.status(500).json({
      error: "Failed to fetch playlists"
    });
  }
});

/* ---------------- GET PLAYLIST DETAILS ---------------- */

router.get("/:id", requireLogin, async (req, res) => {
  try {
    const playlistResult = await pool.query(
      `
      SELECT *
      FROM playlists
      WHERE id = $1
      AND user_id = $2
      `,
      [req.params.id, req.session.user.id]
    );

    const playlist = playlistResult.rows[0];

    if (!playlist) {
      return res.status(404).json({
        error: "Playlist not found"
      });
    }

    const songsResult = await pool.query(
      `
      SELECT songs.*
      FROM playlist_songs
      JOIN songs
        ON songs.id = playlist_songs.song_id
      WHERE playlist_songs.playlist_id = $1
      `,
      [playlist.id]
    );

    const songs = await Promise.all(
      songsResult.rows.map(async (song) => ({
        id: song.id,
        title: song.title,
        artist: song.artist,
        genre: song.genre,
        album: song.album,
        year: song.year,
        lyrics: song.lyrics,
        audioUrl: await getFileUrl(song.audio_url),
        coverUrl: song.cover_url
          ? await getFileUrl(song.cover_url)
          : null
      }))
    );

    res.json({
      playlist,
      songs
    });

  } catch (err) {
    console.error("GET PLAYLIST DETAILS ERROR:", err);

    res.status(500).json({
      error: "Failed to load playlist"
    });
  }
});

module.exports = router;