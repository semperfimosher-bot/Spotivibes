const express = require("express");
const multer = require("multer");
const mm = require("music-metadata");

const pool = require("../database");

const {
  requireLogin,
  requireAdmin
} = require("../middleware/auth.middleware");

const {
  b2,
  getFileUrl,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectVersionsCommand
} = require("../services/storage.service");

const {
  addNotification
} = require("../services/notification.service");

const {
  fetchGenreFromITunes
} = require("../services/genre.service");

const {
  fetchLyrics
} = require("../services/lyrics.service");

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024,
    files: 50
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "audio/mpeg",
      "audio/mp4",
      "audio/mp3",
      "audio/wav",
      "image/jpeg",
      "image/png",
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Invalid file type"));
    }

    cb(null, true);
  }
});

/* ---------------- GET SONGS ---------------- */

router.get("/songs", requireLogin, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 100);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const result = await pool.query(
      `
      SELECT 
  id, title, artist, genre, album, mood, year, duration, cover_url, lyrics
      FROM songs
      ORDER BY id DESC
      LIMIT $1 OFFSET $2
      `,
      [limit, offset]
    );

    const songs = await Promise.all(
      result.rows.map(async (s) => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        genre: s.genre,
        album: s.album,
        mood: s.mood,
        year: s.year,
        duration: s.duration,
        lyrics: s.lyrics,
        coverUrl: s.cover_url ? await getFileUrl(s.cover_url) : null
      }))
    );

    res.json({
      songs,
      limit,
      offset,
      hasMore: songs.length === limit
    });

  } catch (err) {
    console.error("LOAD SONGS ERROR:", err);
    res.status(500).json({ error: "Failed to load songs" });
  }
});

router.get("/songs/:id/audio-url", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT audio_url FROM songs WHERE id = $1",
      [req.params.id]
    );

    const song = result.rows[0];

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    const audioUrl = await getFileUrl(song.audio_url);

    res.json({ audioUrl });
  } catch (err) {
    console.error("AUDIO URL ERROR:", err);
    res.status(500).json({ error: "Failed to get audio URL" });
  }
});

/* ---------------- DOWNLOAD SONG ---------------- */

router.get("/songs/:id/download", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM songs WHERE id = $1",
      [req.params.id]
    );

    const song = result.rows[0];

    if (!song) {
      return res.status(404).send("Song not found");
    }

    const command = new GetObjectCommand({
      Bucket: process.env.B2_BUCKET_NAME,
      Key: song.audio_url,
    });

    const file = await b2.send(command);

    const filename = `${song.title || "song"}.mp3`;

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${filename.replace(/"/g, "")}"`
    );

    res.setHeader(
      "Content-Type",
      file.ContentType || "audio/mpeg"
    );

    file.Body.on("error", (err) => {
      console.error("Stream error:", err);

      if (!res.headersSent) {
        res.status(500).send("Download failed");
      } else {
        res.destroy();
      }
    });

    file.Body.pipe(res);

  } catch (err) {
    console.error("DOWNLOAD ERROR:", err);
    res.status(500).send("Download failed");
  }
});

/* ---------------- UPLOAD SONGS ---------------- */

router.post("/upload-files", requireAdmin, upload.array("songs"), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ error: "No files uploaded" });
    }

    for (const file of req.files) {
      const fileKey = `songs/${Date.now()}-${file.originalname}`;

      let metadata = {};

      try {
        metadata = await mm.parseBuffer(file.buffer, file.mimetype);
      } catch (err) {
        console.warn("Could not read metadata:", file.originalname);
      }

      const title =
        metadata.common?.title || file.originalname;

      const artist =
        metadata.common?.artist || "Unknown";

      let genre =
        metadata.common?.genre?.[0] || null;

      if (!genre) {
        genre = await fetchGenreFromITunes({
          title,
          artist
        });
      }

      if (!genre) {
        genre = "unknown";
      }

      const album =
        metadata.common?.album || null;

      const duration =
        metadata.format?.duration || null;

      let coverKey = null;
      let lyrics = null;

      const year =
        metadata.common?.year?.toString() || null;

      try {
        lyrics = await fetchLyrics({
          title,
          artist,
          album,
          genre,
          duration,
          year
        });
      } catch (err) {
        console.warn("Lyrics fetch failed:", err.message);
      }

      const picture = metadata.common?.picture?.[0];

      if (picture) {
        const imageExt =
          picture.format === "image/png" ? "png" : "jpg";

        coverKey = `covers/${Date.now()}-${file.originalname}.${imageExt}`;

        await b2.send(
          new PutObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: coverKey,
            Body: picture.data,
            ContentType: picture.format,
          })
        );
      }

      await b2.send(
        new PutObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: fileKey,
          Body: file.buffer,
          ContentType: file.mimetype,
        })
      );

      await pool.query(
        `
        INSERT INTO songs 
        (title, artist, audio_url, genre, album, duration, cover_url, lyrics, year)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        `,
        [
          title,
          artist,
          fileKey,
          genre,
          album,
          duration,
          coverKey,
          lyrics,
          year
        ]
      );

      await addNotification(
        "SONG_UPLOADED",
        `Uploaded: ${file.originalname}`
      );
    }

    res.json({ success: true });

  } catch (err) {
    console.error("UPLOAD SONG ERROR:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

/* ---------------- DELETE SONG ---------------- */

router.delete("/songs/:id", requireAdmin, async (req, res) => {
  try {
    const songResult = await pool.query(
      "SELECT * FROM songs WHERE id = $1",
      [req.params.id]
    );

    const song = songResult.rows[0];

    if (!song) {
      return res.status(404).json({ error: "Not found" });
    }

    let fileKey = song.audio_url;

    if (fileKey && fileKey.includes("http")) {
      const url = new URL(fileKey);
      fileKey = url.pathname.split("/file/")[1];
    }

    const versions = await b2.send(
      new ListObjectVersionsCommand({
        Bucket: process.env.B2_BUCKET_NAME,
        Prefix: fileKey
      })
    );

    const allVersions = [
      ...(versions.Versions || []),
      ...(versions.DeleteMarkers || [])
    ];

    for (const v of allVersions) {
      if (v.Key === fileKey) {
        await b2.send(
          new DeleteObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fileKey,
            VersionId: v.VersionId
          })
        );
      }
    }

    await pool.query(
      "DELETE FROM songs WHERE id = $1",
      [req.params.id]
    );

    await addNotification(
      "SONG_DELETED",
      `Deleted: ${song.title}`
    );

    res.json({ success: true });

  } catch (err) {
    console.error("DELETE SONG ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------- SMART SEARCH ---------------- */

router.get("/smart-search", requireLogin, async (req, res) => {
  try {
    const q = (req.query.q || "").trim();

    if (!q) {
      return res.json({
        playlists: [],
        songs: []
      });
    }

    const search = `%${q}%`;

    const result = await pool.query(
      `
      SELECT *
      FROM songs
      WHERE
        LOWER(COALESCE(title, '')) LIKE LOWER($1)
        OR LOWER(COALESCE(artist, '')) LIKE LOWER($1)
        OR LOWER(COALESCE(genre, '')) LIKE LOWER($1)
        OR LOWER(COALESCE(album, '')) LIKE LOWER($1)
      ORDER BY id DESC
      LIMIT 50
      `,
      [search]
    );

    const rows = result.rows;

    async function hydrateSong(s) {
      return {
        id: s.id,
        title: s.title,
        artist: s.artist,
        genre: s.genre,
        album: s.album,
        mood: s.mood,
        lyrics: s.lyrics,
        year: s.year,
        audioUrl: await getFileUrl(s.audio_url),
        coverUrl: s.cover_url
          ? await getFileUrl(s.cover_url)
          : null
      };
    }

    const songs = await Promise.all(
      rows.map(hydrateSong)
    );

    const playlists = [];

    const artistMatches = rows.filter(
      s =>
        s.artist &&
        s.artist.toLowerCase().includes(q.toLowerCase())
    );

    if (artistMatches.length) {
      playlists.push({
        name: `${artistMatches[0].artist} Mix`,
        type: "artist",
        songs: await Promise.all(
          artistMatches.map(hydrateSong)
        )
      });
    }

    const genreMatches = rows.filter(
      s =>
        s.genre &&
        s.genre.toLowerCase().includes(q.toLowerCase())
    );

    if (genreMatches.length) {
      playlists.push({
        name: `${genreMatches[0].genre} Mix`,
        type: "genre",
        songs: await Promise.all(
          genreMatches.map(hydrateSong)
        )
      });
    }

    const albumMatches = rows.filter(
      s =>
        s.album &&
        s.album.toLowerCase().includes(q.toLowerCase())
    );

    if (albumMatches.length) {
      playlists.push({
        name: `${albumMatches[0].album} Mix`,
        type: "album",
        songs: await Promise.all(
          albumMatches.map(hydrateSong)
        )
      });
    }

    if (!playlists.length && !songs.length) {
      await addNotification(
        "SEARCH_MISS",
        `${req.session.user.firstName} ${req.session.user.lastName} searched for "${q}" but nothing was found`
      );
    }

    res.json({
      playlists,
      songs
    });

  } catch (err) {
    console.error("SMART SEARCH ERROR:", err);
    res.status(500).json({ error: "Search failed" });
  }
});

module.exports = router;