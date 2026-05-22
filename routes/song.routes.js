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
  getPublicCoverUrl,
  B2_AUDIO_BUCKET_NAME,
  B2_COVER_BUCKET_NAME,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand
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
  "audio/mp3",
  "audio/mp4",
  "audio/wav",
  "audio/x-wav",
  "audio/wave",
  "audio/vnd.wave",
  "audio/aac",
  "audio/flac",
  "audio/x-flac",
  "audio/ogg",
  "audio/webm",
  "audio/x-m4a",
  "application/octet-stream"
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
    const cursor = Number(req.query.cursor) || null;

    const params = [limit];
    let cursorSql = "";

    if (cursor) {
      params.push(cursor);
      cursorSql = "WHERE id < $2";
    }

    const result = await pool.query(
      `
      SELECT id, title, artist, genre, album, mood, year, duration, cover_url
      FROM songs
      ${cursorSql}
      ORDER BY id DESC
      LIMIT $1
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
        mood: s.mood,
        year: s.year,
        duration: s.duration,
        coverUrl: getPublicCoverUrl(s.cover_url)
      })),
      nextCursor: result.rows.at(-1)?.id || null,
      hasMore: result.rows.length === limit
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
      Bucket: B2_AUDIO_BUCKET_NAME,
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

    const results = [];

    for (const file of req.files) {
      const fileKey = `songs/${Date.now()}-${file.originalname}`;
      let coverKey = null;

      try {

      let metadata = {};

      try {
        metadata = await mm.parseBuffer(file.buffer, {
  mimeType: file.mimetype,
  path: file.originalname
});
      } catch (err) {
        console.warn("Could not read metadata:", file.originalname);
      }

      const title =
        metadata.common?.title || file.originalname;

      const artist =
        metadata.common?.artist || "Unknown";

      let genre =
  Array.isArray(metadata.common?.genre)
    ? metadata.common.genre.filter(Boolean).join(", ")
    : metadata.common?.genre || null;

genre = genre?.trim() || null;

if (!genre) {
  genre = "unknown";
}

      const album =
        metadata.common?.album || null;

      const duration =
        metadata.format?.duration || null;

      let lyrics = null;

      const year =
        metadata.common?.year?.toString() || null;

      lyrics = null;

      const picture =
  metadata.common?.picture?.find(p => p?.data?.length) ||
  metadata.common?.picture?.[0];

if (picture?.data?.length) {
  const imageExt =
    picture.format === "image/png" ? "png" : "jpg";

  const safeName = file.originalname
    .replace(/\.[^/.]+$/, "")
    .replace(/[^a-zA-Z0-9-_]/g, "_")
    .slice(0, 80);

  coverKey = `covers/${Date.now()}-${safeName}.${imageExt}`;

  await b2.send(
    new PutObjectCommand({
      Bucket: B2_COVER_BUCKET_NAME,
      Key: coverKey,
      Body: Buffer.from(picture.data),
      ContentType: picture.format || "image/jpeg",
      CacheControl: "public, max-age=31536000, immutable"
    })
  );
} else {
  console.warn("NO ALBUM ART FOUND:", file.originalname);
}

      await b2.send(
        new PutObjectCommand({
          Bucket: B2_AUDIO_BUCKET_NAME,
          Key: fileKey,
          Body: file.buffer,
          ContentType: file.mimetype,
        })
      );

      const inserted = await pool.query(
  `
  INSERT INTO songs 
  (title, artist, audio_url, genre, album, duration, cover_url, lyrics, year)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
  RETURNING id
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

const songId = inserted.rows[0].id;

if (!genre || genre.toLowerCase() === "unknown") {
  fetchGenreFromITunes({ title, artist })
    .then(async (foundGenre) => {
      if (!foundGenre) return;

      await pool.query(
        "UPDATE songs SET genre = $1 WHERE id = $2",
        [foundGenre, songId]
      );

      console.log(`Genre updated: ${artist} - ${title} → ${foundGenre}`);
    })
    .catch(err =>
      console.warn("Genre background fetch failed:", err.message)
    );
}

fetchLyrics({
  title,
  artist,
  album,
  genre,
  duration,
  year
})

  .then(async (foundLyrics) => {
    if (!foundLyrics) return;

    await pool.query(
      "UPDATE songs SET lyrics = $1 WHERE id = $2",
      [foundLyrics, songId]
    );
  })
  .catch(err =>
    console.warn(
      "Lyrics background fetch failed:",
      err.message
    )
  );

    await addNotification(
  "SONG_UPLOADED",
  `Uploaded: ${file.originalname}`
);

results.push({
  filename: file.originalname,
  success: true,
  songId
});

    } catch (fileErr) {
  console.error("FAILED FILE:", file.originalname, fileErr);

  if (fileKey) {
    try {
      await b2.send(
        new DeleteObjectCommand({
          Bucket: B2_AUDIO_BUCKET_NAME,
          Key: fileKey
        })
      );
    } catch (cleanupErr) {
      console.warn("Audio cleanup failed:", cleanupErr.message);
    }
  }

  if (coverKey) {
    try {
      await b2.send(
        new DeleteObjectCommand({
          Bucket: B2_COVER_BUCKET_NAME,
          Key: coverKey
        })
      );
    } catch (cleanupErr) {
      console.warn("Cover cleanup failed:", cleanupErr.message);
    }
  }

  results.push({
    filename: file.originalname,
    success: false,
    error: fileErr.message
  });
}
}

res.json({
  success: true,
  results
});

  } catch (err) {
    console.error("UPLOAD SONG ERROR:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

/* ---------------- DELETE SONG ---------------- */

router.delete("/songs/:id", requireAdmin, async (req, res) => {
  const songId = req.params.id;

  try {
    const songResult = await pool.query(
      "SELECT * FROM songs WHERE id = $1",
      [songId]
    );

    const song = songResult.rows[0];

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    // Delete audio from private audio bucket
    if (song.audio_url) {
      try {
        await b2.send(
          new DeleteObjectCommand({
            Bucket: B2_AUDIO_BUCKET_NAME,
            Key: song.audio_url
          })
        );
      } catch (err) {
        console.warn("AUDIO DELETE WARNING:", err.message);
      }
    }

    // Delete cover from public cover bucket
    if (song.cover_url) {
      try {
        await b2.send(
          new DeleteObjectCommand({
            Bucket: B2_COVER_BUCKET_NAME,
            Key: song.cover_url
          })
        );
      } catch (err) {
        console.warn("COVER DELETE WARNING:", err.message);
      }
    }

    await pool.query("BEGIN");

    await pool.query(
      "DELETE FROM playlist_songs WHERE song_id = $1",
      [songId]
    );

    await pool.query(
      "DELETE FROM user_library WHERE song_id = $1",
      [songId]
    );

    await pool.query(
      "DELETE FROM listening_history WHERE song_id = $1",
      [songId]
    );

    await pool.query(
      "DELETE FROM songs WHERE id = $1",
      [songId]
    );

    await pool.query("COMMIT");

    await addNotification(
      "SONG_DELETED",
      `Deleted: ${song.title}`
    );

    res.json({ success: true });

  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("DELETE SONG ERROR:", err);
    res.status(500).json({ error: "Failed to delete song" });
  }
});

/* ---------------- SMART SEARCH ---------------- */

router.get("/smart-search", requireLogin, async (req, res) => {
  try {
    const q = (req.query.q || "").trim();

    if (q.length > 80) {
  return res.status(400).json({ error: "Search query too long" });
}

    if (!q || q.length < 2) {
      return res.json({
        playlists: [],
        songs: []
      });
    }

    if (q.length > 80) {
  return res.status(400).json({ error: "Search query too long" });
}

    const search = `%${q}%`;

const result = await pool.query(
  `
  SELECT *
  FROM songs
  WHERE
    (COALESCE(title, '') || ' ' || COALESCE(artist, '') || ' ' || COALESCE(album, '') || ' ' || COALESCE(genre, '')) ILIKE $1
    OR title % $2
    OR artist % $2
    OR album % $2
    OR genre % $2
  ORDER BY
    GREATEST(
      similarity(COALESCE(title, ''), $2),
      similarity(COALESCE(artist, ''), $2),
      similarity(COALESCE(album, ''), $2),
      similarity(COALESCE(genre, ''), $2)
    ) DESC,
    id DESC
  LIMIT 50
  `,
  [search, q]
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
        coverUrl: getPublicCoverUrl(s.cover_url)
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