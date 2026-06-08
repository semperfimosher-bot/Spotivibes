const express = require("express");
const multer = require("multer");
const mm = require("music-metadata");
const pool = require("../database");

const {
  checkArtistCompleteness
} = require("../services/artist-completeness.service");

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
  B2_INGEST_BUCKET_NAME,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectsV2Command
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

function normalizeSongText(value = "") {
  return String(value)
    .toLowerCase()
    .replace(/\([^)]*\)/g, "")
    .replace(/\[[^\]]*\]/g, "")
    .replace(/feat\.|featuring|ft\./g, "")
    .replace(/[^a-z0-9]/g, "")
    .trim();
}

function normalizeDuplicateText(value = "") {
  return String(value)
    .toLowerCase()
    .replace(/\([^)]*\)/g, "")
    .replace(/\[[^\]]*\]/g, "")
    .replace(/feat\.|featuring|ft\./gi, "")
    .replace(/[^a-z0-9]/g, "")
    .trim();
}

async function songAlreadyExists(title, artist) {
  const normalizedTitle = normalizeSongText(title);
  const normalizedArtist = normalizeSongText(artist);

  const result = await pool.query(
    `
    SELECT id, title, artist
    FROM songs
    WHERE regexp_replace(lower(title), '[^a-z0-9]', '', 'g') = $1
      AND regexp_replace(lower(artist), '[^a-z0-9]', '', 'g') = $2
    LIMIT 1
    `,
    [normalizedTitle, normalizedArtist]
  );

  return result.rows[0] || null;
}

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
    const limit = Math.min(Number(req.query.limit) || 1000, 5000);
    const cursor = Number(req.query.cursor) || null;

    const params = [limit];
    let cursorSql = "";

    if (cursor) {
      params.push(cursor);
      cursorSql = "WHERE id < $2";
    }

    const result = await pool.query(
      `
      SELECT id, title, artist, genre, album, mood, year, duration, cover_url, lyrics
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
        lyrics: s.lyrics,
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

router.get("/songs/:id/lyrics", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT id, title, artist, album, genre, duration, year, lyrics
      FROM songs
      WHERE id = $1
      `,
      [req.params.id]
    );

    const song = result.rows[0];

    if (!song) {
      return res.status(404).json({ error: "Song not found" });
    }

    if (song.lyrics) {
      return res.json({ lyrics: song.lyrics });
    }

    const foundLyrics = await fetchLyrics({
      title: song.title,
      artist: song.artist,
      album: song.album,
      genre: song.genre,
      duration: song.duration,
      year: song.year
    });

    if (foundLyrics) {
      await pool.query(
        "UPDATE songs SET lyrics = $1 WHERE id = $2",
        [foundLyrics, song.id]
      );
    }

    res.json({ lyrics: foundLyrics || null });
  } catch (err) {
    console.error("LYRICS ERROR:", err);
    res.status(500).json({ error: "Failed to load lyrics" });
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

router.post(
  "/upload-files",

  (req, res, next) => {
    const token = req.headers["x-upload-token"];

    if (
      token &&
      token === process.env.FOLDER_UPLOAD_TOKEN
    ) {
      return next();
    }

    return requireAdmin(req, res, next);
  },

  upload.array("songs", 50),

  async (req, res) => {
    const results = [];

    if (!req.files || !req.files.length) {
      return res.status(400).json({
        error: "No files uploaded"
      });
    }

    for (const file of req.files) {
      let fileKey = null;
      let coverKey = null;

      try {

        let metadata = {};

        try {
          metadata = await mm.parseBuffer(file.buffer, {
            mimeType: file.mimetype,
            path: file.originalname
          });
        } catch (metaErr) {
          console.warn("Metadata parse failed:", file.originalname, metaErr.message);
        }

        const title =
          metadata.common?.title ||
          file.originalname.replace(/\.[^/.]+$/, "");

        const artist =
          metadata.common?.artist ||
          "Unknown Artist";

        const album =
          metadata.common?.album ||
          "Unknown Album";

        const safeArtistFolder = String(artist || "Unknown Artist")
          .replace(/[<>:"/\\|?*]/g, "")
          .replace(/\s+/g, " ")
          .trim();

        const safeFileName = String(file.originalname)
          .replace(/[<>:"/\\|?*]/g, "")
          .trim();

        fileKey = `songs/${safeArtistFolder}/${Date.now()}-${safeFileName}`;

        const existingSong = await songAlreadyExists(title, artist);

if (existingSong) {
  console.log(
    "SKIPPING DUPLICATE SONG:",
    title,
    artist,
    "already exists as ID",
    existingSong.id
  );

  results.push({
    filename: file.originalname,
    success: true,
    skipped: true,
    reason: "Song already exists",
    existingSongId: existingSong.id
  });

  continue;
}

        let genre =
          Array.isArray(metadata.common?.genre)
            ? metadata.common.genre.filter(Boolean).join(", ")
            : metadata.common?.genre || null;

        genre = genre?.trim() || null;

        if (!genre || genre.toLowerCase() === "unknown") {
  genre = await fetchGenreFromITunes({ title, artist }) || "unknown";
}

        const year =
          metadata.common?.year
            ? String(metadata.common.year)
            : null;

        const duration =
          metadata.format?.duration || null;

        const lyrics =
          metadata.common?.lyrics?.[0] ||
          metadata.native?.ID3v2?.find(t => t.id === "USLT")?.value?.text ||
          null;

        const picture =
          metadata.common?.picture?.find(p => p?.data?.length) ||
          metadata.common?.picture?.[0];

        if (picture?.data?.length) {
          const imageExt =
            picture.format === "image/png" ? "png" :
            picture.format === "image/webp" ? "webp" :
            "jpg";

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
        }

        await b2.send(
          new PutObjectCommand({
            Bucket: B2_AUDIO_BUCKET_NAME,
            Key: fileKey,
            Body: file.buffer,
            ContentType: file.mimetype || "audio/mpeg"
          })
        );

        const inserted = await pool.query(
          `
          INSERT INTO songs
          (
            title,
            artist,
            album,
            genre,
            year,
            duration,
            audio_url,
            cover_url,
            lyrics
          )
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
          RETURNING id
          `,
          [
            title,
            artist,
            album,
            genre,
            year,
            duration,
            fileKey,
            coverKey,
            lyrics
          ]
        );

       const songId = inserted.rows[0].id;

console.log("UPLOAD INSERTED SONG:", songId, title, artist);

checkArtistCompleteness(artist).catch(async err => {
  console.warn(
    "COMPLETENESS CHECK FAILED:",
    err.stack || err.message
  );

  await pool.query(
    `
    INSERT INTO notifications (type, message, time)
    VALUES ($1, $2, NOW())
    `,
    [
      "ARTIST_MISSING_SONGS",
      `DEBUG completeness failed for ${artist}: ${err.message}`
    ]
  );
});

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
  }
);

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

router.post("/playback-event", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { songId, eventType } = req.body;

    const allowed = ["play", "complete", "skip", "replay"];

    if (!songId || !allowed.includes(eventType)) {
      return res.status(400).json({ error: "Invalid playback event" });
    }

    await pool.query(
      `
      INSERT INTO playback_events (user_id, song_id, event_type)
      VALUES ($1, $2, $3)
      `,
      [userId, songId, eventType]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("PLAYBACK EVENT ERROR:", err);
    res.status(500).json({ error: "Failed to save playback event" });
  }
});

router.get("/recommendations/next", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const currentSongId = Number(req.query.currentSongId);

    if (!currentSongId) {
      return res.json({ songs: [] });
    }

    const result = await pool.query(
      `
      WITH current_song AS (
        SELECT id, artist, album, genre, year, mood, energy, era
        FROM songs
        WHERE id = $2
        LIMIT 1
      ),

      recent_plays AS (
        SELECT song_id
        FROM playback_events
        WHERE user_id = $1
        ORDER BY created_at DESC
        LIMIT 30
      ),

      user_artist_scores AS (
        SELECT s.artist,
          SUM(
            CASE
              WHEN pe.event_type = 'complete' THEN 5
              WHEN pe.event_type = 'play' THEN 2
              WHEN pe.event_type = 'replay' THEN 8
              WHEN pe.event_type = 'skip' THEN -6
              ELSE 0
            END
          ) AS score
        FROM playback_events pe
        JOIN songs s ON s.id = pe.song_id
        WHERE pe.user_id = $1
        GROUP BY s.artist
      ),

      user_genre_scores AS (
        SELECT s.genre,
          SUM(
            CASE
              WHEN pe.event_type = 'complete' THEN 5
              WHEN pe.event_type = 'play' THEN 2
              WHEN pe.event_type = 'replay' THEN 8
              WHEN pe.event_type = 'skip' THEN -6
              ELSE 0
            END
          ) AS score
        FROM playback_events pe
        JOIN songs s ON s.id = pe.song_id
        WHERE pe.user_id = $1
          AND s.genre IS NOT NULL
        GROUP BY s.genre
      ),

      scored AS (
        SELECT
          s.*,

          (
            CASE
              WHEN s.mood IS NOT NULL
               AND cs.mood IS NOT NULL
               AND lower(s.mood) = lower(cs.mood) THEN 180
              ELSE 0
            END +

            CASE
              WHEN s.energy IS NOT NULL
               AND cs.energy IS NOT NULL
               AND lower(s.energy) = lower(cs.energy) THEN 160
              ELSE 0
            END +

            CASE
              WHEN s.genre IS NOT NULL
               AND cs.genre IS NOT NULL
               AND lower(s.genre) = lower(cs.genre) THEN 140
              ELSE 0
            END +

            COALESCE((
              SELECT uas.score * 8
              FROM user_artist_scores uas
              WHERE lower(uas.artist) = lower(s.artist)
              LIMIT 1
            ), 0) +

            COALESCE((
              SELECT ugs.score * 6
              FROM user_genre_scores ugs
              WHERE lower(ugs.genre) = lower(s.genre)
              LIMIT 1
            ), 0) +

            CASE
              WHEN lower(s.artist) = lower(cs.artist) THEN 80
              ELSE 0
            END +

            CASE
              WHEN s.album IS NOT NULL
               AND cs.album IS NOT NULL
               AND lower(s.album) = lower(cs.album) THEN 50
              ELSE 0
            END +

            CASE
              WHEN s.era IS NOT NULL
               AND cs.era IS NOT NULL
               AND lower(s.era) = lower(cs.era) THEN 30
              ELSE 0
            END +

            CASE
              WHEN s.year IS NOT NULL
               AND cs.year IS NOT NULL
               AND s.year ~ '^[0-9]+$'
               AND cs.year ~ '^[0-9]+$'
               AND ABS(CAST(s.year AS INT) - CAST(cs.year AS INT)) <= 3 THEN 20
              ELSE 0
            END

          ) AS recommendation_score

        FROM songs s
        CROSS JOIN current_song cs
        WHERE s.id <> cs.id
          AND s.id NOT IN (SELECT song_id FROM recent_plays)
      )

      SELECT *
      FROM scored
      WHERE recommendation_score > 0
      ORDER BY
        recommendation_score DESC,
        artist ASC,
        album ASC,
        title ASC
      LIMIT 25
      `,
      [userId, currentSongId]
    );

    res.json({
      songs: result.rows.map(s => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        album: s.album,
        genre: s.genre,
        year: s.year,
        mood: s.mood,
        energy: s.energy,
        era: s.era,
        coverUrl: getPublicCoverUrl(s.cover_url)
      }))
    });
  } catch (err) {
    console.error("NEXT RECOMMENDATIONS ERROR:", err);
    res.status(500).json({
      error: "Failed to load recommendations"
    });
  }
});

router.post("/ai-dj-command", requireLogin, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const command = String(req.body.command || "").toLowerCase().trim();
    const currentSongId = Number(req.body.currentSongId) || null;

    if (!command) {
      return res.json({
        success: false,
        message: "No command heard."
      });
    }

    if (command.includes("pause") || command.includes("stop")) {
      return res.json({
        success: true,
        action: "pause",
        message: "Paused."
      });
    }

    if (command.includes("resume") || command.includes("play again")) {
      return res.json({
        success: true,
        action: "resume",
        message: "Playing."
      });
    }

    if (command.includes("skip") || command.includes("next")) {
      return res.json({
        success: true,
        action: "skip",
        message: "Skipping."
      });
    }

    if (
      command.includes("continue the mood") ||
      command.includes("keep the vibe") ||
      command.includes("similar songs") ||
      command.includes("something like this")
    ) {
      return res.json({
        success: true,
        action: "continueMood",
        message: "Continuing the vibe."
      });
    }

    let query = command
      .replace(/^play\s+/i, "")
      .replace(/^shuffle\s+/i, "")
      .replace(/^start\s+/i, "")
      .replace(/\s+playlist$/i, "")
      .trim();

    if (!query) {
      return res.json({
        success: false,
        message: "I did not catch what to play."
      });
    }

    const playlistResult = await pool.query(
      `
      SELECT p.id, p.name
      FROM playlists p
      WHERE p.user_id = $1
        AND lower(p.name) LIKE lower($2)
      ORDER BY p.created_at DESC
      LIMIT 1
      `,
      [userId, `%${query}%`]
    );

    if (playlistResult.rows.length) {
      const playlist = playlistResult.rows[0];

      const songsResult = await pool.query(
        `
        SELECT s.*
        FROM playlist_songs ps
        JOIN songs s ON s.id = ps.song_id
        WHERE ps.playlist_id = $1
        ORDER BY s.artist ASC, s.album ASC, s.title ASC
        `,
        [playlist.id]
      );

      const songs = songsResult.rows.map(s => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        album: s.album,
        genre: s.genre,
        year: s.year,
        mood: s.mood,
        energy: s.energy,
        era: s.era,
        coverUrl: getPublicCoverUrl(s.cover_url)
      }));

      if (songs.length) {
        return res.json({
          success: true,
          action: "playSongs",
          contextType: "voice-playlist",
          message: `Playing ${playlist.name}.`,
          songs
        });
      }
    }

const songsResult = await pool.query(
  `
  SELECT *
  FROM songs
  WHERE
    lower(artist) = lower($2)
    OR lower(title) = lower($2)
    OR lower(artist) LIKE lower($1)
    OR lower(title) LIKE lower($1)
    OR lower(album) LIKE lower($1)
    OR lower(genre) LIKE lower($1)
  ORDER BY
    CASE
      WHEN lower(artist) = lower($2) THEN 1
      WHEN lower(title) = lower($2) THEN 2
      WHEN lower(artist) LIKE lower($1) THEN 3
      WHEN lower(title) LIKE lower($1) THEN 4
      WHEN lower(album) LIKE lower($1) THEN 5
      ELSE 6
    END,
    artist ASC,
    album ASC,
    title ASC
  LIMIT 40
  `,
  [`%${query}%`, query]
);

    let songs = songsResult.rows.map(s => ({
      id: s.id,
      title: s.title,
      artist: s.artist,
      album: s.album,
      genre: s.genre,
      year: s.year,
      mood: s.mood,
      energy: s.energy,
      era: s.era,
      coverUrl: getPublicCoverUrl(s.cover_url)
    }));

    if (!songs.length && currentSongId) {
      const recResult = await pool.query(
        `
        SELECT *
        FROM songs
        WHERE id <> $1
        ORDER BY RANDOM()
        LIMIT 25
        `,
        [currentSongId]
      );

      songs = recResult.rows.map(s => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        album: s.album,
        genre: s.genre,
        year: s.year,
        mood: s.mood,
        energy: s.energy,
        era: s.era,
        coverUrl: getPublicCoverUrl(s.cover_url)
      }));
    }

    if (!songs.length) {
      return res.json({
        success: false,
        message: `I could not find ${query}.`
      });
    }

    return res.json({
      success: true,
      action: "playSongs",
      contextType: "voice-search",
      message: `Playing ${query}.`,
      songs
    });

  } catch (err) {
    console.error("AI DJ COMMAND ERROR:", err);
    res.status(500).json({
      success: false,
      error: "AI DJ command failed"
    });
  }
});

router.post("/admin/scan-duplicates", requireAdmin, async (req, res) => {
  try {
    await pool.query("DELETE FROM duplicate_candidates");

    const result = await pool.query(`
      SELECT id, title, artist, album, duration, audio_url, cover_url
      FROM songs
      ORDER BY artist ASC, title ASC, id ASC
    `);

    const songs = result.rows;
    const groups = new Map();

    for (const song of songs) {
      const key = [
        normalizeDuplicateText(song.title),
        normalizeDuplicateText(song.artist)
      ].join("|");

      if (!groups.has(key)) {
        groups.set(key, []);
      }

      groups.get(key).push(song);
    }

    let inserted = 0;

    for (const group of groups.values()) {
      if (group.length < 2) continue;

      group.sort((a, b) => a.id - b.id);

      const original = group[0];
      const duplicates = group.slice(1);

      for (const duplicate of duplicates) {
        const durationClose =
          !original.duration ||
          !duplicate.duration ||
          Math.abs(Number(original.duration) - Number(duplicate.duration)) <= 2;

        if (!durationClose) continue;

        await pool.query(
          `
          INSERT INTO duplicate_candidates
          (original_song_id, duplicate_song_id, reason)
          VALUES ($1, $2, $3)
          `,
          [
            original.id,
            duplicate.id,
            "Same normalized title and artist with close duration"
          ]
        );

        inserted++;
      }
    }

    res.json({
      success: true,
      count: inserted
    });

  } catch (err) {
    console.error("SCAN DUPLICATES ERROR:", err);
    res.status(500).json({
      error: "Failed to scan duplicates"
    });
  }
});

router.get("/admin/duplicates", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        dc.id,
        dc.reason,

        original.id AS original_id,
        original.title AS original_title,
        original.artist AS original_artist,
        original.album AS original_album,
        original.duration AS original_duration,

        duplicate.id AS duplicate_id,
        duplicate.title AS duplicate_title,
        duplicate.artist AS duplicate_artist,
        duplicate.album AS duplicate_album,
        duplicate.duration AS duplicate_duration

      FROM duplicate_candidates dc
      JOIN songs original
        ON original.id = dc.original_song_id
      JOIN songs duplicate
        ON duplicate.id = dc.duplicate_song_id
      ORDER BY duplicate.artist ASC, duplicate.title ASC
    `);

    res.json({
      duplicates: result.rows
    });

  } catch (err) {
    console.error("LOAD DUPLICATES ERROR:", err);
    res.status(500).json({
      error: "Failed to load duplicates"
    });
  }
});

router.delete("/admin/duplicates/:id", requireAdmin, async (req, res) => {

  router.delete("/admin/duplicates", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        dc.id,
        dc.duplicate_song_id,
        s.audio_url,
        s.cover_url
      FROM duplicate_candidates dc
      JOIN songs s
        ON s.id = dc.duplicate_song_id
      ORDER BY dc.id ASC
    `);

    let deleted = 0;

    for (const item of result.rows) {
      if (item.audio_url) {
        try {
          await b2.send(
            new DeleteObjectCommand({
              Bucket: B2_AUDIO_BUCKET_NAME,
              Key: item.audio_url
            })
          );
        } catch (err) {
          console.warn("Duplicate audio B2 delete warning:", err.message);
        }
      }

      if (item.cover_url) {
        try {
          await b2.send(
            new DeleteObjectCommand({
              Bucket: B2_COVER_BUCKET_NAME,
              Key: item.cover_url
            })
          );
        } catch (err) {
          console.warn("Duplicate cover B2 delete warning:", err.message);
        }
      }

      await pool.query("BEGIN");

      await pool.query("DELETE FROM playlist_songs WHERE song_id = $1", [item.duplicate_song_id]);
      await pool.query("DELETE FROM user_library WHERE song_id = $1", [item.duplicate_song_id]);
      await pool.query("DELETE FROM listening_history WHERE song_id = $1", [item.duplicate_song_id]);
      await pool.query("DELETE FROM playback_events WHERE song_id = $1", [item.duplicate_song_id]);
      await pool.query("DELETE FROM songs WHERE id = $1", [item.duplicate_song_id]);
      await pool.query("DELETE FROM duplicate_candidates WHERE id = $1", [item.id]);

      await pool.query("COMMIT");

      deleted++;
    }

    res.json({
      success: true,
      deleted
    });

  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("DELETE ALL DUPLICATES ERROR:", err);
    res.status(500).json({
      error: "Failed to delete all duplicates"
    });
  }
});

  const duplicateCandidateId = req.params.id;

  try {
    const result = await pool.query(
      `
      SELECT
        dc.id,
        dc.duplicate_song_id,
        s.audio_url,
        s.cover_url
      FROM duplicate_candidates dc
      JOIN songs s
        ON s.id = dc.duplicate_song_id
      WHERE dc.id = $1
      LIMIT 1
      `,
      [duplicateCandidateId]
    );

    const item = result.rows[0];

    if (!item) {
      return res.status(404).json({
        error: "Duplicate candidate not found"
      });
    }

    if (item.audio_url) {
      try {
        await b2.send(
          new DeleteObjectCommand({
            Bucket: B2_AUDIO_BUCKET_NAME,
            Key: item.audio_url
          })
        );
      } catch (err) {
        console.warn("Duplicate audio B2 delete warning:", err.message);
      }
    }

    if (item.cover_url) {
      try {
        await b2.send(
          new DeleteObjectCommand({
            Bucket: B2_COVER_BUCKET_NAME,
            Key: item.cover_url
          })
        );
      } catch (err) {
        console.warn("Duplicate cover B2 delete warning:", err.message);
      }
    }

    await pool.query("BEGIN");

    await pool.query(
      "DELETE FROM playlist_songs WHERE song_id = $1",
      [item.duplicate_song_id]
    );

    await pool.query(
      "DELETE FROM user_library WHERE song_id = $1",
      [item.duplicate_song_id]
    );

    await pool.query(
      "DELETE FROM listening_history WHERE song_id = $1",
      [item.duplicate_song_id]
    );

    await pool.query(
      "DELETE FROM playback_events WHERE song_id = $1",
      [item.duplicate_song_id]
    );

    await pool.query(
      "DELETE FROM songs WHERE id = $1",
      [item.duplicate_song_id]
    );

    await pool.query(
      "DELETE FROM duplicate_candidates WHERE id = $1",
      [duplicateCandidateId]
    );

    await pool.query("COMMIT");

    res.json({
      success: true
    });

  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("DELETE DUPLICATE ERROR:", err);
    res.status(500).json({
      error: "Failed to delete duplicate"
    });
  }
});

/* ---------------- SMART SEARCH ---------------- */

router.get("/smart-search", requireLogin, async (req, res) => {
  try {
    const q = (req.query.q || "").trim();

    if (q.length > 80) {
  return res.status(400).json({ error: "Search query too long" });
}

    if (!q || q.length < 1) {
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
  LIMIT 500
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

function requireUploadToken(req, res, next) {
  const token = req.headers["x-upload-token"];

  if (!token || token !== process.env.FOLDER_UPLOAD_TOKEN) {
    return res.sendStatus(403);
  }

  next();
}

router.post("/internal/upload-start", requireUploadToken, async (req, res) => {
  const { filename } = req.body;

  await pool.query(
    `
    INSERT INTO upload_jobs (filename, status, updated_at)
    VALUES ($1, 'uploading', NOW())
    `,
    [filename]
  );

  res.json({ success: true });
});

router.post("/internal/upload-complete", requireUploadToken, async (req, res) => {
  const { filename } = req.body;

  await pool.query(
    `
    UPDATE upload_jobs
    SET status = 'complete', updated_at = NOW()
    WHERE id = (
      SELECT id
      FROM upload_jobs
      WHERE filename = $1
      ORDER BY created_at DESC
      LIMIT 1
    )
    `,
    [filename]
  );

  res.json({ success: true });
});

router.post("/internal/upload-failed", requireUploadToken, async (req, res) => {
  const { filename, error } = req.body;

  await pool.query(
    `
    UPDATE upload_jobs
    SET status = 'failed', error = $2, updated_at = NOW()
    WHERE id = (
      SELECT id
      FROM upload_jobs
      WHERE filename = $1
      ORDER BY created_at DESC
      LIMIT 1
    )
    `,
    [filename, error || "Upload failed"]
  );

  res.json({ success: true });
});

module.exports = router;