require("dotenv").config();
const cors = require("cors");
const express = require("express");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");
const PgSession = require("connect-pg-simple")(session);
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const mm = require("music-metadata");
const { requireLogin, requireAdmin } = require("./middleware/auth.middleware");
const { registerSchema, loginSchema } = require("./utils/validators");
const { b2, getFileUrl, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectVersionsCommand } = require("./services/storage.service");
const { addNotification } = require("./services/notification.service");
const { fetchGenreFromITunes } = require("./services/genre.service");
const { fetchLyrics } = require("./services/lyrics.service");
const configRoutes = require("./routes/config.routes");

require("dotenv").config({ path: path.join(__dirname, ".env") });

const app = express();

app.set("trust proxy", 1);

app.use("/config", configRoutes);

const pool = require("./database");

/* ---------------- SESSION STORE (POSTGRES) ---------------- */

app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: "sessions"
  }),
  secret: process.env.SESSION_SECRET || (() => {
    throw new Error("SESSION_SECRET is required");
  })(),
  resave: false,
  saveUninitialized: false,
 cookie: {
  httpOnly: true,
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  secure: process.env.NODE_ENV === "production",
  maxAge: 1000 * 60 * 60 * 24 * 7
}
}
));

/* ---------------- MIDDLEWARE ---------------- */

app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
}));

app.use("/api/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
}));

/* ---------------- INIT DATABASE TABLES ---------------- */

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name TEXT,
      last_name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user'
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS songs (
      id SERIAL PRIMARY KEY,
      title TEXT,
      artist TEXT,
      audio_url TEXT,
      genre TEXT,
      album TEXT,
      duration REAL,
      cover_url TEXT
    )
  `);

  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS genre TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS album TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS duration REAL`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS cover_url TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS lyrics TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS mood TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS year TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`);
  await pool.query(`ALTER TABLE playlists ADD COLUMN IF NOT EXISTS query TEXT`);
  await pool.query(`ALTER TABLE playlists ADD COLUMN IF NOT EXISTS is_generated BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE playlists ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`);
 
  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      type TEXT,
      message TEXT,
      time TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS playlists (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id),
      name TEXT,
      query TEXT,
      is_generated BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
  ALTER TABLE playlists
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS playlist_songs (
      playlist_id INT REFERENCES playlists(id) ON DELETE CASCADE,
      song_id INT REFERENCES songs(id),
      PRIMARY KEY (playlist_id, song_id)
    )
  `);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS user_library (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    song_id INT REFERENCES songs(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, song_id)
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS custom_playlists (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    name TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS custom_playlist_songs (
    playlist_id INT REFERENCES custom_playlists(id) ON DELETE CASCADE,
    song_id INT REFERENCES songs(id) ON DELETE CASCADE,
    PRIMARY KEY (playlist_id, song_id)
  )
`);
}

/* =========================
   ✅ ADDED: PLAYLIST BUILDER
========================= */
async function buildGeneratedPlaylist(userId, query, songs) {
  const name = `Created for ${query}`;

  const playlistResult = await pool.query(
    `INSERT INTO playlists (user_id, name, query, is_generated)
     VALUES ($1, $2, $3, true)
     RETURNING id`,
    [userId, name, query]
  );

  const playlistId = playlistResult.rows[0].id;

  for (const song of songs) {
    await pool.query(
      `INSERT INTO playlist_songs (playlist_id, song_id)
       VALUES ($1, $2)`,
      [playlistId, song.id]
    );
  }

  return playlistId;
}

/* ---------------- UPLOAD SETUP ---------------- */

const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 100 * 1024 * 1024 },
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

/* ---------------- PAGES ---------------- */

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/", requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/admin", requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

/* ---------------- AUTH ---------------- */

app.post("/api/register", async (req, res) => {
  try {
    const validationResult = registerSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: "Invalid input",
        details: validationResult.error.errors
      });
    }

    const { firstName, lastName, email, password } = validationResult.data;

    const hashed = await bcrypt.hash(password, 10);

    const countResult = await pool.query("SELECT COUNT(*) FROM users");
    const userCount = Number(countResult.rows[0].count);

    const role = userCount === 0 ? "admin" : "user";

    const result = await pool.query(
      "INSERT INTO users (first_name, last_name, email, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING id",
      [firstName, lastName, email, hashed, role]
    );

    await addNotification("USER_CREATED", `User created: ${email}`);

    req.session.user = {
      id: result.rows[0].id,
      email,
      firstName,
      lastName,
      role
    };

    res.json({ success: true });

  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(400).json({ error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user || typeof user.password !== "string") {
      return res.status(401).json({ error: "Invalid login" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: "Invalid login" });
    }

    req.session.regenerate(err => {
      if (err) {
        return res.status(500).json({ error: "Session error" });
      }

      req.session.user = {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role
      };

      res.json({
        success: true,
        user: req.session.user
      });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ error: "Logout failed" });
    }
    res.json({ success: true });
  });
});

app.get("/api/me", async (req, res) => {

  if (!req.session?.user) {
    return res.json({
      loggedIn: false,
      user: null
    });
  }

  const result = await pool.query(
    "SELECT * FROM users WHERE id = $1",
    [req.session.user.id]
  );

  const user = result.rows[0];

  res.json({
    loggedIn: true,
    user: {
      id: user.id,
      email: user.email,
      firstName: user.first_name,
      lastName: user.last_name,
      role: user.role,

      profilePicture:
        user.profile_picture
          ? await getFileUrl(user.profile_picture)
          : null
    }
  });
});

app.post("/api/profile-picture", requireLogin, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No image uploaded" });
    }

    const key = `profiles/${Date.now()}-${req.file.originalname}`;

    await b2.send(new PutObjectCommand({
      Bucket: process.env.B2_BUCKET_NAME,
      Key: key,
      Body: req.file.buffer,
      ContentType: req.file.mimetype
    }));

    await pool.query(
  "UPDATE users SET profile_picture = $1 WHERE id = $2",
  [key, req.session.user.id]
);

    res.json({
      success: true,
      profilePicture: await getFileUrl(key)
    });

  } catch (err) {
    console.error("PROFILE PIC ERROR:", err);
    res.status(500).json({ error: "Upload failed" });
  }
});

app.get("/api/library", requireLogin, async (req, res) => {
  const result = await pool.query(
    `
    SELECT songs.*
    FROM songs
    JOIN user_library ON songs.id = user_library.song_id
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

app.post("/api/library/add", requireLogin, async (req, res) => {
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

app.post("/api/library/remove", requireLogin, async (req, res) => {
  const { songId } = req.body;

  await pool.query(
    `
    DELETE FROM user_library
    WHERE user_id = $1 AND song_id = $2
    `,
    [req.session.user.id, songId]
  );

  res.json({ success: true });
});

/* ---------------- USERS ---------------- */

app.delete("/api/users/:id", requireAdmin, async (req, res) => {
  try {
    const userResult = await pool.query(
      "SELECT email FROM users WHERE id = $1",
      [req.params.id]
    );

    const user = userResult.rows[0];

    await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);

    if (user) {
      await addNotification("USER_DELETED", `User deleted: ${user.email}`);
    }

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------- GET SONGS ---------------- */

app.delete(
  "/api/admin/delete-all-content",
  requireAdmin,
  async (req, res) => {

    try {
      const { code } = req.body;

      if (code !== "2009") {
        return res.status(403).json({
          error: "Invalid confirmation code"
        });
      }

      await pool.query("DELETE FROM playlist_songs");
      await pool.query("DELETE FROM playlists");
      await pool.query("DELETE FROM notifications");
      await pool.query("DELETE FROM settings");
      await pool.query("DELETE FROM songs");

      res.json({ success: true });

    } catch (err) {
      console.error(
        "DELETE ALL CONTENT ERROR:",
        err
      );

      res.status(500).json({
        error: "Failed to delete content"
      });
    }
});

app.get("/ping", (req, res) => {
  res.status(200).send("OK");
});

app.get("/api/songs", requireLogin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM songs ORDER BY id DESC");

    const songsWithUrls = await Promise.all(
      result.rows.map(async (s) => ({
  id: s.id,
  title: s.title,
  artist: s.artist,
  genre: s.genre,
  album: s.album,
  mood: s.mood,
  year: s.year,
  lyrics: s.lyrics,
  audioUrl: await getFileUrl(s.audio_url),
  coverUrl: s.cover_url ? await getFileUrl(s.cover_url) : null
      }))
    );

    res.json({ songs: songsWithUrls });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/songs/:id/download", requireLogin, async (req, res) => {
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

app.post("/api/upload-files", requireAdmin, upload.array("songs"), async (req, res) => {
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
  console.warn(
    "Lyrics fetch failed:",
    err.message
  );
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
  `INSERT INTO songs 
   (title, artist, audio_url, genre, album, duration, cover_url, lyrics, year)
   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
  [title, artist, fileKey, genre, album, duration, coverKey, lyrics, year]
);

      await addNotification("SONG_UPLOADED", `Uploaded: ${file.originalname}`);
    }

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: "Upload failed" });
  }
});

/* ---------------- BACKGROUND UPLOAD ---------------- */

app.post("/api/upload-bg", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Error: No file uploaded" });
    }

    const safeName = req.file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");
    const fileKey = `backgrounds/${Date.now()}-${safeName}`;

    await b2.send(
      new PutObjectCommand({
        Bucket: process.env.B2_BUCKET_NAME,
        Key: fileKey,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
      })
    );

    await pool.query(
      "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
      ["background", fileKey]
    );

    await addNotification("BG_UPDATED", "Background updated");

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: "Upload failed" });
  }
});

/* ---------------- GET BACKGROUND ---------------- */

app.get("/api/background", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT value FROM settings WHERE key = $1",
      ["background"]
    );

    const fileKey = result.rows[0]?.value;

    if (!fileKey) return res.json({ url: null });

    const url = await getFileUrl(fileKey);

    res.json({ url });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------- DELETE SONG ---------------- */

app.delete("/api/songs/:id", requireAdmin, async (req, res) => {
  try {
    const songResult = await pool.query(
      "SELECT * FROM songs WHERE id = $1",
      [req.params.id]
    );

    const song = songResult.rows[0];
    if (!song) return res.status(404).json({ error: "Not found" });

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

    await pool.query("DELETE FROM songs WHERE id = $1", [req.params.id]);

    await addNotification("SONG_DELETED", `Deleted: ${song.title}`);

    res.json({ success: true });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================
   ✅ ADDED: SMART SEARCH
========================= */
app.get("/api/smart-search", requireLogin, async (req, res) => {
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


/* =========================
   ✅ ADDED: SAVE PLAYLIST
========================= */
app.post("/api/playlists/save", requireLogin, async (req, res) => {
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

/* =========================
   ✅ ADDED: GET USER PLAYLISTS
========================= */
app.get("/api/playlists", requireLogin, async (req, res) => {
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

/* =========================
   ✅ ADDED: GET PLAYLIST DETAILS
========================= */
app.get("/api/playlists/:id", requireLogin, async (req, res) => {

  try {

    const playlistResult = await pool.query(
      `
      SELECT *
      FROM playlists
      WHERE id = $1
      `,
      [req.params.id]
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

    console.error(
      "GET PLAYLIST DETAILS ERROR:",
      err
    );

    res.status(500).json({
      error: "Failed to load playlist"
    });
  }
});

/* ---------------- NOTIFICATIONS ---------------- */

app.get("/api/notifications", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM notifications ORDER BY id DESC LIMIT 50"
    );

    res.json({ notifications: result.rows || [] });

  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
});

/* ---------------- START ---------------- */

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
  }
  if (err && err.message === "Invalid file type") {
    return res.status(400).json({ error: err.message });
  }
  next(err);
});

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  if (!res.headersSent) {
    res.status(500).json({ error: "Internal server error" });
  }
});

const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Spotivibes server running on port ${PORT}`);
  });
});
