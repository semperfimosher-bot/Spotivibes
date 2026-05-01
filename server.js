const express = require("express");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");

require("dotenv").config({ path: path.join(__dirname, ".env") });

const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  ListObjectVersionsCommand
} = require("@aws-sdk/client-s3");

const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const b2 = new S3Client({
  region: "us-east-005",
  endpoint: process.env.B2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.B2_KEY_ID,
    secretAccessKey: process.env.B2_APP_KEY
  },
});

async function getFileUrl(fileKey) {
  if (!fileKey) return null;

  const command = new GetObjectCommand({
    Bucket: process.env.B2_BUCKET_NAME,
    Key: fileKey,
  });

  return await getSignedUrl(b2, command, {
    expiresIn: 60 * 60, // 1 hour
  });
}

const app = express();

app.set("trust proxy", 1);
/* ---------------- DATABASE (POSTGRES) ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

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
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

/* ---------------- MIDDLEWARE ---------------- */

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 100 requests per windowMs
}));

app.use("/api/login", rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 5 login requests per windowMs
}));

const registerSchema = z.object({
  firstName: z.string().min(1).max(50),
  lastName: z.string().min(1).max(50),
  email: z.string().email().max(255),
  password: z.string().min(6).max(100),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

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
      audio_url TEXT
    )
  `);

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
}

initDB()
  .then(() => {
    console.log("CONNECTED DB SUCCESSFULLY 🎉 ✅");
  
    const port = process.env.PORT || 3000;

    app.listen(port, () => {
      console.log(`Server running on port ${PORT} 🚀`);
    });
  })
  .catch(err => {
    console.error("DB INIT ERROR:", err);
    process.exit(1);
  });

/* ---------------- HELPERS ---------------- */

async function addNotification(type, message) {
  try {
    const time = new Date().toISOString();

    await pool.query(
      "INSERT INTO notifications (type, message, time) VALUES ($1, $2, $3)",
      [type, message, time]
    );
  } catch (err) {
    console.error("Notification error:", err);
  }
}

/* ---------------- UPLOAD SETUP ---------------- */

const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  storage:multer.memoryStorage(),
  limits: {fileSize: 500 * 1024 * 1024},
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


/* ---------------- AUTH HELPERS ---------------- */

function requireLogin(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "Not logged in" });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
}

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
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

app.get("/api/me", (req, res) => {
  if (!req.session || !req.session.user) {
    return res.json({ loggedIn: false, user: null });
  }

  res.json({
    loggedIn: true,
    user: req.session.user
  });
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

app.get("/api/songs", requireLogin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM songs ORDER BY id DESC");

    const songsWithUrls = await Promise.all(
      result.rows.map(async (s) => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        audioUrl: await getFileUrl(s.audio_url)
      }))
    );

    res.json({ songs: songsWithUrls });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
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

      await b2.send(
        new PutObjectCommand({
          Bucket: process.env.B2_BUCKET_NAME,
          Key: fileKey,
          Body: file.buffer,
          ContentType: file.mimetype,
        })
      );

      await pool.query(
        "INSERT INTO songs (title, artist, audio_url) VALUES ($1, $2, $3)",
        [file.originalname, "Unknown", fileKey]
      );

      await addNotification("SONG_UPLOADED", `Uploaded: ${file.originalname}`);
    }

    res.json({ success: true });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Upload failed" });
  }
});

/* ---------------- BACKGROUND UPLOAD ---------------- */

app.post("/api/upload-bg", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    console.log("File:", req.file);

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

    // ONLY store fileKey in database (NOT URL)
    await pool.query(
      "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
      ["background", fileKey]
    );

    await addNotification("BG_UPDATED", "Background updated");

    // IMPORTANT: return success only
    res.json({ success: true });

  } catch (err) {
    console.error("Upload failed:", err);

    return res.status(500).json({
      error: "Upload failed",
      detail: err.message,
      name: err.name
    });
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

    if (!fileKey) {
      return res.json({ url: null });
    }

    const url = await getFileUrl(fileKey);

    res.json({ url });

  } catch (err) {
    console.error(err);
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

    // normalize old full URLs if needed
    if (fileKey && fileKey.includes("http")) {
      const url = new URL(fileKey);
      fileKey = url.pathname.split("/file/")[1];
    }

    // 🔥 LIST ALL VERSIONS
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

    // 🔥 DELETE EVERY VERSION FOUND
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

    // 🧹 DELETE FROM DATABASE
    await pool.query("DELETE FROM songs WHERE id = $1", [req.params.id]);

    await addNotification("SONG_DELETED", `Deleted: ${song.title}`);

    res.json({ success: true });

  } catch (err) {
    console.error("DELETE SONG ERROR:", err);
    res.status(500).json({ error: "Server error" });
  }
});


/* ---------------- SEARCH ---------------- */

app.get("/api/search", requireLogin, async (req, res) => {
  const q = (req.query.q || "").toLowerCase();

  try {
    const result = await pool.query(
      "SELECT * FROM songs WHERE LOWER(title) LIKE $1 OR LOWER(artist) LIKE $1",
      [`%${q}%`]
    );

    const songs = result.rows;

    if (q && songs.length === 0) {
      await addNotification("SEARCH_MISS", `No results for: "${q}"`);
    }

    res.json({
      songs: songs.map(s => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        audioUrl: s.audio_url
      }))
    });

  } catch (err) {
    res.status(500).json({ error: "Search failed" });
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
  console.error("GLOBAL ERROR:", err);

 if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: err.message });
 }

 if (err && err.message === "Invalid file type") {
    return res.status(400).json({ error: err.message });
 }

 if (!res.headersSent) {
   return res.status(500).json({ error: "Internal server error" });
 }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} 🚀`);
});

