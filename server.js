const express = require("express");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const PgSession = require("connect-pg-simple")(session);
require("dotenv").config();

const app = express();

/* ---------------- DATABASE (POSTGRES) ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

/* ---------------- SESSION STORE (POSTGRES) ---------------- */

app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: "session"
  }),
  secret: process.env.SESSION_SECRET || "spotivibes-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax"
  }
}));

/* ---------------- MIDDLEWARE ---------------- */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

/* ---------------- INIT DATABASE TABLES ---------------- */

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      firstName TEXT,
      lastName TEXT,
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
      audioUrl TEXT
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

initDB();

/* ---------------- HELPERS ---------------- */

async function addNotification(type, message) {
  const time = new Date().toISOString();

  await pool.query(
    "INSERT INTO notifications (type, message, time) VALUES ($1, $2, $3)",
    [type, message, time]
  );
}

/* ---------------- UPLOAD SETUP ---------------- */

const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_"))
});

const upload = multer({ storage });

/* ---------------- AUTH HELPERS ---------------- */

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
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
  const { firstName, lastName, email, password } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    const countResult = await pool.query("SELECT COUNT(*) FROM users");
    const role = countResult.rows[0].count == 0 ? "admin" : "user";

    const result = await pool.query(
      "INSERT INTO users (firstName, lastName, email, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING id",
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
    return res.status(400).json({ error: "Email exists or invalid data" });
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

    if (!user) {
      return res.status(401).json({ error: "Invalid login" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ error: "Invalid login" });
    }

    req.session.user = {
      id: user.id,
      email: user.email,
      firstName: user.firstname,
      lastName: user.lastname,
      role: user.role
    };

    await addNotification("LOGIN", `User logged in: ${email}`);

    res.json({
      success: true,
      user: req.session.user
    });

  } catch (err) {
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
  const userResult = await pool.query(
    "SELECT email FROM users WHERE id = $1",
    [req.params.id]
  );

  const user = userResult.rows[0];

  if (user) {
    await addNotification("USER_DELETED", `User deleted: ${user.email}`);
  }

  await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);

  res.json({ success: true });
});

/* ---------------- SONGS ---------------- */

/* FIXED: map audioUrl correctly */
app.get("/api/songs", requireLogin, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM songs ORDER BY id DESC");

    res.json({
      songs: result.rows.map(s => ({
        id: s.id,
        title: s.title,
        artist: s.artist,
        audioUrl: s.audiourl
      }))
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* ---------------- UPLOAD SONGS ---------------- */

app.post("/api/upload-files", requireAdmin, upload.array("songs"), async (req, res) => {
  for (const file of req.files) {
    await pool.query(
      "INSERT INTO songs (title, artist, audioUrl) VALUES ($1, $2, $3)",
      [file.originalname, "Unknown", "/uploads/" + file.filename]
    );

    await addNotification("SONG_UPLOADED", `Uploaded: ${file.originalname}`);
  }

  res.json({ success: true });
});

/* ---------------- BACKGROUND UPLOAD ---------------- */

app.post("/api/upload-bg", requireAdmin, upload.any(), async (req, res) => {
  const file = req.files?.[0];

  if (!file) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const fileUrl = "/uploads/" + file.filename;

  await pool.query(
    "INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    ["background", fileUrl]
  );

  await addNotification("BG_UPDATED", "Background updated");

  res.json({ url: fileUrl });
});

/* ---------------- GET BACKGROUND ---------------- */

app.get("/api/background", requireLogin, async (req, res) => {
  const result = await pool.query(
    "SELECT value FROM settings WHERE key = $1",
    ["background"]
  );

  res.json({ url: result.rows[0]?.value || null });
});

/* ---------------- DELETE SONG ---------------- */

app.delete("/api/songs/:id", requireAdmin, async (req, res) => {
  const songResult = await pool.query(
    "SELECT * FROM songs WHERE id = $1",
    [req.params.id]
  );

  const song = songResult.rows[0];

  if (!song) return res.status(404).json({ error: "Not found" });

  await addNotification("SONG_DELETED", `Deleted: ${song.title}`);

  fs.unlink(path.join(__dirname, "public", song.audiourl || song.audioUrl), () => {});

  await pool.query("DELETE FROM songs WHERE id = $1", [req.params.id]);

  res.json({ success: true });
});

/* ---------------- SEARCH ---------------- */

/* FIXED: map audioUrl correctly */
app.get("/api/search", requireLogin, async (req, res) => {
  const q = (req.query.q || "").toLowerCase();

  const result = await pool.query("SELECT * FROM songs");

  const songs = result.rows;

  const filtered = songs.filter(s =>
    (s.title + " " + s.artist).toLowerCase().includes(q)
  );

  if (q && filtered.length === 0) {
    await addNotification("SEARCH_MISS", `No results for: "${q}"`);
  }

  res.json({
    songs: filtered.map(s => ({
      id: s.id,
      title: s.title,
      artist: s.artist,
      audioUrl: s.audiourl
    }))
  });
});

/* ---------------- NOTIFICATIONS ---------------- */

app.get("/api/notifications", requireLogin, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM notifications ORDER BY id DESC LIMIT 50"
  );

  res.json({ notifications: result.rows || [] });
});

/* ---------------- START ---------------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
