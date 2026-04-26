const express = require("express");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const Database = require("better-sqlite3");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const bcrypt = require("bcrypt");

const app = express();

/* ---------------- MIDDLEWARE ---------------- */

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new SQLiteStore({ db: "sessions.db", dir: __dirname }),
  secret: "spotivibes-secret-key",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax"
  }
}));

app.use(express.static(path.join(__dirname, "public")));

/* ---------------- DATABASE ---------------- */

const dbPath = path.join(__dirname, "spotivibes.db");
const db = new Database(dbPath);

/* ---------------- TABLE SETUP ---------------- */

db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT,
    lastName TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS songs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    artist TEXT,
    audioUrl TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT,
    message TEXT,
    time TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )
`).run();

/* ---------------- HELPERS ---------------- */

function addNotification(type, message) {
  const time = new Date().toLocaleString();
  db.prepare(
    "INSERT INTO notifications (type, message, time) VALUES (?, ?, ?)"
  ).run(type, message, time);
}

/* ---------------- UPLOAD SETUP ---------------- */

const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + "-" + file.originalname)
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

  const hashed = await bcrypt.hash(password, 10);

  const count = db.prepare("SELECT COUNT(*) as count FROM users").get().count;
  const role = count === 0 ? "admin" : "user";

  try {
    const stmt = db.prepare(
      "INSERT INTO users (firstName, lastName, email, password, role) VALUES (?, ?, ?, ?, ?)"
    );

    const result = stmt.run(firstName, lastName, email, hashed, role);

    addNotification("USER_CREATED", `User created: ${email}`);

    req.session.user = {
      id: result.lastInsertRowid,
      email,
      firstName,
      lastName,
      role
    };

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: "Email exists" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);

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
    firstName: user.firstName,
    lastName: user.lastName,
    role: user.role
  };

  addNotification("LOGIN", `User logged in: ${email}`);

  res.json({ success: true, user: req.session.user });
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

  res.json({ loggedIn: true, user: req.session.user });
});

/* ---------------- USERS ---------------- */

app.delete("/api/users/:id", requireAdmin, (req, res) => {
  const user = db.prepare("SELECT email FROM users WHERE id = ?").get(req.params.id);

  if (user) {
    addNotification("USER_DELETED", `User deleted: ${user.email}`);
  }

  db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);

  res.json({ success: true });
});

/* ---------------- SONGS ---------------- */

app.get("/api/songs", requireLogin, (req, res) => {
  const rows = db.prepare("SELECT * FROM songs ORDER BY id DESC").all();
  res.json({ songs: rows });
});

/* ---------------- UPLOAD SONGS ---------------- */

app.post("/api/upload-files", requireAdmin, upload.array("songs"), (req, res) => {
  req.files.forEach(file => {
    db.prepare(
      "INSERT INTO songs (title, artist, audioUrl) VALUES (?, ?, ?)"
    ).run(file.originalname, "Unknown", "/uploads/" + file.filename);

    addNotification("SONG_UPLOADED", `Uploaded: ${file.originalname}`);
  });

  res.json({ success: true });
});

/* ---------------- BACKGROUND UPLOAD ---------------- */

app.post("/api/upload-bg", requireAdmin, upload.any(), (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: "No file uploaded" });
  }

  const file = req.files[0];
  const fileUrl = "/uploads/" + file.filename;

  db.prepare(
    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)"
  ).run("background", fileUrl);

  addNotification("BG_UPDATED", "Background updated");

  res.json({ url: fileUrl });
});

app.get("/api/background", requireLogin, (req, res) => {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get("background");
  res.json({ url: row ? row.value : null });
});

/* ---------------- DELETE SONG ---------------- */

app.delete("/api/songs/:id", requireAdmin, (req, res) => {
  const song = db.prepare("SELECT * FROM songs WHERE id = ?").get(req.params.id);

  if (!song) return res.status(404).json({ error: "Not found" });

  addNotification("SONG_DELETED", `Deleted: ${song.title}`);

  fs.unlink(path.join(__dirname, "public", song.audioUrl), () => {});

  db.prepare("DELETE FROM songs WHERE id = ?").run(req.params.id);

  res.json({ success: true });
});

/* ---------------- SEARCH ---------------- */

app.get("/api/search", requireLogin, (req, res) => {
  const q = (req.query.q || "").toLowerCase();

  const songs = db.prepare("SELECT * FROM songs").all();

  const results = songs.filter(s =>
    (s.title + " " + s.artist).toLowerCase().includes(q)
  );

  if (q && results.length === 0) {
    addNotification("SEARCH_MISS", `No results for: "${q}"`);
  }

  res.json({ songs: results });
});

/* ---------------- NOTIFICATIONS ---------------- */

app.get("/api/notifications", requireLogin, (req, res) => {
  const rows = db.prepare(
    "SELECT * FROM notifications ORDER BY id DESC LIMIT 50"
  ).all();

  res.json({ notifications: rows || [] });
});

/* ---------------- START ---------------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
