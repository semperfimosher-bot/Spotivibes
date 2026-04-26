const express = require("express");
const path = require("path");
const multer = require("multer");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
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

const db = new sqlite3.Database(path.join(__dirname, "spotivibes.db"));

db.serialize(() => {

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      firstName TEXT,
      lastName TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS songs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      artist TEXT,
      audioUrl TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT,
      message TEXT,
      time TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

});

/* ---------------- HELPERS ---------------- */

function addNotification(type, message) {
  const time = new Date().toLocaleString();

  db.run(
    "INSERT INTO notifications (type, message, time) VALUES (?, ?, ?)",
    [type, message, time]
  );
}

/* ---------------- UPLOAD SETUP ---------------- */

const uploadDir = path.join(__dirname, "public/uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

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

  db.get("SELECT COUNT(*) as count FROM users", [], (err, row) => {

    const role = row.count === 0 ? "admin" : "user";

    db.run(
      "INSERT INTO users (firstName, lastName, email, password, role) VALUES (?, ?, ?, ?, ?)",
      [firstName, lastName, email, hashed, role],
      function (err) {
        if (err) return res.status(400).json({ error: "Email exists" });

        addNotification("USER_CREATED", `User created: ${email}`);

        req.session.user = {
          id: this.lastID,
          email,
          firstName,
          lastName,
          role
        };

        res.json({ success: true });
      }
    );

  });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {

    if (err) return res.status(500).json({ error: "Database error" });

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

    res.json({
      success: true,
      user: req.session.user
    });
  });
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

app.delete("/api/users/:id", requireAdmin, (req, res) => {

  db.get("SELECT email FROM users WHERE id = ?", [req.params.id], (err, user) => {

    if (user) {
      addNotification("USER_DELETED", `User deleted: ${user.email}`);
    }

    db.run("DELETE FROM users WHERE id = ?", [req.params.id], () => {
      res.json({ success: true });
    });

  });

});

/* ---------------- SONGS ---------------- */

app.get("/api/songs", requireLogin, (req, res) => {
  db.all("SELECT * FROM songs ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ songs: rows });
  });
});

/* ---------------- UPLOAD SONGS ---------------- */

app.post("/api/upload-files", requireAdmin, upload.array("songs"), (req, res) => {

  req.files.forEach(file => {

    db.run(
      "INSERT INTO songs (title, artist, audioUrl) VALUES (?, ?, ?)",
      [file.originalname, "Unknown", "/uploads/" + file.filename]
    );

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

  db.run(
    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
    ["background", fileUrl]
  );

  addNotification("BG_UPDATED", "Background updated");

  res.json({ url: fileUrl });
});

app.get("/api/background", requireLogin, (req, res) => {
  db.get(
    "SELECT value FROM settings WHERE key = ?",
    ["background"],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });

      res.json({ url: row ? row.value : null });
    }
  );
});

/* ---------------- DELETE SONG ---------------- */

app.delete("/api/songs/:id", requireAdmin, (req, res) => {

  db.get("SELECT * FROM songs WHERE id = ?", [req.params.id], (err, song) => {
    if (!song) return res.status(404).json({ error: "Not found" });

    addNotification("SONG_DELETED", `Deleted: ${song.title}`);

    fs.unlink(path.join(__dirname, "public", song.audioUrl), () => {});

    db.run("DELETE FROM songs WHERE id = ?", [req.params.id], () => {
      res.json({ success: true });
    });
  });

});

/* ---------------- SEARCH ---------------- */

app.get("/api/search", requireLogin, (req, res) => {

  const q = (req.query.q || "").toLowerCase();

  db.all("SELECT * FROM songs", (err, songs) => {
    if (err) return res.status(500).json({ error: err.message });

    const results = songs.filter(s =>
      (s.title + " " + s.artist).toLowerCase().includes(q)
    );

    if (q && results.length === 0) {
      addNotification("SEARCH_MISS", `No results for: "${q}"`);
    }

    res.json({ songs: results });
  });

});

/* ---------------- NOTIFICATIONS ---------------- */

app.get("/api/notifications", requireLogin, (req, res) => {

  db.all(
    "SELECT * FROM notifications ORDER BY id DESC LIMIT 50",
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });

      res.json({ notifications: rows || [] });
    }
  );

});

/* ---------------- START ---------------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
