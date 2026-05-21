require("dotenv").config();

const cors = require("cors");
const express = require("express");
const path = require("path");
const session = require("express-session");
const PgSession = require("connect-pg-simple")(session);
const rateLimit = require("express-rate-limit");
const pool = require("./database");
const initDB = require("./db/initDB");
const configRoutes = require("./routes/config.routes");
const authRoutes = require("./routes/auth.routes");
const libraryRoutes = require("./routes/library.routes");
const songRoutes = require("./routes/song.routes");
const adminRoutes = require("./routes/admin.routes");
const playlistRoutes = require("./routes/playlist.routes");
const usersRoutes = require("./routes/users.routes");
const statsRoutes = require("./routes/stats.routes");
const helmet = require("helmet");
const Sentry = require("@sentry/node");

if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN
  });
}

const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: [
        "'self'",
        "https://s3.us-east-005.backblazeb2.com"
      ],
      imgSrc: [
        "'self'",
        "data:",
        "blob:",
        "https://s3.us-east-005.backblazeb2.com"
      ],
      mediaSrc: [
        "'self'",
        "blob:",
        "https://s3.us-east-005.backblazeb2.com"
      ]
    }
  }
}));

app.set("trust proxy", 1);

app.use(cors({
  origin: [
  process.env.FRONTEND_URL,
  "https://spotivibes.com",
  "https://www.spotivibes.com"
].filter(Boolean),
  credentials: true
}));

app.use("/config", configRoutes);

app.use(session({
  store: new PgSession({
    pool,
    tableName: "sessions"
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: 1000 * 60 * 60 * 24 * 7
}
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/app", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "app", "index.html"));
});

app.use("/api/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: "Too many login attempts. Try again later." }
}));

app.use("/api/register", rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: "Too many accounts created. Try again later." }
}));

app.use("/api", authRoutes);
app.use("/api/library", libraryRoutes);
app.use("/api", songRoutes);
app.use("/api", adminRoutes);
app.use("/api/playlists", playlistRoutes);
app.use("/api/users", usersRoutes);
app.use("/api/listening-stats", statsRoutes);

app.get("/ping", (req, res) => {
  res.status(200).send("OK");
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error({
    message: err.message,
    stack: process.env.NODE_ENV === "production" ? undefined : err.stack,
    path: req.path,
    method: req.method
  });

  if (process.env.SENTRY_DSN) {
  Sentry.captureException(err);
}

  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === "production"
      ? "Internal server error"
      : err.message
  });
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  initDB()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
      });
    })
    .catch((err) => {
      console.error("Database init failed:", err);
      process.exit(1);
    });
}

module.exports = app;