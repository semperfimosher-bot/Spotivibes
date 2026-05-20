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

const app = express();
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "blob:", "https:"],
        mediaSrc: ["'self'", "https:"],
        connectSrc: ["'self'", process.env.FRONTEND_URL || "'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
      },
    },
  })
);

app.set("trust proxy", 1);

app.use(cors({
  origin: process.env.FRONTEND_URL,
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
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
}));

app.use("/api/login", rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
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

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);

  if (!res.headersSent) {
    res.status(500).json({
      error: err.message || "Internal server error"
    });
  }
});

const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`🚀 Spotivibes server running on port ${PORT}`);
  });
});