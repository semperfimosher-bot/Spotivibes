const express = require("express");
const bcrypt = require("bcrypt");
const multer = require("multer");

const pool = require("../database");

const {
  requireLogin
} = require("../middleware/auth.middleware");

const {
  registerSchema
} = require("../utils/validators");

const {
  addNotification
} = require("../services/notification.service");

const {
  normalizeEmail,
  recordRequestActivity
} = require("../services/activity.service");

const {
  b2,
  getPublicCoverUrl,
  B2_COVER_BUCKET_NAME,
  PutObjectCommand
} = require("../services/storage.service");

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only JPG, PNG, or WEBP images allowed"));
    }

    cb(null, true);
  }
});

/* ---------------- REGISTER ---------------- */

router.post("/register", async (req, res) => {
  try {
    const validationResult = registerSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: "Invalid input",
        details: validationResult.error.errors
      });
    }

    const { firstName, lastName, email, password } =
      validationResult.data;

    const hashed = await bcrypt.hash(password, 10);

    const countResult =
      await pool.query("SELECT COUNT(*) FROM users");

    const userCount =
      Number(countResult.rows[0].count);

    const role =
      userCount === 0 ? "admin" : "user";

    const result = await pool.query(
      `
      INSERT INTO users
      (first_name, last_name, email, password, role)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING id
      `,
      [firstName, lastName, email, hashed, role]
    );

    await addNotification(
      "USER_CREATED",
      `User created: ${email}`
    );

    req.session.user = {
      id: result.rows[0].id,
      email,
      firstName,
      lastName,
      role
    };

    await recordRequestActivity(req, "REGISTER_SUCCESS", {
      userId: result.rows[0].id,
      firstName,
      lastName,
      email
    });

    res.json({ success: true });

  } catch (err) {
    console.error("REGISTER ERROR:", err);

    return res.status(400).json({
      error: err.message
    });
  }
});

/* ---------------- LOGIN ---------------- */

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    const user = result.rows[0];

    if (!user || typeof user.password !== "string") {
      await recordRequestActivity(req, "LOGIN_FAILED", {
        email: normalizeEmail(email),
        metadata: { reason: "unknown_account" }
      });

      return res.status(401).json({
        error: "Invalid login"
      });
    }

    const match =
      await bcrypt.compare(password, user.password);

    if (!match) {
      await recordRequestActivity(req, "LOGIN_FAILED", {
        userId: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        metadata: { reason: "incorrect_password" }
      });

      return res.status(401).json({
        error: "Invalid login"
      });
    }

    req.session.regenerate(async err => {
      if (err) {
        return res.status(500).json({
          error: "Session error"
        });
      }

      req.session.user = {
        id: user.id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role
      };

      await recordRequestActivity(req, "LOGIN_SUCCESS", {
        userId: user.id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email
      });

      res.json({
        success: true,
        user: req.session.user
      });
    });

  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "Server error"
    });
  }
});

/* ---------------- LOGOUT ---------------- */

router.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);

      return res.status(500).json({
        error: "Logout failed"
      });
    }

    res.json({ success: true });
  });
});

/* ---------------- CURRENT USER ---------------- */

router.get("/me", async (req, res) => {

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

      profilePicUrl: getPublicCoverUrl(user.profile_pic_url)
    }
  });
});

/* ---------------- PROFILE PICTURE ---------------- */

router.post(
  "/profile-picture",
  requireLogin,
  upload.single("image"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "No image uploaded"
        });
      }

      const ext =
        req.file.originalname.split(".").pop()?.toLowerCase() || "jpg";

      const safeName = req.file.originalname
        .replace(/\.[^/.]+$/, "")
        .replace(/[^a-zA-Z0-9-_]/g, "_")
        .slice(0, 60);

      const fileKey =
        `profiles/${req.session.user.id}-${Date.now()}-${safeName}.${ext}`;

      await b2.send(
        new PutObjectCommand({
          Bucket: B2_COVER_BUCKET_NAME,
          Key: fileKey,
          Body: req.file.buffer,
          ContentType: req.file.mimetype,
          CacheControl: "public, max-age=31536000"
        })
      );

      await pool.query(
        `
        UPDATE users
        SET profile_pic_url = $1
        WHERE id = $2
        `,
        [fileKey, req.session.user.id]
      );

      res.json({
        success: true,
        profilePicUrl: getPublicCoverUrl(fileKey)
      });

    } catch (err) {
      console.error("PROFILE PIC ERROR:", err);

      res.status(500).json({
        error: "Upload failed"
      });
    }
  }
);

router.post(
  "/profile-pic",
  requireLogin,
  upload.single("image"),
  async (req, res, next) => {
    req.url = "/profile-picture";
    next();
  }
);

module.exports = router;