const express = require("express");
const multer = require("multer");

const pool = require("../database");

const {
  requireLogin,
  requireAdmin
} = require("../middleware/auth.middleware");

const {
  b2,
  getPublicCoverUrl,
  B2_AUDIO_BUCKET_NAME,
  B2_COVER_BUCKET_NAME,
  PutObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  ListObjectsV2Command
} = require("../services/storage.service");

async function deleteB2Prefix(bucketName, prefix) {
  let ContinuationToken;

  do {
    const listResult = await b2.send(
      new ListObjectsV2Command({
        Bucket: bucketName,
        Prefix: prefix,
        ContinuationToken
      })
    );

    const objects = (listResult.Contents || []).map(obj => ({
      Key: obj.Key
    }));

    if (objects.length > 0) {
      await b2.send(
        new DeleteObjectsCommand({
          Bucket: bucketName,
          Delete: {
            Objects: objects,
            Quiet: true
          }
        })
      );
    }

    ContinuationToken = listResult.NextContinuationToken;
  } while (ContinuationToken);
}

const {
  addNotification
} = require("../services/notification.service");

const router = express.Router();
const DELETE_ALL_CODE = process.env.DELETE_ALL_CODE;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024
  },
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

/* ---------------- DELETE ALL CONTENT ---------------- */

router.post("/admin/delete-all-content", requireAdmin, async (req, res) => {
  try {
    const { code } = req.body;

    if (code !== DELETE_ALL_CODE) {
      return res.status(403).json({
        error: "Invalid confirmation code"
      });
    }

    const songsResult = await pool.query(`
      SELECT audio_url, cover_url
      FROM songs
    `);

    const settingsResult = await pool.query(`
      SELECT value
      FROM settings
      WHERE key = 'background'
    `);

    for (const song of songsResult.rows) {
      if (song.audio_url) {
        try {
          await b2.send(
            new DeleteObjectCommand({
              Bucket: B2_AUDIO_BUCKET_NAME,
              Key: song.audio_url
            })
          );
        } catch (err) {
          console.warn("AUDIO DELETE WARNING:", song.audio_url, err.message);
        }
      }

      if (song.cover_url) {
        try {
          await b2.send(
            new DeleteObjectCommand({
              Bucket: B2_COVER_BUCKET_NAME,
              Key: song.cover_url
            })
          );
        } catch (err) {
          console.warn("COVER DELETE WARNING:", song.cover_url, err.message);
        }
      }
    }

    for (const row of settingsResult.rows) {
      if (row.value) {
        try {
          await b2.send(
            new DeleteObjectCommand({
              Bucket: B2_COVER_BUCKET_NAME,
              Key: row.value
            })
          );
        } catch (err) {
          console.warn("BACKGROUND DELETE WARNING:", row.value, err.message);
        }
      }
    }

await deleteB2Prefix(B2_AUDIO_BUCKET_NAME, "songs/");
await deleteB2Prefix(B2_COVER_BUCKET_NAME, "covers/");
await deleteB2Prefix(B2_COVER_BUCKET_NAME, "backgrounds/");
await deleteB2Prefix(B2_COVER_BUCKET_NAME, "avatars/");

await pool.query("BEGIN");

await pool.query("DELETE FROM playlist_songs");
await pool.query("DELETE FROM user_library");
await pool.query("DELETE FROM listening_history");
await pool.query("DELETE FROM playlists");
await pool.query("DELETE FROM notifications");
await pool.query("DELETE FROM settings");
await pool.query("DELETE FROM songs");

await pool.query("COMMIT");

    res.json({ success: true });

  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});

    console.error("DELETE ALL CONTENT ERROR:", err);

    res.status(500).json({
      error: "Failed to delete content"
    });
  }
});

/* ---------------- BACKGROUND UPLOAD ---------------- */

router.post("/upload-bg", requireAdmin, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        error: "Error: No file uploaded"
      });
    }

    const safeName =
      req.file.originalname.replace(/[^a-zA-Z0-9.-]/g, "_");

    const fileKey =
      `backgrounds/${Date.now()}-${safeName}`;

    await b2.send(
      new PutObjectCommand({
        Bucket: B2_COVER_BUCKET_NAME,
        Key: fileKey,
        Body: req.file.buffer,
        ContentType: req.file.mimetype,
      })
    );

    await pool.query(
      `
      INSERT INTO settings (key, value)
      VALUES ($1, $2)
      ON CONFLICT (key)
      DO UPDATE SET value = EXCLUDED.value
      `,
      ["background", fileKey]
    );

    await addNotification(
      "BG_UPDATED",
      "Background updated"
    );

    res.json({ success: true });

  } catch (err) {
    console.error("BACKGROUND UPLOAD ERROR:", err);

    res.status(500).json({
      error: "Upload failed"
    });
  }
});

/* ---------------- GET BACKGROUND ---------------- */

router.get("/background", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT value FROM settings WHERE key = $1",
      ["background"]
    );

    const fileKey = result.rows[0]?.value;

    if (!fileKey) {
      return res.json({ url: null });
    }

    const url = getPublicCoverUrl(fileKey);

    res.json({ url });

  } catch (err) {
    console.error("BACKGROUND FETCH ERROR:", err);

    res.status(500).json({
      error: "Server error"
    });
  }
});

/* ---------------- NOTIFICATIONS ---------------- */

router.get("/notifications", requireLogin, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM notifications ORDER BY id DESC LIMIT 50"
    );

    res.json({
      notifications: result.rows || []
    });

  } catch (err) {
    console.error("NOTIFICATIONS ERROR:", err);

    res.status(500).json({
      error: "Server error"
    });
  }
});

module.exports = router;