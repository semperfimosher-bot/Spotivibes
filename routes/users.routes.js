const express = require("express");

const pool = require("../database");

const {
  requireAdmin
} = require("../middleware/auth.middleware");

const {
  addNotification
} = require("../services/notification.service");

const router = express.Router();

/* ---------------- DELETE USER ---------------- */

router.delete("/:id", requireAdmin, async (req, res) => {
  try {
    const userResult = await pool.query(
      "SELECT email FROM users WHERE id = $1",
      [req.params.id]
    );

    const user = userResult.rows[0];

    await pool.query(
      "DELETE FROM users WHERE id = $1",
      [req.params.id]
    );

    if (user) {
      await addNotification(
        "USER_DELETED",
        `User deleted: ${user.email}`
      );
    }

    res.json({ success: true });

  } catch (err) {
    console.error("DELETE USER ERROR:", err);

    res.status(500).json({
      error: "Server error"
    });
  }
});

module.exports = router;