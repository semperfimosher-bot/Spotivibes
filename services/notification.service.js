const pool = require("../database");

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

module.exports = {
  addNotification
};