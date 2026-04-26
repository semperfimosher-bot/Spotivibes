const { Pool } = require("pg");
require("dotenv").config();

/* ---------------- POSTGRES POOL ---------------- */

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

/* ---------------- OPTIONAL: TEST CONNECTION ---------------- */

pool.connect()
  .then(() => {
    console.log("✅ PostgreSQL connected successfully");
  })
  .catch((err) => {
    console.error("❌ PostgreSQL connection error:", err);
  });

module.exports = pool;
