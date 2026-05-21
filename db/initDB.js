/* ---------------- INIT DATABASE TABLES ---------------- */
const pool = require("../database");

async function initDB() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      first_name TEXT,
      last_name TEXT,
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
      audio_url TEXT,
      genre TEXT,
      album TEXT,
      duration REAL,
      cover_url TEXT
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS playlists (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id),
      name TEXT,
      query TEXT,
      is_generated BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
  ALTER TABLE playlists
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()
`);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS playlist_songs (
      playlist_id INT REFERENCES playlists(id) ON DELETE CASCADE,
      song_id INT REFERENCES songs(id),
      PRIMARY KEY (playlist_id, song_id)
    )
  `);

  await pool.query(`
  CREATE TABLE IF NOT EXISTS user_library (
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    song_id INT REFERENCES songs(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, song_id)
  )
`);

await pool.query(`
  CREATE TABLE IF NOT EXISTS listening_history (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    song_id INT REFERENCES songs(id) ON DELETE CASCADE,
    played_at TIMESTAMP DEFAULT NOW()
  )
`);

await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS genre TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS album TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS duration REAL`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS cover_url TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS lyrics TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS mood TEXT`);
  await pool.query(`ALTER TABLE songs ADD COLUMN IF NOT EXISTS year TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture TEXT`);
  await pool.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`);
  await pool.query(`ALTER TABLE playlists ADD COLUMN IF NOT EXISTS query TEXT`);
  await pool.query(`ALTER TABLE playlists ADD COLUMN IF NOT EXISTS is_generated BOOLEAN DEFAULT false`);
  await pool.query(`ALTER TABLE playlists ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()`);

 await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_id_desc
  ON songs (id DESC)
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_title_lower
  ON songs (LOWER(title))
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_artist
  ON songs (LOWER(artist))
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_album_lower
  ON songs (LOWER(album))
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_playlist_songs_playlist_id
  ON playlist_songs (playlist_id)
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_playlists_user_id
  ON playlists (user_id)
`);

await pool.query(`
  CREATE EXTENSION IF NOT EXISTS pg_trgm
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_title_trgm
  ON songs USING gin (title gin_trgm_ops)
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_artist_trgm
  ON songs USING gin (artist gin_trgm_ops)
`);

await pool.query(`
  CREATE INDEX IF NOT EXISTS idx_songs_album_trgm
  ON songs USING gin (album gin_trgm_ops)
`);

}

module.exports = initDB;