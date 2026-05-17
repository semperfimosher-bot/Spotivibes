require("dotenv").config();
const pool = require("./database");

async function fetchGenreFromITunes({ title, artist }) {
  try {
    const term = `${artist || ""} ${title || ""}`.trim();
    if (!term) return null;

    const res = await fetch(
      `https://itunes.apple.com/search?term=${encodeURIComponent(term)}&entity=song&limit=1`
    );

    if (!res.ok) return null;

    const data = await res.json();

    return data.results?.[0]?.primaryGenreName || null;
  } catch (err) {
    console.warn("iTunes lookup failed:", title, err.message);
    return null;
  }
}

async function main() {
  const result = await pool.query(`
    SELECT id, title, artist
    FROM songs
    WHERE genre IS NULL
       OR genre = ''
       OR genre = 'unknown'
  `);

  console.log(`Found ${result.rows.length} songs missing genre`);

  for (const song of result.rows) {
    const genre = await fetchGenreFromITunes(song);

    if (!genre) {
      console.log(`No genre found: ${song.artist} - ${song.title}`);
      continue;
    }

    await pool.query(
      `UPDATE songs SET genre = $1 WHERE id = $2`,
      [genre, song.id]
    );

    console.log(`Updated: ${song.artist} - ${song.title} → ${genre}`);
  }

  console.log("Done");
  process.exit();
}

main();