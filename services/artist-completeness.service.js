const fetch = require("node-fetch");
const pool = require("../database");

const MB_BASE = "https://musicbrainz.org/ws/2";
const USER_AGENT = "Spotivibes/1.0.0 (https://spotivibes.com)";

function normalizeTitle(title = "") {
  return title
    .toLowerCase()
    .replace(/\(.*?\)|\[.*?\]/g, "")
    .replace(/feat\.|ft\./g, "")
    .replace(/[^a-z0-9 ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

async function mbFetch(url) {
  console.log("FETCHING MUSICBRAINZ:", url);

  const res = await fetch(url, {
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "application/json"
    }
  });

  if (!res.ok) {
    console.log("MUSICBRAINZ STATUS:", res.status);
    throw new Error(`MusicBrainz error ${res.status}`);
  }

  return res.json();
}

async function checkArtistCompleteness(artist) {

  if (!artist || artist.toLowerCase() === "unknown artist") return;

  const ownedResult = await pool.query(
    `
    SELECT title
    FROM songs
    WHERE artist ILIKE $1
    `,
    [artist]
  );

  const ownedTitles = new Set(
    ownedResult.rows.map(r => normalizeTitle(r.title))
  );

  const artistSearch = await mbFetch(
    `${MB_BASE}/artist?query=${encodeURIComponent(`artist:"${artist}"`)}&fmt=json&limit=1`
  );

  const mbArtist = artistSearch.artists?.[0];

  if (!mbArtist?.id) return;

  await new Promise(resolve => setTimeout(resolve, 1200));

  const recordings = await mbFetch(
    `${MB_BASE}/recording?query=${encodeURIComponent(`arid:${mbArtist.id}`)}&fmt=json&limit=150`
  );

  const suggested = [];

  for (const rec of recordings.recordings || []) {
    const title = rec.title;
    const normalized = normalizeTitle(title);

    if (!title || !normalized) continue;
    if (ownedTitles.has(normalized)) continue;

    if (!suggested.some(s => normalizeTitle(s) === normalized)) {
      suggested.push(title);
    }

    if (suggested.length >= 100) break;
  }

  if (!suggested.length) return;

  await pool.query(
    `
    DELETE FROM notifications
    WHERE type = 'ARTIST_MISSING_SONGS'
      AND message ILIKE $1
    `,
    [`%${artist}%`]
  );

  await pool.query(
    `
    INSERT INTO notifications (type, message, time)
    VALUES ($1, $2, NOW())
    `,
    [
      "ARTIST_MISSING_SONGS",
      `You uploaded music by ${artist}.\n\nNew suggested songs:\n• ${suggested.join("\n• ")}`
    ]
  );

  console.log("Notification inserted:", artist);
}

module.exports = {
  checkArtistCompleteness
};