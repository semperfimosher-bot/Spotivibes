const pool = require("../database");

const fetchFn =
  global.fetch ||
  ((...args) => import("node-fetch").then(({ default: fetch }) => fetch(...args)));

function normalize(value = "") {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

async function deezerFetch(path) {
  const res = await fetchFn(`https://api.deezer.com${path}`);
  const data = await res.json();

  if (data.error) {
    throw new Error(data.error.message || "Deezer error");
  }

  return data;
}

async function getExistingArtists() {
  const result = await pool.query(`
    SELECT artist, COUNT(*)::int AS song_count
    FROM songs
    WHERE artist IS NOT NULL
    GROUP BY artist
    ORDER BY song_count DESC
    LIMIT 75
  `);

  const artists = result.rows.map(row => row.artist);

  const normalized = new Set(
    artists.map(artist => normalize(artist))
  );

  return { artists, normalized };
}

async function searchDeezerArtist(name) {
  const data = await deezerFetch(
    `/search/artist?q=${encodeURIComponent(name)}&limit=1`
  );

  return data.data?.[0] || null;
}

async function getRelatedArtists(artistId) {
  try {
    const data = await deezerFetch(`/artist/${artistId}/related?limit=25`);
    return data.data || [];
  } catch (err) {
    console.warn("Related artist lookup failed:", err.message);
    return [];
  }
}

async function getPopularChartArtists() {
  const genreIds = [
    0,   // all
    132, // pop
    116, // rap/hip-hop
    152, // rock
    113, // dance
    165, // r&b
    85   // alternative
  ];

  const artists = [];

  for (const genreId of genreIds) {
    try {
      const data = await deezerFetch(`/chart/${genreId}/artists?limit=100`);
      artists.push(...(data.data || []));
    } catch (err) {
      console.warn("Chart artist discovery failed:", err.message);
    }
  }

  return artists;
}

async function discoverMissingArtists() {
  const existing = await getExistingArtists();

  const artistMap = new Map();

  // 1. Popular chart artists
  const chartArtists = await getPopularChartArtists();

  for (const artist of chartArtists) {
    if (!artist?.name) continue;

    const key = normalize(artist.name);
    if (!key || existing.normalized.has(key)) continue;

    artistMap.set(key, {
      name: artist.name,
      deezerId: artist.id,
      score: 50,
      reason: "Popular"
    });
  }

  // 2. Related artists based on your existing library
  for (const artistName of existing.artists.slice(0, 25)) {
    try {
      const deezerArtist = await searchDeezerArtist(artistName);
      if (!deezerArtist?.id) continue;

      const related = await getRelatedArtists(deezerArtist.id);

      for (const artist of related) {
        if (!artist?.name) continue;

        const key = normalize(artist.name);
        if (!key || existing.normalized.has(key)) continue;

        const current = artistMap.get(key);

        if (current) {
          current.score += 35;
          current.reason =
            current.reason.includes("Related")
              ? current.reason
              : `${current.reason} + Related`;
        } else {
          artistMap.set(key, {
            name: artist.name,
            deezerId: artist.id,
            score: 80,
            reason: `Related to ${artistName}`
          });
        }
      }
    } catch (err) {
      console.warn("Related discovery failed for", artistName, err.message);
    }
  }

  return Array.from(artistMap.values())
    .sort((a, b) => b.score - a.score)
    .slice(0, 200);
}

async function createMissingArtistsNotification() {
  const artists = await discoverMissingArtists();

  if (!artists.length) {
    return { success: true, count: 0 };
  }

  const lines = artists.map(artist => `• ${artist.name}`);

  await pool.query(
    `
    INSERT INTO notifications (type, message, time)
    VALUES ($1, $2, NOW())
    `,
    [
      "MISSING_ARTISTS",
      `Modern artists you may want to add:\n\nSuggested artists to consider uploading:\n${lines.join("\n")}`
    ]
  );

  return {
    success: true,
    count: artists.length
  };
}

module.exports = {
  discoverMissingArtists,
  createMissingArtistsNotification
};
