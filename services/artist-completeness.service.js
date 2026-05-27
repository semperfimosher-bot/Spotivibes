const pool = require("../database");

const deezer = require("./deezer.service");
const musicBrainz = require("./musicbrainz.service");

const MAX_SUGGESTIONS = Number(process.env.MAX_ARTIST_SUGGESTIONS || 50);

function normalizeTitle(title = "") {
  return title
    .toLowerCase()
    .replace(/\(.*?\)|\[.*?\]/g, "")
    .replace(/feat\.|ft\./g, "")
    .replace(/[^a-z0-9 ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function isBadSuggestionTitle(title = "") {
  const cleaned = title.toLowerCase();

  return [
  "karaoke",
  "sped up",
  "slowed",
  "nightcore",
  "remix",
  "live",
  "commentary",
  "interlude",
  "skit",
  "intro",
  "outro",
  "freestyle",
  "demo",
  "edit",
  "version",
  "tribute",
  "cover",
  "official music video",
  "official video"
].some(word => cleaned.includes(word));
}

function addSuggestion(map, suggestion) {
  if (!suggestion?.title) return;
  if (isBadSuggestionTitle(suggestion.title)) return;

  const normalized = normalizeTitle(suggestion.title);

  if (!normalized) return;

  const existing = map.get(normalized);

  if (!existing) {
    map.set(normalized, {
      title: suggestion.title,
      source: suggestion.source || "Unknown",
      popularity: suggestion.popularity || 0,
      album: suggestion.album || null,
      externalUrl: suggestion.externalUrl || null,
      previewUrl: suggestion.previewUrl || null,
      providerId: suggestion.providerId || null
    });
    return;
  }

  // Keep the better-ranked version if duplicate titles appear.
  if ((suggestion.popularity || 0) > (existing.popularity || 0)) {
    map.set(normalized, {
      ...existing,
      ...suggestion,
      source: existing.source === suggestion.source
        ? existing.source
        : `${existing.source} + ${suggestion.source}`
    });
  } else if (!existing.source.includes(suggestion.source || "")) {
    existing.source = `${existing.source} + ${suggestion.source}`;
  }
}

async function getOwnedTitlesForArtist(artist) {
  const ownedResult = await pool.query(
    `
    SELECT title
    FROM songs
    WHERE artist ILIKE $1
    `,
    [artist]
  );

  return new Set(
    ownedResult.rows.map(r => normalizeTitle(r.title))
  );
}

async function getDeezerSuggestions(artist) {
  console.log("Searching Deezer artist:", artist);

  const foundArtist = await deezer.searchArtist(artist);

  console.log("Deezer found artist:", foundArtist?.name, foundArtist?.id);

  if (!foundArtist?.id) return [];

  const suggestions = [];

  // These are usually the best admin upload recommendations.
  const topTracks = await deezer.getArtistTopTracks(foundArtist.id, 100);

  for (const track of topTracks) {
    suggestions.push(deezer.deezerTrackToSuggestion(track, "Deezer Top Tracks"));
  }

  // Albums are useful for filling gaps, but keep this smaller so notifications stay clean.
  const albums = await deezer.getArtistAlbums(foundArtist.id, 5);

  for (const album of albums) {
    try {
      const tracks = await deezer.getAlbumTracks(album.id, 50);

      for (const track of tracks) {
        suggestions.push({
          title: track.title_short || track.title,
          source: "Deezer Albums",
          popularity: 0,
          album: album.title,
          externalUrl: track.link || null,
          previewUrl: track.preview || null,
          providerId: track.id ? String(track.id) : null
        });
      }
    } catch (err) {
      console.warn(`Deezer album lookup failed for album ${album.id}:`, err.message);
    }
  }

  return suggestions;
}

async function getMusicBrainzSuggestions(artist) {
  const foundArtist = await musicBrainz.searchArtist(artist);

  if (!foundArtist?.id) return [];

  const recordings = await musicBrainz.getArtistRecordings(foundArtist.id, 25);

  return recordings.map(recording => ({
    title: recording.title,
    source: "MusicBrainz",
    popularity: 0,
    album: null,
    externalUrl: null,
    previewUrl: null,
    providerId: null
  }));
}

async function checkArtistCompleteness(artist) {
  if (!artist || artist.toLowerCase() === "unknown artist") return;

  const ownedTitles = await getOwnedTitlesForArtist(artist);
  const suggestionMap = new Map();

  const results = await Promise.allSettled([
    getDeezerSuggestions(artist),
    getMusicBrainzSuggestions(artist)
  ]);

  for (const result of results) {
    if (result.status === "rejected") {
      console.warn("Suggestion provider failed:", result.reason?.message || result.reason);
      continue;
    }

    for (const suggestion of result.value) {
      const normalized = normalizeTitle(suggestion.title);

      if (ownedTitles.has(normalized)) continue;

      addSuggestion(suggestionMap, suggestion);
    }
  }

  const suggested = [...suggestionMap.values()]
    .sort((a, b) => {
      // Deezer ranked songs first, then alphabetically.
      if ((b.popularity || 0) !== (a.popularity || 0)) {
        return (b.popularity || 0) - (a.popularity || 0);
      }

      return a.title.localeCompare(b.title);
    })
    .slice(0, MAX_SUGGESTIONS);

  if (!suggested.length) return;

  await pool.query(
    `
    DELETE FROM notifications
    WHERE type = 'ARTIST_MISSING_SONGS'
      AND message ILIKE $1
    `,
    [`%${artist}%`]
  );

  const lines = suggested.map(song =>
  `• ${song.title || song.name} - ${song.artist || artist}`
);

await pool.query(
  `
  INSERT INTO notifications (type, message, time)
  VALUES ($1, $2, NOW())
  `,
  [
    "ARTIST_MISSING_SONGS",
    `You uploaded music by ${artist}.\n\nSuggested songs to consider uploading:\n${lines.join("\n")}`
  ]
);

  console.log("Deezer + MusicBrainz recommendation notification inserted:", artist);
}

module.exports = {
  checkArtistCompleteness,
  normalizeTitle
};
