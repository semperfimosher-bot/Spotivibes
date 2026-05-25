const pool = require("../database");

const spotify = require("./spotify.service");
const musicBrainz = require("./musicbrainz.service");

const MAX_SUGGESTIONS = Number(process.env.MAX_ARTIST_SUGGESTIONS || 50);
const SPOTIFY_MARKET = process.env.SPOTIFY_MARKET || "US";

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
    "instrumental",
    "karaoke",
    "sped up",
    "slowed",
    "nightcore",
    "remix",
    "live",
    "commentary",
    "interlude",
    "skit"
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
      spotifyUrl: suggestion.spotifyUrl || null
    });
    return;
  }

  // Keep the better Spotify-ranked version if duplicate titles appear.
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

async function getSpotifySuggestions(artist) {
  console.log("Spotify configured?", spotify.spotifyIsConfigured());

  if (!spotify.spotifyIsConfigured()) {
    console.warn("Spotify is not configured. Skipping Spotify suggestions.");
    return [];
  }

  console.log("Searching Spotify artist:", artist);

  const foundArtist = await spotify.searchArtist(artist);

console.log("Spotify found artist:", foundArtist?.name, foundArtist?.id);

if (!foundArtist?.id) return [];

  const suggestions = [];

  const topTracks = await spotify.getArtistTopTracks(foundArtist.id, SPOTIFY_MARKET);

  for (const track of topTracks) {
    suggestions.push(spotify.spotifyTrackToSuggestion(track, "Spotify Top Tracks"));
  }

  const albums = await spotify.getArtistAlbums(foundArtist.id, SPOTIFY_MARKET, 8);

  for (const album of albums) {
    const tracks = await spotify.getAlbumTracks(album.id, SPOTIFY_MARKET);

    for (const track of tracks) {
      suggestions.push({
        title: track.name,
        source: "Spotify Albums",
        popularity: 0,
        album: album.name,
        spotifyUrl: track.external_urls?.spotify || null
      });
    }
  }

  return suggestions;
}

async function getMusicBrainzSuggestions(artist) {
  const foundArtist = await musicBrainz.searchArtist(artist);

  if (!foundArtist?.id) return [];

  const recordings = await musicBrainz.getArtistRecordings(foundArtist.id, 150);

  return recordings.map(recording => ({
    title: recording.title,
    source: "MusicBrainz",
    popularity: 0,
    album: null,
    spotifyUrl: null
  }));
}

async function checkArtistCompleteness(artist) {
  if (!artist || artist.toLowerCase() === "unknown artist") return;

  const ownedTitles = await getOwnedTitlesForArtist(artist);
  const suggestionMap = new Map();

  const results = await Promise.allSettled([
    getSpotifySuggestions(artist),
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
      // Spotify popular songs first, then alphabetically.
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

  const lines = suggested.map(song => {
    const extras = [
      song.album ? `album: ${song.album}` : null,
      song.source ? `source: ${song.source}` : null
    ].filter(Boolean);

    return `• ${song.title}${extras.length ? ` (${extras.join(", ")})` : ""}`;
  });

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

  console.log("Hybrid recommendation notification inserted:", artist);
}

module.exports = {
  checkArtistCompleteness,
  normalizeTitle
};
