const fetch = require("node-fetch");

const DEEZER_API_BASE = "https://api.deezer.com";

function deezerIsConfigured() {
  // Deezer public catalog endpoints do not need an API key for this use case.
  return true;
}

async function deezerFetch(path) {
  const url = `${DEEZER_API_BASE}${path}`;

  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      "User-Agent": "Spotivibes/1.0.0"
    }
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Deezer API error ${res.status}: ${text}`);
  }

  const data = await res.json();

  // Deezer sometimes returns API errors inside a 200 response.
  if (data?.error) {
    throw new Error(`Deezer API error: ${data.error.message || JSON.stringify(data.error)}`);
  }

  return data;
}

async function searchArtist(artistName) {
  if (!artistName) return null;

  const data = await deezerFetch(
    `/search/artist?q=${encodeURIComponent(artistName)}&limit=1`
  );

  return data?.data?.[0] || null;
}

async function getArtistTopTracks(artistId, limit = 25) {
  if (!artistId) return [];

  const data = await deezerFetch(
    `/artist/${encodeURIComponent(artistId)}/top?limit=${encodeURIComponent(limit)}`
  );

  return data?.data || [];
}

async function getArtistAlbums(artistId, limit = 8) {
  if (!artistId) return [];

  const data = await deezerFetch(
    `/artist/${encodeURIComponent(artistId)}/albums?limit=${encodeURIComponent(limit)}`
  );

  return data?.data || [];
}

async function getAlbumTracks(albumId, limit = 50) {
  if (!albumId) return [];

  const data = await deezerFetch(
    `/album/${encodeURIComponent(albumId)}/tracks?limit=${encodeURIComponent(limit)}`
  );

  return data?.data || [];
}

function deezerTrackToSuggestion(track, source = "Deezer Top Tracks") {
  return {
    title: track.title_short || track.title,
    source,
    // Deezer rank is bigger for more popular tracks. This lets your existing sort put Deezer songs first.
    popularity: track.rank || 0,
    album: track.album?.title || null,
    externalUrl: track.link || null,
    previewUrl: track.preview || null,
    providerId: track.id ? String(track.id) : null
  };
}

module.exports = {
  deezerIsConfigured,
  searchArtist,
  getArtistTopTracks,
  getArtistAlbums,
  getAlbumTracks,
  deezerTrackToSuggestion
};
