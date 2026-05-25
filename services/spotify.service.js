const fetch = require("node-fetch");

const SPOTIFY_TOKEN_URL = "https://accounts.spotify.com/api/token";
const SPOTIFY_API_BASE = "https://api.spotify.com/v1";

let cachedToken = null;
let tokenExpiresAt = 0;

function spotifyIsConfigured() {
  return Boolean(process.env.SPOTIFY_CLIENT_ID && process.env.SPOTIFY_CLIENT_SECRET);
}

async function getSpotifyAccessToken() {
  if (!spotifyIsConfigured()) {
    return null;
  }

  // Reuse the token until about 1 minute before it expires.
  if (cachedToken && Date.now() < tokenExpiresAt - 60_000) {
    return cachedToken;
  }

  const basicAuth = Buffer
    .from(`${process.env.SPOTIFY_CLIENT_ID}:${process.env.SPOTIFY_CLIENT_SECRET}`)
    .toString("base64");

  const res = await fetch(SPOTIFY_TOKEN_URL, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basicAuth}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "grant_type=client_credentials"
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Spotify token error ${res.status}: ${text}`);
  }

  const data = await res.json();

  cachedToken = data.access_token;
  tokenExpiresAt = Date.now() + ((data.expires_in || 3600) * 1000);

  return cachedToken;
}

async function spotifyFetch(path) {
  const token = await getSpotifyAccessToken();

  if (!token) {
    // This keeps your app working even before Spotify env vars are added.
    return null;
  }

  const res = await fetch(`${SPOTIFY_API_BASE}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });

  if (res.status === 429) {
    const retryAfter = res.headers.get("retry-after");
    throw new Error(`Spotify rate limited. Retry after ${retryAfter || "a few"} seconds.`);
  }

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Spotify API error ${res.status}: ${text}`);
  }

  return res.json();
}

async function searchArtist(artistName) {
  if (!artistName) return null;

  const data = await spotifyFetch(
    `/search?type=artist&limit=1&q=${encodeURIComponent(artistName)}`
  );

  return data?.artists?.items?.[0] || null;
}

async function getArtistTopTracks(artistId, market = "US") {
  if (!artistId) return [];

  const data = await spotifyFetch(
    `/artists/${encodeURIComponent(artistId)}/top-tracks?market=${encodeURIComponent(market)}`
  );

  return data?.tracks || [];
}

async function getArtistAlbums(artistId, market = "US", limit = 8) {
  if (!artistId) return [];

  const data = await spotifyFetch(
    `/artists/${encodeURIComponent(artistId)}/albums?include_groups=album,single&market=${encodeURIComponent(market)}&limit=${limit}`
  );

  return data?.items || [];
}

async function getAlbumTracks(albumId, market = "US") {
  if (!albumId) return [];

  const data = await spotifyFetch(
    `/albums/${encodeURIComponent(albumId)}/tracks?market=${encodeURIComponent(market)}&limit=50`
  );

  return data?.items || [];
}

function spotifyTrackToSuggestion(track, source = "Spotify") {
  return {
    title: track.name,
    source,
    popularity: track.popularity || 0,
    album: track.album?.name || null,
    spotifyUrl: track.external_urls?.spotify || null
  };
}

module.exports = {
  spotifyIsConfigured,
  searchArtist,
  getArtistTopTracks,
  getArtistAlbums,
  getAlbumTracks,
  spotifyTrackToSuggestion
};
