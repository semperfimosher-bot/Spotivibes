const fetch = require("node-fetch");

const MB_BASE = "https://musicbrainz.org/ws/2";
const USER_AGENT = "Spotivibes/1.0.0 (https://spotivibes.com)";

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function mbFetch(path) {
  const url = `${MB_BASE}${path}`;

  const res = await fetch(url, {
    headers: {
      "User-Agent": USER_AGENT,
      Accept: "application/json"
    }
  });

  if (!res.ok) {
    throw new Error(`MusicBrainz error ${res.status}`);
  }

  return res.json();
}

async function searchArtist(artistName) {
  if (!artistName) return null;

  const data = await mbFetch(
    `/artist?query=${encodeURIComponent(`artist:"${artistName}"`)}&fmt=json&limit=1`
  );

  return data.artists?.[0] || null;
}

async function getArtistRecordings(mbArtistId, limit = 150) {
  if (!mbArtistId) return [];

  // MusicBrainz asks clients not to hammer the API. This keeps your old behavior.
  await sleep(1200);

  const data = await mbFetch(
    `/recording?query=${encodeURIComponent(`arid:${mbArtistId}`)}&fmt=json&limit=${limit}`
  );

  return data.recordings || [];
}

module.exports = {
  searchArtist,
  getArtistRecordings
};
