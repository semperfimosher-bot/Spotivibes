async function fetchLyricsFromLRCLIB({ title, artist, album, duration }) {
  try {
    const params = new URLSearchParams({
      track_name: title || "",
      artist_name: artist || "",
    });

    if (album) {
      params.append("album_name", album);
    }

    if (duration) {
      params.append("duration", Math.round(duration));
    }

    const res = await fetch(
      `https://lrclib.net/api/get?${params.toString()}`
    );

    if (!res.ok) {
      console.warn("LRCLIB lyrics not found:", title, artist);
      return null;
    }

    const data = await res.json();

    return data.syncedLyrics || data.plainLyrics || null;
  } catch (err) {
    console.warn("LRCLIB fetch failed:", err.message);
    return null;
  }
}

async function fetchLyrics({ title, artist, album, duration }) {
  const lrclibLyrics = await fetchLyricsFromLRCLIB({
    title,
    artist,
    album,
    duration
  });

  if (lrclibLyrics) return lrclibLyrics;

  return null;
}

module.exports = {
  fetchLyricsFromLRCLIB,
  fetchLyrics
};