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
    console.warn("iTunes genre lookup failed:", err.message);
    return null;
  }
}

module.exports = {
  fetchGenreFromITunes
};