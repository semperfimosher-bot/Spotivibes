function getApiBase() {
  return window.SPOTIVIBES_CONFIG?.API_BASE || "";
}
// =========================
// GENERIC FETCH HELPER
// =========================
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(`${getApiBase()}${url}`, {
      credentials: "include",
      ...options,
    });

    const text = await res.text();

    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = { error: text };
    }

    if (!res.ok) {
  const message = data?.error || `Request failed with status ${res.status}`;
  throw new Error(message);
}

    return data;
  } catch (err) {
  console.error("Network error:", url, err);
  throw err;
}
}

// =========================
// LOAD SONGS
// =========================
let songsCursor = null;
let songsLoading = false;
let songsHasMore = true;

async function loadSongs(reset = true) {
  if (songsLoading) return;

  songsLoading = true;

  if (reset) {
    songsCursor = null;
    songsHasMore = true;
    state.songs = [];
  }

  let data;

try {
  const cursorParam = songsCursor ? `&cursor=${songsCursor}` : "";
data = await apiFetch(`/api/songs?limit=50${cursorParam}`);
} catch (err) {
  console.warn("Failed to load songs:", err.message);
  songsLoading = false;
  return;
}

songsLoading = false;

  state.songs = reset
    ? data.songs || []
    : [...state.songs, ...(data.songs || [])];

  songsCursor = data.nextCursor;
songsHasMore = data.hasMore;

  renderHome();
}

async function loadMoreSongs() {
  if (!songsHasMore || songsLoading) return;
  await loadSongs(false);
}

const audioUrlCache = new Map();

async function getAudioUrl(songId) {
  if (audioUrlCache.has(songId)) {
    return audioUrlCache.get(songId);
  }

  let data;

try {
  data = await apiFetch(`/api/songs/${songId}/audio-url`);
} catch (err) {
  console.warn("Failed to get audio URL:", err.message);
  return null;
}

  const url = data?.audioUrl || null;

  if (url) {
    audioUrlCache.set(songId, url);
  }

  return url;
}

// =========================
// LOAD BACKGROUND
// =========================
async function loadBackground() {
  const data = await apiFetch("/api/background");

  if (!data || !data.url) return;

  document.body.style.backgroundImage = `url('${data.url}')`;
  document.body.style.backgroundSize = "cover";
  document.body.style.backgroundPosition = "center";
}

// =========================
// LOGOUT
// =========================
async function logout() {
  await apiFetch("/api/logout", { method: "POST" });

  window.location.href = "/login";
}
