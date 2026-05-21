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
      console.error("API error:", url, res.status, data);
      return null;
    }

    return data;
  } catch (err) {
    console.error("Network error:", url, err);
    return null;
  }
}

// =========================
// LOAD SONGS
// =========================
let songsOffset = 0;
let songsLoading = false;
let songsHasMore = true;

async function loadSongs(reset = true) {
  if (songsLoading) return;

  songsLoading = true;

  if (reset) {
    songsOffset = 0;
    songsHasMore = true;
    state.songs = [];
  }

  const data = await apiFetch(`/api/songs?limit=50&offset=${songsOffset}`);

  songsLoading = false;

  if (!data) {
    console.warn("Failed to load songs");
    return;
  }

  state.songs = reset
    ? data.songs || []
    : [...state.songs, ...(data.songs || [])];

  songsOffset += data.songs?.length || 0;
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

  const data = await apiFetch(`/api/songs/${songId}/audio-url`);

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
