// =========================
// GENERIC FETCH HELPER
// =========================
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, {
      credentials: "include",
      ...options,
    });

    if (!res.ok) {
      console.error("API error:", url, res.status);
      return null;
    }

    return await res.json();
  } catch (err) {
    console.error("Network error:", url, err);
    return null;
  }
}

// =========================
// LOAD USER
// =========================
async function loadUser() {
  const data = await apiFetch("/api/me");
  const box = document.getElementById("userBox");

  if (!data || !data.loggedIn) {
    box.innerText = "Not logged in";
    return;
  }

  box.innerText = `👤 ${data.user.firstName} ${data.user.lastName}`;
}

// =========================
// LOAD SONGS
// =========================
async function loadSongs() {
  const data = await apiFetch("/api/songs");

  if (!data) {
    console.warn("Failed to load songs");
    return;
  }

  state.songs = data.songs || [];

  // keep your existing flow
  renderHome();
  renderLibrary();
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
