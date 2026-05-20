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
// LOAD USER
// =========================
async function loadUser() {
  const data = await apiFetch("/api/me");
  const box = document.getElementById("userBox");
  const avatar = document.getElementById("profileAvatar");

  if (!data || !data.loggedIn) {
    if (box) box.innerText = "Not logged in";
    if (avatar) avatar.innerText = "?";
    return;
  }

  const firstName = data.user.firstName || "";
  const lastName = data.user.lastName || "";

  if (box) {
    box.innerText = `${firstName} ${lastName}`;
  }

  if (avatar) {
    avatar.innerText =
      `${firstName[0] || ""}${lastName[0] || ""}`.toUpperCase();
  }

data.user.profilePicture
 if (data.user.profilePicture && avatar) {
    avatar.innerText = "";
    avatar.style.backgroundImage = `url('${data.user.profilePicture}')`;
    avatar.style.backgroundSize = "cover";
    avatar.style.backgroundPosition = "center";
  }
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
