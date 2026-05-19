window.SPOTIVIBES_CONFIG = {
  API_BASE: ""
};

async function loadConfig() {
  const isLocal =
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

  if (isLocal) {
    window.SPOTIVIBES_CONFIG.API_BASE = "";
    return;
  }

  const res = await fetch("https://api.spotivibes.com/config");
  const data = await res.json();

  window.SPOTIVIBES_CONFIG.API_BASE = data.apiBase || "";
}