window.SPOTIVIBES_CONFIG = {
  API_BASE: ""
};

async function loadConfig() {
  try {
    const configUrl =
      window.location.hostname === "localhost"
        ? "/config"
        : "/config";

    const res = await fetch(configUrl);
    const data = await res.json();

    window.SPOTIVIBES_CONFIG.API_BASE = data.apiBase || "";
  } catch (err) {
    console.error("Failed to load config:", err);
  }
}