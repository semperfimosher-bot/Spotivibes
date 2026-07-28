(() => {
  function getReferrerOrigin() {
    if (!document.referrer) return null;

    try {
      return new URL(document.referrer).origin;
    } catch {
      return null;
    }
  }

  async function trackPageView() {
    try {
      if (typeof loadConfig === "function") {
        await loadConfig();
      }

      let apiBase = window.SPOTIVIBES_CONFIG?.API_BASE || "";

      if (!apiBase && !["localhost", "127.0.0.1"].includes(window.location.hostname)) {
        apiBase = "https://api.spotivibes.com";
      }

      const payload = {
        path: window.location.pathname === "/"
          ? "/"
          : window.location.pathname.replace(/\/+$/, ""),
        pageTitle: document.title,
        referrerOrigin: getReferrerOrigin(),
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        webdriver: navigator.webdriver === true
      };

      await fetch(`${apiBase}/api/activity/page-view`, {
        method: "POST",
        credentials: "include",
        keepalive: true,
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });
    } catch {
      // Analytics must never interrupt page loading or app use.
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", trackPageView, { once: true });
  } else {
    trackPageView();
  }
})();
