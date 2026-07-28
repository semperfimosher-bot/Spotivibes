const TRACKED_PATHS = new Set(["/", "/login", "/register", "/app"]);

function normalizePath(pathname) {
  if (!pathname || pathname === "/") return "/";
  return pathname.replace(/\/+$/, "");
}

function getReferrerOrigin(request) {
  const referrer = request.headers.get("referer");
  if (!referrer) return null;

  try {
    return new URL(referrer).origin;
  } catch {
    return null;
  }
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);
  const shouldTrack = ["GET", "HEAD"].includes(request.method)
    && TRACKED_PATHS.has(path);

  const response = await context.next();

  if (
    shouldTrack
    && response.status < 400
    && env.ACTIVITY_INGEST_SECRET
  ) {
    const apiBase = String(
      env.ACTIVITY_API_BASE || "https://api.spotivibes.com"
    ).replace(/\/+$/, "");

    const botManagement = request.cf?.botManagement;
    const verifiedBot = Boolean(
      botManagement?.verifiedBot || botManagement?.verifiedBotCategory
    );

    const activityRequest = fetch(`${apiBase}/api/activity/server-page-view`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-activity-secret": env.ACTIVITY_INGEST_SECRET
      },
      body: JSON.stringify({
        path,
        method: request.method,
        ipAddress: request.headers.get("CF-Connecting-IP"),
        userAgent: request.headers.get("user-agent"),
        referrerOrigin: getReferrerOrigin(request),
        country: request.cf?.country || null,
        verifiedBot
      })
    });

    context.waitUntil(activityRequest.catch(() => {}));
  }

  return response;
}
