const BOT_PATTERN = /bot|crawler|spider|slurp|bingpreview|facebookexternalhit|whatsapp|telegrambot|discordbot|headless|playwright|puppeteer|selenium|curl|wget|python-requests|axios|postmanruntime/i;
const PAGE_PATHS = new Set(["/", "/login", "/register", "/app"]);

let lastCleanupAt = 0;
let pool;

function getPool() {
  if (!pool) {
    pool = require("../database");
  }

  return pool;
}

function cleanText(value, maxLength = 500) {
  if (value === undefined || value === null) return null;

  const text = String(value)
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .trim();

  if (!text) return null;
  return text.slice(0, maxLength);
}

function normalizeEmail(value) {
  const email = cleanText(value, 320);
  return email ? email.toLowerCase() : null;
}

function isLikelyBot(userAgent = "") {
  return BOT_PATTERN.test(String(userAgent));
}

function maskIp(ipAddress) {
  if (!ipAddress) return null;

  let ip = String(ipAddress).trim();

  if (ip.startsWith("::ffff:")) {
    ip = ip.slice(7);
  }

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) {
    const parts = ip.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
  }

  if (ip.includes(":")) {
    const parts = ip.split(":").filter(Boolean);
    return `${parts.slice(0, 4).join(":")}::`;
  }

  return cleanText(ip, 100);
}

function getRequestContext(req) {
  const userAgent = cleanText(req.get?.("user-agent"), 500);
  const sessionUser = req.session?.user || null;

  return {
    userId: sessionUser?.id || null,
    firstName: cleanText(sessionUser?.firstName, 100),
    lastName: cleanText(sessionUser?.lastName, 100),
    email: normalizeEmail(sessionUser?.email),
    path: cleanText(req.originalUrl || req.path, 500),
    method: cleanText(req.method, 12),
    ipAddress: maskIp(req.ip || req.socket?.remoteAddress),
    userAgent,
    isBot: isLikelyBot(userAgent)
  };
}

async function cleanupOldActivity() {
  const now = Date.now();

  if (now - lastCleanupAt < 6 * 60 * 60 * 1000) return;
  lastCleanupAt = now;

  await getPool().query(`
    DELETE FROM activity_events
    WHERE created_at < NOW() - INTERVAL '90 days'
  `);
}

async function recordActivity(eventType, details = {}) {
  try {
    const event = {
      eventType: cleanText(eventType, 80),
      userId: details.userId || null,
      firstName: cleanText(details.firstName, 100),
      lastName: cleanText(details.lastName, 100),
      email: normalizeEmail(details.email),
      path: cleanText(details.path, 500),
      method: cleanText(details.method, 12),
      ipAddress: cleanText(details.ipAddress, 100),
      userAgent: cleanText(details.userAgent, 500),
      isBot: Boolean(details.isBot),
      metadata: details.metadata && typeof details.metadata === "object"
        ? details.metadata
        : {}
    };

    if (!event.eventType) return;

    const insertSql = event.eventType === "PAGE_VIEW"
      ? `
        WITH recent AS (
          SELECT id
          FROM activity_events
          WHERE event_type = 'PAGE_VIEW'
            AND COALESCE(path, '') = COALESCE($6, '')
            AND COALESCE(ip_address, '') = COALESCE($8, '')
            AND COALESCE(user_agent, '') = COALESCE($9, '')
            AND created_at > NOW() - INTERVAL '3 seconds'
          ORDER BY created_at DESC
          LIMIT 1
        ),
        updated AS (
          UPDATE activity_events
          SET
            user_id = COALESCE($2, user_id),
            first_name = COALESCE($3, first_name),
            last_name = COALESCE($4, last_name),
            email = COALESCE($5, email),
            is_bot = is_bot OR $10,
            metadata = COALESCE(metadata, '{}'::jsonb) || $11::jsonb
          WHERE id = (SELECT id FROM recent)
          RETURNING id
        )
        INSERT INTO activity_events (
          event_type,
          user_id,
          first_name,
          last_name,
          email,
          path,
          method,
          ip_address,
          user_agent,
          is_bot,
          metadata
        )
        SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb
        WHERE NOT EXISTS (SELECT 1 FROM recent)
      `
      : `
        INSERT INTO activity_events (
          event_type,
          user_id,
          first_name,
          last_name,
          email,
          path,
          method,
          ip_address,
          user_agent,
          is_bot,
          metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)
      `;

    await getPool().query(
      insertSql,
      [
        event.eventType,
        event.userId,
        event.firstName,
        event.lastName,
        event.email,
        event.path,
        event.method,
        event.ipAddress,
        event.userAgent,
        event.isBot,
        JSON.stringify(event.metadata)
      ]
    );

    cleanupOldActivity().catch(err => {
      console.warn("Activity cleanup warning:", err.message);
    });
  } catch (err) {
    // Activity tracking must never break login or page loading.
    console.error("Activity tracking error:", err.message);
  }
}

function recordRequestActivity(req, eventType, overrides = {}) {
  return recordActivity(eventType, {
    ...getRequestContext(req),
    ...overrides
  });
}

function shouldTrackPageRequest(req) {
  if (!['GET', 'HEAD'].includes(req.method)) return false;

  const path = req.path && req.path.length > 1
    ? req.path.replace(/\/+$/, "")
    : req.path;

  if (!PAGE_PATHS.has(path)) return false;

  const accept = String(req.get?.("accept") || "");
  const userAgent = String(req.get?.("user-agent") || "");

  return accept.includes("text/html")
    || accept.includes("*/*")
    || isLikelyBot(userAgent);
}

module.exports = {
  cleanText,
  getRequestContext,
  isLikelyBot,
  maskIp,
  normalizeEmail,
  recordActivity,
  recordRequestActivity,
  shouldTrackPageRequest
};
