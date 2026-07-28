const express = require("express");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const {
  cleanText,
  getRequestContext,
  isLikelyBot,
  maskIp,
  recordActivity
} = require("../services/activity.service");

const router = express.Router();

const pageViewLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many activity requests" }
});

function secretsMatch(provided, expected) {
  if (!provided || !expected) return false;

  const providedBuffer = Buffer.from(String(provided));
  const expectedBuffer = Buffer.from(String(expected));

  if (providedBuffer.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(providedBuffer, expectedBuffer);
}

function normalizePath(value) {
  const submittedPath = cleanText(value, 500);

  if (!submittedPath?.startsWith("/")) return "/";
  if (submittedPath === "/") return "/";

  return submittedPath.replace(/\/+$/, "");
}

router.post("/page-view", pageViewLimiter, async (req, res) => {
  const requestContext = getRequestContext(req);
  const path = normalizePath(req.body?.path);

  await recordActivity("PAGE_VIEW", {
    ...requestContext,
    path,
    method: "GET",
    isBot: requestContext.isBot || req.body?.webdriver === true,
    metadata: {
      source: "browser_tracker",
      pageTitle: cleanText(req.body?.pageTitle, 200),
      referrerOrigin: cleanText(req.body?.referrerOrigin, 300),
      viewport: cleanText(req.body?.viewport, 50),
      webdriver: req.body?.webdriver === true
    }
  });

  res.status(202).json({ accepted: true });
});

router.post("/server-page-view", async (req, res) => {
  const expectedSecret = process.env.ACTIVITY_INGEST_SECRET;
  const providedSecret = req.get("x-activity-secret");

  if (!secretsMatch(providedSecret, expectedSecret)) {
    return res.status(403).json({ error: "Invalid activity ingest secret" });
  }

  const path = normalizePath(req.body?.path);
  const originalUserAgent = cleanText(req.body?.userAgent, 500);

  await recordActivity("PAGE_VIEW", {
    path,
    method: cleanText(req.body?.method, 12) || "GET",
    ipAddress: maskIp(req.body?.ipAddress),
    userAgent: originalUserAgent,
    isBot: isLikelyBot(originalUserAgent) || req.body?.verifiedBot === true,
    metadata: {
      source: "cloudflare_pages",
      referrerOrigin: cleanText(req.body?.referrerOrigin, 300),
      country: cleanText(req.body?.country, 2),
      verifiedBot: req.body?.verifiedBot === true
    }
  });

  return res.status(202).json({ accepted: true });
});

module.exports = router;
