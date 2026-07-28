const {
  isLikelyBot,
  maskIp,
  normalizeEmail,
  shouldTrackPageRequest
} = require("../services/activity.service");

describe("activity service helpers", () => {
  test("detects common automated clients", () => {
    expect(isLikelyBot("Mozilla/5.0")).toBe(false);
    expect(isLikelyBot("Googlebot/2.1")).toBe(true);
    expect(isLikelyBot("Playwright")).toBe(true);
  });

  test("masks network addresses", () => {
    expect(maskIp("203.0.113.42")).toBe("203.0.113.x");
    expect(maskIp("::ffff:10.0.0.4")).toBe("10.0.0.x");
    expect(maskIp("2001:db8:1234:5678:abcd::1")).toBe("2001:db8:1234:5678::");
  });

  test("normalizes submitted email addresses", () => {
    expect(normalizeEmail(" Test@Example.COM ")).toBe("test@example.com");
  });

  test("tracks page navigations but excludes health checks", () => {
    const pageRequest = {
      method: "GET",
      path: "/login/",
      get: header => header === "accept" ? "text/html" : "Mozilla/5.0"
    };

    const healthRequest = {
      method: "GET",
      path: "/health",
      get: () => "*/*"
    };

    expect(shouldTrackPageRequest(pageRequest)).toBe(true);
    expect(shouldTrackPageRequest(healthRequest)).toBe(false);
  });
});
