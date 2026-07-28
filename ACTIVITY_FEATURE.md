# Admin visitor and login activity

This version adds a dedicated **Activity** tab to the admin dashboard.

## What is recorded

- Visits to `/`, `/login`, `/register`, and `/app`
- Successful logins
- Failed login attempts
- Successful registrations
- Whether the request looks automated (crawler, Playwright, Puppeteer, curl, and similar clients)
- The page, time, browser/user-agent, and a masked network address
- First name, last name, and email when they are available from an account or submitted login

Passwords are never stored in activity records. IPv4 addresses have their final segment hidden, and older activity is automatically deleted after 90 days.

## Admin dashboard behavior

- The sidebar shows an unread Activity badge.
- The badge and browser-tab title refresh every 10 seconds while the admin dashboard is open.
- Activity can be filtered by unread, logins, failed logins, visits, or bots.
- Records can be marked read or cleared by an admin.

## Deployment

Restart or redeploy the API once. `initDB()` will create the `activity_events` table and indexes automatically.

The browser tracker works without any new environment variable and covers ordinary browsers and JavaScript-capable automation.

### Optional: catch crawlers that do not run JavaScript

The included `functions/_middleware.js` can report Cloudflare Pages requests directly to the API. Set the same strong random value as `ACTIVITY_INGEST_SECRET` in both:

1. The API/server environment
2. The Cloudflare Pages project environment

You can generate a value locally with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

The Pages middleware defaults to `https://api.spotivibes.com`. Set `ACTIVITY_API_BASE` in Cloudflare Pages only when your API uses another base URL.

## Privacy notice

Because this feature records visitor metadata and login identifiers, describe the logging and retention period in the app's privacy notice before enabling it for public users.
