const STATIC_CACHE = "spotivibes-static-v1";
const AUDIO_CACHE = "spotivibes-audio-v1";

self.addEventListener("install", event => {
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", event => {
  const url = new URL(event.request.url);

  // Offline audio cache
  if (event.request.destination === "audio") {
    event.respondWith(
      caches.open(AUDIO_CACHE).then(async cache => {
        const cached = await cache.match(event.request);
        if (cached) return cached;

        const res = await fetch(event.request);
        return res;
      })
    );
    return;
  }

  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});