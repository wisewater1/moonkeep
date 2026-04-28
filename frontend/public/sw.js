// Minimal service worker — exists so Android Chrome / Edge / Samsung Internet
// offer a proper "Install app" prompt for the admin console. It does NOT
// cache API responses (recon/strike data must always be live) and deliberately
// does NOT cache WebSocket endpoints. The only caching is a network-first pass
// for the static shell so the app loads once in a spotty cell signal.

const SHELL_CACHE = 'moonkeep-shell-v1';
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/apple-touch-icon.svg',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE).then((c) => c.addAll(SHELL_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// Network-first shell, never-cache API/WS.
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // Bypass same-origin API routes and anything that isn't in-scope for caching.
  const apiPrefixes = [
    '/auth', '/admin', '/plugins', '/campaigns', '/scan', '/wifi', '/bettercap',
    '/graph', '/interfaces', '/vuln_scan', '/secret_hunter', '/cyber_strike',
    '/ai', '/post_exploit', '/fuzzer', '/sniffer', '/hid_ble', '/proxy',
    '/spoofer', '/docs', '/openapi.json', '/ws', '/rogue_ap', '/rogue_radius',
    '/wifi_fingerprint', '/baseline', '/mesh', '/report', '/cred_spray',
  ];
  if (apiPrefixes.some((p) => url.pathname.startsWith(p))) return;

  event.respondWith(
    fetch(req)
      .then((res) => {
        // Stash a copy of successful shell fetches.
        if (res.ok && (req.destination === 'document' || req.destination === 'script' || req.destination === 'style')) {
          const copy = res.clone();
          caches.open(SHELL_CACHE).then((c) => c.put(req, copy)).catch(() => {});
        }
        return res;
      })
      .catch(() => caches.match(req).then((c) => c || Response.error()))
  );
});
