const CACHE = 'brazada-v11';

const PRECACHE = [
  './Aquatech.html',
  './Aquatech.css',
  './Aquatech.js',
  './manifest.json',
  './Multimedia/logo1.webp',
  './Multimedia/logo1.png',
  './Multimedia/icon-192.png',
  './Multimedia/icon-512.png',
  './Multimedia/icon-512-maskable.png',
  './lib/jspdf.umd.min.js',
  './lib/jspdf.plugin.autotable.min.js',
  './fonts/fonts.css',
  './fonts/inter-latin.woff2',
  './fonts/inter-latin-ext.woff2',
  './fonts/space-grotesk-latin.woff2',
  './fonts/space-grotesk-latin-ext.woff2',
];

// Archivos de app shell — siempre red primero, caché como respaldo offline
const NETWORK_FIRST = [
  'Aquatech.html',
  'Aquatech.css',
  'Aquatech.js',
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  const parsedUrl = new URL(e.request.url);
  // Ignorar esquemas no soportados (chrome-extension, etc.)
  if (!parsedUrl.protocol.startsWith('http')) return;

  const isSameOrigin = parsedUrl.origin === self.location.origin;
  // No interceptar recursos de terceros (Google Fonts, CDN externos)
  if (!isSameOrigin) return;
  const isNetworkFirst = isSameOrigin && NETWORK_FIRST.some(f => parsedUrl.pathname.includes(f));

  if (isNetworkFirst) {
    // Network-first: siempre intenta la red; si falla (offline) usa caché
    e.respondWith(
      fetch(e.request)
        .then(res => {
          if (res && res.status === 200) {
            const resClone = res.clone();
            caches.open(CACHE).then(c => c.put(e.request, resClone));
          }
          return res;
        })
        .catch(() => caches.match(e.request))
    );
  } else {
    // Cache-first para imágenes y recursos estáticos
    e.respondWith(
      caches.open(CACHE).then(cache =>
        cache.match(e.request).then(cached => {
          const networkFetch = fetch(e.request)
            .then(res => {
              if (res && res.status === 200) {
                const resClone = res.clone();
                cache.put(e.request, resClone);
              }
              return res;
            })
            .catch(() => null);
          return cached || networkFetch;
        })
      )
    );
  }
});
