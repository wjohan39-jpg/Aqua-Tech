const CACHE = 'brazada-v4';

const PRECACHE = [
  './Brazada.html',
  './Brazada.css',
  './Brazada.js',
  './manifest.json',
  './Multimedia/logo1.webp',
  './Multimedia/logo1.png',
];

// Archivos de app shell — siempre red primero, caché como respaldo offline
const NETWORK_FIRST = [
  'Brazada.html',
  'Brazada.css',
  'Brazada.js',
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

  const url = e.request.url;
  const isNetworkFirst = NETWORK_FIRST.some(f => url.includes(f));

  if (isNetworkFirst) {
    // Network-first: siempre intenta la red; si falla (offline) usa caché
    e.respondWith(
      fetch(e.request)
        .then(res => {
          if (res && res.status === 200) {
            caches.open(CACHE).then(c => c.put(e.request, res.clone()));
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
              if (res && res.status === 200) cache.put(e.request, res.clone());
              return res;
            })
            .catch(() => null);
          return cached || networkFetch;
        })
      )
    );
  }
});
