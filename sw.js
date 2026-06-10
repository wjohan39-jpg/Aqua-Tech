const CACHE = 'brazada-v3';

const PRECACHE = [
  './Brazada.html',
  './Brazada.css',
  './Brazada.js',
  './manifest.json',
  './Multimedia/logo1.webp',
  './Multimedia/logo1.png',
];

// Instalar: pre-cachear app shell
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

// Activar: eliminar caches viejos
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// Fetch: stale-while-revalidate
// — sirve cache inmediatamente si existe, actualiza cache desde red en background
// — si no hay cache, espera la red
// — solo cachea respuestas 200 completas (no 206 partial content de videos/streams)
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

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
});
