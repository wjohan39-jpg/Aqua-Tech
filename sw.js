const CACHE = 'brazada-v1';

const PRECACHE = [
  './Brazada.html',
  './Brazada.css',
  './Brazada.js',
  './manifest.json',
  './Multimedia/Logo.png',
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
self.addEventListener('fetch', e => {
  if (e.request.method !== 'GET') return;

  e.respondWith(
    caches.open(CACHE).then(cache =>
      cache.match(e.request).then(cached => {
        const networkFetch = fetch(e.request)
          .then(res => {
            if (res && res.ok) cache.put(e.request, res.clone());
            return res;
          })
          .catch(() => null);

        return cached || networkFetch;
      })
    )
  );
});
