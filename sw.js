const CACHE = 'aquatech-v13';

const PRECACHE = [
  './Aquatech.html',
  './Aquatech.css',
  './Aquatech.js',
  './manifest.json',
  './Multimedia/logo1.webp',
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

const APP_SHELL = new Set(['Aquatech.html', 'Aquatech.css', 'Aquatech.js']);

async function cacheResponse(request, response) {
  if (!response || !response.ok) return response;
  const cache = await caches.open(CACHE);
  cache.put(request, response.clone());
  return response;
}

async function networkFirst(request) {
  try {
    const response = await fetch(request);
    return cacheResponse(request, response);
  } catch {
    const cached = await caches.match(request);
    return cached || caches.match('./Aquatech.html');
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE);
  const cached = await cache.match(request);
  const networkPromise = fetch(request)
    .then(response => cacheResponse(request, response))
    .catch(() => null);
  return cached || networkPromise || Response.error();
}

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE)
      .then(cache => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE).map(key => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (!url.protocol.startsWith('http')) return;
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate' || APP_SHELL.has(url.pathname.split('/').pop())) {
    event.respondWith(networkFirst(request));
    return;
  }

  event.respondWith(staleWhileRevalidate(request));
});
