/**
 * Servis işçisi — bildirim teslimi.
 *
 * Kapsam bilinçli olarak DAR: yalnızca bildirimler ve kabuk dosyalarının
 * önbelleği. Posta içeriği ÖNBELLEĞE ALINMIYOR — paylaşılan bir cihazda
 * çıkış yapmış bir kullanıcının postasının önbellekte kalması kabul edilemez
 * ve önbelleği doğru boşaltmak, hiç önbelleğe almamaktan çok daha kırılgan.
 */

const SHELL_CACHE = 'fitfak-mail-shell-v2';
const SHELL_FILES = ['/', '/static/webmail.css', '/static/fitfak-ui.css', '/static/app.js'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_FILES))
      .then(() => self.skipWaiting())
      .catch(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // API ve ek istekleri ASLA önbellekten karşılanmaz.
  if (url.pathname.startsWith('/api/') || event.request.method !== 'GET') return;
  if (!SHELL_FILES.includes(url.pathname)) return;

  // Önce ağ, sonra önbellek: kabuk dosyası güncellenmişse eski sürüm
  // gösterilmemeli, ama çevrimdışıyken uygulama yine açılmalı.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        const copy = response.clone();
        caches.open(SHELL_CACHE).then((cache) => cache.put(event.request, copy)).catch(() => {});
        return response;
      })
      .catch(() => caches.match(event.request)),
  );
});

self.addEventListener('push', (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; }
  catch { payload = { title: 'Fitfak Posta', body: event.data ? event.data.text() : '' }; }

  const options = {
    body: payload.body || '',
    icon: payload.icon || '/static/icon-192.png',
    badge: payload.badge || '/static/badge.png',
    tag: payload.tag || 'fitfak-mail',
    // Aynı etiketli bildirimler üst üste yığılmaz ama sessizce de değişmez:
    // yeni posta geldiğinde kullanıcı fark etmeli.
    renotify: true,
    data: payload.data || {},
    timestamp: Date.now(),
    actions: payload.data && payload.data.kind === 'mail'
      ? [{ action: 'open', title: 'Aç' }, { action: 'read', title: 'Okundu say' }]
      : [],
  };
  event.waitUntil(self.registration.showNotification(payload.title || 'Fitfak Posta', options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};

  if (event.action === 'read' && data.messageRef) {
    event.waitUntil(
      fetch(`/api/v1/messages/${encodeURIComponent(data.messageRef)}/flags`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ seen: true }),
      }).catch(() => {}),
    );
    return;
  }

  const target = data.url || '/';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      // Açık bir sekme varsa ona odaklan: her bildirimde yeni sekme açmak,
      // kullanıcıda onlarca sekme bırakır.
      for (const client of clients) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.navigate(target).catch(() => {});
          return client.focus();
        }
      }
      return self.clients.openWindow(target);
    }),
  );
});
