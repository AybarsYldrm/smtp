/* Kişisel site servis işçisi — yalnızca bildirim teslimi.
   Önbellek yok: site zaten küçük ve statik, önbellek yalnızca eski
   içerik gösterme riski getirirdi. */

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch { payload = {}; }
  event.waitUntil(self.registration.showNotification(payload.title || 'Yeni ziyaret', {
    body: payload.body || '',
    icon: payload.icon || '/static/icon-192.png',
    badge: '/static/badge.png',
    tag: payload.tag || 'site-visit',
    renotify: true,
    data: payload.data || {},
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || '/bildirimler';
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
    for (const client of clients) {
      if (client.url.includes(self.location.origin) && 'focus' in client) {
        client.navigate(target).catch(() => {});
        return client.focus();
      }
    }
    return self.clients.openWindow(target);
  }));
});
