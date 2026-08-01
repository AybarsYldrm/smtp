'use strict';

const https = require('node:https');
const { URL } = require('node:url');

const { HttpError } = require('./router');

/**
 * Kişisel site (aybars.net.tr) — 127.0.1.1 üzerindeki cloudflared çıkışı.
 *
 * Buradaki tek "canlı" özellik Instagram'dan gelen ziyaretlerin bildirimi.
 * Önceki sürümden taşınırken üç şey değişti:
 *
 *   1. Ziyaretler bellekte bir dizide değil veritabanında. Yeniden başlatma
 *      geçmişi silmiyor.
 *   2. IP zenginleştirme (konum/ISP sorgusu) YANIT YOLUNU BEKLETMİYOR.
 *      Önceki sürüm ana sayfayı, üçüncü taraf bir API yanıt verene kadar
 *      bekletiyordu: o API yavaşladığında site yavaşlıyordu.
 *   3. Bildirim yalnızca "site" konusuna abone olanlara gidiyor.
 */
function registerSiteRoutes(router, deps) {
  const { config, logger, stores, push, sessions } = deps;

  const enrichmentQueue = [];
  let draining = false;

  router.get('/', async (ctx) => {
    // Ziyaret kaydı yanıtı BEKLETMEZ: sayfa hemen döner, kayıt arkada.
    trackVisit(ctx).catch((err) => logger.debug({ error: err.message, msg: 'ziyaret kaydedilemedi' }));
    ctx.html(200, await deps.renderSite());
  });

  // Yol İngilizce; Türkçe adı takma ad olarak duruyor. Eski bağlantılar
  // (ve bu yolu kullanan testler) 404 almasın diye ikisi de kayıtlı.
  const notificationsPanel = async (ctx) => {
    const session = await requireSession(ctx);
    const visits = await stores.visits.recent({ limit: 200 });
    const stats = await stores.visits.stats();
    ctx.html(200, await deps.renderNotifications({ visits, stats, session }));
  };
  router.get('/notifications', notificationsPanel);
  router.get('/bildirimler', notificationsPanel);

  router.get('/api/v1/site/visits', async (ctx) => {
    await requireSession(ctx);
    ctx.json(200, {
      visits: await stores.visits.recent({
        limit: Math.min(500, Number(ctx.query.get('limit') || 100)),
        source: ctx.query.get('source') || null,
      }),
      stats: await stores.visits.stats(),
    });
  });

  async function requireSession(ctx) {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    if (!session) {
      // Kişisel sitede giriş sayfasına yönlendirmek, ziyaretçiye panelin
      // varlığını duyurmaktan daha az gürültülü.
      throw new HttpError(401, 'Bu sayfa için giriş gerekli', { code: 'UNAUTHENTICATED' });
    }
    return session;
  }

  async function trackVisit(ctx) {
    if (!config.site.trackInstagram) return;
    const userAgent = String(ctx.header('user-agent') || '');
    const client = parseUserAgent(userAgent);
    if (!client.isInstagram) return;

    const visit = {
      ts: Date.now(),
      source: 'instagram',
      ip: ctx.ip,
      os: client.os,
      deviceModel: client.deviceModel,
      browser: client.browser,
      path: ctx.pathname,
      referrer: String(ctx.header('referer') || ''),
      userAgent,
      isp: '', asn: '', country: '', city: '',
    };
    const visitId = await stores.visits.record(visit);
    visit.visitId = visitId;

    // Zenginleştirme ve bildirim kuyruğa alınır: ikisi de ağ işlemi ve
    // ikisi de ziyaretçinin sayfasını bekletmemeli.
    enrichmentQueue.push(visit);
    if (!draining) drainEnrichment();
  }

  async function drainEnrichment() {
    draining = true;
    while (enrichmentQueue.length) {
      const visit = enrichmentQueue.shift();
      try {
        if (config.site.ipLookupEnabled) {
          const info = await lookupIp(visit.ip, config.site.ipLookupUrl).catch(() => null);
          if (info) {
            Object.assign(visit, info);
            const rows = await stores.visits.visits.find('visitId', visit.visitId).catch(() => []);
            if (rows[0]) {
              await stores.visits.visits.update(String(rows[0]._id), {
                isp: info.isp, asn: info.asn, country: info.country, city: info.city,
              });
            }
          }
        }
        await push.notifySiteVisit(visit).catch(() => {});
        await stores.visits.prune({ keep: config.site.visitRetention }).catch(() => {});
      } catch (err) {
        logger.debug({ error: err.message, msg: 'ziyaret zenginleştirilemedi' });
      }
    }
    draining = false;
  }
}

/**
 * Kullanıcı aracısı çözümlemesi.
 * Instagram'ın gömülü tarayıcısı kendini `Instagram` olarak tanıtıyor; asıl
 * ayırt edici bu.
 */
function parseUserAgent(userAgent) {
  const ua = String(userAgent || '');
  const lower = ua.toLowerCase();
  const out = { os: 'Bilinmiyor', device: 'Masaüstü', deviceModel: '', browser: 'Bilinmiyor', isInstagram: false };

  if (lower.includes('android')) {
    out.os = 'Android';
    out.device = 'Mobil';
    const m = ua.match(/Android\s+[\d.]+;\s*([^;)]+?)(?:\s+Build|\))/i);
    if (m) out.deviceModel = m[1].trim();
  } else if (/iphone|ipad|ipod/.test(lower)) {
    out.os = 'iOS';
    out.device = lower.includes('ipad') ? 'Tablet' : 'Mobil';
    const m = ua.match(/(iPhone\d+,\d+|iPad\d+,\d+)/i);
    out.deviceModel = m ? m[1] : (lower.includes('ipad') ? 'iPad' : 'iPhone');
  } else if (lower.includes('windows')) { out.os = 'Windows'; out.deviceModel = 'PC'; }
  else if (/mac os x|macintosh/.test(lower)) { out.os = 'macOS'; out.deviceModel = 'Mac'; }
  else if (lower.includes('linux')) { out.os = 'Linux'; out.deviceModel = 'PC'; }

  if (lower.includes('instagram')) { out.browser = 'Instagram'; out.isInstagram = true; }
  else if (lower.includes('fban') || lower.includes('fbav')) out.browser = 'Facebook';
  else if (lower.includes('edg/')) out.browser = 'Edge';
  else if (lower.includes('chrome')) out.browser = 'Chrome';
  else if (lower.includes('firefox')) out.browser = 'Firefox';
  else if (lower.includes('safari')) out.browser = 'Safari';

  return out;
}

function lookupIp(ip, baseUrl) {
  if (!ip || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|localhost)/.test(ip)) {
    return Promise.resolve({ isp: 'Yerel', asn: '', country: 'Yerel', city: '' });
  }
  return new Promise((resolve, reject) => {
    const target = new URL(`${String(baseUrl).replace(/\/+$/, '')}/${encodeURIComponent(ip)}`);
    const req = https.request({
      method: 'GET',
      hostname: target.hostname,
      path: target.pathname,
      headers: { accept: 'application/json', 'user-agent': 'Fitfak-Site/2.0' },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (data && data.success !== false) {
            resolve({
              isp: (data.connection && data.connection.isp) || '',
              asn: String((data.connection && data.connection.asn) || ''),
              country: data.country || '',
              city: data.city || '',
            });
            return;
          }
        } catch { /* ayrıştırılamadı */ }
        resolve(null);
      });
    });
    // Kısa zaman aşımı: bu bilgi "olsa iyi olur" kategorisinde, sayfayı
    // bekletmemeli ve kuyruğu tıkamamalı.
    req.setTimeout(4000, () => { req.destroy(); reject(new Error('IP sorgusu zaman aşımı')); });
    req.on('error', reject);
    req.end();
  });
}

module.exports = { registerSiteRoutes, parseUserAgent };
