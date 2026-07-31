'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');

const { Router, HttpError, securityHeaders, rateLimit } = require('./router');
const { SlidingWindowLimiter } = require('../util/rate-limit');
const { registerAuthRoutes } = require('./api/auth');
const { registerWebmailRoutes } = require('./api/webmail');
const { registerStatusRoutes } = require('./api/status');
const { registerAdminRoutes } = require('./api/admin');
const { registerSiteRoutes } = require('./site');

/**
 * HTTP sunucuları — vhost başına bir dinleyici.
 *
 * İki isim, iki ayrı loopback adresi, iki ayrı soket:
 *
 *   aybars.net.tr   -> 127.0.1.1   (kişisel site)
 *   mail.fitfak.net -> 127.0.1.2   (webmail + API)
 *
 * cloudflared her tüneli kendi adresine yönlendiriyor. Tek adrese koyup Host
 * başlığıyla ayırmak da mümkündü; ayrı soket seçilmesinin nedeni, yanlış
 * yapılandırılmış bir tünelin diğerinin trafiğine hiç ulaşamaması. Host
 * başlığı denetimi yine de var — ayrı soket ilk savunma, başlık denetimi
 * ikincisi.
 */
class HttpServers {
  constructor(deps) {
    this.deps = deps;
    this.config = deps.config;
    this.logger = deps.logger;
    this.servers = [];
    this.staticCache = new Map();

    this.generalLimiter = new SlidingWindowLimiter({
      windowMs: this.config.http.rateLimit.windowMs,
      max: this.config.http.rateLimit.max,
    });
    this.sendLimiter = new SlidingWindowLimiter({
      windowMs: this.config.http.rateLimit.windowMs,
      max: this.config.http.rateLimit.sendMax,
    });
    this.sweeper = setInterval(() => {
      this.generalLimiter.sweep();
      this.sendLimiter.sweep();
    }, 300_000);
    if (this.sweeper.unref) this.sweeper.unref();
  }

  /* ── yönlendiriciler ───────────────────────────────────────── */

  buildWebmailRouter() {
    const router = new Router({ logger: this.logger.child('webmail'), config: this.config });
    const deps = { ...this.deps, renderSite: null };

    router.use(securityHeaders({
      // Webmail kendi betiğini çalıştırır; harici kaynak yok. `img-src`
      // data: ve cid: içerir çünkü gömülü görseller böyle geliyor.
      csp: [
        "default-src 'self'",
        
        // Cloudflare analiz betiğine izin ver
        "script-src 'self' https://static.cloudflareinsights.com",
        
        "style-src 'self' 'unsafe-inline' https://session.fitfak.net",
        "img-src 'self' data: blob:",
        "font-src 'self' https://session.fitfak.net data:",
        
        // Service Worker fetch() istekleri, WebSocket ve Cloudflare veri gönderimi için bağlantı izinleri
        "connect-src 'self' https://session.fitfak.net wss://envelope.fitfak.net wss://mail.fitfak.net https://cloudflareinsights.com",
        
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "form-action 'self'",
      ].join('; '),
    }));
    router.use(this._hostGuard('webmail'));
    router.use(rateLimit(this.generalLimiter, {
      skip: (ctx) => ctx.pathname.startsWith('/static/') || ctx.pathname === '/healthz',
    }));
    // Gönderim ayrı ve daha sıkı sınırlanır: bir hesabın ele geçmesi
    // durumunda hasar hızını sınırlayan tek şey bu.
    router.use(async (ctx) => {
      if (!/\/(send|campaigns|forward)$/.test(ctx.pathname) || ctx.method !== 'POST') return;
      const verdict = this.sendLimiter.check(`send:${ctx.ip}`);
      if (!verdict.allowed) {
        throw new HttpError(429, 'Gönderim hızı sınırı aşıldı', { code: 'SEND_RATE_LIMITED' });
      }
    });

    registerAuthRoutes(router, deps);
    registerWebmailRoutes(router, deps);
    registerStatusRoutes(router, deps);
    registerAdminRoutes(router, deps);

    router.get('/static/*', (ctx) => this._serveStatic(ctx, 'webmail'));
    router.get('/sw.js', (ctx) => this._serveStatic(ctx, 'webmail', 'sw.js'));
    router.get('/manifest.webmanifest', (ctx) => this._serveStatic(ctx, 'webmail', 'manifest.webmanifest'));
    router.get('/favicon.ico', (ctx) => this._serveStatic(ctx, 'webmail', 'favicon.ico'));

    // Tek sayfalık arayüz: API dışındaki her yol arayüze düşer, böylece
    // /posta/... gibi derin bağlantılar yenilendiğinde 404 vermez.
    const serveApp = async (ctx) => {
      const html = await this._readAsset('webmail/index.html');
      if (!html) throw new HttpError(500, 'Arayüz dosyası bulunamadı');
      ctx.html(200, html);
    };
    router.get('/', serveApp);
    router.notFound(async (ctx) => {
      if (ctx.pathname.startsWith('/api/')) {
        ctx.json(404, { error: 'Bulunamadı', code: 'NOT_FOUND' });
        return;
      }
      await serveApp(ctx);
    });

    return router;
  }

  buildSiteRouter() {
    const router = new Router({ logger: this.logger.child('site'), config: this.config });
    router.use(securityHeaders({
      "csp": [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  // Görseller için storage adresin ve Spotify'ın resim CDN'leri:
  "img-src 'self' data: https://storage.aybars.net.tr https://i.scdn.co https://*.spotifycdn.com",
  // Fetch/Axios (API) istekleri ve WebSocket için:
  "connect-src 'self' https://storage.aybars.net.tr https://api.spotify.com",
  // Eğer Spotify Embed Player (iframe) kullanıyorsan:
  "frame-src 'self' https://open.spotify.com",
  // Eğer storage'ından ses veya video çekeceksen (opsiyonel):
  "media-src 'self' https://storage.aybars.net.tr",
  "frame-ancestors 'none'"
].join('; '),
    }));
    router.use(this._hostGuard('site'));
    router.use(rateLimit(this.generalLimiter, { skip: (ctx) => ctx.pathname.startsWith('/static/') }));

    registerSiteRoutes(router, {
      ...this.deps,
      renderSite: () => this._readAsset('site/index.html'),
      renderNotifications: (data) => this._renderNotifications(data),
    });
    // Kişisel sitede de giriş gerekiyor (bildirim paneli için).
    registerAuthRoutes(router, this.deps);

    router.get('/static/*', (ctx) => this._serveStatic(ctx, 'site'));
    router.get('/sw.js', (ctx) => this._serveStatic(ctx, 'site', 'sw.js'));
    router.get('/favicon.ico', (ctx) => this._serveStatic(ctx, 'site', 'favicon.ico'));

    router.notFound(async (ctx) => {
      if (ctx.pathname.startsWith('/api/')) {
        ctx.json(404, { error: 'Bulunamadı', code: 'NOT_FOUND' });
        return;
      }
      const html = await this._readAsset('site/404.html');
      ctx.html(404, html || '<h1>Sayfa bulunamadı</h1>');
    });

    return router;
  }

  /**
   * Host başlığı denetimi.
   *
   * Ayrı soketler ilk savunma; bu ikincisi. Beklenmeyen bir Host ile gelen
   * istek reddedilir, çünkü mutlak bağlantı üreten her yer (OAuth
   * yönlendirmesi) Host'a güvenirse zehirlenebilir.
   */
  _hostGuard(kind) {
    const vhost = this.config.vhosts.find((v) => v.kind === kind);
    if (!vhost) return async () => {};
    const allowed = new Set([vhost.host, ...(vhost.aliases || [])]);
    // Yerel geliştirme ve sağlık denetimi için loopback adları da kabul.
    allowed.add('localhost');
    allowed.add('127.0.0.1');
    allowed.add(vhost.bind);
    return async (ctx) => {
      if (allowed.has(ctx.host)) return;
      this.logger.warn({ host: ctx.host, expected: vhost.host, ip: ctx.ip, msg: 'beklenmeyen Host başlığı' });
      throw new HttpError(421, 'Bu ad bu sunucuda karşılanmıyor', { code: 'BAD_HOST' });
    };
  }

  /* ── statik dosyalar ───────────────────────────────────────── */

  async _readAsset(relativePath) {
    const cached = this.staticCache.get(relativePath);
    if (cached && this.config.http.cacheStatic) return cached.body;
    const full = path.join(this.config.publicDir, relativePath);
    const resolved = path.resolve(full);
    // Yol kaçışı: `..` ile public dizininin dışına çıkılamaz.
    if (!resolved.startsWith(path.resolve(this.config.publicDir))) return null;
    try {
      const body = await fsp.readFile(resolved);
      this.staticCache.set(relativePath, { body, at: Date.now() });
      return body;
    } catch { return null; }
  }

  async _serveStatic(ctx, area, forcedName = null) {
    const name = forcedName || ctx.params.wildcard || '';
    const clean = String(name).replace(/\.\.+/g, '').replace(/^\/+/, '');
    if (!clean) throw new HttpError(404, 'Bulunamadı');

    // Ortak varlıklar (fitfak-ui.css) her iki alanda da aynı dosyadan gelir.
    const candidates = [`${area}/${clean}`, `shared/${clean}`];
    for (const candidate of candidates) {
      const body = await this._readAsset(candidate);
      if (!body) continue;
      // Başlıklar yanıttan ÖNCE konur: `send` yanıtı yazıp bitirdiği için
      // sonrasında `setHeader` sessizce hiçbir şey yapmaz ve önbellek
      // yönergesi hiç gitmez.
      ctx.setHeader('cache-control', /sw\.js$/.test(clean)
        ? 'no-cache, no-store, must-revalidate'
        : 'public, max-age=3600');
      ctx.send(200, body, contentTypeFor(clean));
      return;
    }
    throw new HttpError(404, 'Bulunamadı');
  }

  async _renderNotifications({ visits, stats, session }) {
    const template = await this._readAsset('site/bildirimler.html');
    const rows = visits.length
      ? visits.map((v) => `<tr>
          <td>${escapeHtml(new Date(v.ts).toLocaleString('tr-TR', { timeZone: 'Europe/Istanbul' }))}</td>
          <td>${escapeHtml(v.ip)}</td>
          <td>${escapeHtml(`${v.os} ${v.deviceModel}`.trim())}</td>
          <td>${escapeHtml([v.isp, v.country, v.city].filter(Boolean).join(' / ') || '—')}</td>
        </tr>`).join('\n')
      : '<tr><td colspan="4" class="ff-empty">Henüz kayıt yok.</td></tr>';

    const body = String(template || '<main>{{ROWS}}</main>')
      .replace('{{ROWS}}', rows)
      .replace('{{TOTAL}}', String(stats.total))
      .replace('{{EMAIL}}', escapeHtml(session.idpEmail))
      .replace('{{CSRF}}', escapeHtml(session.csrfToken || ''));
    return body;
  }

  /* ── yaşam döngüsü ─────────────────────────────────────────── */

  async start() {
    for (const vhost of this.config.vhosts) {
      const router = vhost.kind === 'site' ? this.buildSiteRouter() : this.buildWebmailRouter();
      const server = http.createServer((req, res) => {
        router.handle(req, res).catch((err) => {
          this.logger.error({ error: err.message, stack: err.stack, msg: 'yönlendirici çöktü' });
          if (!res.headersSent) { res.writeHead(500); res.end('Sunucu hatası'); }
        });
      });

      // WebSocket yalnızca webmail alanında.
      if (vhost.kind === 'webmail' && this.deps.realtime) {
        server.on('upgrade', (req, socket, head) => {
          this._handleUpgrade(req, socket, head).catch(() => {
            try { socket.destroy(); } catch { /* yok say */ }
          });
        });
      }

      server.on('clientError', (err, socket) => {
        if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
      });
      // Ters proxy arkasında keep-alive süresi proxy'ninkinden UZUN olmalı;
      // aksi hâlde proxy'nin yeniden kullandığı bağlantı sunucuda kapanmış
      // olur ve istek 502 döner.
      server.keepAliveTimeout = 76_000;
      server.headersTimeout = 80_000;

      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(vhost.port, vhost.bind, () => {
          const address = server.address();
          this.logger.info({
            vhost: vhost.host, bind: address.address, port: address.port, kind: vhost.kind,
            msg: 'HTTP dinleniyor',
          });
          resolve();
        });
      });
      this.servers.push({ server, vhost });
    }
    return this;
  }

  async _handleUpgrade(req, socket, head) {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/ws') { socket.destroy(); return; }

    const cookies = require('./router').parseCookies(req.headers.cookie);
    const sid = cookies[this.config.http.sessionCookieName];
    const session = sid
      ? await this.deps.sessions.authenticate({ sid }).catch(() => null)
      : null;
    this.deps.realtime.handleUpgrade({ req, socket, head, session });
  }

  async stop() {
    clearInterval(this.sweeper);
    await Promise.all(this.servers.map(({ server }) => new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(resolve);
    })));
    this.servers = [];
  }

  addresses() {
    return this.servers.map(({ server, vhost }) => {
      const address = server.address();
      return { kind: vhost.kind, host: vhost.host, bind: address.address, port: address.port };
    });
  }
}

function contentTypeFor(name) {
  const ext = String(name).toLowerCase().match(/\.[a-z0-9]+$/);
  const map = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'application/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.webmanifest': 'application/manifest+json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
    '.woff2': 'font/woff2',
    '.txt': 'text/plain; charset=utf-8',
  };
  return (ext && map[ext[0]]) || 'application/octet-stream';
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

module.exports = { HttpServers };
