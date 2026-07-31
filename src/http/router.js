'use strict';

const crypto = require('node:crypto');
const { URL } = require('node:url');

/**
 * Küçük yönlendirici (router).
 *
 * Harici bir çatı yok, çünkü ihtiyaç duyulan yüzey küçük: yol eşleme,
 * gövde ayrıştırma, çerez, güvenlik başlıkları ve hata biçimi. Bir çatı
 * getirmek bu kod tabanına kendisiyle birlikte çok daha büyük bir yüzey
 * getirirdi.
 *
 * Tasarımda iki şey açık:
 *   - Hata yanıtları TEK BİÇİM. Bir yerde `{error}`, başka yerde düz metin
 *     dönen bir API'yi istemci tarafında ele almak imkânsızdır.
 *   - Gövde okuma SINIRLI. Sınırsız gövde okumak, tek istekle belleği
 *     tüketmenin en kolay yolu.
 */

const MAX_URL_LENGTH = 4096;

class HttpError extends Error {
  constructor(status, message, { code = null, detail = null } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.detail = detail;
  }
}

class Router {
  constructor({ logger, config }) {
    this.logger = logger;
    this.config = config;
    this.routes = [];
    this.middlewares = [];
    this.notFoundHandler = null;
  }

  use(fn) { this.middlewares.push(fn); return this; }

  /**
   * @param {string} method
   * @param {string} pattern  `/api/v1/messages/:ref/attachments/:attRef`
   */
  add(method, pattern, handler, options = {}) {
    const paramNames = [];
    // Önce düzenli ifade metakarakterleri kaçırılır, sonra `:ad` ve `*`
    // yakalama gruplarına çevrilir. `/` kaçırılmıyor (JS'te gerekmez), bu
    // yüzden desen `/:ad` biçiminde aranmalı — `\/:ad` aramak hiçbir zaman
    // eşleşmez ve bütün parametreli yollar sessizce 404 döner.
    const regexSource = pattern
      .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\/:([A-Za-z0-9_]+)/g, (_m, name) => { paramNames.push(name); return '/([^/]+)'; })
      .replace(/\\\*$/, '(.*)');
    if (pattern.endsWith('*')) paramNames.push('wildcard');
    this.routes.push({
      method: method.toUpperCase(),
      regex: new RegExp(`^${regexSource}$`),
      paramNames,
      handler,
      options,
      pattern,
    });
    return this;
  }

  get(p, h, o) { return this.add('GET', p, h, o); }
  post(p, h, o) { return this.add('POST', p, h, o); }
  put(p, h, o) { return this.add('PUT', p, h, o); }
  patch(p, h, o) { return this.add('PATCH', p, h, o); }
  delete(p, h, o) { return this.add('DELETE', p, h, o); }

  notFound(handler) { this.notFoundHandler = handler; return this; }

  match(method, pathname) {
    const upper = method.toUpperCase();
    let pathMatched = false;
    for (const route of this.routes) {
      const m = route.regex.exec(pathname);
      if (!m) continue;
      pathMatched = true;
      if (route.method !== upper && !(upper === 'HEAD' && route.method === 'GET')) continue;
      const params = {};
      route.paramNames.forEach((name, i) => { params[name] = safeDecode(m[i + 1]); });
      return { route, params };
    }
    // Yol var ama yöntem yok: 405 dönmek, istemcinin yolu yanlış yazdığını
    // sanmasını engeller.
    return pathMatched ? { methodNotAllowed: true } : null;
  }

  async handle(req, res) {
    const ctx = createContext(req, res, this.config, this.logger);
    try {
      if ((req.url || '').length > MAX_URL_LENGTH) throw new HttpError(414, 'İstek adresi çok uzun');

      for (const middleware of this.middlewares) {
        const result = await middleware(ctx);
        if (result === false || ctx.responded) return;
      }

      const matched = this.match(req.method, ctx.pathname);
      if (!matched) {
        if (this.notFoundHandler) return this.notFoundHandler(ctx);
        throw new HttpError(404, 'Bulunamadı');
      }
      if (matched.methodNotAllowed) throw new HttpError(405, 'Yöntem kabul edilmiyor');

      ctx.params = matched.params;
      ctx.route = matched.route;
      await matched.route.handler(ctx);
      if (!ctx.responded) throw new HttpError(500, 'İşleyici yanıt üretmedi');
    } catch (err) {
      this._handleError(ctx, err);
    }
  }

  _handleError(ctx, err) {
    const status = err.status || 500;
    if (status >= 500) {
      this.logger.error({
        method: ctx.method, path: ctx.pathname, error: err.message,
        stack: err.stack, msg: 'istek işlenemedi',
      });
    } else {
      this.logger.debug({ method: ctx.method, path: ctx.pathname, status, error: err.message });
    }
    if (ctx.responded) return;
    // İç hata ayrıntısı istemciye SIZDIRILMAZ: yığın izi, dosya yolları ve
    // sürüm bilgisi taşır.
    const body = {
      error: status >= 500 ? 'Sunucu hatası' : err.message,
      code: err.code || (status >= 500 ? 'INTERNAL' : 'ERROR'),
    };
    if (err.detail && status < 500) body.detail = err.detail;
    if (status >= 500) body.requestId = ctx.requestId;
    ctx.json(status, body);
  }
}

function safeDecode(value) {
  try { return decodeURIComponent(String(value == null ? '' : value)); }
  catch { return String(value == null ? '' : value); }
}

function createContext(req, res, config, logger) {
  const host = String(req.headers.host || '').split(':')[0] || 'localhost';
  let parsed;
  try { parsed = new URL(req.url, `https://${host}`); }
  catch { parsed = new URL('/', `https://${host}`); }

  const ctx = {
    req,
    res,
    config,
    logger,
    method: (req.method || 'GET').toUpperCase(),
    host,
    url: parsed,
    pathname: parsed.pathname,
    query: parsed.searchParams,
    params: {},
    requestId: crypto.randomBytes(8).toString('hex'),
    responded: false,
    startedAt: Date.now(),
    state: {},

    get ip() { return clientIp(req, config); },

    cookies() {
      if (ctx._cookies) return ctx._cookies;
      ctx._cookies = parseCookies(req.headers.cookie);
      return ctx._cookies;
    },

    header(name) { return req.headers[String(name).toLowerCase()]; },

    setHeader(name, value) { if (!ctx.responded) res.setHeader(name, value); },

    setCookie(name, value, opts = {}) {
      const parts = [`${name}=${encodeURIComponent(value)}`];
      if (opts.maxAge != null) parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
      if (opts.expires) parts.push(`Expires=${new Date(opts.expires).toUTCString()}`);
      parts.push(`Path=${opts.path || '/'}`);
      if (opts.domain) parts.push(`Domain=${opts.domain}`);
      if (opts.httpOnly !== false) parts.push('HttpOnly');
      // SameSite=Lax öntanımlı: Strict, IdP'den geri dönüşte çerezin
      // gönderilmemesine yol açar ve giriş akışı sessizce kırılır.
      parts.push(`SameSite=${opts.sameSite || 'Lax'}`);
      if (opts.secure !== false && config.http.secureCookies) parts.push('Secure');
      const existing = res.getHeader('Set-Cookie');
      const list = existing ? [].concat(existing) : [];
      list.push(parts.join('; '));
      res.setHeader('Set-Cookie', list);
    },

    clearCookie(name, opts = {}) {
      ctx.setCookie(name, '', { ...opts, maxAge: 0 });
    },

    /** Gövdeyi okur; sınırı aşarsa 413. */
    async body({ limit = null } = {}) {
      if (ctx._body !== undefined) return ctx._body;
      const max = limit || config.http.maxBodyBytes;
      const declared = Number(req.headers['content-length'] || 0);
      if (declared && declared > max) throw new HttpError(413, 'İstek gövdesi çok büyük');

      ctx._body = await new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', (chunk) => {
          size += chunk.length;
          if (size > max) {
            reject(new HttpError(413, 'İstek gövdesi çok büyük'));
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
      });
      return ctx._body;
    },

    // İSTEK gövdesini JSON olarak okur. Adı bilerek `json` DEĞİL: `json`
    // yanıt göndericisidir ve aynı nesnede iki kez tanımlanan bir ad
    // sessizce üzerine yazılır — okuyucu kaybolur, çağıran da yanıt
    // göndericisini gövde ayrıştırıcısı sanarak `writeHead({limit:null})`
    // çağırır ve istek hiç yanıtlanmadan asılı kalır.
    async readJson({ limit = null } = {}) {
      const buf = await ctx.body({ limit });
      if (!buf.length) return {};
      try { return JSON.parse(buf.toString('utf8')); }
      catch { throw new HttpError(400, 'Geçersiz JSON'); }
    },

    async form({ limit = null } = {}) {
      const buf = await ctx.body({ limit });
      return Object.fromEntries(new URLSearchParams(buf.toString('utf8')));
    },

    /** JSON ya da multipart/form-data — hangisi geldiyse. */
    async input({ limit = null } = {}) {
      const type = String(req.headers['content-type'] || '');
      if (type.includes('multipart/form-data')) {
        const { parseMultipart } = require('./multipart');
        const buf = await ctx.body({ limit });
        return parseMultipart(buf, type);
      }
      if (type.includes('application/x-www-form-urlencoded')) {
        return { fields: await ctx.form({ limit }), files: [] };
      }
      return { fields: await ctx.readJson({ limit }), files: [] };
    },

    status(code) { ctx._status = code; return ctx; },

    json(code, obj) {
      const payload = JSON.stringify(obj);
      ctx.send(code, payload, 'application/json; charset=utf-8');
    },

    text(code, body, contentType = 'text/plain; charset=utf-8') {
      ctx.send(code, body, contentType);
    },

    html(code, body) { ctx.send(code, body, 'text/html; charset=utf-8'); },

    send(code, body, contentType) {
      if (ctx.responded) return;
      ctx.responded = true;
      const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body == null ? '' : body), 'utf8');
      res.writeHead(code, {
        'content-type': contentType || 'application/octet-stream',
        'content-length': buf.length,
        'x-request-id': ctx.requestId,
      });
      if (ctx.method === 'HEAD') res.end();
      else res.end(buf);
      logRequest(ctx, code);
    },

    stream(code, headers, readable) {
      if (ctx.responded) return;
      ctx.responded = true;
      res.writeHead(code, { ...headers, 'x-request-id': ctx.requestId });
      if (ctx.method === 'HEAD') { res.end(); return; }
      readable.pipe(res);
      logRequest(ctx, code);
    },

    redirect(location, code = 302) {
      if (ctx.responded) return;
      ctx.responded = true;
      res.writeHead(code, { location, 'content-length': 0 });
      res.end();
      logRequest(ctx, code);
    },

    noContent() {
      if (ctx.responded) return;
      ctx.responded = true;
      res.writeHead(204, { 'x-request-id': ctx.requestId });
      res.end();
      logRequest(ctx, 204);
    },
  };

  return ctx;
}

function logRequest(ctx, status) {
  const level = status >= 500 ? 'warn' : 'debug';
  ctx.logger[level]({
    method: ctx.method,
    path: ctx.pathname,
    status,
    ms: Date.now() - ctx.startedAt,
    ip: ctx.ip,
  });
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    if (!key) continue;
    try { out[key] = decodeURIComponent(part.slice(eq + 1).trim()); }
    catch { out[key] = part.slice(eq + 1).trim(); }
  }
  return out;
}

/**
 * İstemci IP'si.
 *
 * cloudflared arkasındayız, dolayısıyla gerçek IP başlıkta. Ama başlığa
 * YALNIZCA güvenilen kaynaktan gelen bağlantılarda güvenilir: aksi hâlde
 * herhangi bir istemci `x-forwarded-for` yazıp hız sınırlamasını ve
 * denetim kaydını yanıltabilir.
 */
function clientIp(req, config) {
  const socketIp = String(req.socket && req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  const trusted = config.http.trustedProxies.includes(socketIp);
  if (!trusted) return socketIp;

  const cf = req.headers['cf-connecting-ip'];
  if (cf) return String([].concat(cf)[0]).trim();
  const real = req.headers['x-real-ip'];
  if (real) return String([].concat(real)[0]).trim();
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String([].concat(forwarded)[0]).split(',')[0].trim();
  return socketIp;
}

/* ── ortak ara katmanlar ───────────────────────────────────── */

/** Güvenlik başlıkları. */
function securityHeaders({ csp = null, frameAncestors = "'none'" } = {}) {
  return async (ctx) => {
    ctx.setHeader('x-content-type-options', 'nosniff');
    ctx.setHeader('x-frame-options', 'DENY');
    ctx.setHeader('referrer-policy', 'strict-origin-when-cross-origin');
    ctx.setHeader('cross-origin-opener-policy', 'same-origin');
    ctx.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
    if (ctx.config.http.secureCookies) {
      ctx.setHeader('strict-transport-security', 'max-age=63072000; includeSubDomains');
    }
    if (csp) ctx.setHeader('content-security-policy', csp);
    else ctx.setHeader('content-security-policy', `default-src 'self'; frame-ancestors ${frameAncestors}`);
  };
}

/** Hız sınırlama. */
function rateLimit(limiter, { keyFn = null, cost = 1, skip = null } = {}) {
  return async (ctx) => {
    if (skip && skip(ctx)) return;
    const key = keyFn ? keyFn(ctx) : ctx.ip;
    const verdict = limiter.check(key, cost);
    if (!verdict.allowed) {
      ctx.setHeader('retry-after', String(Math.ceil(verdict.retryAfterMs / 1000)));
      throw new HttpError(429, 'Çok fazla istek, lütfen bekleyin', { code: 'RATE_LIMITED' });
    }
    ctx.setHeader('x-ratelimit-remaining', String(verdict.remaining));
  };
}

module.exports = { Router, HttpError, securityHeaders, rateLimit, parseCookies, clientIp };
