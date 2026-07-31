'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

const { b64url } = require('../util/encoding');
const { verifyAsym } = require('../util/jwt');
const log = require('../util/log');

/**
 * Fitfak kimlik sağlayıcı (session.fitfak.net) istemcisi.
 *
 * Bu, Microsoft OAuth'un yerini alıyor. Değişimin tek satırlık özeti "başka
 * bir sağlayıcı" değil: posta kutusu yetkilendirmesi artık bizim kendi
 * kimlik sistemimizin öznesine (sub) ve doğrulanmış posta adresine dayanıyor.
 * `email` kapsamı bu yüzden zorunlu — o kapsam olmadan IdP adresi döndürmez
 * ve "bu kişi hangi kutuya erişebilir" sorusu cevaplanamaz.
 *
 * Desteklenen akışlar:
 *   - Yetki kodu + PKCE (tarayıcı, webmail girişi)
 *   - Cihaz kodu, RFC 8628 (CLI, sertifika alma)
 *   - Jeton inceleme, RFC 7662 (API jetonu doğrulama)
 *   - client_credentials (servisin kendi adına, sertifika verme)
 */

const DEFAULT_TIMEOUT_MS = 10_000;

class IdpError extends Error {
  constructor(message, { status = 0, body = null, code = null } = {}) {
    super(message);
    this.status = status;
    this.body = body;
    this.code = code;
  }
}

class IdpClient {
  constructor({
    baseUrl, clientId, clientSecret, redirectUri,
    scopes = ['openid', 'profile', 'email'], logger = null, config = null,
    timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = null,
  }) {
    this.baseUrl = String(baseUrl || '').replace(/\/+$/, '');
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.scopes = scopes;
    this.logger = logger || log.child('idp');
    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
    this.paths = {
      authorize: (config && config.idp.authorizePath) || '/oauth/authorize',
      token: (config && config.idp.tokenPath) || '/oauth/token',
      introspect: (config && config.idp.introspectPath) || '/oauth/introspect',
      userinfo: (config && config.idp.userinfoPath) || '/oauth/userinfo',
      deviceAuth: (config && config.idp.deviceAuthPath) || '/oauth/device_authorization',
      jwks: (config && config.idp.jwksPath) || '/.well-known/jwks.json',
      revoke: '/oauth/revoke',
      sessions: '/api/sessions',
    };
    this.jwksCache = null;
    this.introspectionCache = new Map();
  }

  /* ── düşük seviye HTTP ────────────────────────────────────── */

  /* ── düşük seviye HTTP ────────────────────────────────────── */

  async _request(method, path, { body = null, headers = {}, form = null, auth = null, json = true } = {}) {
    const url = /^https?:\/\//.test(path) ? path : `${this.baseUrl}${path}`;
    const target = new URL(url);
    const payload = form ? new URLSearchParams(form).toString() : (body ? JSON.stringify(body) : null);

    const finalHeaders = {
      accept: 'application/json',
      // Bazı ters proxy'ler ve güvenlik duvarları User-Agent'ı olmayan
      // istekleri engelliyor; sunucudan sunucuya çağrılarda bu, teşhisi zor
      // bir 403 olarak görünür.
      'user-agent': 'Fitfak-Mail/2.0',
      ...(form ? { 'content-type': 'application/x-www-form-urlencoded' } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...headers,
    };
      
    if (payload) finalHeaders['content-length'] = Buffer.byteLength(payload);
    if (auth === 'basic') {
      finalHeaders.authorization = `Basic ${Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64')}`;
    } else if (auth) {
      finalHeaders.authorization = `Bearer ${auth}`;
    }

    // İzleme kaydı seviyeye BAĞLI ve maskeli. Buradaki gövde bir jeton
    // takası olabiliyor; `client_secret`/`code` gibi alanlar düz metin
    // yazılırsa kaydı okuyan herkes oturum açabilir hâle gelir.
    this.logger.http('→ idp', {
      method,
      url,
      headers: log.safeHeaders(finalHeaders),
      body: payload ? log.snippet(redactFormPayload(payload), 400) : undefined,
    });

    if (this.fetchImpl) {
      return this.fetchImpl({ method, url, headers: finalHeaders, body: payload, json });
    }

    const transport = target.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      const req = transport.request({
        method,
        hostname: target.hostname,
        port: target.port || (target.protocol === 'https:' ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        headers: finalHeaders,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');

          this.logger.http('← idp', {
            method,
            url,
            status: res.statusCode,
            contentType: res.headers['content-type'] || '',
            body: log.snippet(redactTokenResponse(raw), 400),
          });

          let parsed = null;
          if (json && raw) {
            try { parsed = JSON.parse(raw); } catch { parsed = null; }
          }
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ status: res.statusCode, json: parsed, raw, headers: res.headers });
            return;
          }
          // Ham gövde hataya eklenir: IdP'nin önündeki bir güvenlik duvarı
          // HTML döndürdüğünde "JSON ayrıştırılamadı" demek, sorunun nerede
          // olduğunu gizler.
          reject(new IdpError(
            `IdP ${method} ${target.pathname} -> HTTP ${res.statusCode}`,
            { status: res.statusCode, body: parsed || raw.slice(0, 500), code: parsed && parsed.error },
          ));
        });
      });
      req.setTimeout(this.timeoutMs, () => {
        req.destroy();
        reject(new IdpError(`IdP zaman aşımı (${this.timeoutMs}ms): ${target.pathname}`));
      });
      req.on('error', (err) => reject(new IdpError(`IdP erişilemedi: ${err.message}`)));
      if (payload) req.write(payload);
      req.end();
    });
  }

  /* ── yetki kodu + PKCE ────────────────────────────────────── */

  /**
   * Yetkilendirme URL'i ve ona ait durum üretir.
   * PKCE zorunlu: yetki kodunu ele geçiren biri, doğrulayıcı olmadan onu
   * jetona çeviremez.
   */
  createAuthorizationRequest({ scopes = null, prompt = null, loginHint = null, extraParams = {} } = {}) {
    const state = b64url(crypto.randomBytes(24));
    const nonce = b64url(crypto.randomBytes(16));
    const codeVerifier = b64url(crypto.randomBytes(32));
    const codeChallenge = b64url(crypto.createHash('sha256').update(codeVerifier).digest());

    const url = new URL(`${this.baseUrl}${this.paths.authorize}`);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', this.clientId);
    url.searchParams.set('redirect_uri', this.redirectUri);
    url.searchParams.set('scope', (scopes || this.scopes).join(' '));
    url.searchParams.set('state', state);
    url.searchParams.set('nonce', nonce);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');
    if (prompt) url.searchParams.set('prompt', prompt);
    if (loginHint) url.searchParams.set('login_hint', loginHint);
    for (const [k, v] of Object.entries(extraParams)) url.searchParams.set(k, v);

    return { url: url.toString(), state, nonce, codeVerifier };
  }

  async exchangeCode({ code, codeVerifier, redirectUri = null }) {
    const res = await this._request('POST', this.paths.token, {
      form: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri || this.redirectUri,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        code_verifier: codeVerifier,
      },
    });
    if (!res.json || !res.json.access_token) {
      throw new IdpError('IdP jeton yanıtı access_token içermiyor', { body: res.json || res.raw });
    }
    return normalizeTokenResponse(res.json);
  }

  async refresh(refreshToken) {
    const res = await this._request('POST', this.paths.token, {
      form: {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      },
    });
    return normalizeTokenResponse(res.json || {});
  }

  /** Servisin kendi adına jeton (sertifika verme gibi işler için). */
  async clientCredentials({ scopes = ['cert:issue'] } = {}) {
    const res = await this._request('POST', this.paths.token, {
      form: {
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        scope: scopes.join(' '),
      },
    });
    return normalizeTokenResponse(res.json || {});
  }

  /* ── cihaz kodu (RFC 8628) ────────────────────────────────── */

  async startDeviceAuthorization({ scopes = null, clientId = null } = {}) {
    const res = await this._request('POST', this.paths.deviceAuth, {
      form: {
        client_id: clientId || this.clientId,
        scope: (scopes || this.scopes).join(' '),
      },
    });
    const data = res.json || {};
    if (!data.device_code || !data.user_code) {
      throw new IdpError('cihaz yetkilendirme yanıtı eksik', { body: data });
    }
    return {
      deviceCode: data.device_code,
      userCode: data.user_code,
      verificationUri: data.verification_uri || data.verification_url,
      verificationUriComplete: data.verification_uri_complete || null,
      expiresIn: Number(data.expires_in || 600),
      interval: Number(data.interval || 5),
    };
  }

  /**
   * Cihaz kodunu jetona çevirmek için yoklama.
   *
   * `slow_down` yanıtında aralık ARTIRILIR. Yok saymak, IdP'nin bizi
   * kısıtlamasına ve akışın hiç tamamlanmamasına yol açar.
   */
  async pollDeviceToken({ deviceCode, interval = 5, expiresIn = 600, clientId = null, onPending = null }) {
    const deadline = Date.now() + expiresIn * 1000;
    let waitMs = interval * 1000;

    while (Date.now() < deadline) {
      await new Promise((r) => { const t = setTimeout(r, waitMs); if (t.unref) t.unref(); });
      try {
        const res = await this._request('POST', this.paths.token, {
          form: {
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            device_code: deviceCode,
            client_id: clientId || this.clientId,
            ...(this.clientSecret ? { client_secret: this.clientSecret } : {}),
          },
        });
        if (res.json && res.json.access_token) return normalizeTokenResponse(res.json);
      } catch (err) {
        const code = err.code || (err.body && err.body.error);
        if (code === 'authorization_pending') { if (onPending) onPending(); continue; }
        if (code === 'slow_down') { waitMs += 5000; if (onPending) onPending(); continue; }
        if (code === 'access_denied') throw new IdpError('kullanıcı isteği reddetti', { code });
        if (code === 'expired_token') throw new IdpError('cihaz kodunun süresi doldu', { code });
        throw err;
      }
    }
    throw new IdpError('cihaz yetkilendirme süresi doldu');
  }

  /* ── jeton doğrulama ──────────────────────────────────────── */

  /**
   * RFC 7662 jeton inceleme.
   *
   * Sonuç kısa süre önbelleklenir: her API isteğinde IdP'ye gitmek, IdP'yi
   * posta sunucusunun istek hacmine maruz bırakır. Önbellek süresi kısa,
   * çünkü iptal edilmiş bir jetonun kabul edilmeye devam ettiği pencere bu.
   */
  async introspect(token, { cacheMs = 30_000 } = {}) {
    if (!token) return { active: false };
    const key = crypto.createHash('sha256').update(token).digest('hex');
    const cached = this.introspectionCache.get(key);
    if (cached && Date.now() - cached.at < cacheMs) return cached.value;

    let value;
    try {
      const res = await this._request('POST', this.paths.introspect, {
        form: { token, client_id: this.clientId, client_secret: this.clientSecret },
        auth: 'basic',
      });
      value = res.json || { active: false };
    } catch (err) {
      // IdP erişilemezse bu bir YETKİLENDİRME KARARI DEĞİL. `active: false`
      // döndürmek, kesintiyi sessizce "jeton geçersiz"e çevirir ve operatör
      // ret yığını görür, erişilemeyen bir bağımlılık görmez.
      const wrapped = new IdpError(`jeton incelenemedi: ${err.message}`, { status: err.status });
      wrapped.temporary = true;
      throw wrapped;
    }

    if (this.introspectionCache.size > 5000) this.introspectionCache.clear();
    this.introspectionCache.set(key, { value, at: Date.now() });
    return value;
  }

  async userinfo(accessToken) {
    const res = await this._request('GET', this.paths.userinfo, { auth: accessToken });
    return res.json || {};
  }

  async getJwks({ maxAgeMs = 3600_000 } = {}) {
    if (this.jwksCache && Date.now() - this.jwksCache.at < maxAgeMs) return this.jwksCache.keys;
    const res = await this._request('GET', this.paths.jwks);
    const keys = (res.json && res.json.keys) || [];
    this.jwksCache = { keys, at: Date.now() };
    return keys;
  }

  /**
   * Kimlik jetonunu (id_token) JWKS ile doğrular.
   *
   * Kimlik jetonuna İMZASINI DOĞRULAMADAN güvenmek, istemcinin gönderdiği
   * herhangi bir JSON'a güvenmekle aynı şey. Anahtar bulunamazsa doğrulama
   * BAŞARISIZ sayılır; "imzayı atla" diye bir yol yok.
   */
  async verifyIdToken(idToken, { nonce = null } = {}) {
    const { decode } = require('../util/jwt');
    const parsed = decode(idToken);
    if (!parsed) return { ok: false, reason: 'malformed' };

    const keys = await this.getJwks();
    const candidates = parsed.header.kid
      ? keys.filter((k) => k.kid === parsed.header.kid)
      : keys;
    if (!candidates.length) return { ok: false, reason: 'no_matching_key' };

    for (const jwk of candidates) {
      const result = verifyAsym(idToken, jwk, {
        issuer: this.baseUrl,
        audience: this.clientId,
      });
      if (!result.ok) continue;
      if (nonce && result.payload.nonce !== nonce) return { ok: false, reason: 'nonce_mismatch' };
      return result;
    }
    return { ok: false, reason: 'bad_signature' };
  }

  async revokeToken(token, { tokenTypeHint = 'refresh_token' } = {}) {
    try {
      await this._request('POST', this.paths.revoke, {
        form: {
          token, token_type_hint: tokenTypeHint,
          client_id: this.clientId, client_secret: this.clientSecret,
        },
      });
      return true;
    } catch (err) {
      if (this.logger) this.logger.debug({ error: err.message, msg: 'jeton iptali başarısız' });
      return false;
    }
  }

  /* ── IdP oturum yönetimi ──────────────────────────────────── */
  // auth-client.js'deki IdentityClient yüzeyiyle aynı: çıkışta kullanıcının
  // IdP oturumlarını da kapatabilmek için.

  async getUserSessions(userId, accessToken = null) {
    const res = await this._request('GET', `${this.paths.sessions}?user_id=${encodeURIComponent(userId)}`, {
      auth: accessToken || 'basic',
    });
    return { sessions: (res.json && (res.json.sessions || res.json.data)) || [] };
  }

  async revokeSession(sessionId, accessToken = null) {
    try {
      await this._request('DELETE', `${this.paths.sessions}/${encodeURIComponent(sessionId)}`, {
        auth: accessToken || 'basic',
      });
      return true;
    } catch (err) {
      if (this.logger) this.logger.debug({ sessionId, error: err.message, msg: 'IdP oturumu kapatılamadı' });
      return false;
    }
  }

  /**
   * Kullanıcı bilgisini tek biçime indirger.
   *
   * IdP'ler aynı bilgiyi farklı adlarla döndürür (`email`,
   * `preferred_username`, `mail`); posta kutusu yetkilendirmesi bu değere
   * dayandığı için burada tek yere toplanıyor.
   */
  static normalizeProfile(claims) {
    const c = claims || {};
    const email = String(c.email || c.mail || c.preferred_username || c.upn || '').trim().toLowerCase();
    const roles = []
      .concat(c.roles || [], c.role ? [c.role] : [], c.groups || [],
        typeof c.realm_access === 'object' && c.realm_access ? (c.realm_access.roles || []) : [])
      .map((r) => String(r).toLowerCase());
    return {
      sub: String(c.sub || c.user_id || c.uid || ''),
      email,
      emailVerified: c.email_verified === true || c.email_verified === 'true',
      name: c.name || c.display_name || c.given_name || '',
      preferredUsername: c.preferred_username || '',
      roles: [...new Set(roles)],
      isAdmin: c.is_admin === true || c.isAdmin === true || roles.includes('admin'),
      scope: String(c.scope || '').split(/\s+/).filter(Boolean),
      sessionId: c.sid || c.session_id || '',
      raw: c,
    };
  }
}

/**
 * Form gövdesindeki sırları maskeler.
 *
 * `client_secret`, `code`, `code_verifier`, `refresh_token`, `device_code` ve
 * `token`: hepsi tek başına oturum açmaya ya da jeton almaya yeter. Kayda
 * yazılan sürümde yalnızca ALANIN VAR OLDUĞU görünür — hata ayıklarken
 * sorulan soru zaten "gönderdik mi", "değeri neydi" değil.
 */
const SENSITIVE_FORM_KEYS = new Set([
  'client_secret', 'code', 'code_verifier', 'refresh_token', 'device_code',
  'token', 'assertion', 'password',
]);

function redactFormPayload(payload) {
  const text = String(payload || '');
  if (!text.includes('=')) return text;
  if (text.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(text);
      for (const key of Object.keys(parsed)) {
        if (SENSITIVE_FORM_KEYS.has(key)) parsed[key] = log.maskSecret(parsed[key]);
      }
      return JSON.stringify(parsed);
    } catch { return text; }
  }
  const params = new URLSearchParams(text);
  const out = new URLSearchParams();
  for (const [key, value] of params) {
    out.set(key, SENSITIVE_FORM_KEYS.has(key) ? log.maskSecret(value) : value);
  }
  return out.toString();
}

/** Jeton yanıtındaki access/refresh/id jetonlarını maskeler. */
function redactTokenResponse(raw) {
  const text = String(raw || '');
  if (!text.trim().startsWith('{')) return text;
  try {
    const parsed = JSON.parse(text);
    for (const key of ['access_token', 'refresh_token', 'id_token']) {
      if (parsed[key]) parsed[key] = log.maskSecret(parsed[key]);
    }
    return JSON.stringify(parsed);
  } catch { return text; }
}

function normalizeTokenResponse(json) {
  return {
    accessToken: json.access_token,
    refreshToken: json.refresh_token || null,
    idToken: json.id_token || null,
    tokenType: json.token_type || 'Bearer',
    expiresIn: Number(json.expires_in || 0),
    expiresAt: json.expires_in ? Date.now() + Number(json.expires_in) * 1000 : 0,
    scope: String(json.scope || ''),
    raw: json,
  };
}

module.exports = { IdpClient, IdpError, normalizeTokenResponse };
