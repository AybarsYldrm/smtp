'use strict';

const crypto = require('node:crypto');

const { sha256Hex, normalizeAddress } = require('../../util/encoding');

/**
 * Oturumlar, API jetonları ve kısa ömürlü durum (OAuth state/PKCE, cihaz
 * kodu, tekilleştirme anahtarları).
 *
 * Oturum kimliği veritabanında DÜZ olarak durmaz, SHA-256 özeti durur. Bir
 * oturum kimliği taşıyıcı bir kimlik bilgisidir: veritabanı kopyası ele
 * geçtiğinde düz kimlikler doğrudan kullanılabilir olurdu. Özet, çerezdeki
 * değeri bilmeyen birinin oturumu kullanamaması demek.
 */
class SessionRepo {
  constructor(db, { config, vault = null, logger = null } = {}) {
    this.db = db;
    this.config = config;
    this.vault = vault;
    this.logger = logger;
  }

  get sessions() { return this.db.collection('sessions'); }
  get tokens() { return this.db.collection('api_tokens'); }
  get ephemeral() { return this.db.collection('ephemeral'); }

  /* ── oturumlar ────────────────────────────────────────────── */

  async create({
    idpSub, idpEmail, mailboxes = [], scope = '', isAdmin = false,
    ip = '', userAgent = '', accessToken = null, refreshToken = null,
    idpSessionId = '', deviceId = '', ttlMs = null,
  }) {
    const sid = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    const expiresAt = now + (ttlMs || this.config.idp.sessionTtlMs);
    const csrfToken = crypto.randomBytes(24).toString('base64url');

    // IdP jetonları kasaya sarılır. Oturum satırında jetonun kendisi
    // dursaydı, veritabanını okuyan biri kullanıcı adına IdP'ye gidebilirdi.
    let accessTokenSecretRef = '';
    let refreshTokenSecretRef = '';
    if (this.vault && accessToken) {
      const name = `session/${sha256Hex(sid).slice(0, 24)}/access`;
      await this.vault.put({ kind: 'idp-token', name, value: accessToken, contentType: 'application/jwt', notAfter: expiresAt });
      accessTokenSecretRef = name;
    }
    if (this.vault && refreshToken) {
      const name = `session/${sha256Hex(sid).slice(0, 24)}/refresh`;
      await this.vault.put({ kind: 'idp-token', name, value: refreshToken, contentType: 'text/plain', notAfter: expiresAt });
      refreshTokenSecretRef = name;
    }

    await this.sessions.insert({
      sidHash: sha256Hex(sid),
      idpSub: String(idpSub || ''),
      idpEmail: normalizeAddress(idpEmail),
      mailboxesJson: JSON.stringify(mailboxes),
      scope: String(scope || ''),
      isAdmin: !!isAdmin,
      createdAt: now,
      lastSeenAt: now,
      expiresAt,
      revalidatedAt: now,
      ip: String(ip || ''),
      userAgent: String(userAgent || '').slice(0, 300),
      revoked: false,
      revokedReason: '',
      accessTokenSecretRef,
      refreshTokenSecretRef,
      csrfToken,
      idpSessionId: String(idpSessionId || ''),
      deviceId: String(deviceId || ''),
    });

    return { sid, csrfToken, expiresAt };
  }

  static shape(row) {
    if (!row) return null;
    return {
      ref: String(row._id),
      idpSub: row.idpSub,
      idpEmail: row.idpEmail,
      mailboxes: parseJson(row.mailboxesJson, []),
      scope: row.scope || '',
      isAdmin: !!row.isAdmin,
      createdAt: Number(row.createdAt || 0),
      lastSeenAt: Number(row.lastSeenAt || 0),
      expiresAt: Number(row.expiresAt || 0),
      revalidatedAt: Number(row.revalidatedAt || 0),
      ip: row.ip || '',
      userAgent: row.userAgent || '',
      csrfToken: row.csrfToken || '',
      idpSessionId: row.idpSessionId || '',
      deviceId: row.deviceId || '',
      accessTokenSecretRef: row.accessTokenSecretRef || '',
      refreshTokenSecretRef: row.refreshTokenSecretRef || '',
    };
  }

  async getBySid(sid) {
    if (!sid) return null;
    const row = await this.sessions.findOne('sidHash', sha256Hex(String(sid)));
    if (!row) return null;
    if (row.revoked) return null;
    if (Number(row.expiresAt || 0) < Date.now()) return null;
    return SessionRepo.shape(row);
  }

  async getByRef(sessionRef) {
    if (!sessionRef) return null;
    const row = await this.sessions.get(String(sessionRef)).catch(() => null);
    if (!row || row.revoked) return null;
    return SessionRepo.shape(row);
  }

  async touch(sessionRef, { ip = null, revalidated = false } = {}) {
    const patch = { lastSeenAt: Date.now() };
    if (ip) patch.ip = ip;
    if (revalidated) patch.revalidatedAt = Date.now();
    await this.sessions.update(String(sessionRef), patch);
  }

  async updateMailboxes(sessionRef, mailboxes, { isAdmin = null } = {}) {
    const patch = { mailboxesJson: JSON.stringify(mailboxes), revalidatedAt: Date.now() };
    if (isAdmin != null) patch.isAdmin = !!isAdmin;
    await this.sessions.update(String(sessionRef), patch);
  }

  async revoke(sessionRefOrSid, reason = 'user_logout') {
    let row = null;
    if (String(sessionRefOrSid).length >= 40) {
      row = await this.sessions.findOne('sidHash', sha256Hex(String(sessionRefOrSid)));
    }
    if (!row) row = await this.sessions.get(String(sessionRefOrSid));
    if (!row) return false;
    await this.sessions.update(String(row._id), { revoked: true, revokedReason: reason });
    // Kasadaki jetonlar da geçersizleştirilir: oturum kapandıysa o jetonun
    // saklanmaya devam etmesi için bir neden yok.
    if (this.vault) {
      for (const ref of [row.accessTokenSecretRef, row.refreshTokenSecretRef]) {
        if (!ref) continue;
        const existing = await this.vault.get('idp-token', ref).catch(() => null);
        if (existing) await this.vault.markCompromised('idp-token', ref, existing.version, `session_revoked:${reason}`).catch(() => {});
      }
    }
    return true;
  }

  async revokeAllForSub(idpSub, reason = 'admin_revoke') {
    const rows = await this.sessions.find('idpSub', String(idpSub));
    let n = 0;
    for (const row of rows) {
      if (row.revoked) continue;
      await this.sessions.update(String(row._id), { revoked: true, revokedReason: reason });
      n++;
    }
    return n;
  }

  /**
   * Bir posta adresine ait açık oturumların hepsini kapatır.
   *
   * TARAMA ile yapılıyor, `idpEmail` üzerinde bir dizinle değil. Adresi düz
   * dizine koymak, veritabanı kopyasını ele geçirene sıralanabilir bir adres
   * listesi vermek olurdu (bkz. şema notu). Tarama maliyeti kabul edilebilir:
   * bu yol yalnızca bir yetki geri alındığında çalışıyor ve tarama açık
   * oturum sayısıyla sınırlı.
   */
  async revokeAllForEmail(email, reason = 'access_revoked') {
    const needle = normalizeAddress(email);
    if (!needle) return 0;
    let n = 0;
    for await (const row of this.sessions.scan()) {
      if (row.revoked) continue;
      if (normalizeAddress(row.idpEmail) !== needle) continue;
      await this.sessions.update(String(row._id), { revoked: true, revokedReason: reason });
      n++;
    }
    return n;
  }

  /** Belirli bir posta kutusuna erişimi olan oturumları kapatır. */
  async revokeAllForMailbox(mailboxRef, reason = 'mailbox_access_revoked') {
    const needle = String(mailboxRef);
    let n = 0;
    for await (const row of this.sessions.scan()) {
      if (row.revoked) continue;
      const mailboxes = parseJson(row.mailboxesJson, []);
      if (!mailboxes.some((m) => m && m.ref === needle)) continue;
      await this.sessions.update(String(row._id), { revoked: true, revokedReason: reason });
      n++;
    }
    return n;
  }

  async listForSub(idpSub) {
    const rows = await this.sessions.find('idpSub', String(idpSub));
    return rows.filter((r) => !r.revoked && Number(r.expiresAt || 0) > Date.now()).map(SessionRepo.shape);
  }

  async getAccessToken(session) {
    if (!this.vault || !session.accessTokenSecretRef) return null;
    const secret = await this.vault.get('idp-token', session.accessTokenSecretRef).catch(() => null);
    return secret ? secret.value.toString('utf8') : null;
  }

  async getRefreshToken(session) {
    if (!this.vault || !session.refreshTokenSecretRef) return null;
    const secret = await this.vault.get('idp-token', session.refreshTokenSecretRef).catch(() => null);
    return secret ? secret.value.toString('utf8') : null;
  }

  /**
   * Yenilenmiş IdP jetonlarını oturuma yazar.
   *
   * Kasa adları DEĞİŞMEZ, sürüm artar. Ad oturum kimliğinden türetiliyor;
   * her yenilemede yeni bir ad üretmek kasada oturum başına sınırsız kayıt
   * bırakırdı ve eskilerini kimin temizleyeceği belirsiz kalırdı.
   */
  async updateIdpTokens(session, { accessToken = null, refreshToken = null, scope = null } = {}) {
    const patch = {};
    if (this.vault && accessToken) {
      const name = session.accessTokenSecretRef
        || `session/${String(session.ref).slice(0, 24)}/access`;
      await this.vault.put({
        kind: 'idp-token', name, value: accessToken,
        contentType: 'application/jwt', notAfter: session.expiresAt,
      });
      patch.accessTokenSecretRef = name;
    }
    if (this.vault && refreshToken) {
      const name = session.refreshTokenSecretRef
        || `session/${String(session.ref).slice(0, 24)}/refresh`;
      await this.vault.put({
        kind: 'idp-token', name, value: refreshToken,
        contentType: 'text/plain', notAfter: session.expiresAt,
      });
      patch.refreshTokenSecretRef = name;
    }
    // Kapsam YALNIZCA dolu geldiğinde yazılır.
    //
    // Bazı IdP'ler jeton yanıtında `scope` döndürmüyor (RFC 6749 §5.1 onu
    // yalnızca istenenden FARKLIYSA zorunlu kılıyor). Boş değeri olduğu gibi
    // yazmak, bilinen kapsamı siliyor ve kullanıcı izni verdiği hâlde
    // "kapsamınız yok" döngüsüne düşürüyordu.
    const trimmedScope = scope == null ? '' : String(scope).trim();
    if (trimmedScope) patch.scope = trimmedScope;
    if (Object.keys(patch).length) await this.sessions.update(String(session.ref), patch);
    return patch;
  }

  async sweepExpired({ limit = 500 } = {}) {
    const rows = await this.sessions.findRange('expiresAt', 1, Date.now(), { limit });
    let n = 0;
    for (const row of rows) { await this.sessions.delete(String(row._id)); n++; }
    return n;
  }

  /* ── API jetonları ────────────────────────────────────────── */

  /**
   * Jeton düz metni YALNIZCA burada döner. Saklanan şey özeti.
   * `fitmail_` ön eki, jetonun sızdığında ne olduğunun anlaşılmasını
   * (ve gizli tarama araçlarının yakalamasını) sağlar.
   */
  async createApiToken({ label, ownerSub, mailboxRef = '', scopes = [], expiresInMs = null, createdBySub = '', ipAllow = [] }) {
    const raw = `fitmail_${crypto.randomBytes(32).toString('base64url')}`;
    const now = Date.now();
    await this.tokens.insert({
      tokenHash: sha256Hex(raw),
      label: String(label || 'api'),
      ownerSub: String(ownerSub || ''),
      mailboxRef: String(mailboxRef || ''),
      scopesJson: JSON.stringify(scopes),
      createdAt: now,
      expiresAt: expiresInMs ? now + expiresInMs : 0,
      lastUsedAt: 0,
      revoked: false,
      ipAllowJson: JSON.stringify(ipAllow),
      createdBySub: String(createdBySub || ownerSub || ''),
      useCount: 0,
    });
    return { token: raw, label, scopes };
  }

  async verifyApiToken(raw, { ip = '' } = {}) {
    if (!raw) return { ok: false, reason: 'missing' };
    const row = await this.tokens.findOne('tokenHash', sha256Hex(String(raw)));
    if (!row) return { ok: false, reason: 'unknown' };
    if (row.revoked) return { ok: false, reason: 'revoked' };
    if (Number(row.expiresAt || 0) && Date.now() > Number(row.expiresAt)) return { ok: false, reason: 'expired' };
    const allow = parseJson(row.ipAllowJson, []);
    if (allow.length && ip && !allow.includes(ip)) return { ok: false, reason: 'ip_not_allowed' };

    await this.tokens.update(String(row._id), { lastUsedAt: Date.now(), useCount: Number(row.useCount || 0) + 1 });
    return {
      ok: true,
      token: {
        ref: String(row._id),
        label: row.label,
        ownerSub: row.ownerSub,
        mailboxRef: row.mailboxRef || '',
        scopes: parseJson(row.scopesJson, []),
      },
    };
  }

  async revokeApiToken(ref) {
    const row = await this.tokens.get(String(ref));
    if (!row) return false;
    await this.tokens.update(String(ref), { revoked: true });
    return true;
  }

  async listApiTokens(ownerSub) {
    const rows = await this.tokens.find('ownerSub', String(ownerSub));
    return rows.filter((r) => !r.revoked).map((r) => ({
      ref: String(r._id),
      label: r.label,
      mailboxRef: r.mailboxRef || '',
      scopes: parseJson(r.scopesJson, []),
      createdAt: Number(r.createdAt || 0),
      expiresAt: Number(r.expiresAt || 0),
      lastUsedAt: Number(r.lastUsedAt || 0),
      useCount: Number(r.useCount || 0),
    }));
  }

  /* ── kısa ömürlü durum ────────────────────────────────────── */

  async putEphemeral(key, value, { kind = 'generic', ttlMs = 600_000 } = {}) {
    const existing = await this.ephemeral.findOne('key', String(key));
    const payload = {
      kind,
      valueJson: JSON.stringify(value),
      expiresAt: Date.now() + ttlMs,
      createdAt: Date.now(),
      usedAt: 0,
    };
    if (existing) { await this.ephemeral.update(String(existing._id), payload); return String(existing._id); }
    return this.ephemeral.insert({ key: String(key), ...payload });
  }

  async getEphemeral(key) {
    const row = await this.ephemeral.findOne('key', String(key));
    if (!row) return null;
    if (Number(row.expiresAt || 0) < Date.now()) return null;
    return parseJson(row.valueJson, null);
  }

  /**
   * Tek kullanımlık tüketim. OAuth `state`/PKCE ve cihaz kodu için: aynı
   * değerin iki kez kullanılabilmesi, yeniden oynatma saldırısına kapı açar.
   * Kayıt okunur ve AYNI ANDA silinir; ikinci çağrı null döner.
   */
  async consumeEphemeral(key) {
    const row = await this.ephemeral.findOne('key', String(key));
    if (!row) return null;
    await this.ephemeral.delete(String(row._id));
    if (Number(row.expiresAt || 0) < Date.now()) return null;
    return parseJson(row.valueJson, null);
  }

  async sweepEphemeral({ limit = 1000 } = {}) {
    const rows = await this.ephemeral.findRange('expiresAt', 1, Date.now(), { limit });
    let n = 0;
    for (const row of rows) { await this.ephemeral.delete(String(row._id)); n++; }
    return n;
  }
}

function parseJson(s, fallback) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

module.exports = { SessionRepo };
