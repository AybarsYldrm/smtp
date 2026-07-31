'use strict';

const crypto = require('node:crypto');

const { IdpClient } = require('./idp-client');
const { normalizeAddress, timingSafeEqualStr } = require('../util/encoding');

/**
 * Oturum yönetimi: IdP kimliğinden posta kutusu erişimine.
 *
 * Buradaki asıl iş, "giriş yapan kişi hangi kutulara erişebilir" sorusunu
 * cevaplamak. Üç kaynak birleşiyor (bkz. MailboxRepo.mailboxesForIdentity):
 * kendi adresi, ona verilmiş yetkiler, ve YÖNETİCİNİN kurduğu harici kimlik
 * bağı. Üçüncüsü kullanıcının kendi kendine yapabileceği bir şey değil —
 * "gmail adresimi network@fitfak.net'e bağla" demek, o kutunun tamamını
 * istemek demek.
 *
 * Yetkiler her istekte değil, belirli aralıklarla yeniden hesaplanır: her
 * istekte hesaplamak, kutu listesi için birkaç veritabanı sorgusu demek.
 * Ama süresiz önbelleklemek de olmaz — IdP'de kapatılan bir hesabın
 * postaları okumaya devam etmesi kabul edilemez.
 */
class SessionManager {
  constructor({ config, logger, stores, idp = null }) {
    this.config = config;
    this.logger = logger;
    this.stores = stores;
    this.idp = idp || new IdpClient({
      baseUrl: config.idp.baseUrl,
      clientId: config.idp.clientId,
      clientSecret: config.idp.clientSecret,
      redirectUri: config.redirectUri(),
      scopes: config.idp.scopes,
      logger,
      config,
    });
  }

  /* ── giriş akışı ──────────────────────────────────────────── */

  /**
   * Girişi başlatır. `state`, PKCE doğrulayıcısı ve `nonce` veritabanındaki
   * kısa ömürlü tabloda tutulur — çerezde tutmak da mümkündü ama o zaman
   * çerezi silen bir tarayıcı akışı bozar ve daha kötüsü, çerez taşan bir
   * saldırgan kendi state'ini yerleştirebilir.
   */
  async beginLogin({ ip = '', userAgent = '', returnTo = '/', loginHint = null } = {}) {
    const request = this.idp.createAuthorizationRequest({
      loginHint,
      scopes: this.config.idp.scopes,
    });
    await this.stores.sessions.putEphemeral(`oauth:${request.state}`, {
      codeVerifier: request.codeVerifier,
      nonce: request.nonce,
      ip,
      userAgent: String(userAgent).slice(0, 200),
      returnTo: sanitizeReturnTo(returnTo),
      createdAt: Date.now(),
    }, { kind: 'oauth-state', ttlMs: 10 * 60_000 });
    return { url: request.url, state: request.state };
  }

  /**
   * Geri dönüşü tamamlar: kodu jetona çevirir, kimliği doğrular, oturumu açar.
   */
  async completeLogin({ code, state, ip = '', userAgent = '' }) {
    if (!code || !state) throw new Error('kod ya da state eksik');

    // TEK KULLANIMLIK: state okunur ve aynı anda silinir. Aksi hâlde aynı
    // yetki kodu iki kez kullanılabilir hâle gelir.
    const stored = await this.stores.sessions.consumeEphemeral(`oauth:${state}`);
    if (!stored) throw new Error('state geçersiz ya da süresi dolmuş');

    const tokens = await this.idp.exchangeCode({ code, codeVerifier: stored.codeVerifier });

    let profile = null;
    if (tokens.idToken) {
      const verified = await this.idp.verifyIdToken(tokens.idToken, { nonce: stored.nonce });
      if (!verified.ok) {
        // Kimlik jetonu doğrulanamadıysa userinfo'ya düşülür; ikisi de
        // olmazsa giriş başarısızdır. İmzasız bir id_token'ın içine
        // güvenmek yok.
        this.logger.warn({ reason: verified.reason, msg: 'id_token doğrulanamadı, userinfo deneniyor' });
      } else {
        profile = IdpClient.normalizeProfile(verified.payload);
      }
    }
    if (!profile || !profile.sub) {
      const claims = await this.idp.userinfo(tokens.accessToken);
      profile = IdpClient.normalizeProfile(claims);
    }
    if (!profile.sub) throw new Error('IdP kimlik öznesi (sub) döndürmedi');
    if (!profile.email) {
      // `email` kapsamı olmadan hangi kutuya erişileceği belirlenemez.
      throw new Error('IdP posta adresi döndürmedi — "email" kapsamı isteniyor mu?');
    }

    const scopeList = tokens.scope ? tokens.scope.split(/\s+/).filter(Boolean) : profile.scope;
    const isAdmin = this.isAdminIdentity(profile);
    const mailboxes = await this.resolveMailboxes(profile);

    const session = await this.stores.sessions.create({
      idpSub: profile.sub,
      idpEmail: profile.email,
      mailboxes: mailboxes.map(summarizeAccess),
      scope: scopeList.join(' '),
      isAdmin,
      ip,
      userAgent,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      idpSessionId: profile.sessionId,
    });

    await this.stores.audit.record({
      actorSub: profile.sub,
      actorEmail: profile.email,
      action: 'session.login',
      targetType: 'session',
      targetId: session.sid.slice(0, 8),
      ip,
      userAgent,
      detail: { mailboxes: mailboxes.length, isAdmin, scope: scopeList },
    });

    this.logger.info({
      email: profile.email, sub: profile.sub, mailboxes: mailboxes.length, isAdmin,
      msg: 'oturum açıldı',
    });

    return {
      sid: session.sid,
      csrfToken: session.csrfToken,
      expiresAt: session.expiresAt,
      returnTo: stored.returnTo || '/',
      profile,
      mailboxes,
      isAdmin,
    };
  }

  isAdminIdentity(profile) {
    if (profile.isAdmin) return true;
    if (this.config.idp.adminSubjects.includes(profile.sub)) return true;
    return profile.roles.some((role) => this.config.idp.adminRoles.includes(role));
  }

  async resolveMailboxes(profile) {
    return this.stores.mailboxes.mailboxesForIdentity({
      idpSub: profile.sub,
      email: profile.email,
    });
  }

  /**
   * Çerezdeki oturum kimliğini çözer ve gerektiğinde IdP'ye karşı yeniden
   * doğrular.
   */
  async authenticate({ sid, ip = '', requireFresh = false }) {
    const session = await this.stores.sessions.getBySid(sid);
    if (!session) return null;

    const needsRevalidation = requireFresh
      || Date.now() - session.revalidatedAt > this.config.idp.revalidateIntervalMs;

    if (needsRevalidation) {
      const stillValid = await this.revalidate(session);
      if (!stillValid) {
        await this.stores.sessions.revoke(session.ref, 'idp_revoked');
        this.logger.info({ email: session.idpEmail, msg: 'IdP oturumu geçersiz, yerel oturum kapatıldı' });
        return null;
      }
    } else {
      await this.stores.sessions.touch(session.ref, { ip });
    }

    return { ...session, mailboxes: session.mailboxes || [] };
  }

  /**
   * IdP'ye "bu oturum hâlâ geçerli mi" sorusu.
   *
   * IdP erişilemezse oturum GEÇERLİ sayılır. Aksi davranış (kesintiyi
   * geçersizliğe çevirmek), IdP'nin kısa bir kesintisinde bütün
   * kullanıcıları dışarı atardı; ve o karar zaten yerel oturum süresiyle
   * sınırlı.
   */
  async revalidate(session) {
    const accessToken = await this.stores.sessions.getAccessToken(session);
    if (!accessToken) {
      // Jeton yok: yalnızca yerel süreye güvenilir.
      await this.stores.sessions.touch(session.ref, { revalidated: true });
      return true;
    }
    try {
      const info = await this.idp.introspect(accessToken);
      if (info && info.active === false) return false;

      const profile = IdpClient.normalizeProfile(info || {});
      if (profile.sub && profile.sub !== session.idpSub) return false;

      // Yetkiler yeniden hesaplanır: yönetici bu arada bir kimlik bağı
      // eklemiş ya da kaldırmış olabilir.
      const mailboxes = await this.resolveMailboxes({
        sub: session.idpSub,
        email: session.idpEmail,
        roles: profile.roles || [],
        isAdmin: profile.isAdmin,
      });
      const isAdmin = this.isAdminIdentity({
        sub: session.idpSub, email: session.idpEmail,
        roles: profile.roles || [], isAdmin: profile.isAdmin,
      });
      await this.stores.sessions.updateMailboxes(session.ref, mailboxes.map(summarizeAccess), { isAdmin });
      session.mailboxes = mailboxes.map(summarizeAccess);
      session.isAdmin = isAdmin;
      return true;
    } catch (err) {
      if (err.temporary) {
        this.logger.warn({ error: err.message, msg: 'IdP erişilemedi, oturum yerel süreyle sürüyor' });
        await this.stores.sessions.touch(session.ref, { revalidated: true });
        return true;
      }
      this.logger.warn({ error: err.message, msg: 'oturum yeniden doğrulanamadı' });
      return false;
    }
  }

  async logout({ sid, revokeIdpSessions = false }) {
    const session = await this.stores.sessions.getBySid(sid);
    if (!session) return false;

    if (revokeIdpSessions && session.idpSessionId) {
      await this.idp.revokeSession(session.idpSessionId).catch(() => {});
    }
    const refreshToken = session.refreshTokenSecretRef
      ? await this.stores.vault.get('idp-token', session.refreshTokenSecretRef).catch(() => null)
      : null;
    if (refreshToken) {
      await this.idp.revokeToken(refreshToken.value.toString('utf8')).catch(() => {});
    }

    await this.stores.sessions.revoke(session.ref, 'user_logout');
    await this.stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: 'session.logout', targetType: 'session', targetId: session.ref,
    });
    return true;
  }

  /**
   * CSRF denetimi.
   *
   * Çerezler SameSite=Lax; bu, GET dışı istekler için çoğu senaryoyu kapatır
   * ama hepsini değil (üst düzey POST gezinmeleri). Durum değiştiren her
   * istekte ayrıca jeton isteniyor.
   */
  verifyCsrf(session, token) {
    if (!session || !session.csrfToken) return false;
    return timingSafeEqualStr(session.csrfToken, token || '');
  }

  /** Bir oturumun belirli bir kutuya erişimi var mı, hangi rolle? */
  accessFor(session, mailboxRefOrAddress) {
    if (!session) return null;
    const needle = String(mailboxRefOrAddress || '');
    const normalized = normalizeAddress(needle);
    for (const entry of session.mailboxes || []) {
      if (entry.ref === needle || entry.address === normalized) return entry;
    }
    return null;
  }

  requireAccess(session, mailboxRefOrAddress, minimumRole = 'reader') {
    const access = this.accessFor(session, mailboxRefOrAddress);
    if (!access) {
      const err = new Error('bu posta kutusuna erişiminiz yok');
      err.status = 403;
      err.code = 'MAILBOX_FORBIDDEN';
      throw err;
    }
    const rank = { reader: 1, sender: 2, delegate: 3, owner: 4 };
    if ((rank[access.role] || 0) < (rank[minimumRole] || 0)) {
      const err = new Error(`bu işlem için "${minimumRole}" yetkisi gerekir (mevcut: ${access.role})`);
      err.status = 403;
      err.code = 'ROLE_INSUFFICIENT';
      throw err;
    }
    return access;
  }

  requireAdmin(session) {
    if (!session || !session.isAdmin) {
      const err = new Error('bu işlem Fitfak yönetici yetkisi gerektirir');
      err.status = 403;
      err.code = 'ADMIN_REQUIRED';
      throw err;
    }
    return true;
  }

  /* ── yönetici işlemleri: harici kimlik bağları ─────────────── */

  /**
   * Harici bir adresi yerel bir kutuya bağlar.
   *
   * YALNIZCA yönetici. Kayıt, bağı kimin kurduğunu ve gerekçesini taşır;
   * çünkü bu bağ bir kutunun tamamını başka bir kimliğe açar ve sonradan
   * "bunu kim yaptı" sorusu mutlaka sorulur.
   */
  async linkExternalIdentity({ session, externalEmail, mailboxAddress, allowSendAs = false, reason = '', expiresAt = 0, ip = '' }) {
    this.requireAdmin(session);

    const mailbox = await this.stores.mailboxes.getByAddress(mailboxAddress);
    if (!mailbox) {
      const err = new Error(`posta kutusu bulunamadı: ${mailboxAddress}`);
      err.status = 404;
      throw err;
    }
    const email = normalizeAddress(externalEmail);
    if (!email.includes('@')) {
      const err = new Error('geçersiz harici adres');
      err.status = 400;
      throw err;
    }
    // Yerel bir adresi "harici bağ" olarak eklemek anlamsız ve tehlikeli:
    // o kutunun sahibi zaten var, bağ ikinci bir sahip yaratır.
    const { domain } = require('../util/encoding').splitAddress(email);
    if (this.config.isLocalDomain(domain)) {
      const err = new Error('yerel adresler için yetki devri (grant) kullanılmalı, kimlik bağı değil');
      err.status = 400;
      throw err;
    }

    const result = await this.stores.mailboxes.linkExternalIdentity({
      externalEmail: email,
      mailboxRef: mailbox.ref,
      createdBySub: session.idpSub,
      createdByEmail: session.idpEmail,
      allowSendAs,
      reason,
      expiresAt,
    });

    await this.stores.audit.record({
      actorSub: session.idpSub,
      actorEmail: session.idpEmail,
      action: 'identity_link.create',
      targetType: 'mailbox',
      targetId: mailbox.ref,
      ip,
      detail: { externalEmail: email, mailboxAddress: mailbox.address, allowSendAs, reason, expiresAt },
    });

    this.logger.warn({
      admin: session.idpEmail, externalEmail: email, mailbox: mailbox.address, allowSendAs,
      msg: 'harici kimlik bağı kuruldu',
    });

    // Bağı etkilenen açık oturumların yetkileri, sonraki yeniden doğrulamada
    // güncellenir; anında etkili olması gerekiyorsa oturumlar kapatılır.
    return { ...result, mailbox: mailbox.address, externalEmail: email };
  }

  async revokeExternalIdentity({ session, externalEmail, reason = '', ip = '' }) {
    this.requireAdmin(session);
    const email = normalizeAddress(externalEmail);
    const existing = await this.stores.mailboxes.resolveExternalIdentity(email);
    const removed = await this.stores.mailboxes.revokeExternalIdentity(email, {
      revokedBySub: session.idpSub, reason,
    });
    if (removed) {
      await this.stores.audit.record({
        actorSub: session.idpSub, actorEmail: session.idpEmail,
        action: 'identity_link.revoke', targetType: 'mailbox',
        targetId: existing ? existing.mailboxRef : '', ip,
        detail: { externalEmail: email, reason },
      });
      // Bağ kaldırıldığında o kimliğin açık oturumları kapatılır: yeniden
      // doğrulama aralığı kadar (5 dakika) erişimin sürmesi kabul edilemez.
      const closed = await this.stores.sessions.revokeAllForEmail(email, 'identity_link_revoked');
      if (closed) this.logger.info({ email, closed, msg: 'bağ kaldırıldı, oturumlar kapatıldı' });
    }
    return removed;
  }

  async listExternalIdentities({ session, mailboxAddress = null }) {
    this.requireAdmin(session);
    let mailboxRef = null;
    if (mailboxAddress) {
      const mailbox = await this.stores.mailboxes.getByAddress(mailboxAddress);
      if (!mailbox) return [];
      mailboxRef = mailbox.ref;
    }
    return this.stores.mailboxes.listExternalIdentities({ mailboxRef });
  }

  /** Yerel bir kimliğe kutu yetkisi verir (yönetici ya da kutu sahibi). */
  async grantMailboxAccess({ session, mailboxAddress, idpSub, idpEmail = '', role = 'reader', note = '', ip = '' }) {
    const mailbox = await this.stores.mailboxes.getByAddress(mailboxAddress);
    if (!mailbox) {
      const err = new Error(`posta kutusu bulunamadı: ${mailboxAddress}`);
      err.status = 404;
      throw err;
    }
    if (!session.isAdmin) this.requireAccess(session, mailbox.ref, 'owner');

    const result = await this.stores.mailboxes.grant({
      mailboxRef: mailbox.ref, idpSub, idpEmail, role, grantedBySub: session.idpSub, note,
    });
    await this.stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: 'mailbox.grant', targetType: 'mailbox', targetId: mailbox.ref, ip,
      detail: { idpSub, idpEmail, role, note },
    });
    return result;
  }
}

function summarizeAccess(mailbox) {
  return {
    ref: mailbox.ref,
    address: mailbox.address,
    displayName: mailbox.displayName,
    role: mailbox.role || 'reader',
    accessSource: mailbox.accessSource || 'unknown',
    unreadCount: mailbox.unreadCount || 0,
    smimeEnabled: mailbox.smimeEnabled !== false,
  };
}

function sanitizeReturnTo(value) {
  const s = String(value || '/');
  // Yalnızca site içi yollar: açık yönlendirme, kimlik avı için hazır bir
  // araçtır ("giriş yaptınız" sonrası saldırganın sayfasına gitmek).
  if (!s.startsWith('/') || s.startsWith('//')) return '/';
  return s.slice(0, 300);
}

module.exports = { SessionManager, summarizeAccess };
