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

    // Kapsam yükseltmesi (ör. sertifika için `cert:issue`) aynı geri dönüş
    // adresini kullanıyor: IdP'de ikinci bir redirect_uri kaydetmek, aynı
    // akışı iki yerde bakımı gereken iki yola bölerdi. Ayrım state'te.
    if (stored.upgradeSessionRef) {
      const result = await this.completeScopeUpgrade({ code, stored });
      return { scopeUpgrade: true, ...result };
    }

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
    await this.autoProvisionMailbox(profile);
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
      noMailbox: mailboxes.length ? null : this.describeNoMailbox(profile),
    };
  }

  isAdminIdentity(profile) {
    if (profile.isAdmin) return true;
    if (this.config.idp.adminSubjects.includes(profile.sub)) return true;
    // IdP'nin kendi yönetici kuralı TEK bir doğrulanmış adrese dayanıyor
    // (bkz. oauth-server requireAdmin). Aynı kuralı burada da tanıyoruz;
    // aksi hâlde IdP'de yönetici olan kişi posta tarafında olmuyordu.
    const email = String(profile.email || '').toLowerCase();
    if (email && profile.emailVerified !== false
      && this.config.idp.adminEmails.includes(email)) return true;
    return profile.roles.some((role) => this.config.idp.adminRoles.includes(role));
  }

  /**
   * Kendi alan adımızdaki doğrulanmış bir kimlik için posta kutusunu açar.
   *
   * ── BİLDİRİLEN HATA ────────────────────────────────────────────────────
   * "Sistemde var olan e-posta adresleriyle giriş yapılabiliyor, ama
   * karşılığı olmayan bir adresle (ör. bir Gmail adresi) girildiğinde
   * karmaşa çıkıyor."
   *
   * Karmaşanın iki ayrı kaynağı vardı ve ikisi de burada ayrılıyor:
   *
   *   1. KENDİ alan adımızdan bir adresle giren kişinin kutusu henüz
   *      açılmamış olabiliyordu. IdP o kişiyi tanıyor, adres bizim, ama
   *      `mailboxesForIdentity` boş dönüyordu — kullanıcı "hesabım var ama
   *      hiçbir şey yok" durumunda kalıyordu. Bu bir yetki sorunu değil,
   *      eksik bir kayıt: kutuyu burada açıyoruz.
   *
   *   2. HARİCİ bir adresle (gmail.com) giren kişinin bir kutusu OLMAMALI.
   *      Ona kutu açmak, bizim alan adımızda karşılığı olmayan bir kimliğe
   *      posta kutusu vermek olurdu. Bu durum bir hata değil, bir yetki
   *      durumudur ve `describeNoMailbox` ile açıkça anlatılır.
   *
   * Otomatik açma DOĞRULANMIŞ adres ister. Aksi hâlde IdP'de doğrulanmamış
   * bir adresi "benim" diye yazan biri, o adresin kutusunu açtırabilirdi.
   */
  async autoProvisionMailbox(profile) {
    if (!this.config.idp.autoProvisionMailbox) return null;
    const email = normalizeAddress(profile.email);
    if (!email || !email.includes('@')) return null;
    if (profile.emailVerified === false) {
      this.logger.warn({ email, msg: 'adres IdP tarafından doğrulanmamış, kutu açılmadı' });
      return null;
    }
    const { domain } = require('../util/encoding').splitAddress(email);
    if (!this.config.isLocalDomain(domain)) return null;

    const existing = await this.stores.mailboxes.getByAddress(email);
    if (existing) {
      // Kutu var ama sahibi yazılmamışsa (elle ya da teslimatla açılmışsa)
      // IdP öznesini bağlıyoruz: sahiplik adrese değil özneye bağlanmalı.
      if (!existing.ownerSub && profile.sub) {
        await this.stores.mailboxes.ensure(email, { ownerSub: profile.sub, ownerEmail: email });
        this.logger.info({ mailbox: email, sub: profile.sub, msg: 'kutu sahibi IdP kimliğine bağlandı' });
      }
      return existing;
    }

    const { mailbox, created } = await this.stores.mailboxes.ensure(email, {
      kind: 'user',
      displayName: profile.name || profile.preferredUsername || '',
      ownerSub: profile.sub,
      ownerEmail: email,
    });
    if (created) {
      this.logger.info({ mailbox: email, sub: profile.sub, msg: 'ilk girişte posta kutusu açıldı' });
      await this.stores.audit.record({
        actorSub: profile.sub, actorEmail: email, action: 'mailbox.auto_provision',
        targetType: 'mailbox', targetId: mailbox.ref,
        detail: { reason: 'IdP kimliği yerel alan adında ve doğrulanmış' },
      });
    }
    return mailbox;
  }

  /**
   * Erişilebilir kutu yoksa NEDENİNİ söyler.
   *
   * "Kutu yok" tek başına bir bilgi değil; kullanıcının ne yapması gerektiği
   * bilgisi eksik. Üç ayrı durum var ve her birinin farklı bir çıkışı var.
   */
  describeNoMailbox(profile) {
    const email = normalizeAddress(profile.email);
    const { domain } = require('../util/encoding').splitAddress(email);
    if (!email) {
      return {
        code: 'no_email',
        message: 'Kimlik sağlayıcı bir posta adresi döndürmedi.',
        action: 'Giriş isteğinde "email" kapsamı isteniyor mu, kontrol edin.',
      };
    }
    if (this.config.isLocalDomain(domain)) {
      return {
        code: 'local_pending',
        email,
        message: `${email} bu sunucunun alan adında ama tanımlı bir posta kutusu yok.`,
        action: profile.emailVerified === false
          ? 'Adresinizi fitfak kimlik hesabınızda doğrulayın; doğrulandığında kutunuz kendiliğinden açılır.'
          : 'Bir yöneticinin kutuyu oluşturması gerekiyor.',
      };
    }
    return {
      code: 'external_identity',
      email,
      message: `${email} harici bir adres; bu sunucuda karşılığı olan bir posta kutusu yok.`,
      action: 'Bir yöneticinin bu adresi bir posta kutusuna bağlaması (kimlik bağı) gerekir. '
        + 'Kendi alan adımızdaki bir adresle giriş yaparsanız kutunuz kendiliğinden açılır.',
    };
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

  /* ── kullanıcı adına IdP çağrıları ────────────────────────── */

  /**
   * Oturumun IdP erişim jetonunu, KULLANICI ADINA bir çağrıda kullanılmak
   * üzere döndürür.
   *
   * Bu, sertifika verme akışının dayandığı nokta. IdP'nin sertifika servisi
   * sahibi jetonun `sub` alanından belirliyor; dolayısıyla "bu kullanıcı için
   * sertifika" demenin tek yolu, o kullanıcının kendi jetonuyla sormak.
   * Servisin kendi jetonu (client_credentials) bir kullanıcıyı temsil etmez
   * ve IdP onu haklı olarak reddeder.
   *
   * Kapsam denetimi ÖNCE yapılır: kapsamı olmayan bir jetonla gidip 403
   * almak, kullanıcıya "bir şeyler ters gitti" demek olurdu. Kapsam eksikse
   * arayüzün kullanıcıyı yeniden onaya yönlendirebilmesi için açık bir kod
   * döner.
   *
   * @returns {Promise<{ok: boolean, accessToken?: string, code?: string, ...}>}
   */
  async idpAccessTokenFor(session, { requiredScope = null } = {}) {
    if (!session || session.isApiToken) {
      return { ok: false, code: 'not_interactive', message: 'Bu işlem tarayıcı oturumu gerektirir.' };
    }

    const scopes = String(session.scope || '').split(/\s+/).filter(Boolean);
    if (requiredScope && !scopes.includes(requiredScope)) {
      return {
        ok: false,
        code: 'scope_required',
        requiredScope,
        grantedScopes: scopes,
        message: `Oturumunuz "${requiredScope}" kapsamını taşımıyor.`,
      };
    }

    let accessToken = await this.stores.sessions.getAccessToken(session);
    if (accessToken) {
      // Jeton hâlâ geçerli mi? Süresi dolmuş bir jetonla IdP'ye gitmek 401
      // döner ve o 401, arayüzde "sertifika alınamadı" olarak görünür.
      const active = await this.idp.introspect(accessToken, { cacheMs: 10_000 })
        .then((info) => info && info.active !== false)
        .catch((err) => (err.temporary ? true : false));
      if (active) return { ok: true, accessToken, scopes, refreshed: false };
      this.logger.debug({ email: session.idpEmail, msg: 'IdP erişim jetonu geçersiz, yenileniyor' });
      accessToken = null;
    }

    const refreshToken = await this.stores.sessions.getRefreshToken(session);
    if (!refreshToken) {
      return {
        ok: false,
        code: 'reauth_required',
        message: 'IdP oturum jetonu yok ya da süresi dolmuş. Yeniden giriş yapmanız gerekiyor.',
      };
    }

    try {
      const tokens = await this.idp.refresh(refreshToken);
      if (!tokens.accessToken) throw new Error('access_token dönmedi');
      await this.stores.sessions.updateIdpTokens(session, {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        scope: tokens.scope || session.scope,
      });
      return {
        ok: true,
        accessToken: tokens.accessToken,
        scopes: String(tokens.scope || session.scope || '').split(/\s+/).filter(Boolean),
        refreshed: true,
      };
    } catch (err) {
      this.logger.warn({ email: session.idpEmail, error: err.message, msg: 'IdP jetonu yenilenemedi' });
      return {
        ok: false,
        code: 'reauth_required',
        message: `IdP jetonu yenilenemedi: ${err.message}`,
      };
    }
  }

  /**
   * Eksik bir kapsam için yeniden yetkilendirme adresi üretir.
   *
   * Kullanıcı buraya gidip onay verdiğinde geri döner ve kod jetona
   * çevrilerek AYNI yerel oturuma yazılır — yeni bir oturum açılmaz, çünkü
   * kullanıcı zaten giriş yapmış durumda ve onu tekrar giriş ekranına atmak
   * yaptığı işi kaybettirirdi.
   */
  async beginScopeUpgrade({ session, scope, returnTo = '/', ip = '', userAgent = '' }) {
    const requested = [...new Set([...String(session.scope || '').split(/\s+/).filter(Boolean), scope])];
    const request = this.idp.createAuthorizationRequest({
      scopes: requested,
      prompt: 'consent',
      loginHint: session.idpEmail || null,
    });
    await this.stores.sessions.putEphemeral(`oauth:${request.state}`, {
      codeVerifier: request.codeVerifier,
      nonce: request.nonce,
      ip,
      userAgent: String(userAgent).slice(0, 200),
      returnTo: sanitizeReturnTo(returnTo),
      upgradeSessionRef: session.ref,
      requestedScope: scope,
      createdAt: Date.now(),
    }, { kind: 'oauth-state', ttlMs: 10 * 60_000 });
    return { url: request.url, state: request.state, scopes: requested };
  }

  /**
   * Kapsam yükseltme dönüşü: kodu jetona çevirir ve MEVCUT oturuma yazar.
   * @returns {Promise<{upgraded: boolean, returnTo: string, scope: string}>}
   */
  async completeScopeUpgrade({ code, stored }) {
    const tokens = await this.idp.exchangeCode({ code, codeVerifier: stored.codeVerifier });
    const target = await this.stores.sessions.getByRef(stored.upgradeSessionRef);
    if (!target) {
      const err = new Error('yükseltilecek oturum bulunamadı ya da kapatılmış');
      err.status = 401;
      throw err;
    }
    await this.stores.sessions.updateIdpTokens(target, {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      scope: tokens.scope,
    });
    this.logger.info({ scope: tokens.scope, msg: 'oturum kapsamı yükseltildi' });
    return { upgraded: true, returnTo: stored.returnTo || '/', scope: tokens.scope };
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
