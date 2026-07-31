'use strict';

const crypto = require('node:crypto');

const { IdpClient } = require('./idp-client');
const { normalizeAddress, timingSafeEqualStr } = require('../util/encoding');
const { decode: decodeJwt } = require('../util/jwt');

/**
 * Bir erişim jetonunun TAŞIDIĞI kapsamlar.
 *
 * ── BİLDİRİLEN HATA ──────────────────────────────────────────────────────
 *   "yetki yükselt kısmından geçtikten sonra jetonu alıyoruz ... ama sertifika
 *    istediğimde sürekli 409 'Oturumunuz cert:issue kapsamını taşımıyor'
 *    oluyor, oysa uygulama yönetiminde cert:issue açık"
 *
 * Sebep, kapsamın YANLIŞ YERDEN okunmasıydı. Kapsam denetimi yalnızca yerel
 * oturum kaydındaki `scope` dizgesine bakıyordu; o dizge ise IdP'nin
 * `/oauth/token` YANITINDAKİ `scope` alanından geliyor — ve fitfak-idp o
 * alanı yanıta hiç koymuyor (bkz. oauth-server.js: yanıt yalnızca
 * access_token/refresh_token/token_type/expires_in taşıyor).
 *
 * Sonuç bir kısır döngüydü:
 *   1. kapsam eksik  -> 409 -> kullanıcı onay turuna gider
 *   2. onay verilir, IdP `scope: "cert:issue"` İÇEREN bir jeton döndürür
 *   3. yanıtta `scope` alanı yok -> yerel kayda BOŞ dizge yazılır
 *   4. kapsam yine eksik görünür -> 409. Başa dön.
 *
 * Oysa kapsam zaten elimizdeydi: jetonun KENDİ içinde. Kullanıcının
 * paylaştığı jetonun gövdesi tam olarak şunu diyor:
 *
 *     {"sub":"3578…","iss":"https://session.fitfak.net","scope":"cert:issue",…}
 *
 * Bu yüzden kapsam artık üç kaynaktan birleştiriliyor ve JETONUN KENDİSİ
 * belirleyici olan: jetonu taşıyan istek neyi yapabiliyorsa kapsam odur.
 * Jeton imzası burada doğrulanmıyor — doğrulama IdP'de, `introspect` ile
 * yapılıyor; buradaki okuma yalnızca "hangi kapsam isteneceğini" belirliyor
 * ve yanlış olması durumunda IdP isteği zaten reddeder.
 */
function scopesFromAccessToken(accessToken) {
  const parsed = decodeJwt(accessToken);
  if (!parsed || !parsed.payload) return [];
  const raw = parsed.payload.scope != null ? parsed.payload.scope : parsed.payload.scp;
  if (Array.isArray(raw)) return raw.map(String).filter(Boolean);
  return String(raw || '').split(/\s+/).filter(Boolean);
}

/** Jetonun öznesi (sub) — hangi hesaba ait olduğunu söyler. */
function subjectFromAccessToken(accessToken) {
  const parsed = decodeJwt(accessToken);
  return parsed && parsed.payload ? String(parsed.payload.sub || '') : '';
}

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

    // 1. Elimizdeki jetonla dene. Kapsam denetimi jetonun KENDİSİNE bakarak
    //    yapılır; yerel kayıttaki `scope` yalnızca bir ipucu.
    let accessToken = await this.stores.sessions.getAccessToken(session);
    if (accessToken) {
      const verdict = await this._evaluateToken(session, accessToken, requiredScope);
      if (verdict) return verdict;
      this.logger.debug({
        email: session.idpEmail, requiredScope,
        msg: 'eldeki IdP jetonu yetersiz ya da geçersiz, yenileniyor',
      });
      accessToken = null;
    }

    // 2. Yenilemeyi dene. Yenilenen jeton eskisinin kapsamını taşır; eksik
    //    kapsam yenilemeyle KAZANILMAZ ama süresi dolmuş bir jeton yüzünden
    //    kullanıcıyı gereksiz bir onay turuna göndermemek için önce denenir.
    const refreshToken = await this.stores.sessions.getRefreshToken(session);
    if (!refreshToken) {
      return this._missingScopeVerdict(session, requiredScope, {
        code: 'reauth_required',
        message: 'IdP oturum jetonu yok ya da süresi dolmuş. Yeniden giriş yapmanız gerekiyor.',
      });
    }

    let tokens;
    try {
      tokens = await this.idp.refresh(refreshToken);
      if (!tokens.accessToken) throw new Error('access_token dönmedi');
    } catch (err) {
      this.logger.warn({ email: session.idpEmail, error: err.message, msg: 'IdP jetonu yenilenemedi' });
      return {
        ok: false,
        code: 'reauth_required',
        message: `IdP jetonu yenilenemedi: ${err.message}`,
      };
    }

    await this.stores.sessions.updateIdpTokens(session, {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      scope: this.effectiveScope(tokens.accessToken, tokens.scope, session.scope),
    });
    session.scope = this.effectiveScope(tokens.accessToken, tokens.scope, session.scope);

    const verdict = await this._evaluateToken(session, tokens.accessToken, requiredScope, { refreshed: true });
    if (verdict) return verdict;

    return this._missingScopeVerdict(session, requiredScope, {
      code: 'scope_required',
      message: `Oturumunuz "${requiredScope}" kapsamını taşımıyor.`,
    });
  }

  /**
   * Bir jetonun kullanılabilir olup olmadığına karar verir.
   * @returns {Promise<object|null>} kullanılabilirse sonuç, değilse null
   */
  async _evaluateToken(session, accessToken, requiredScope, extra = {}) {
    // Jeton hâlâ geçerli mi? Süresi dolmuş bir jetonla IdP'ye gitmek 401
    // döner ve o 401, arayüzde "sertifika alınamadı" olarak görünür.
    let info = null;
    let active;
    try {
      info = await this.idp.introspect(accessToken, { cacheMs: 10_000 });
      active = !info || info.active !== false;
    } catch (err) {
      // IdP erişilemiyorsa bu bir yetkilendirme kararı değil; jetonun kendi
      // son kullanma tarihi hâlâ geçerliyse devam edilir.
      if (!err.temporary) return null;
      active = !isExpiredToken(accessToken);
    }
    if (!active) return null;

    const scopes = this.effectiveScopeList(accessToken, info && info.scope, session.scope);
    if (requiredScope && !scopes.includes(requiredScope)) return null;

    // Jetonun taşıdığı kapsam yerel kayıtla çelişiyorsa kayıt DÜZELTİLİR.
    // Aksi hâlde her istek aynı hesabı yeniden yapıyor ve kullanıcı, IdP'de
    // onay verilmiş bir kapsam için tekrar tekrar onaya yönlendiriliyordu.
    const joined = scopes.join(' ');
    if (joined && joined !== String(session.scope || '')) {
      await this.stores.sessions.updateIdpTokens(session, { scope: joined }).catch(() => {});
      session.scope = joined;
    }

    return { ok: true, accessToken, scopes, refreshed: !!extra.refreshed };
  }

  _missingScopeVerdict(session, requiredScope, base) {
    return {
      ...base,
      ok: false,
      requiredScope,
      grantedScopes: String(session.scope || '').split(/\s+/).filter(Boolean),
    };
  }

  /**
   * Bir jetonun gerçek kapsam listesi.
   *
   * Öncelik sırası, güvenilirlik sırasıdır:
   *   1. jetonun kendi `scope` savı — isteği taşıyan şey bu,
   *   2. IdP'nin inceleme (introspection) yanıtı,
   *   3. yerel oturum kaydı — yalnızca ilk ikisi boşsa.
   *
   * Birleştirme değil ELEME yapılıyor: yerel kaydı jetonun kapsamına
   * EKLEMEK, IdP'nin geri aldığı bir kapsamı yerel kayıt sayesinde hayatta
   * tutmak olurdu.
   */
  effectiveScopeList(accessToken, introspectedScope = null, fallbackScope = '') {
    const fromToken = scopesFromAccessToken(accessToken);
    if (fromToken.length) return fromToken;
    const fromIntrospection = String(introspectedScope || '').split(/\s+/).filter(Boolean);
    if (fromIntrospection.length) return fromIntrospection;
    return String(fallbackScope || '').split(/\s+/).filter(Boolean);
  }

  effectiveScope(accessToken, introspectedScope = null, fallbackScope = '') {
    return this.effectiveScopeList(accessToken, introspectedScope, fallbackScope).join(' ');
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
      // Hesap seçme ekranında HANGİ hesabın seçileceği burada söyleniyor.
      // Bu tek başına bir güvence DEĞİL (kullanıcı başka bir hesap seçebilir);
      // asıl güvence dönüşteki özne denetimi — bkz. completeScopeUpgrade.
      loginHint: session.idpEmail || null,
    });
    await this.stores.sessions.putEphemeral(`oauth:${request.state}`, {
      codeVerifier: request.codeVerifier,
      nonce: request.nonce,
      ip,
      userAgent: String(userAgent).slice(0, 200),
      returnTo: sanitizeReturnTo(returnTo),
      upgradeSessionRef: session.ref,
      // Yükseltmeyi başlatan oturumun ÖZNESİ durumla birlikte saklanır:
      // dönüşte gelen jetonun aynı kişiye ait olduğu buna karşı denetlenir.
      upgradeSubject: session.idpSub,
      upgradeEmail: session.idpEmail,
      requestedScope: scope,
      createdAt: Date.now(),
    }, { kind: 'oauth-state', ttlMs: 10 * 60_000 });
    return { url: request.url, state: request.state, scopes: requested };
  }

  /**
   * Kapsam yükseltme dönüşü: kodu jetona çevirir ve MEVCUT oturuma yazar.
   *
   * ── BİLDİRİLEN AÇIK ──────────────────────────────────────────────────
   *   "yetki yükseltte hesap seçmemiz var; orada posta kutusundaki açık
   *    oturumun epostasından onay verilmesi daha iyi olur, öbür türlü başka
   *    oturumlardan başka kişilerin sertifikası alınabilir"
   *
   * Doğru tespit. IdP'de aynı tarayıcıda birden fazla hesap açık olabiliyor
   * (çoklu hesap çerezi) ve onay ekranında BAŞKA bir hesap seçilirse, dönen
   * jeton o kişiye ait oluyordu. Eski kod jetonu hiçbir denetim yapmadan
   * yerel oturuma yazıyordu; sonuç, A kişisinin posta kutusu oturumunun B
   * kişisinin IdP jetonunu taşıması — ve o jetonla istenen sertifikanın
   * B'ye yazılmasıydı.
   *
   * Artık jetonun öznesi, yükseltmeyi BAŞLATAN oturumun öznesiyle
   * karşılaştırılıyor. Uyuşmuyorsa yükseltme reddediliyor: yeni jeton
   * saklanmıyor, eski oturum olduğu gibi kalıyor ve kullanıcıya hangi
   * hesapla devam etmesi gerektiği söyleniyor.
   *
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

    const expectedSub = String(stored.upgradeSubject || target.idpSub || '');
    const tokenSub = await this._subjectOf(tokens);
    if (expectedSub && tokenSub && tokenSub !== expectedSub) {
      this.logger.warn({
        expectedSub, tokenSub, sessionEmail: target.idpEmail,
        msg: 'kapsam yükseltmesinde BAŞKA bir hesap onay verdi — yükseltme reddedildi',
      });
      await this.stores.audit.record({
        actorSub: expectedSub,
        actorEmail: target.idpEmail,
        action: 'session.scope_upgrade_rejected',
        targetType: 'session',
        targetId: target.ref,
        result: 'rejected',
        detail: { reason: 'subject_mismatch', tokenSub },
      }).catch(() => {});
      // Yanlış hesaba ait jeton bizde KALMAZ.
      if (tokens.refreshToken) await this.idp.revokeToken(tokens.refreshToken).catch(() => {});
      const err = new Error(
        `Onay ${target.idpEmail || 'bu oturumun'} hesabı yerine başka bir hesapla verildi. `
        + 'Lütfen posta kutusunun açık olduğu hesapla onaylayın.',
      );
      err.status = 403;
      err.code = 'SCOPE_UPGRADE_SUBJECT_MISMATCH';
      throw err;
    }
    if (expectedSub && !tokenSub) {
      // Özne okunamadıysa (jeton JWT değil ve inceleme erişilemedi) sessizce
      // kabul etmek, denetimi hiç yapmamakla aynı şey olurdu.
      const err = new Error('Onay veren hesap doğrulanamadı; lütfen tekrar deneyin.');
      err.status = 503;
      err.code = 'SCOPE_UPGRADE_SUBJECT_UNKNOWN';
      throw err;
    }

    // IdP jeton yanıtında `scope` göndermeyebilir; kapsam jetonun kendisinden
    // okunur. Boş bir dizge yazmak, az önce kazanılan kapsamı silmek olurdu.
    const scope = this.effectiveScope(tokens.accessToken, tokens.scope, target.scope);
    await this.stores.sessions.updateIdpTokens(target, {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      scope,
    });
    this.logger.info({
      email: target.idpEmail, scope, requested: stored.requestedScope,
      msg: 'oturum kapsamı yükseltildi',
    });
    return { upgraded: true, returnTo: stored.returnTo || '/', scope };
  }

  /** Jetonun öznesi: önce id_token, sonra erişim jetonu, sonra inceleme. */
  async _subjectOf(tokens) {
    if (tokens.idToken) {
      const verified = await this.idp.verifyIdToken(tokens.idToken).catch(() => null);
      if (verified && verified.ok && verified.payload && verified.payload.sub) {
        return String(verified.payload.sub);
      }
    }
    const fromAccess = subjectFromAccessToken(tokens.accessToken);
    if (fromAccess) return fromAccess;
    const info = await this.idp.introspect(tokens.accessToken).catch(() => null);
    return info && info.sub ? String(info.sub) : '';
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

/** İmza doğrulamadan yalnızca `exp` bakışı — IdP erişilemezken kullanılır. */
function isExpiredToken(accessToken) {
  const parsed = decodeJwt(accessToken);
  if (!parsed || !parsed.payload || parsed.payload.exp == null) return false;
  return Math.floor(Date.now() / 1000) > Number(parsed.payload.exp);
}

function sanitizeReturnTo(value) {
  const s = String(value || '/');
  // Yalnızca site içi yollar: açık yönlendirme, kimlik avı için hazır bir
  // araçtır ("giriş yaptınız" sonrası saldırganın sayfasına gitmek).
  if (!s.startsWith('/') || s.startsWith('//')) return '/';
  return s.slice(0, 300);
}

module.exports = { SessionManager, summarizeAccess };
