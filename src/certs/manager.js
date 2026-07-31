'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');
const { URL } = require('node:url');

const { createSmimeRequest, isAvailable: sslAvailable, inspectRequest } = require('./csr');
const { normalizeAddress } = require('../util/encoding');
const { createInterval } = require('../util/async');
const log = require('../util/log');

/**
 * S/MIME sertifika yöneticisi.
 *
 * ── BİLDİRİLEN HATA: "kullanıcı bulunamadı" ──────────────────────────────
 *
 * Sertifikayı biz üretmiyoruz; fitfak-idp'nin sertifika servisi üretiyor
 * (trust.fitfak.net/device/certificate). O uç nokta isteği ŞÖYLE çözüyor:
 *
 *     resolveCurrentSession(req) -> access token doğrulanır
 *       payload.sid varsa  -> userId = payload.sub  (KULLANICI oturumu)
 *       payload.sid yoksa  -> userId = payload.sub  ("m2m_session")
 *     certificateService.requestCertificate({ userId, ... })
 *       users.get(userId) -> yoksa AppError('user_not_found')
 *
 * Yani IdP, sertifikanın sahibini YALNIZCA jetonun öznesinden (`sub`)
 * belirliyor; gövdedeki `userId` alanına hiç bakmıyor. `client_credentials`
 * ile alınan bir jetonda `sub` bir KULLANICI değil, İSTEMCİNİN kendisidir —
 * dolayısıyla `users.get(sub)` her zaman boş döner ve istek "Kullanıcı
 * bulunamadı" ile reddedilir. Hata mesajı yanıltıcı: kullanıcı gerçekten
 * yok değil, yanlış kimlikle soruluyor.
 *
 * Buradaki çözüm bunu bir yapılandırma sorunu olmaktan çıkarıp bir TÜR
 * sorunu yapıyor: her istek açık bir `identity` ile gelir.
 *
 *   identity: 'user'     -> taşıyıcı jeton, o kullanıcının KENDİ IdP erişim
 *                           jetonudur (tarayıcı oturumundan ya da cihaz kodu
 *                           akışından). Sertifika IdP'de o kullanıcıya
 *                           yazılır, yönetim panelinde görünür, RBAC
 *                           (`certProfiles`) ona göre uygulanır.
 *   identity: 'service'  -> client_credentials. Sertifika UYGULAMANIN kendi
 *                           adına üretilir. Bir kullanıcı posta kutusu için
 *                           KULLANILAMAZ; IdP kabul etmez ve etmemeli.
 *
 * Bir kullanıcı kutusu için servis jetonuna düşmek yasak: eskiden yapılan
 * buydu ve ortaya çıkan hata, IdP'de o kullanıcının olmamasıymış gibi
 * görünüyordu.
 */

/** IdP'nin döndürdüğü hata kodları -> ne yapılması gerektiği. */
const IDP_ERROR_HINTS = {
  user_not_found:
    'IdP bu jetonun sahibini bir kullanıcı olarak tanımadı. Sertifika, kullanıcının '
    + 'KENDİ oturum jetonuyla istenmelidir; servis (client_credentials) jetonu yalnızca '
    + 'uygulamanın kendi sertifikaları için geçerlidir.',
  profile_not_allowed:
    'IdP bu hesabın bu profilde sertifika almasına izin vermiyor. fitfak kimlik yönetim '
    + 'panelinde Kullanıcılar > Sertifika yetkileri altından ilgili profili işaretleyin.',
  key_already_certified:
    'Bu açık anahtar için zaten bir sertifika üretilmiş. Yenilemek için yeni bir anahtar '
    + 'çifti üretilmeli (force ile yeniden deneyin).',
  unauthenticated:
    'IdP oturumu geçersiz ya da süresi dolmuş. Kullanıcının yeniden giriş yapması gerekir.',
  invalid_csr: 'Sertifika isteği (CSR) IdP tarafından biçimsel olarak reddedildi.',
  forbidden: 'IdP isteği yetki nedeniyle reddetti.',
};

class CertificateError extends Error {
  constructor(message, { code = null, status = 0, hint = null, retryable = false } = {}) {
    super(message);
    this.name = 'CertificateError';
    this.code = code;
    this.status = status;
    this.hint = hint;
    this.retryable = retryable;
  }
}

class CertificateManager {
  constructor({ config, logger, stores, serviceToken = null, signer = null }) {
    this.config = config;
    this.logger = logger || log.child('cert');
    this.stores = stores;
    this.serviceToken = serviceToken;
    this.signer = signer;
    this.sweeper = null;
    this._caBundle = undefined;
  }

  get available() { return sslAvailable(); }

  /* ── trust.fitfak.net ile konuşma ─────────────────────────── */

  /**
   * Sertifika isteği gönderir.
   *
   * @param {object} p
   * @param {string} p.csrPem
   * @param {string} p.profile      IdP profil adı ('smime', 'client-auth', …)
   * @param {string} p.accessToken  taşıyıcı jeton
   * @param {'user'|'service'} p.identity  jetonun kimin adına konuştuğu
   * @param {string} [p.path]       uç nokta
   */
  async requestCertificate({
    csrPem, profile = null, accessToken, identity = 'user', path = null,
    extra = {}, requestedBySub = '',
  }) {
    if (!accessToken) {
      throw new CertificateError('sertifika isteği için taşıyıcı jeton yok', { code: 'no_token' });
    }
    const endpoint = `${this.config.trust.baseUrl}${path || this.config.trust.devicePath}`;
    const effectiveProfile = profile || this.config.trust.smimeProfile;

    // Gövdedeki `userId` IdP tarafından YOK SAYILIYOR (sahip jetondan gelir).
    // Yine de gönderiyoruz: IdP tarafındaki kayıtlarda isteği başlatanın kim
    // olduğunu görmek, "bu sertifikayı kim istedi" sorusunu cevaplıyor.
    const payload = JSON.stringify({
      csrPem,
      profile: effectiveProfile,
      requestedBySub: requestedBySub || '',
      ...extra,
    });

    const done = this.logger.timer('sertifika isteği');
    let response;
    try {
      response = await this._postJson(endpoint, payload, {
        // IdP'nin `requireTrustOrigin` kapısı Origin başlığına bakıyor ve
        // yalnızca ISSUER ile TRUST_ISSUER'ı kabul ediyor. Tarayıcı dışı bir
        // istemciyiz, o yüzden başlığı kendimiz koyuyoruz — koymazsak istek
        // "köken yok" diye reddedilir ve hata, sertifikayla ilgisi olmayan
        // bir 403 olarak görünür.
        origin: this.config.idp.baseUrl,
        referer: `${this.config.idp.baseUrl}/`,
        authorization: `Bearer ${accessToken}`,
      });
    } catch (err) {
      done({ ok: false, profile: effectiveProfile, identity });
      throw err;
    }

    const data = response.json || {};
    const certPem = data.certPem || data.certificate || data.cert;
    if (!certPem) {
      throw new CertificateError(
        `sertifika sunucusu sertifika döndürmedi: ${log.snippet(response.raw, 200)}`,
        { code: 'no_certificate', status: response.status },
      );
    }

    const issued = {
      certPem,
      chainPem: data.chainPem || data.chain || data.caPem || '',
      serialHex: data.serialNumberHex || data.serialNumber || data.serialHex || '',
      notBefore: data.notBefore || null,
      notAfter: data.notAfter || null,
      issuedVia: identity === 'service' ? 'service-token' : 'user-token',
    };
    done({ ok: true, profile: effectiveProfile, identity, serialHex: issued.serialHex });
    return issued;
  }

  /** Kullanıcının IdP'deki sertifikalarını listeler (yalnızca kullanıcı jetonuyla). */
  async listRemoteCertificates(accessToken) {
    const endpoint = `${this.config.trust.baseUrl}${this.config.trust.certificatesPath}`;
    const response = await this._request('GET', endpoint, null, {
      origin: this.config.idp.baseUrl,
      authorization: `Bearer ${accessToken}`,
    });
    return (response.json && response.json.certificates) || [];
  }

  _postJson(url, payload, headers) {
    return this._request('POST', url, payload, { 'content-type': 'application/json', ...headers });
  }

  /**
   * CA paketi bir kez okunur.
   *
   * Önceki sürüm her istekte diskten okuyor ve okuma başarısız olduğunda
   * yalnızca ekrana yazıp devam ediyordu — yani yanlış yapılandırılmış bir
   * yolda TLS doğrulaması sessizce sistem köklerine düşüyordu. Artık okuma
   * bir kez yapılır ve sonucu (başarılı ya da başarısız) kayda geçer.
   */
  _caBundleOrNull() {
    if (this._caBundle !== undefined) return this._caBundle;
    const caPath = this.config.trust.caBundlePath;
    if (!caPath) {
      this.logger.debug({ msg: 'trust CA paketi ayarlanmamış, sistem kökleri kullanılacak' });
      this._caBundle = null;
      return null;
    }
    try {
      const ca = require('node:fs').readFileSync(caPath);
      // Sistem kökleri SİLİNMEZ, kendi kökümüz EKLENİR: trust.fitfak.net'in
      // önünde herkese açık bir sertifika (Cloudflare) durabiliyor.
      this._caBundle = [...tls.rootCertificates, ca.toString('utf8')];
      this.logger.info({ caPath, msg: 'trust CA paketi yüklendi' });
    } catch (err) {
      this.logger.warn({ caPath, error: err.message, msg: 'trust CA paketi okunamadı, sistem kökleriyle devam ediliyor' });
      this._caBundle = null;
    }
    return this._caBundle;
  }

  _request(method, url, payload, headers) {
    const target = new URL(url);
    const transport = target.protocol === 'https:' ? https : http;
    const finalHeaders = {
      accept: 'application/json',
      'user-agent': 'Fitfak-Mail/2.0',
      ...headers,
    };
    if (payload != null) finalHeaders['content-length'] = Buffer.byteLength(payload);

    const options = {
      method,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      headers: finalHeaders,
    };
    const ca = this._caBundleOrNull();
    if (ca) options.ca = ca;

    this.logger.http('→ trust', {
      method, url, headers: log.safeHeaders(finalHeaders), body: payload ? log.snippet(payload, 300) : undefined,
    });

    return new Promise((resolve, reject) => {
      const req = transport.request(options, (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          this.logger.http('← trust', {
            method, url, status: res.statusCode, body: log.snippet(raw, 400),
          });

          let parsed = null;
          try { parsed = JSON.parse(raw); } catch { /* JSON değil (proxy hata sayfası olabilir) */ }

          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ status: res.statusCode, json: parsed, raw });
            return;
          }
          reject(this._describeFailure(res.statusCode, parsed, raw));
        });
      });

      req.setTimeout(30_000, () => {
        req.destroy();
        reject(new CertificateError('sertifika sunucusu zaman aşımı (30s)', {
          code: 'timeout', retryable: true,
        }));
      });
      req.on('error', (err) => reject(new CertificateError(
        `sertifika sunucusuna erişilemedi: ${err.message}`,
        { code: err.code || 'network', retryable: true },
      )));
      if (payload != null) req.write(payload);
      req.end();
    });
  }

  /**
   * IdP hatasını anlaşılır bir hataya çevirir.
   *
   * Önceki sürüm ham gövdeyi mesaja koyuyordu; kullanıcı arayüzünde
   * "Kullanıcı bulunamadı" görünüyordu ve bu, yanlış soruyu sordurtuyordu
   * ("kullanıcıyı IdP'ye ekledim, hâlâ olmuyor"). Artık hangi kimliğin
   * kullanıldığı ve ne yapılması gerektiği mesajın parçası.
   */
  _describeFailure(status, parsed, raw) {
    const code = (parsed && (parsed.error || parsed.code)) || `http_${status}`;
    const description = (parsed && (parsed.error_description || parsed.message)) || log.snippet(raw, 200);
    const hint = IDP_ERROR_HINTS[code] || null;
    return new CertificateError(
      `sertifika sunucusu reddetti (HTTP ${status}, ${code}): ${description}`,
      { code, status, hint, retryable: status >= 500 || status === 429 },
    );
  }

  /* ── kutu başına sertifika ─────────────────────────────────── */

  /**
   * Bir posta kutusu için S/MIME sertifikası olduğundan emin olur.
   *
   * @param {object} mailbox
   * @param {object} [opts]
   * @param {boolean} [opts.force=false]        süresi dolmamış olsa da yenile
   * @param {string}  [opts.userAccessToken]    kullanıcının IdP erişim jetonu
   * @param {string}  [opts.requestedBySub]     isteği başlatan IdP öznesi
   * @param {boolean} [opts.allowServiceToken]  sistem kutuları için servis jetonuna izin
   */
  async ensureForMailbox(mailbox, {
    force = false, requestedBySub = '', userAccessToken = null, allowServiceToken = null,
  } = {}) {
    const address = normalizeAddress(mailbox.address);
    const logger = this.logger.child(address);

    if (!this.available) {
      return { status: 'skipped', reason: '@fitfak/ssl yüklü değil', code: 'ssl_missing' };
    }
    if (mailbox.smimeEnabled === false) {
      return { status: 'skipped', reason: 'kutuda S/MIME kapalı', code: 'smime_disabled' };
    }

    const existing = await this.stores.certificates.get('smime', address);
    if (existing && !force) {
      const now = Date.now();
      const active = existing.status === 'active';
      const notExpired = !existing.notAfter || existing.notAfter > now;
      const notDueForRenewal = !existing.renewAfter || existing.renewAfter > now;
      if (active && notExpired && notDueForRenewal) {
        return { status: 'current', notAfter: existing.notAfter, serialHex: existing.serialHex };
      }
    }

    // Hangi kimlikle isteyeceğimize BURADA karar veriliyor ve karar tek
    // kurala dayanıyor: sertifika bir kişiye mi yoksa uygulamaya mı ait?
    const identity = this._identityFor(mailbox, { userAccessToken, allowServiceToken });
    if (!identity.ok) {
      logger.warn({ reason: identity.reason, msg: 'S/MIME sertifikası istenemedi' });
      return { status: 'skipped', reason: identity.reason, code: identity.code, hint: identity.hint };
    }

    let accessToken;
    try {
      accessToken = identity.kind === 'user'
        ? identity.accessToken
        : await this.serviceToken.getAccessToken();
    } catch (err) {
      logger.error({ error: err.message, msg: 'jeton alınamadı' });
      return { status: 'failed', reason: err.message, code: 'token_unavailable' };
    }

    const request = createSmimeRequest({
      address,
      displayName: mailbox.displayName || address,
      organization: 'Fitfak',
    });

    // İsteği göndermeden önce kendi ürettiğimizi doğrularız: imzası geçersiz
    // bir CSR, sunucuda anlaşılmaz bir hata olarak döner.
    const inspected = inspectRequest(request.csrPem);
    if (!inspected.signatureValid) throw new Error('üretilen CSR öz-imzası geçersiz');
    if (!inspected.emails.includes(address)) {
      throw new Error(`CSR SAN'ında adres yok: ${address}`);
    }
    logger.debug({
      profile: this.config.trust.smimeProfile,
      identity: identity.kind,
      keyAlgorithm: request.algorithmLabel,
      san: inspected.emails.join(','),
      msg: 'CSR hazırlandı',
    });

    let issued;
    try {
      issued = await this.requestCertificate({
        csrPem: request.csrPem,
        profile: this.config.trust.smimeProfile,
        accessToken,
        identity: identity.kind,
        requestedBySub,
        extra: { subjectAddress: address, mailboxRef: mailbox.ref },
      });
    } catch (err) {
      logger.error({
        error: err.message, code: err.code, identity: identity.kind,
        hint: err.hint || undefined,
        msg: 'S/MIME sertifikası alınamadı',
      });
      return {
        status: 'failed', reason: err.message, code: err.code || 'request_failed',
        hint: err.hint || null, retryable: !!err.retryable,
      };
    }

    const stored = await this.stores.certificates.store({
      usage: 'smime',
      subjectAddress: address,
      mailboxRef: mailbox.ref,
      certPem: issued.certPem,
      chainPem: issued.chainPem,
      privateKeyPem: request.privateKeyPem,
      issuedVia: issued.issuedVia,
      keyAlgorithm: request.algorithmLabel,
      requestedBySub,
      renewAtRatio: this.config.trust.renewAtLifetimeRatio,
    });

    if (this.signer) this.signer.invalidate(address);
    await this.stores.audit.record({
      actorSub: requestedBySub,
      actorEmail: address,
      action: 'certificate.issue',
      targetType: 'mailbox',
      targetId: mailbox.ref,
      detail: { usage: 'smime', version: stored.version, issuedVia: issued.issuedVia, identity: identity.kind },
    });
    logger.info({
      version: stored.version, issuedVia: issued.issuedVia, serialHex: issued.serialHex,
      msg: 'S/MIME sertifikası verildi',
    });

    return {
      status: existing ? 'renewed' : 'issued',
      version: stored.version,
      ref: stored.ref,
      issuedVia: issued.issuedVia,
      serialHex: issued.serialHex,
    };
  }

  /**
   * Hangi kimliğin kullanılacağı.
   *
   * Kullanıcı kutuları için servis jetonuna DÜŞÜLMEZ. Düşmek, IdP'nin
   * anlamsız bir "kullanıcı bulunamadı" ile reddetmesi demek — ve o hata,
   * sorunun IdP'deki kullanıcı kaydında olduğunu düşündürüyor. Onun yerine
   * burada durup ne gerektiğini söylüyoruz.
   */
  _identityFor(mailbox, { userAccessToken, allowServiceToken }) {
    if (userAccessToken) {
      return { ok: true, kind: 'user', accessToken: userAccessToken };
    }

    const isSystemMailbox = mailbox.kind === 'system' || mailbox.kind === 'catchall';
    const serviceAllowed = allowServiceToken == null
      ? (isSystemMailbox && this.config.trust.allowServiceIdentity)
      : allowServiceToken;

    if (serviceAllowed && this.serviceToken) {
      return { ok: true, kind: 'service' };
    }
    if (!this.serviceToken && !userAccessToken) {
      return { ok: false, code: 'no_token_source', reason: 'jeton kaynağı yok (ne kullanıcı jetonu ne servis jetonu)' };
    }
    return {
      ok: false,
      code: 'user_token_required',
      reason: 'bu kutu için sertifika, kutu sahibinin kendi IdP oturumuyla istenmelidir',
      hint: IDP_ERROR_HINTS.user_not_found,
    };
  }

  /**
   * Bütün etkin kutular için sertifika sağlar.
   *
   * Arka plan taraması KULLANICI kutularına dokunmaz: onlar için gereken
   * jeton yalnızca kullanıcı giriş yaptığında var. Tarama, sistem kutularını
   * (postmaster, dmarc) ve yenilenmesi gerekenleri kapsar.
   */
  async ensureAll({ force = false, includeUserMailboxes = false } = {}) {
    const mailboxes = (await this.stores.mailboxes.listAll())
      .filter((m) => m.status === 'active' && m.kind !== 'alias')
      .filter((m) => includeUserMailboxes || m.kind === 'system' || m.kind === 'catchall');

    const summary = {
      total: mailboxes.length, issued: 0, renewed: 0, current: 0, failed: 0, skipped: 0,
    };
    for (const mailbox of mailboxes) {
      const result = await this.ensureForMailbox(mailbox, { force });
      if (result.status === 'issued') summary.issued++;
      else if (result.status === 'renewed') summary.renewed++;
      else if (result.status === 'current') summary.current++;
      else if (result.status === 'failed') summary.failed++;
      else summary.skipped++;
    }

    if (summary.issued || summary.renewed || summary.failed) {
      this.logger.info({ ...summary, msg: 'S/MIME sertifika taraması tamamlandı' });
    } else {
      this.logger.debug({ ...summary, msg: 'S/MIME sertifika taraması: değişiklik yok' });
    }
    return summary;
  }

  /** Yenileme zamanı gelenleri yeniler (yalnızca servis kimliğiyle alınmış olanları). */
  async renewDue() {
    const due = await this.stores.certificates.listNeedingRenewal();
    const results = [];
    for (const cert of due) {
      if (cert.usage !== 'smime') continue;
      const mailbox = cert.mailboxRef
        ? await this.stores.mailboxes.getByRef(cert.mailboxRef)
        : await this.stores.mailboxes.getByAddress(cert.subjectAddress);
      if (!mailbox) continue;
      // Kullanıcı jetonuyla alınmış bir sertifikayı arka planda yenileyemeyiz:
      // jeton yok. Sahibine haber vermek doğru davranış.
      if (cert.issuedVia === 'user-token' || cert.issuedVia === 'device-code') {
        this.logger.warn({
          address: cert.subjectAddress,
          daysLeft: Math.floor((cert.notAfter - Date.now()) / 86400_000),
          msg: 'kullanıcı sertifikasının süresi yaklaşıyor — sahibinin arayüzden yenilemesi gerekiyor',
        });
        results.push({ address: cert.subjectAddress, status: 'needs_user', code: 'user_token_required' });
        continue;
      }
      results.push({
        address: cert.subjectAddress,
        ...(await this.ensureForMailbox(mailbox, { force: true })),
      });
    }
    return results;
  }

  /**
   * Cihaz akışıyla kullanıcının kendi makinesinde üretilmiş bir sertifikayı
   * kaydeder.
   *
   * Özel anahtar İSTENMEZ ve saklanmaz: kullanıcının cihazında kalır. Sunucu
   * bu sertifikayla imzalayamaz — imzalamayı kullanıcının istemcisi yapar.
   * Kayıt, doğrulama tarafı için: gelen imzaların hangi sertifikaya ait
   * olduğunu bilmek ve iptal edilenleri tanımak.
   */
  async registerUserCertificate({ address, certPem, chainPem = '', requestedBySub = '', ip = '' }) {
    const addr = normalizeAddress(address);
    const x509 = new crypto.X509Certificate(certPem);

    // Sertifikanın gerçekten bu adrese ait olduğu doğrulanır: kullanıcının
    // gönderdiği herhangi bir sertifikayı bir adrese bağlamak, o adresin
    // imzalarını taklit etmeye izin vermek olurdu.
    const san = String(x509.subjectAltName || '').toLowerCase();
    const subject = String(x509.subject || '').toLowerCase();
    if (!san.includes(`email:${addr}`) && !subject.includes(`emailaddress=${addr}`)) {
      const err = new Error(`sertifika ${addr} adresini içermiyor`);
      err.status = 400;
      throw err;
    }
    if (new Date(x509.validTo).getTime() < Date.now()) {
      const err = new Error('sertifikanın süresi dolmuş');
      err.status = 400;
      throw err;
    }

    const mailbox = await this.stores.mailboxes.getByAddress(addr);
    const stored = await this.stores.certificates.store({
      usage: 'smime-user',
      subjectAddress: addr,
      mailboxRef: mailbox ? mailbox.ref : '',
      certPem,
      chainPem,
      privateKeyPem: null,
      issuedVia: 'device-code',
      requestedBySub,
      renewAtRatio: this.config.trust.renewAtLifetimeRatio,
    });

    await this.stores.audit.record({
      actorSub: requestedBySub, actorEmail: addr,
      action: 'certificate.register_user', targetType: 'certificate', targetId: stored.ref, ip,
      detail: { fingerprint: String(x509.fingerprint256 || '').replace(/:/g, '').toLowerCase() },
    });
    this.logger.info({ address: addr, msg: 'kullanıcı sertifikası kaydedildi (özel anahtar sunucuda değil)' });
    return { ref: stored.ref, version: stored.version, notAfter: new Date(x509.validTo).getTime() };
  }

  async revoke({ address, usage = 'smime', reason = 'unspecified', actorSub = '' }) {
    const done = await this.stores.certificates.revoke(usage, address, reason);
    if (done && this.signer) this.signer.invalidate(normalizeAddress(address));
    if (done) {
      await this.stores.audit.record({
        actorSub, actorEmail: address, action: 'certificate.revoke',
        targetType: 'certificate', targetId: `${usage}|${normalizeAddress(address)}`,
        detail: { reason },
      });
    }
    return done;
  }

  async status() {
    const smime = await this.stores.certificates.listByUsage('smime');
    const user = await this.stores.certificates.listByUsage('smime-user');
    const mailboxes = (await this.stores.mailboxes.listAll())
      .filter((m) => m.status === 'active' && m.kind !== 'alias');
    const covered = new Set(smime.filter((c) => c.status === 'active').map((c) => c.subjectAddress));
    const now = Date.now();
    return {
      sslAvailable: this.available,
      trustBaseUrl: this.config.trust.baseUrl,
      profile: this.config.trust.smimeProfile,
      serviceToken: this.serviceToken ? this.serviceToken.status() : { available: false },
      serviceIdentityAllowed: !!this.config.trust.allowServiceIdentity,
      mailboxes: mailboxes.length,
      covered: covered.size,
      missing: mailboxes.filter((m) => !covered.has(m.address)).map((m) => m.address),
      expiringSoon: smime
        .filter((c) => c.status === 'active' && c.notAfter && c.notAfter - now < 30 * 86400_000)
        .map((c) => ({ address: c.subjectAddress, notAfter: c.notAfter, daysLeft: Math.floor((c.notAfter - now) / 86400_000) })),
      userCertificates: user.length,
      revoked: smime.filter((c) => c.status === 'revoked').length,
    };
  }

  /** Arka plan taraması: eksikleri ver, süresi yaklaşanları yenile. */
  start() {
    if (this.sweeper) return this;
    if (!this.config.trust.autoIssue) {
      this.logger.info({ msg: 'otomatik sertifika verme kapalı (FITFAK_TRUST_AUTO_ISSUE)' });
      return this;
    }
    this.sweeper = createInterval(async () => {
      await this.ensureAll();
      await this.renewDue();
    }, this.config.trust.checkIntervalMs, {
      immediate: false,
      logger: this.logger,
      name: 'certificate-sweeper',
    });
    this.logger.info({ intervalMs: this.config.trust.checkIntervalMs, msg: 'sertifika taraması planlandı' });
    return this;
  }

  stop() {
    if (this.sweeper) { this.sweeper.stop(); this.sweeper = null; }
  }
}

module.exports = { CertificateManager, CertificateError, IDP_ERROR_HINTS };
