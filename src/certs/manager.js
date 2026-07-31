'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const tls = require('node:tls');
const { URL } = require('node:url');

const { createSmimeRequest, isAvailable: sslAvailable, inspectRequest } = require('./csr');
const { normalizeAddress } = require('../util/encoding');
const { createInterval } = require('../util/async');

/**
 * S/MIME sertifika yöneticisi.
 *
 * "Sistemde kayıtlı her eposta adresi için sertifika tamamlanmış olacaktır"
 * gereğinin karşılığı: her etkin posta kutusu için bir S/MIME sertifikası
 * bulunur, süresi dolmadan yenilenir ve özel anahtarı kasada durur.
 *
 * Sertifikayı BİZ ÜRETMİYORUZ — trust.fitfak.net üretiyor. Buradaki iş,
 * @fitfak/ssl ile anahtar ve istek (CSR) hazırlamak, isteği kimlik
 * doğrulamasıyla göndermek ve dönen sertifikayı kasaya yazmak. Özel anahtar
 * bu süreçte hiçbir yere gitmiyor: CSR ile istemenin bütün anlamı bu.
 *
 * İki yol:
 *   - SERVİS YOLU: sunucu, kendi jetonuyla kutular adına sertifika ister.
 *     Otomatik ve arka planda.
 *   - CİHAZ YOLU: kullanıcı kendi cihazında (CLI) cihaz kodu akışıyla giriş
 *     yapar, sertifikayı kendi adına alır. Özel anahtar kullanıcının
 *     makinesinde kalır; sunucu yalnızca sertifikayı (açık veriyi) kaydeder.
 */
class CertificateManager {
  constructor({ config, logger, stores, serviceToken = null, signer = null }) {
    this.config = config;
    this.logger = logger;
    this.stores = stores;
    this.serviceToken = serviceToken;
    this.signer = signer;
    this.sweeper = null;
  }

  get available() { return sslAvailable(); }

  /* ── trust.fitfak.net ile konuşma ─────────────────────────── */

  /**
   * Sertifika isteği gönderir.
   *
   * @param {object} p
   * @param {string} p.csrPem
   * @param {string} p.profile      @fitfak/ssl profil adı ('email' = S/MIME)
   * @param {string} p.accessToken  taşıyıcı jeton
   * @param {string} [p.path]       uç nokta (servis ya da cihaz)
   */
  async requestCertificate({ csrPem, profile = null, accessToken, path = null, extra = {}, requestedBySub = '' }) {
    const endpoint = `${this.config.trust.baseUrl}${path || this.config.trust.servicePath}`;
    const payload = JSON.stringify({
      csrPem,
      profile: profile || this.config.trust.smimeProfile,
      userId: requestedBySub,
      ...extra,
    });

    const response = await httpJson('POST', endpoint, payload, {
      'content-type': 'application/json',
      accept: 'application/json',
      authorization: `Bearer ${accessToken}`,
      // Origin başlığı: trust sunucusu tarayıcı dışı istemcileri de
      // Origin'e göre süzüyor (bkz. device-client örneği).
      origin: this.config.trust.baseUrl,
      'user-agent': 'Fitfak-Mail/2.0',
    }, this.config.trust.caBundlePath);

    const data = response.json || {};
    const certPem = data.certPem || data.certificate || data.cert;
    if (!certPem) {
      throw new Error(`sertifika sunucusu sertifika döndürmedi: ${JSON.stringify(data).slice(0, 300)}`);
    }
    return {
      certPem,
      chainPem: data.chainPem || data.chain || data.caPem || '',
      serialHex: data.serialNumber || data.serialHex || '',
      issuedVia: path === this.config.trust.devicePath ? 'device-code' : 'service-token',
    };
  }

  /* ── kutu başına sertifika ─────────────────────────────────── */

  /**
   * Bir posta kutusu için S/MIME sertifikası olduğundan emin olur.
   *
   * @param {object} mailbox
   * @param {object} [opts]
   * @param {boolean} [opts.force=false]  süresi dolmamış olsa da yenile
   */
  async ensureForMailbox(mailbox, { force = false, requestedBySub = '' } = {}) {
    if (!this.available) {
      return { status: 'skipped', reason: '@fitfak/ssl yüklü değil' };
    }
    if (mailbox.smimeEnabled === false) {
      return { status: 'skipped', reason: 'kutuda S/MIME kapalı' };
    }
    if (!this.serviceToken) {
      return { status: 'skipped', reason: 'servis jetonu sağlayıcısı yok' };
    }

    const address = normalizeAddress(mailbox.address);
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

    let issued;
    try {
      const accessToken = await this.serviceToken.getAccessToken();

      issued = await this.requestCertificate({
        csrPem: request.csrPem,
        profile: this.config.trust.smimeProfile,
        accessToken,
        requestedBySub,
        extra: { subjectAddress: address, mailboxRef: mailbox.ref },
      });
    } catch (err) {
      this.logger.error({ mailbox: address, error: err.message, msg: 'S/MIME sertifikası alınamadı' });
      return { status: 'failed', reason: err.message };
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
      actorSub: requestedBySub, actorEmail: address,
      action: 'certificate.issue', targetType: 'mailbox', targetId: mailbox.ref,
      detail: { usage: 'smime', version: stored.version, issuedVia: issued.issuedVia },
    });
    this.logger.info({
      mailbox: address, version: stored.version, issuedVia: issued.issuedVia,
      msg: 'S/MIME sertifikası verildi',
    });

    return { status: existing ? 'renewed' : 'issued', version: stored.version, ref: stored.ref };
  }

  /** Bütün etkin kutular için sertifika sağlar. */
  async ensureAll({ force = false } = {}) {
    const mailboxes = (await this.stores.mailboxes.listAll())
      .filter((m) => m.status === 'active' && m.kind !== 'alias');
    const summary = { total: mailboxes.length, issued: 0, renewed: 0, current: 0, failed: 0, skipped: 0 };

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
    }
    return summary;
  }

  /** Yenileme zamanı gelenleri yeniler. */
  async renewDue() {
    const due = await this.stores.certificates.listNeedingRenewal();
    const results = [];
    for (const cert of due) {
      if (cert.usage !== 'smime') continue;
      const mailbox = cert.mailboxRef
        ? await this.stores.mailboxes.getByRef(cert.mailboxRef)
        : await this.stores.mailboxes.getByAddress(cert.subjectAddress);
      if (!mailbox) continue;
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
      serviceToken: this.serviceToken ? this.serviceToken.status() : { available: false },
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

function httpJson(method, url, payload, headers, caPath = '') {
  const target = new URL(url);
  const transport = target.protocol === 'https:' ? https : http;
  const options = {
    method,
    hostname: target.hostname,
    port: target.port || (target.protocol === 'https:' ? 443 : 80),
    path: `${target.pathname}${target.search}`,
    headers: { ...headers, 'content-length': Buffer.byteLength(payload || '') },
  };

  // ========================================================
  // 🟡 GİDEN İSTEĞİ LOGLAMA (SARI)
  // ========================================================
  console.log('\x1b[93m' + '================ CERT HTTP GİDEN İSTEK ==================' + '\x1b[0m');
  console.log('\x1b[93m' + `METOT/URL : ${method} ${url}` + '\x1b[0m');
  console.log('\x1b[93m' + `HEADERS   : ${JSON.stringify(options.headers, null, 2)}` + '\x1b[0m');

  // CA SERTİFİKASI KONTROLÜ VE LOGU
  if (caPath) {
    try { 
      const ca = require('node:fs').readFileSync(caPath); 
      
      // Node.js'in varsayılan global sertifikalarını SİLMEDEN bizimkini EKLİYORUZ:
      options.ca = [...tls.rootCertificates, ca];
      console.log('\x1b[92m' + `CA OKUNDU : ✅ Başarılı! Yol: ${caPath} (Boyut: ${options.ca.length} byte)` + '\x1b[0m');
    } catch (caErr) { 
      console.log('\x1b[91m' + `CA HATASI : ❌ Dosya okunamadı! Yol: ${caPath} | Sebep: ${caErr.message}` + '\x1b[0m');
    }
  } else {
    console.log('\x1b[91m' + `CA UYARISI: ❌ caPath parametresi boş gönderildi!` + '\x1b[0m');
  }

  if (payload) {
    // Çok uzun olabileceği için payload'ın sadece başını basıyoruz
    console.log('\x1b[93m' + `PAYLOAD   :  ${payload}` + '\x1b[0m');
  }
  console.log('\x1b[93m' + '=========================================================' + '\x1b[0m');

  return new Promise((resolve, reject) => {
    const req = transport.request(options, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');

        // ========================================================
        // 🔵 GELEN YANITI LOGLAMA (MAVİ)
        // ========================================================
        console.log('\x1b[36m' + '================ CERT HTTP GELEN YANIT ==================' + '\x1b[0m');
        console.log('\x1b[36m' + `STATUS : ${res.statusCode}` + '\x1b[0m');
        console.log('\x1b[36m' + `BODY   : ${raw.slice(0, 300)}${raw.length > 300 ? '... (kısaltıldı)' : ''}` + '\x1b[0m');
        console.log('\x1b[36m' + '=========================================================' + '\x1b[0m');

        let parsed = null;
        try { parsed = JSON.parse(raw); } catch { /* JSON değil */ }
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ status: res.statusCode, json: parsed, raw });
          return;
        }
        reject(new Error(`sertifika sunucusu HTTP ${res.statusCode}: ${(parsed && (parsed.error || parsed.message)) || raw.slice(0, 300)}`));
      });
    });
    
    req.setTimeout(30_000, () => { 
      console.log('\x1b[91m' + `[CERT HTTP HATA] Zaman Aşımı (Timeout)!` + '\x1b[0m');
      req.destroy(); 
      reject(new Error('sertifika sunucusu zaman aşımı')); 
    });
    
    req.on('error', (err) => {
      console.log('\x1b[91m' + `[CERT HTTP HATA] Bağlantı Koptu: ${err.message}` + '\x1b[0m');
      reject(new Error(`sertifika sunucusuna erişilemedi: ${err.message}`));
    });
    
    if (payload) req.write(payload);
    req.end();
  });
}

module.exports = { CertificateManager };
