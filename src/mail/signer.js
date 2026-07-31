'use strict';

const dkim = require('./dkim');

/**
 * İmzalama hizmeti: alan adı başına DKIM anahtarı, adres başına S/MIME
 * sertifikası.
 *
 * Anahtarlar kasadan gelir ve önbelleklenir. Önbellek olmadan her giden ileti
 * için bir kasa okuması (ve uzak veritabanında bir tur) gerekirdi; toplu
 * gönderimde bu tek başına darboğaz olur. Önbellek süreli: bir anahtar
 * döndürüldüğünde en fazla bu süre kadar eski anahtar kullanılır.
 */
class MailSigner {
  constructor({ vault, certificates, config, logger }) {
    this.vault = vault;
    this.certificates = certificates;
    this.config = config;
    this.logger = logger;
    this.dkimCache = new Map(); // domain -> { privateKeyPem, algorithm, selector, at }
    this.smimeCache = new Map(); // address -> { certPem, privateKeyPem, chainPem, at }
    this.cacheTtlMs = 5 * 60 * 1000;
  }

  static dkimSecretName(domain, selector) { return `dkim/${domain}/${selector}`; }

  /**
   * Alan adının DKIM anahtarını döndürür; yoksa ÜRETİR.
   *
   * Üretmek burada yapılır çünkü alternatif, ilk gönderimde imzasız posta
   * göndermektir — ve imzasız gönderilen ilk postalar alan adının itibarını
   * en kırılgan olduğu anda zedeler.
   */
  async getDkimKey(domain) {
    const domainConfig = this.config.domainConfig(domain);
    if (!domainConfig) return null;
    const selector = domainConfig.dkimSelector;

    const cached = this.dkimCache.get(domain);
    if (cached && Date.now() - cached.at < this.cacheTtlMs) return cached;

    const name = MailSigner.dkimSecretName(domain, selector);
    let secret = await this.vault.get('dkim-key', name);

    if (!secret) {
      const generated = dkim.generateKeyPair({ algorithm: 'rsa', modulusLength: 2048 });
      await this.vault.put({
        kind: 'dkim-key',
        name,
        value: generated.privateKeyPem,
        contentType: 'application/x-pem-file',
        meta: {
          domain,
          selector,
          algorithm: generated.algorithm,
          dnsRecord: dkim.dnsRecordValue(generated),
        },
      });
      secret = await this.vault.get('dkim-key', name);
      this.logger.warn({
        domain,
        selector,
        dnsName: `${selector}._domainkey.${domain}`,
        msg: 'DKIM anahtarı üretildi — DNS TXT kaydı yayımlanana kadar imzalar doğrulanamaz',
      });
    }

    const privateKeyPem = secret.value.toString('utf8');
    const entry = {
      privateKeyPem,
      algorithm: dkim.algorithmForKey(privateKeyPem),
      selector,
      domain,
      version: secret.version,
      at: Date.now(),
    };
    this.dkimCache.set(domain, entry);
    return entry;
  }

  /** Yayımlanması gereken DNS kaydı — durum API'si ve DNS denetimi kullanır. */
  async dkimDnsRecord(domain) {
    const key = await this.getDkimKey(domain);
    if (!key) return null;
    return {
      name: `${key.selector}._domainkey.${domain}`,
      type: 'TXT',
      value: dkim.dnsRecordFromPrivateKey(key.privateKeyPem),
    };
  }

  /**
   * Ham iletiyi DKIM ile imzalar. İmza, GÖNDERİLECEK baytlar üzerinden
   * hesaplanır ve başlık iletinin başına eklenir.
   */
  async signDkim(rawMessage, { fromAddress, domain = null }) {
    const signingDomain = domain || String(fromAddress || '').split('@')[1];
    if (!signingDomain) return { rawMessage, signed: false, reason: 'alan adı belirlenemedi' };

    const key = await this.getDkimKey(signingDomain);
    if (!key) {
      // Bizim olmayan bir alan adına DKIM imzası atmak mümkün değil (anahtar
      // yok) ve atmaya çalışmak yanlış: imza atılamadı bilgisi kayda yazılır.
      return { rawMessage, signed: false, reason: `${signingDomain} bu sunucunun alan adı değil` };
    }

    try {
      const result = dkim.signMessage({
        rawMessage,
        domain: signingDomain,
        selector: key.selector,
        privateKeyPem: key.privateKeyPem,
        algorithm: key.algorithm,
      });
      return {
        rawMessage: result.rawMessage,
        signed: true,
        domain: signingDomain,
        selector: key.selector,
        header: result.signatureHeader,
      };
    } catch (err) {
      // İmzalama hatası iletiyi DÜŞÜRMEZ: imzasız gönderim, hiç
      // gönderilmemekten iyidir. Ama sessiz de kalmaz.
      this.logger.error({ domain: signingDomain, error: err.message, msg: 'DKIM imzalama başarısız' });
      return { rawMessage, signed: false, reason: err.message };
    }
  }

  /** Adresin S/MIME imzalama çifti (sertifika + özel anahtar). */
  async getSmimeMaterial(address) {
    const addr = String(address || '').toLowerCase();
    const cached = this.smimeCache.get(addr);
    if (cached && Date.now() - cached.at < this.cacheTtlMs) return cached.material;

    const pair = await this.certificates.getSigningPair('smime', addr);
    if (!pair) {
      this.smimeCache.set(addr, { material: null, at: Date.now() });
      return null;
    }
    const material = {
      certPem: pair.certPem,
      privateKeyPem: pair.privateKeyPem,
      chainPem: pair.chainPem || '',
      notAfter: pair.notAfter,
      serialHex: pair.serialHex,
    };
    this.smimeCache.set(addr, { material, at: Date.now() });
    return material;
  }

  invalidate(address = null, domain = null) {
    if (address) this.smimeCache.delete(String(address).toLowerCase());
    if (domain) this.dkimCache.delete(String(domain).toLowerCase());
    if (!address && !domain) { this.smimeCache.clear(); this.dkimCache.clear(); }
  }
}

module.exports = { MailSigner };
