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
  /**
   * Yeni bir DKIM anahtarı üretip kasaya yazar ve geri okur.
   * Kasa yazması doğrulanır: yazılamayan bir anahtarla dönmek, çağıranın
   * `null.value` üzerinde patlaması demekti.
   */
  async _createDkimKey(domain, selector, name) {
    const generated = dkim.generateKeyPair({ algorithm: 'rsa', modulusLength: 2048 });
    const dnsRecord = dkim.dnsRecordValue(generated);
    await this.vault.put({
      kind: 'dkim-key',
      name,
      value: generated.privateKeyPem,
      contentType: 'application/x-pem-file',
      meta: { domain, selector, algorithm: generated.algorithm, dnsRecord },
    });
    const secret = await this.vault.get('dkim-key', name);
    if (!secret) {
      throw new Error(`[signer] DKIM anahtarı kasaya yazıldı ama geri okunamadı: ${domain}`);
    }
    this.logger.warn({
      domain,
      selector,
      dnsName: `${selector}._domainkey.${domain}`,
      dnsValue: dnsRecord,
      msg: 'DKIM anahtarı üretildi — bu TXT kaydı yayımlanana kadar imzalar doğrulanamaz',
    });
    return secret;
  }

  /**
   * Alan adının DKIM anahtarını döndürür; yoksa ÜRETİR.
   *
   * ── AÇILAMAYAN ANAHTAR ───────────────────────────────────────────────
   * Kasadaki anahtar açılamıyorsa (kasa sırrı değişmiş, kayıt bozulmuş)
   * eskiden buradan bir istisna çıkıyor ve GİDEN HER POSTA 500 ile
   * düşüyordu — imzalanamayan bir anahtar yüzünden hiç posta gitmiyordu.
   *
   * Açılamayan bir anahtar zaten KULLANILAMAZ: onunla imza atılamaz,
   * doğrulanamaz, döndürülemez. Onu tutmanın tek etkisi, postayı
   * durdurmaktır. Bu yüzden kayıt "ele geçmiş" olarak işaretlenip yerine
   * yenisi üretiliyor ve durum GÜRÜLTÜLÜ biçimde kayda geçiyor: DNS'teki
   * TXT kaydının güncellenmesi gerekiyor ve bu yapılana kadar imzalar
   * doğrulanmayacak.
   */
  async getDkimKey(domain) {
    const domainConfig = this.config.domainConfig(domain);
    if (!domainConfig) return null;
    const selector = domainConfig.dkimSelector;

    const cached = this.dkimCache.get(domain);
    if (cached && Date.now() - cached.at < this.cacheTtlMs) return cached;

    const name = MailSigner.dkimSecretName(domain, selector);
    let secret = null;
    try {
      secret = await this.vault.get('dkim-key', name);
    } catch (err) {
      this.logger.error({
        domain, selector, code: err.code, error: err.message,
        msg: 'kasadaki DKIM anahtarı açılamadı — yerine yenisi üretiliyor, DNS kaydı GÜNCELLENMELİ',
      });
      await this._retireUnreadableDkimKey(name, err.message);
      secret = null;
    }

    if (!secret) secret = await this._createDkimKey(domain, selector, name);

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

  /** Açılamayan sürümleri işaretler; `get` bir daha onlara dönmesin. */
  async _retireUnreadableDkimKey(name, reason) {
    try {
      const rows = (await this.vault.collection.find('name', name))
        .filter((r) => r.kind === 'dkim-key' && r.status !== 'compromised');
      for (const row of rows) {
        await this.vault.markCompromised('dkim-key', name, Number(row.version), `unreadable: ${reason}`);
      }
    } catch (err) {
      this.logger.warn({ error: err.message, msg: 'açılamayan DKIM anahtarı işaretlenemedi' });
    }
  }

  /**
   * Kasadaki DKIM anahtarına BAKAR — yoksa üretmez.
   *
   * `getDkimKey` ile arasındaki fark, "anahtar var mı?" sorusunu sorabilmenin
   * tek yolu olması. Üreten bir okuma ile bu soru sorulamıyor: çağırmak
   * cevabı değiştiriyor, ve her çağıran (durum ekranı, DNS denetimi, açılış
   * denetimi) sırf bakmak isterken yeni bir anahtar yaratmış oluyordu.
   *
   * @returns {{present: boolean, unreadable?: boolean, ...}}
   */
  async peekDkimKey(domain) {
    const domainConfig = this.config.domainConfig(domain);
    if (!domainConfig) return { present: false, reason: 'not-a-local-domain' };
    const selector = domainConfig.dkimSelector;
    const name = MailSigner.dkimSecretName(domain, selector);

    let secret = null;
    try {
      secret = await this.vault.get('dkim-key', name);
    } catch (err) {
      return { present: false, unreadable: true, selector, domain, reason: err.message };
    }
    if (!secret) return { present: false, selector, domain, reason: 'vault-empty' };

    const privateKeyPem = secret.value.toString('utf8');
    return {
      present: true,
      selector,
      domain,
      version: secret.version,
      privateKeyPem,
      dnsName: `${selector}._domainkey.${domain}`,
      dnsValue: dkim.dnsRecordFromPrivateKey(privateKeyPem),
    };
  }

  /**
   * Yayımlanması gereken DNS kaydı — durum API'si ve DNS denetimi kullanır.
   *
   * `create` ÖNTANIMLI OLARAK KAPALI. Açık olduğu sürece DNS denetimi, sırf
   * "beklenen kayıtlar neler" listesini kurarken kasaya yeni bir anahtar
   * yazıyordu; denetim salt okunur olduğunu söylerken yan etkisi anahtar
   * üretmekti ve yayımdaki TXT kaydı o anda geçersizleşiyordu.
   */
  async dkimDnsRecord(domain, { create = false } = {}) {
    const key = create ? await this.getDkimKey(domain) : await this.peekDkimKey(domain);
    if (!key || (!create && !key.present)) return null;
    const selector = key.selector;
    return {
      name: `${selector}._domainkey.${domain}`,
      type: 'TXT',
      value: dkim.dnsRecordFromPrivateKey(key.privateKeyPem),
    };
  }

  /**
   * Açılış denetimi: kasadaki anahtar ile YAYINDAKİ TXT kaydı aynı mı?
   *
   * Sıra bilerek böyle: ÖNCE kasa, SONRA DNS.
   *
   *   - Kasada anahtar yoksa, yayındaki kayıt (varsa) artık bize ait olmayan
   *     bir anahtarı duyuruyor demektir. O hâlde imzalarımız doğrulanamaz ve
   *     bunu ilk gönderimde değil, açılışta bilmek gerekir.
   *   - Kasada anahtar varsa ama DNS başka bir `p=` gösteriyorsa, kayıt eskide
   *     kalmış demektir (anahtar yenilenmiş, TXT güncellenmemiş). Sonuç aynı:
   *     giden imzalar doğrulanmaz.
   *
   * Hiçbir şey ÜRETMEZ ve hiçbir şey YAZMAZ; yalnızca durumu bildirir.
   */
  async verifyDkimPublication(domain, { resolver = null } = {}) {
    const peek = await this.peekDkimKey(domain);
    const result = {
      domain,
      selector: peek.selector || null,
      vault: peek.present ? 'present' : (peek.unreadable ? 'unreadable' : 'missing'),
      dns: 'unknown',
      match: false,
      published: [],
      expected: peek.present ? peek.dnsValue : null,
    };

    const dnsName = peek.dnsName || `${peek.selector || 'mail'}._domainkey.${domain}`;
    let published = [];
    try {
      const resolveTxt = resolver || require('node:dns').promises.resolveTxt;
      const rows = await resolveTxt(dnsName);
      published = rows.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
    } catch (err) {
      result.dns = err.code === 'ENOTFOUND' || err.code === 'ENODATA' ? 'absent' : 'lookup-failed';
      result.dnsError = err.code || err.message;
      return result;
    }

    result.published = published;
    result.dns = published.length ? 'present' : 'absent';
    if (peek.present && published.length) {
      const wanted = publicKeyTag(peek.dnsValue);
      result.match = published.some((value) => wanted && publicKeyTag(value) === wanted);
    }
    return result;
  }

  /**
   * Ham iletiyi DKIM ile imzalar. İmza, GÖNDERİLECEK baytlar üzerinden
   * hesaplanır ve başlık iletinin başına eklenir.
   */
  async signDkim(rawMessage, { fromAddress, domain = null }) {
    const signingDomain = domain || String(fromAddress || '').split('@')[1];
    if (!signingDomain) return { rawMessage, signed: false, reason: 'alan adı belirlenemedi' };

    let key;
    try {
      key = await this.getDkimKey(signingDomain);
    } catch (err) {
      // Anahtar alınamadı (kasa erişilemiyor ya da yazılamıyor). İMZASIZ
      // GÖNDERMEK, HİÇ GÖNDERMEMEKTEN İYİDİR: kendi alan adımızdan çıkan
      // posta SPF ile zaten hizalı ve DMARC'ı geçebilir. Ama sessiz kalmaz.
      this.logger.error({
        domain: signingDomain, code: err.code, error: err.message,
        msg: 'DKIM anahtarı alınamadı — ileti İMZASIZ gönderiliyor',
      });
      return { rawMessage, signed: false, reason: `DKIM anahtarı alınamadı: ${err.message}` };
    }
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

/**
 * DKIM TXT kaydından yalnızca `p=` (açık anahtar) değerini çıkarır.
 *
 * Karşılaştırma metin olarak yapılamaz: aynı anahtar `v=`, `k=`, `t=` ve
 * `h=` etiketleri farklı sırayla ya da fazladan boşlukla yayımlanmış
 * olabilir, ve DNS sağlayıcıları uzun TXT değerlerini parçalara bölüp geri
 * birleştirirken boşluk ekleyebiliyor. Anlamlı olan tek alan `p=`.
 */
function publicKeyTag(record) {
  const match = /(?:^|;)\s*p\s*=\s*([^;]*)/i.exec(String(record || ''));
  if (!match) return null;
  const value = match[1].replace(/\s+/g, '');
  return value || null;
}

module.exports = { MailSigner, publicKeyTag };
