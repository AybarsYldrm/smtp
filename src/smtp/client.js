'use strict';

const dns = require('node:dns').promises;

const { deliver, deliverToHost, DeliveryError } = require('./delivery');
const { buildMessage } = require('../mail/mime-builder');
const dkim = require('../mail/dkim');
const { normalizeAddress, splitAddress } = require('../util/encoding');
const log = require('../util/log');

/**
 * Bağımsız SMTP istemcisi.
 *
 * Bu sınıf sunucunun geri kalanından BAĞIMSIZ: veritabanı, kasa,
 * yapılandırma ya da kimlik sağlayıcı istemiyor. `@fitfak/smtp`'yi yalnızca
 * posta göndermek için kuran biri sadece bunu kullanabilir.
 *
 * İki kip, ve hangisinin seçileceği açıkça belirtiliyor:
 *
 *   - DOĞRUDAN (öntanımlı): alıcının MX kayıtları çözülür ve iletiye
 *     doğrudan onun sunucusuna gidilir. Kendi alan adınızdan gönderirken
 *     doğru olan bu — aradaki her atlama, imzanızın ve itibarınızın
 *     başkasının eline geçmesi demek. DKIM anahtarınız varsa iletiyi
 *     imzalar.
 *   - AKTARICI (`host` verilirse): bir submission sunucusuna (587/465)
 *     kimlik doğrulayarak bağlanır. Sağlayıcınızın sunucusundan gönderirken
 *     kullanılır; imzayı o sunucu atar.
 *
 * `sendMail` bir alıcı için değil, ALICI BAŞINA sonuç döndürür. Tek bir
 * "başarılı/başarısız" değeri, üç alıcının ikisine ulaşan bir iletiyi
 * anlatamıyor — ve ulaşmayan alıcının hangisi olduğu tam olarak sorulan şey.
 *
 * @example Doğrudan teslimat, DKIM imzalı
 *   const client = new SmtpClient({
 *     heloName: 'mail.ornek.com',
 *     dkim: { domain: 'ornek.com', selector: 'mail', privateKeyPem: key },
 *   });
 *   await client.sendMail({
 *     from: 'bilgi@ornek.com',
 *     to: ['ali@example.com'],
 *     subject: 'Merhaba',
 *     text: 'Deneme',
 *   });
 *
 * @example Aktarıcı üzerinden
 *   const client = new SmtpClient({
 *     host: 'mail.fitfak.net', port: 587,
 *     auth: { username: 'bilgi@fitfak.net', password: '…' },
 *   });
 */
class SmtpClient {
  /**
   * @param {object} [options]
   * @param {string} [options.host]         aktarıcı sunucu (verilmezse MX'e doğrudan)
   * @param {number} [options.port]         587 (STARTTLS) | 465 (örtük TLS) | 25
   * @param {object} [options.auth]         { username, password } — yalnızca aktarıcı kipinde
   * @param {string} [options.heloName]     EHLO adı; öntanımlı gönderenin alan adı
   * @param {boolean} [options.requireTls]  TLS kurulamazsa gönderme
   * @param {object} [options.dkim]         { domain, selector, privateKeyPem }
   * @param {string} [options.localAddress] çıkış IP'si (PTR kaydı olan adres)
   */
  constructor(options = {}) {
    this.host = options.host || null;
    this.port = Number(options.port) || (this.host ? 587 : 25);
    this.auth = options.auth || null;
    this.heloName = options.heloName || null;
    // Aktarıcıya giderken TLS varsayılan olarak ZORUNLU: orada bir parola
    // taşınıyor. MX teslimatında fırsatçı, çünkü seçenek düz metin.
    this.requireTls = options.requireTls != null ? !!options.requireTls : !!this.host;
    this.implicitTls = options.implicitTls != null ? !!options.implicitTls : this.port === 465;
    this.dkim = options.dkim || null;
    this.localAddress = options.localAddress || null;
    this.timeouts = options.timeouts || {};
    this.resolver = options.resolver || dns;
    this.logger = options.logger || log.child('smtp-client');

    if (this.auth && !this.host) {
      throw new Error('[smtp-client] kimlik doğrulama yalnızca aktarıcı kipinde geçerli (`host` verin)');
    }
  }

  /**
   * İleti oluşturur, imzalar ve gönderir.
   *
   * @returns {Promise<{messageId, accepted: string[], rejected: Array, dkimSigned: boolean, sizeBytes: number}>}
   */
  async sendMail({
    from, to = [], cc = [], bcc = [], subject = '', text = '', html = '',
    attachments = [], headers = {}, replyTo = null, inReplyTo = '', references = [],
    envelopeFrom = null, priority = null,
  }) {
    const built = buildMessage({
      from: typeof from === 'string' ? { address: normalizeAddress(from) } : from,
      to, cc, bcc, subject, text, html, attachments,
      inReplyTo, references, priority,
      extraHeaders: { ...(replyTo ? { 'Reply-To': replyTo } : {}), ...headers },
    });
    return this.sendRaw({
      raw: built.raw,
      envelopeFrom: envelopeFrom || built.envelope.from,
      recipients: built.envelope.to,
      messageId: built.messageId,
    });
  }

  /**
   * Hazır bir ham iletiyi gönderir.
   *
   * İmza TELE VERİLECEK baytlar üzerinden atılır: başlıkları sonradan
   * yeniden yazan hiçbir katman yok. Bu kural olmadan imza atılsa bile
   * doğrulama başarısız olur, çünkü doğrulayanın gördüğü baytlar
   * imzalananla aynı olmaz.
   */
  async sendRaw({ raw, envelopeFrom, recipients, messageId = '' }) {
    const targets = [].concat(recipients).map(normalizeAddress).filter((r) => r && r.includes('@'));
    if (!targets.length) throw new Error('[smtp-client] geçerli alıcı yok');

    const sender = normalizeAddress(envelopeFrom || '');
    let outgoing = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
    let dkimSigned = false;

    if (this.dkim && this.dkim.privateKeyPem) {
      try {
        const signed = dkim.signMessage({
          rawMessage: outgoing,
          domain: this.dkim.domain || splitAddress(sender).domain,
          selector: this.dkim.selector || 'mail',
          privateKeyPem: this.dkim.privateKeyPem,
          algorithm: this.dkim.algorithm || dkim.algorithmForKey(this.dkim.privateKeyPem),
        });
        outgoing = signed.rawMessage;
        dkimSigned = true;
      } catch (err) {
        // İmzasız gönderim, hiç göndermemekten iyidir — ama sessiz kalmaz.
        this.logger.warn({ error: err.message, msg: 'DKIM imzalanamadı, imzasız gönderiliyor' });
      }
    }

    const helo = this.heloName || splitAddress(sender).domain || 'localhost';
    const accepted = [];
    const rejected = [];

    for (const recipient of targets) {
      try {
        const result = this.host
          ? await deliverToHost({
            host: this.host,
            port: this.port,
            rawMessage: outgoing,
            envelopeFrom: sender,
            recipient,
            heloName: helo,
            logger: this.logger,
            timeouts: { ...this.timeouts },
            localAddress: this.localAddress,
            requireTls: this.requireTls,
            dsnRequested: false,
            auth: this.auth,
            implicitTls: this.implicitTls,
          })
          : await deliver({
            rawMessage: outgoing,
            envelopeFrom: sender,
            recipient,
            heloName: helo,
            resolver: this.resolver,
            logger: this.logger,
            timeouts: this.timeouts,
            localAddress: this.localAddress,
            requireTls: this.requireTls,
            port: this.port,
          });

        accepted.push(recipient);
        this.logger.info({
          to: recipient, mx: result.mx || this.host, code: result.code,
          tls: result.tlsUsed ? (result.tlsVerified ? 'doğrulanmış' : 'doğrulanmamış') : 'yok',
          msg: 'teslim edildi',
        });
      } catch (err) {
        rejected.push({
          recipient,
          error: err.message,
          code: err.code || 0,
          permanent: !!err.permanent,
          stage: err.stage || '',
        });
        this.logger.warn({
          to: recipient, code: err.code, permanent: !!err.permanent, error: err.message,
          msg: 'teslim edilemedi',
        });
      }
    }

    return {
      messageId,
      accepted,
      rejected,
      dkimSigned,
      sizeBytes: outgoing.length,
    };
  }

  /**
   * Bir adresin teslim edilebilir görünüp görünmediğini bakar — ileti
   * GÖNDERMEDEN.
   *
   * Sonucu "adres var" diye okumayın: birçok sunucu her alıcıya 250 der
   * (adres numaralandırmayı engellemek için, biz de öyle yapıyoruz). Bu
   * yalnızca "alan adının MX'i var ve konuşuyor" sorusunu cevaplıyor.
   */
  async probe(address) {
    const { domain } = splitAddress(normalizeAddress(address));
    if (!domain) return { ok: false, reason: 'geçersiz adres' };
    try {
      const { resolveMailExchangers } = require('./delivery');
      const exchangers = await resolveMailExchangers(domain, { resolver: this.resolver, logger: this.logger });
      return { ok: exchangers.length > 0, domain, exchangers };
    } catch (err) {
      return { ok: false, domain, reason: err.message };
    }
  }
}

module.exports = { SmtpClient, DeliveryError };
