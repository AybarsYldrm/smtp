'use strict';

const dns = require('node:dns').promises;

const dkim = require('./dkim');
const spf = require('./spf');
const dmarc = require('./dmarc');
const { parseMessage } = require('./mime-parser');
const { buildMessage, buildForward, buildDsn } = require('./mime-builder');
const { normalizeAddress, splitAddress, sha256Hex } = require('../util/encoding');

/**
 * Posta hattı: gelen iletinin kabulden saklanmaya, giden iletinin
 * oluşturulmaktan kuyruğa kadarki yolu.
 *
 * Bu dosya "kim ne gönderebilir" kararının verildiği yer ve iki karar burada
 * bilinçli olarak katı:
 *
 *   1. GÖNDEREN YETKİSİ. Kimlik doğrulaması yapmış bir kullanıcı, yalnızca
 *      erişebildiği kutuların adresleriyle gönderebilir. Aksi hâlde bir
 *      kullanıcı, aynı sunucudaki başka bir kutunun adresini From'a yazıp
 *      onun adına posta gönderebilirdi — ve bu posta DKIM ile imzalanıp
 *      alıcıya tam yetkili görünürdü.
 *
 *   2. AKTARMA (RELAY) KAPALI. 25 portu yalnızca yerel alanlara teslim eder.
 *      Açık aktarma, alan adının itibarını saatler içinde bitirir.
 */
// RFC 5321 §6.3 en az 100 önerir; biz daha erken duruyoruz çünkü kendi
// alanlarımız arasında bu kadar sıçrama meşru bir yol değil.
const MAX_RECEIVED_HOPS = 25;

/** Ham iletideki Received başlıklarını sayar (başlık bloğuyla sınırlı). */
function countReceivedHeaders(raw) {
  const text = (Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw))).toString('latin1');
  const end = text.search(/\r?\n\r?\n/);
  const headerBlock = end === -1 ? text : text.slice(0, end);
  const matches = headerBlock.match(/^received:/gim);
  return matches ? matches.length : 0;
}

class MailPipeline {
  constructor({ config, logger, stores, signer, queue = null, notifier = null, realtime = null }) {
    this.config = config;
    this.logger = logger;
    this.stores = stores;
    this.signer = signer;
    this.queue = queue;
    this.notifier = notifier;
    this.realtime = realtime;
    this.resolver = dns;
  }

  /* ── SMTP kancaları ───────────────────────────────────────── */

  /** SMTP AUTH: kullanıcı adı + parola -> posta kutusu. */
  async authenticate({ username, password, ip }) {
    const result = await this.stores.mailboxes.verifySmtpCredential(username, password, { ip });
    if (!result.ok) return { ok: false, reason: result.reason };
    return { ok: true, username: normalizeAddress(username), mailbox: result.mailbox };
  }

  /** RCPT TO denetimi. */
  async validateRecipient({ address, session }) {
    const { domain } = splitAddress(address);
    const isLocalDomain = this.config.isLocalDomain(domain);

    if (session.mode === 'mx') {
      if (!isLocalDomain) {
        // Açık aktarma reddi. Kimlik doğrulamamış bir istemci bizden başka
        // alanlara posta taşımamızı isteyemez.
        return { accept: false, reply: '550 5.7.1 Aktarma yasak' };
      }
      const resolved = await this.stores.mailboxes.resolveDelivery(address);
      if (!resolved.mailbox) {
        return { accept: false, reply: '550 5.1.1 Böyle bir posta kutusu yok' };
      }
      if (resolved.reason === 'over_quota') {
        return { accept: false, reply: '452 4.2.2 Posta kutusu dolu' };
      }
      if (resolved.reason !== 'ok' && resolved.reason !== 'catchall') {
        return { accept: false, reply: '550 5.2.1 Posta kutusu devre dışı' };
      }
      return { accept: true, local: true, mailbox: resolved.mailbox };
    }

    // Submission: kimlik doğrulanmış kullanıcı her yere gönderebilir.
    if (!session.authenticated) return { accept: false, reply: '530 5.7.0 Kimlik doğrulama gerekli' };
    if (isLocalDomain) {
      const resolved = await this.stores.mailboxes.resolveDelivery(address);
      return { accept: true, local: !!resolved.mailbox, mailbox: resolved.mailbox };
    }
    return { accept: true, local: false };
  }

  /** DATA sonrası: iletiyi işle. */
  async handleMessage({ raw, envelope }) {
    if (envelope.mode === 'mx') return this.handleInbound({ raw, envelope });
    return this.handleSubmission({ raw, envelope });
  }

  /* ── gelen posta ──────────────────────────────────────────── */

  async handleInbound({ raw, envelope }) {
    const parsed = parseMessage(raw, { limits: this.config.limits });
    const auth = await this.evaluateAuthentication({ raw, parsed, envelope });

    // DMARC "reject" politikası olan bir alandan gelen ve hizalaması olmayan
    // ileti SMTP düzeyinde reddedilir. Kabul edip çöp klasörüne koymak da bir
    // seçenek ama alan sahibi açıkça "reddet" demişse ona uymak doğru olan;
    // ayrıca kabul edilen her ileti, bizim adımıza bir geri dönüş üretme
    // sorumluluğu doğurur.
    if (this.config.smtp.enforceDmarc && auth.dmarc
      && auth.dmarc.result === 'fail' && auth.dmarc.disposition === 'reject') {
      this.logger.warn({
        from: parsed.from.address, remoteIp: envelope.remoteIp,
        spf: auth.spf && auth.spf.result, dkim: auth.dkim && auth.dkim.overall,
        msg: 'DMARC reddi',
      });
      return { reply: '550 5.7.1 DMARC politikası gereği reddedildi' };
    }

    const spamScore = this.scoreSpam({ parsed, auth, envelope });
    const results = [];

    for (const recipient of envelope.recipients) {
      try {
        const stored = await this.deliverLocal({ raw, parsed, envelope, recipient, auth, spamScore });
        results.push({ recipient: recipient.address, ok: true, ref: stored ? stored.ref : null });
      } catch (err) {
        this.logger.error({
          recipient: recipient.address, error: err.message, stack: err.stack,
          msg: 'yerel teslimat başarısız',
        });
        results.push({ recipient: recipient.address, ok: false, error: err.message });
      }
    }

    const failed = results.filter((r) => !r.ok);
    if (failed.length === results.length) return { reply: '451 4.3.0 Geçici saklama hatası' };
    if (failed.length) {
      // Kısmi başarı: SMTP tek yanıt verir. Bir kısmı saklandıysa 250 dönmek
      // zorundayız (yoksa gönderen hepsini yeniden gönderir ve kopya oluşur);
      // başarısızlar kayda yazılır.
      this.logger.warn({ failed: failed.length, total: results.length, msg: 'kısmi teslimat' });
    }
    return { reply: `250 2.0.0 Kabul edildi (${results.filter((r) => r.ok).length} alıcı)` };
  }

  /**
   * SPF + DKIM + DMARC + S/MIME değerlendirmesi.
   *
   * Sonuçlar her zaman AYRINTILI kaydedilir. "DKIM fail" tek başına
   * eyleme dönüşmüyor: gövde özeti mi tutmadı, DNS'te anahtar mı yok,
   * yoksa aradaki bir sunucu başlık mı değiştirdi — üçü farklı sorunlar.
   * Bu satır olmadan, gelen bir iletinin neden başarısız olduğu ancak
   * iletiyi tekrar üretip elle denenerek anlaşılabiliyordu.
   */
  async evaluateAuthentication({ raw, parsed, envelope }) {
    if (!this.config.smtp.inboundChecks) return { enabled: false };

    const out = { enabled: true, spf: null, dkim: null, dmarc: null, smime: null, iprev: null };
    const done = this.logger.timer('gelen doğrulama');

    const [spfResult, dkimResult] = await Promise.all([
      spf.check({
        ip: envelope.remoteIp,
        sender: envelope.mailFrom || '',
        heloDomain: envelope.heloName || '',
        resolver: this.resolver,
      }).catch((err) => ({ result: 'temperror', domain: '', explanation: err.message })),
      dkim.verifyMessage(raw, { resolver: this.resolver, diagnostics: true })
        .catch((err) => ({ results: [], overall: 'temperror', reason: err.message })),
    ]);
    out.spf = spfResult;
    out.dkim = dkimResult;

    const fromDomain = String(parsed.from.address || '').split('@')[1] || '';
    if (fromDomain) {
      out.dmarc = await dmarc.evaluate({
        fromDomain, spf: spfResult, dkim: dkimResult, resolver: this.resolver,
      }).catch((err) => ({ result: 'temperror', disposition: 'none', reason: err.message, alignment: {} }));
    } else {
      this.logger.warn({
        remoteIp: envelope.remoteIp, mailFrom: envelope.mailFrom,
        msg: 'From başlığı çözümlenemedi — DMARC değerlendirilemiyor',
      });
    }

    // Başarısız her doğrulama, NEDENİYLE birlikte kayda geçer.
    if (spfResult.result !== 'pass') {
      this.logger.debug({
        remoteIp: envelope.remoteIp,
        mailFrom: envelope.mailFrom,
        helo: envelope.heloName,
        spf: spfResult.result,
        spfDomain: spfResult.domain,
        mechanism: spfResult.mechanism,
        lookups: spfResult.lookups,
        explanation: spfResult.explanation,
        msg: 'SPF geçmedi',
      });
    }
    for (const signature of dkimResult.results || []) {
      if (signature.result === 'pass') continue;
      this.logger.debug({
        d: signature.domain,
        s: signature.selector,
        a: signature.algorithm,
        result: signature.result,
        bodyHashMatch: signature.bodyHashMatch,
        reason: signature.reason,
        detail: signature.detail || undefined,
        msg: 'DKIM imzası geçmedi',
      });
    }
    if (out.dmarc && out.dmarc.result !== 'pass') {
      this.logger.debug({
        fromDomain,
        dmarc: out.dmarc.result,
        disposition: out.dmarc.disposition,
        alignment: out.dmarc.alignment,
        reason: out.dmarc.reason,
        msg: 'DMARC geçmedi',
      });
    }
    done({
      spf: spfResult.result,
      dkim: dkimResult.overall,
      dmarc: out.dmarc ? out.dmarc.result : 'skip',
    });

    if (parsed.signedContent && parsed.signaturePart) {
      try {
        const { verifyMessageSignature } = require('../certs/smime');
        out.smime = verifyMessageSignature(parsed, {
          trustedCaPems: await this.trustedCaPems(),
          expectedAddress: parsed.from.address || null,
        });
      } catch (err) {
        out.smime = { status: 'signed-invalid', reason: err.message };
      }
    } else if (parsed.encrypted) {
      out.smime = { status: 'encrypted' };
    }

    return out;
  }

  async trustedCaPems() {
    if (this._trustedCaCache && Date.now() - this._trustedCaCache.at < 300_000) {
      return this._trustedCaCache.pems;
    }
    const pems = [];
    try {
      const cas = await this.stores.certificates.listByUsage('ca');
      for (const ca of cas) if (ca.certPem) pems.push(ca.certPem);
    } catch { /* kasa erişilemezse boş liste: doğrulama "untrusted" der */ }
    this._trustedCaCache = { pems, at: Date.now() };
    return pems;
  }

  /**
   * Basit istenmeyen posta puanı. Amaç sınıflandırıcı olmak değil, doğrulama
   * sonuçlarını tek bir sayıya indirip klasörleme kararı verebilmek.
   */
  scoreSpam({ parsed, auth, envelope }) {
    let score = 0;
    if (!auth.enabled) return 0;
    if (auth.spf) {
      if (auth.spf.result === 'fail') score += 3;
      else if (auth.spf.result === 'softfail') score += 1;
      else if (auth.spf.result === 'none') score += 1;
    }
    if (auth.dkim && auth.dkim.overall === 'fail') score += 2;
    if (auth.dkim && auth.dkim.overall === 'none') score += 1;
    if (auth.dmarc) {
      if (auth.dmarc.result === 'fail') score += 3;
      if (auth.dmarc.disposition === 'quarantine') score += 2;
    }
    if (!parsed.messageId) score += 1;
    if (!parsed.from.address) score += 3;
    // Zarf göndereni ile başlık göndereni farklı: tek başına şüphe değil
    // (posta listeleri böyle çalışır) ama diğer işaretlerle birleşince anlamlı.
    if (envelope.mailFrom && parsed.from.address
      && normalizeAddress(envelope.mailFrom) !== normalizeAddress(parsed.from.address)) score += 1;
    if (!parsed.text && !parsed.html) score += 2;
    if (parsed.subject && /^\s*$/.test(parsed.subject)) score += 1;
    return score;
  }

  /** Bir alıcıya yerel teslimat: saklama + yönlendirme + bildirim. */
  async deliverLocal({ raw, parsed, envelope, recipient, auth, spamScore }) {
    const mailbox = recipient.mailbox
      || (await this.stores.mailboxes.resolveDelivery(recipient.address)).mailbox;
    if (!mailbox) throw new Error(`posta kutusu çözümlenemedi: ${recipient.address}`);

    // Aynı Message-ID aynı kutuya iki kez yazılmaz: gönderen tarafın yeniden
    // denemesi (bizim geçici hatamız yüzünden) kopya oluşturmamalı.
    if (parsed.messageId && await this.stores.messages.existsByMessageId(mailbox.ref, parsed.messageId)) {
      this.logger.info({ mailbox: mailbox.address, messageId: parsed.messageId, msg: 'kopya ileti atlandı' });
      return null;
    }

    const folder = this.chooseFolder({ mailbox, parsed, auth, spamScore });
    const withReceived = this.prependReceivedHeaders({ raw, envelope, recipient, auth });

    const stored = await this.stores.messages.store({
      mailbox,
      parsed,
      rawBuffer: withReceived,
      folder,
      envelopeFrom: envelope.mailFrom,
      envelopeTo: recipient.address,
      remoteIp: envelope.remoteIp,
      authResults: auth.enabled ? {
        spf: auth.spf ? {
          result: auth.spf.result,
          domain: auth.spf.domain,
          mechanism: auth.spf.mechanism || null,
          explanation: auth.spf.explanation || '',
        } : null,
        dkim: auth.dkim ? {
          overall: auth.dkim.overall,
          reason: auth.dkim.reason || null,
          signatures: auth.dkim.results,
        } : null,
        dmarc: auth.dmarc ? {
          result: auth.dmarc.result,
          disposition: auth.dmarc.disposition,
          alignment: auth.dmarc.alignment,
          reason: auth.dmarc.reason || null,
          policy: auth.dmarc.policy
            ? { p: auth.dmarc.policy.effectivePolicy || auth.dmarc.policy.policy, foundAt: auth.dmarc.policy.foundAt }
            : null,
        } : null,
      } : null,
      smime: auth.smime,
      spamScore,
    });

    this.logger.info({
      from: parsed.fromAddr || parsed.from.address,
      to: mailbox.address,
      subject: (parsed.subject || '').slice(0, 60),
      folder,
      bytes: withReceived.length,
      spf: auth.spf ? auth.spf.result : 'off',
      dmarc: auth.dmarc ? auth.dmarc.result : 'off',
      smime: auth.smime ? auth.smime.status : 'none',
      msg: 'gelen ileti saklandı',
    });

    // Gerçek zamanlı ve bildirim, saklama TAMAMLANDIKTAN sonra: önce haber
    // verip sonra saklamak, istemcinin var olmayan bir iletiyi istemesine
    // yol açar.
    const summary = await this.stores.messages.get(stored.ref);
    if (this.realtime) this.realtime.publishMessage(mailbox.ref, summary);
    if (this.notifier && folder === 'inbox') {
      this.notifier.notifyNewMail({ mailbox, message: summary }).catch((err) => {
        this.logger.debug({ error: err.message, msg: 'bildirim gönderilemedi' });
      });
    }

    await this.applyForwarding({ mailbox, raw: withReceived, parsed, envelope });
    return stored;
  }

  chooseFolder({ mailbox, parsed, auth, spamScore }) {
    if (spamScore >= 5) return 'spam';
    if (auth.dmarc && auth.dmarc.disposition === 'quarantine') return 'spam';
    for (const rule of mailbox.filterRules || []) {
      if (!rule || !rule.folder) continue;
      const haystack = `${parsed.subject || ''} ${parsed.from.address || ''} ${parsed.listId || ''}`.toLowerCase();
      if (rule.contains && haystack.includes(String(rule.contains).toLowerCase())) return rule.folder;
      if (rule.fromEquals && normalizeAddress(rule.fromEquals) === normalizeAddress(parsed.from.address)) return rule.folder;
    }
    return 'inbox';
  }

  /**
   * Received başlığı eklenir (RFC 5321 §4.4) ve doğrulama sonuçları yazılır.
   * Received zincirini kesmek, bir iletinin nereden geldiğini sonradan
   * anlamayı imkânsız kılar.
   */
  prependReceivedHeaders({ raw, envelope, recipient, auth }) {
    const lines = [];
    if (auth.enabled) {
      lines.push(dmarc.authenticationResultsHeader({
        hostname: this.config.hostname,
        spf: auth.spf,
        dkim: auth.dkim,
        dmarc: auth.dmarc,
        smime: auth.smime,
      }));
      if (auth.spf) {
        lines.push(spf.receivedSpfHeader({
          result: auth.spf.result,
          domain: auth.spf.domain,
          ip: envelope.remoteIp,
          sender: envelope.mailFrom,
          helo: envelope.heloName,
          hostname: this.config.hostname,
        }));
      }
    }
    const tlsInfo = envelope.secure && envelope.tlsCipher
      ? ` (using ${envelope.tlsCipher.version} with cipher ${envelope.tlsCipher.name})`
      : '';
    lines.push(
      `Received: from ${envelope.heloName || 'unknown'} (${envelope.remoteIp})`
      + `\r\n\tby ${this.config.hostname} with ESMTP${envelope.secure ? 'S' : ''}${tlsInfo}`
      + `\r\n\tid ${envelope.sessionId}; ${new Date(envelope.receivedAt).toUTCString().replace('GMT', '+0000')}`,
    );
    lines.push(`Delivered-To: ${recipient.address}`);
    return Buffer.concat([Buffer.from(`${lines.join('\r\n')}\r\n`, 'utf8'), raw]);
  }

  /**
   * Yönlendirme. Zarf göndereni DEĞİŞTİRİLMEZ ama SPF için bizim alanımızdan
   * bir adres kullanılır — aksi hâlde yönlendirilen her ileti alıcıda SPF
   * hatası verir (klasik yönlendirme sorunu). Özgün gönderen Reply-To'da
   * korunur.
   *
   * ── DÖNGÜ KORUMASI ─────────────────────────────────────────────────────
   * Bir yönlendirme hedefi, iletiyi GÖNDEREN adres olabiliyor. Örnek:
   * gmail'den gelen bir posta, hedefi yine o gmail adresi olan bir kutuya
   * düşerse, gelen ileti göndericisine geri gider — "gmail'in gönderdiğini
   * gmail'e atmak" tam olarak budur. Karşı taraf onu yeni bir ileti olarak
   * kabul edip kendi kuralını uygularsa iki sunucu arasında sonsuz bir
   * çember oluşur.
   *
   * Üç ayrı kapı var ve üçü de farklı bir yolu kesiyor:
   *   1. Hedef, zarf göndereni ya da From adresiyle aynıysa gönderme.
   *   2. İleti zaten bizim tarafımızdan yönlendirilmişse (X-Fitfak-Forwarded)
   *      tekrar yönlendirme — iki kutu birbirine yönlendirilmiş olabilir.
   *   3. Received zinciri çok uzunsa dur: bu, bir yerde bir çember olduğunun
   *      taşıma katmanındaki karşılığı (RFC 5321 §6.3).
   */
  async applyForwarding({ mailbox, raw, parsed, envelope }) {
    const targets = (mailbox.forwardTo || []).map(normalizeAddress).filter(Boolean);
    if (!targets.length || !this.queue) return;

    if (parsed.headers && parsed.headers['x-fitfak-forwarded']) {
      this.logger.warn({
        mailbox: mailbox.address,
        msg: 'ileti zaten yönlendirilmiş, ikinci kez yönlendirilmiyor (döngü koruması)',
      });
      return;
    }
    const receivedCount = countReceivedHeaders(raw);
    if (receivedCount > MAX_RECEIVED_HOPS) {
      this.logger.error({
        mailbox: mailbox.address, receivedCount,
        msg: 'Received zinciri çok uzun, yönlendirme durduruldu (posta döngüsü)',
      });
      return;
    }

    // Otomatik üretilmiş posta yönlendirilmez (RFC 3834): bir "ofis dışındayım"
    // yanıtını yönlendirmek, karşı tarafın otomatik yanıtını tetikleyebilir.
    if (/auto-(generated|replied)/i.test(parsed.autoSubmitted || '')
      || /^(bulk|junk|list)$/i.test(parsed.precedence || '')) {
      this.logger.debug({
        mailbox: mailbox.address, autoSubmitted: parsed.autoSubmitted, precedence: parsed.precedence,
        msg: 'otomatik ileti yönlendirilmedi',
      });
      return;
    }

    const originators = new Set([
      normalizeAddress(envelope.mailFrom || ''),
      normalizeAddress(parsed.from && parsed.from.address),
      normalizeAddress(parsed.replyTo),
      normalizeAddress(mailbox.address),
    ].filter(Boolean));

    for (const target of targets) {
      if (originators.has(target)) {
        this.logger.warn({
          mailbox: mailbox.address, to: target,
          msg: 'yönlendirme hedefi iletinin göndereni — atlandı (döngü koruması)',
        });
        continue;
      }
      try {
        const marked = Buffer.concat([
          Buffer.from(`X-Fitfak-Forwarded: ${mailbox.address}\r\n`, 'utf8'),
          raw,
        ]);
        const signed = await this.signer.signDkim(marked, { fromAddress: mailbox.address });
        await this.queue.enqueue({
          rawBuffer: signed.rawMessage,
          envelopeFrom: `${this.config.queue.bounceMailbox}`,
          recipients: [target],
          mailboxRef: mailbox.ref,
          subject: parsed.subject,
          messageId: parsed.messageId,
          priority: 1,
          dkimSigned: signed.signed,
        });
        this.logger.info({ mailbox: mailbox.address, to: target, msg: 'ileti yönlendirildi' });
      } catch (err) {
        this.logger.error({ mailbox: mailbox.address, to: target, error: err.message, msg: 'yönlendirme başarısız' });
      }
    }
  }

  /* ── giden posta (submission) ──────────────────────────────── */

  /**
   * Kimlik doğrulanmış bir istemciden gelen ileti.
   *
   * BURASI bildirilen hatanın çözüldüğü yer: istemciden gelen ham ileti,
   * aktarılmadan önce DKIM ile imzalanıyor. Önceki sürüm bu yolda hiç
   * imzalamıyordu; imzalama yalnızca panelin kendi gönderim işlevinde vardı.
   */
  async handleSubmission({ raw, envelope }) {
    const parsed = parseMessage(raw, { limits: this.config.limits });
    const mailbox = envelope.authMailbox;
    if (!mailbox) return { reply: '530 5.7.0 Kimlik doğrulama gerekli' };

    const fromHeader = normalizeAddress(parsed.from.address || '');
    const envelopeFrom = normalizeAddress(envelope.mailFrom || '') || mailbox.address;

    const permitted = await this.senderAllowed({ mailbox, address: fromHeader || envelopeFrom });
    if (!permitted.allowed) {
      this.logger.warn({
        authUser: envelope.authUser, from: fromHeader, reason: permitted.reason,
        msg: 'yetkisiz gönderen adresi',
      });
      return { reply: `550 5.7.1 Bu adresle gönderme yetkiniz yok: ${fromHeader || envelopeFrom}` };
    }

    const sendingAddress = fromHeader || mailbox.address;
    let outgoing = raw;

    // Message-ID yoksa eklenir: onsuz gönderilen ileti birçok alıcıda spam
    // puanı alır ve yanıt zincirleri kurulamaz.
    if (!parsed.messageId) {
      const { newMessageId } = require('../util/encoding');
      const generated = newMessageId(splitAddress(sendingAddress).domain || this.config.primaryDomain);
      outgoing = Buffer.concat([Buffer.from(`Message-ID: ${generated}\r\n`, 'utf8'), outgoing]);
    }
    if (!parsed.date) {
      outgoing = Buffer.concat([
        Buffer.from(`Date: ${new Date().toUTCString().replace('GMT', '+0000')}\r\n`, 'utf8'),
        outgoing,
      ]);
    }

    const signed = await this.signer.signDkim(outgoing, { fromAddress: sendingAddress });
    outgoing = signed.rawMessage;
    if (!signed.signed) {
      this.logger.warn({ from: sendingAddress, reason: signed.reason, msg: 'DKIM imzası atılamadı' });
    }

    const localRecipients = envelope.recipients.filter((r) => r.local && r.mailbox);
    const remoteRecipients = envelope.recipients.filter((r) => !r.local || !r.mailbox);

    // Yerel alıcılara doğrudan teslim: kendi kuyruğumuza kendi MX'imize
    // bağlanmak için iş vermek gereksiz bir tur ve gereksiz bir hata kaynağı.
    const reparsed = parseMessage(outgoing, { limits: this.config.limits });
    for (const recipient of localRecipients) {
      try {
        await this.deliverLocal({
          raw: outgoing,
          parsed: reparsed,
          envelope: { ...envelope, mailFrom: envelopeFrom },
          recipient,
          auth: {
            enabled: true,
            spf: { result: 'pass', domain: splitAddress(envelopeFrom).domain },
            dkim: signed.signed
              ? { overall: 'pass', results: [{ domain: signed.domain, selector: signed.selector, result: 'pass' }] }
              : { overall: 'none', results: [] },
            dmarc: { result: 'pass', disposition: 'none', reason: 'yerel gönderim', alignment: {} },
            smime: reparsed.signedContent ? { status: 'signed-local' } : null,
          },
          spamScore: 0,
        });
      } catch (err) {
        this.logger.error({ to: recipient.address, error: err.message, msg: 'yerel teslimat başarısız' });
      }
    }

    if (remoteRecipients.length && this.queue) {
      await this.queue.enqueue({
        rawBuffer: outgoing,
        envelopeFrom,
        recipients: remoteRecipients.map((r) => r.address),
        mailboxRef: mailbox.ref,
        subject: parsed.subject,
        messageId: reparsed.messageId,
        priority: 2,
        dkimSigned: signed.signed,
        smimeSigned: !!reparsed.signedContent,
        dsnRequested: remoteRecipients.some((r) => r.dsn && /FAILURE/i.test(r.dsn)),
      });
    }

    // Gönderilenler klasörüne kopya: istemci (Thunderbird vb.) genelde kendi
    // kopyasını IMAP ile yükler, ama biz IMAP sunmuyoruz — kopyayı burada
    // saklamazsak kullanıcının gönderdiği posta webmail'de hiç görünmez.
    try {
      await this.stores.messages.store({
        mailbox,
        parsed: reparsed,
        rawBuffer: outgoing,
        folder: 'sent',
        envelopeFrom,
        envelopeTo: envelope.recipients.map((r) => r.address).join(', '),
        remoteIp: envelope.remoteIp,
        seen: true,
        authResults: { submission: true, dkimSigned: signed.signed },
        smime: reparsed.signedContent ? { status: 'signed-local' } : null,
      });
    } catch (err) {
      this.logger.error({ error: err.message, msg: 'gönderilen kopyası saklanamadı' });
    }

    this.logger.info({
      from: sendingAddress,
      recipients: envelope.recipients.length,
      dkim: signed.signed,
      smime: !!reparsed.signedContent,
      msg: 'gönderim kabul edildi',
    });
    return { reply: '250 2.0.0 Kuyruğa alındı' };
  }

  /**
   * Bir kutunun sahibi bu adresle gönderebilir mi?
   *
   * Üç yol geçerli: adresin kendisi, kutunun takma adı, ya da yöneticinin
   * kurduğu bir kimlik bağı (`allowSendAs`). Dördüncü bir yol yok — özellikle
   * "aynı alan adı olduğu için" gönderime izin vermek, her kullanıcıyı
   * postmaster yapmak olurdu.
   */
  async senderAllowed({ mailbox, address }) {
    const addr = normalizeAddress(address);
    if (!addr) return { allowed: false, reason: 'adres yok' };
    if (addr === mailbox.address) return { allowed: true, reason: 'kutu sahibi' };

    const target = await this.stores.mailboxes.getByAddress(addr);
    if (target && target.ref === mailbox.ref) return { allowed: true, reason: 'aynı kutu' };
    if (target && target.kind === 'alias' && target.aliasOfRef === mailbox.ref) {
      return { allowed: true, reason: 'takma ad' };
    }

    const link = await this.stores.mailboxes.resolveExternalIdentity(addr);
    if (link && link.mailboxRef === mailbox.ref && link.allowSendAs) {
      return { allowed: true, reason: 'kimlik bağı' };
    }

    const grants = await this.stores.mailboxes.listGrantsForMailbox(target ? target.ref : '');
    if (target && grants.some((g) => g.idpSub && g.idpSub === mailbox.ownerSub && (g.role === 'owner' || g.role === 'delegate' || g.role === 'sender'))) {
      return { allowed: true, reason: 'yetki devri' };
    }

    return { allowed: false, reason: 'yetki yok' };
  }

  /* ── API üzerinden gönderim ────────────────────────────────── */

  /**
   * Uygulama katmanından ileti gönderimi (webmail, durum API'si, bildirimler).
   *
   * @param {object} p
   * @param {object} p.mailbox        gönderen kutu
   * @param {string} [p.fromAddress]  kutudan farklıysa (kimlik bağı)
   * @param {boolean} [p.smime=false] S/MIME ile imzala
   */
  async send({
    mailbox, fromAddress = null, fromName = null, to = [], cc = [], bcc = [],
    subject = '', text = '', html = '', attachments = [], inReplyTo = '', references = [],
    smime = false, priority = null, extraHeaders = {}, campaignId = null,
    listUnsubscribe = null, saveToSent = true, actorSub = '',
  }) {
    const sendingAddress = normalizeAddress(fromAddress || mailbox.address);
    const permitted = await this.senderAllowed({ mailbox, address: sendingAddress });
    if (!permitted.allowed) {
      const err = new Error(`bu adresle gönderme yetkiniz yok: ${sendingAddress}`);
      err.code = 'SENDER_NOT_ALLOWED';
      throw err;
    }

    const totalAttachmentBytes = attachments.reduce((sum, a) => sum + (a.content ? a.content.length : 0), 0);
    if (attachments.length > this.config.limits.maxAttachmentsPerMessage) {
      const err = new Error(`en fazla ${this.config.limits.maxAttachmentsPerMessage} ek eklenebilir`);
      err.code = 'TOO_MANY_ATTACHMENTS';
      throw err;
    }
    if (totalAttachmentBytes > this.config.limits.maxTotalAttachmentBytes) {
      const err = new Error(`toplam ek boyutu sınırı aşıldı (${this.config.limits.maxTotalAttachmentBytes} bayt)`);
      err.code = 'ATTACHMENTS_TOO_LARGE';
      throw err;
    }
    for (const att of attachments) {
      if (att.content && att.content.length > this.config.limits.maxAttachmentBytes) {
        const err = new Error(`"${att.fileName}" tek ek sınırını aşıyor`);
        err.code = 'ATTACHMENT_TOO_LARGE';
        throw err;
      }
    }

    let smimeMaterial = null;
    if (smime) {
      smimeMaterial = await this.signer.getSmimeMaterial(sendingAddress);
      if (!smimeMaterial) {
        const err = new Error(`${sendingAddress} için S/MIME sertifikası yok`);
        err.code = 'NO_SMIME_CERT';
        throw err;
      }
    }

    const built = buildMessage({
      from: { address: sendingAddress, name: fromName || mailbox.displayName },
      to, cc, bcc, subject, text, html, attachments,
      inReplyTo, references, extraHeaders, priority, campaignId, listUnsubscribe,
      smime: smimeMaterial,
      sender: sendingAddress !== mailbox.address ? mailbox.address : null,
    });

    const signed = await this.signer.signDkim(built.raw, { fromAddress: sendingAddress });
    const outgoing = signed.rawMessage;

    const localTargets = [];
    const remoteTargets = [];
    for (const address of built.envelope.to) {
      const { domain } = splitAddress(address);
      if (this.config.isLocalDomain(domain)) {
        const resolved = await this.stores.mailboxes.resolveDelivery(address);
        if (resolved.mailbox) { localTargets.push({ address, mailbox: resolved.mailbox }); continue; }
      }
      remoteTargets.push(address);
    }

    const parsedOutgoing = parseMessage(outgoing, { limits: this.config.limits });

    for (const target of localTargets) {
      await this.deliverLocal({
        raw: outgoing,
        parsed: parsedOutgoing,
        envelope: {
          mailFrom: built.envelope.from, remoteIp: '127.0.0.1', heloName: this.config.hostname,
          secure: true, tlsCipher: null, sessionId: `api-${sha256Hex(built.messageId).slice(0, 12)}`,
          receivedAt: Date.now(), recipients: [], mode: 'api',
        },
        recipient: { address: target.address, mailbox: target.mailbox, local: true },
        auth: {
          enabled: true,
          spf: { result: 'pass', domain: splitAddress(built.envelope.from).domain },
          dkim: signed.signed
            ? { overall: 'pass', results: [{ domain: signed.domain, selector: signed.selector, result: 'pass' }] }
            : { overall: 'none', results: [] },
          dmarc: { result: 'pass', disposition: 'none', reason: 'yerel gönderim', alignment: {} },
          smime: built.smimeSigned ? { status: 'signed-local' } : null,
        },
        spamScore: 0,
      });
    }

    let queued = [];
    if (remoteTargets.length) {
      if (!this.queue) throw new Error('kuyruk yapılandırılmamış');
      const result = await this.queue.enqueue({
        rawBuffer: outgoing,
        envelopeFrom: built.envelope.from,
        recipients: remoteTargets,
        mailboxRef: mailbox.ref,
        subject,
        messageId: built.messageId,
        priority: priority === 'high' ? 5 : 2,
        dkimSigned: signed.signed,
        smimeSigned: built.smimeSigned,
        campaignId: campaignId || '',
      });
      queued = result.queued;
    }

    let sentRef = null;
    if (saveToSent) {
      const stored = await this.stores.messages.store({
        mailbox,
        parsed: parsedOutgoing,
        rawBuffer: outgoing,
        folder: 'sent',
        envelopeFrom: built.envelope.from,
        envelopeTo: built.envelope.to.join(', '),
        remoteIp: '',
        seen: true,
        campaignId: campaignId || '',
        authResults: { api: true, dkimSigned: signed.signed, smimeSigned: built.smimeSigned },
        smime: built.smimeSigned ? { status: 'signed-local' } : null,
      });
      sentRef = stored.ref;
      const summary = await this.stores.messages.get(sentRef);
      if (this.realtime) this.realtime.publishMessage(mailbox.ref, summary);
    }

    await this.stores.audit.record({
      actorSub, actorEmail: mailbox.address, action: 'mail.send',
      targetType: 'message', targetId: built.messageId,
      detail: {
        to: built.envelope.to.length, dkim: signed.signed, smime: built.smimeSigned,
        attachments: attachments.length, campaignId: campaignId || null,
      },
    });

    return {
      messageId: built.messageId,
      queued,
      localDelivered: localTargets.map((t) => t.address),
      dkimSigned: signed.signed,
      smimeSigned: built.smimeSigned,
      sentRef,
      sizeBytes: outgoing.length,
    };
  }

  /** Var olan bir iletiyi iletir. */
  async forward({ mailbox, messageRef, to, comment = '', smime = false, actorSub = '' }) {
    const message = await this.stores.messages.getFull(messageRef);
    if (!message) throw new Error('ileti bulunamadı');
    if (message.mailboxRef !== mailbox.ref) throw new Error('bu ileti bu kutuya ait değil');

    const raw = await this.stores.messages.getRaw(messageRef);
    let smimeMaterial = null;
    if (smime) {
      smimeMaterial = await this.signer.getSmimeMaterial(mailbox.address);
      if (!smimeMaterial) throw new Error(`${mailbox.address} için S/MIME sertifikası yok`);
    }

    const built = buildForward({
      from: { address: mailbox.address, name: mailbox.displayName },
      to: [].concat(to),
      originalSubject: message.subject,
      comment,
      // Ham ileti yoksa gövdeden yeniden kurulmuş bir kopya gönderilir; bu
      // durumda özgün imza korunamaz ve bu açıkça bildirilir.
      originalRaw: raw || Buffer.from(`Subject: ${message.subject}\r\n\r\n${message.text || message.html}`, 'utf8'),
      smime: smimeMaterial,
      extraHeaders: raw ? {} : { 'X-Fitfak-Note': 'ham ileti bulunamadı, gövde yeniden kuruldu' },
    });

    const signed = await this.signer.signDkim(built.raw, { fromAddress: mailbox.address });
    const result = await this.queue.enqueue({
      rawBuffer: signed.rawMessage,
      envelopeFrom: mailbox.address,
      recipients: built.envelope.to,
      mailboxRef: mailbox.ref,
      subject: built.subject,
      messageId: built.messageId,
      priority: 2,
      dkimSigned: signed.signed,
      smimeSigned: built.smimeSigned,
      sourceMessageRef: messageRef,
    });

    await this.stores.messages.setFlags(messageRef, { answered: true });
    await this.stores.audit.record({
      actorSub, actorEmail: mailbox.address, action: 'mail.forward',
      targetType: 'message', targetId: messageRef,
      detail: { to: built.envelope.to, hasOriginalRaw: !!raw },
    });

    return { messageId: built.messageId, queued: result.queued, hasOriginalRaw: !!raw };
  }

  /** Teslim edilemedi bildirimi üretir ve kuyruğa koyar. */
  async sendDsn({ to, originalRecipient, originalMessageId, status, diagnostic, originalRaw = null }) {
    const raw = buildDsn({
      from: this.config.queue.dsnFrom,
      to,
      originalRecipient,
      originalMessageId,
      status,
      diagnostic,
      reportingMta: this.config.hostname,
      originalRaw,
    });
    const signed = await this.signer.signDkim(raw, { fromAddress: this.config.queue.dsnFrom });
    // DSN'in kendisi teslim edilemezse İKİNCİ bir DSN üretilmez: geri dönüş
    // döngüsü, iki sunucu arasında sonsuz posta üretebilir. Zarf göndereni bu
    // yüzden boş (<>).
    return this.queue.enqueue({
      rawBuffer: signed.rawMessage,
      envelopeFrom: '',
      recipients: [to],
      subject: 'Teslim edilemedi',
      priority: 3,
      dkimSigned: signed.signed,
    });
  }
}

module.exports = { MailPipeline };
