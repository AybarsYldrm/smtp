'use strict';

const { deliver } = require('./delivery');
const { createInterval, createLimiter, createRateLimiter, sleep } = require('../util/async');
const { splitAddress } = require('../util/encoding');

/**
 * Giden kuyruk işçisi.
 *
 * Toplu gönderim burada gerçek bir kısıt getiriyor ve tasarım ona göre:
 *
 *   - ALAN ADI BAŞINA EŞZAMANLILIK. Gmail'e 50 paralel bağlantı açmak
 *     teslimatı hızlandırmaz; hız sınırına ve geçici bloklara yol açar.
 *     Bu yüzden eşzamanlılık alan adı başına sayılıyor, toplam üzerinden
 *     değil.
 *
 *   - ALAN ADI BAŞINA GERİ ÇEKİLME. Bir alan adı 4xx döndürmeye başladığında
 *     o alana giden diğer iletiler de beklemeye alınıyor. Aksi hâlde kuyruk,
 *     zaten bizi kısıtlayan bir sunucuya ısrarla bağlanmaya devam eder ve
 *     kısıtlama uzar.
 *
 *   - ÖNCELİK. İşlemsel posta (parola sıfırlama, güvenlik uyarısı) yüksek
 *     öncelikle girer ve 50 bin kişilik bir kampanyanın arkasında saatlerce
 *     beklemez.
 */
class OutboundQueue {
  constructor({ config, logger, stores, signer, pipeline = null }) {
    this.config = config;
    this.logger = logger;
    this.stores = stores;
    this.signer = signer;
    this.pipeline = pipeline;
    this.workerId = config.instanceId;

    this.limiter = createLimiter(config.queue.workers * config.queue.perDomainConcurrency);
    this.domainSlots = new Map(); // domain -> aktif sayısı
    this.domainBackoff = new Map(); // domain -> geri çekilme bitiş zamanı
    this.campaignRates = new Map(); // campaignId -> rate limiter
    this.running = false;
    this.ticker = null;
    this._ticking = null;      // uçuştaki tur (varsa) — bkz. tick()
    this._tickPending = false; // tur sırasında yeni iş geldi mi?
    // `deliver()` çağrısına eklenen alanlar (resolver, port, mxOverride,
    // requireTls). Üretimde boş; uçtan uca teslimat testinin gerçek kuyruk
    // kodunu, sahte bir MX'e karşı, yerel bir portta çalıştırabilmesi için var
    // — teslimat yolunu test edebilmenin tek yolu ya bu ya da onu taklit
    // etmek, ve taklit edilen bir yol test edilmiş sayılmaz.
    this.deliveryOptions = {};
    this.stats = {
      delivered: 0, deferred: 0, failed: 0, cycles: 0,
      lastCycleAt: 0, inFlight: 0,
    };
  }

  /** Kuyruğa iş ekler (depo katmanına yönlendirir). */
  async enqueue(args) {
    const result = await this.stores.outbound.enqueue(args);
    this.logger.info({
      recipients: result.recipients.length,
      queueIds: result.queued,
      blobId: result.blobId,
      envelopeFrom: args.envelopeFrom,
      running: this.running,
      msg: 'kuyruğa alındı',
    });
    if (!this.running) {
      // Kuyruk işçisi çalışmıyorken sıraya girmiş bir ileti hiç gönderilmez ve
      // bunu gösteren tek şey, bir daha asla gelmeyen "teslim edildi" satırı
      // olurdu. Kayıt satırının kendisi bu durumu söylemeli.
      this.logger.warn({
        recipients: result.recipients.length,
        msg: 'kuyruk işçisi çalışmıyor — ileti sırada bekliyor, işçi başlayana kadar gönderilmeyecek',
      });
    }
    // Yeni iş varsa beklemeden bir tur başlat: 5 saniyelik yoklama aralığı,
    // tek bir postayı gönderirken fark edilir bir gecikme demek.
    if (this.running) {
      setImmediate(() => this.tick().catch((err) => {
        this.logger.error({ error: err.message, stack: err.stack, msg: 'kuyruk turu hata verdi' });
      }));
    }
    return result;
  }

  start() {
    if (this.running) return this;
    this.running = true;
    this.ticker = createInterval(() => this.tick(), this.config.queue.pollIntervalMs, {
      immediate: true,
      logger: this.logger,
      name: 'outbound-queue',
    });
    this.logger.info({
      workers: this.config.queue.workers,
      perDomain: this.config.queue.perDomainConcurrency,
      msg: 'giden kuyruk işçisi başladı',
    });
    return this;
  }

  async stop() {
    this.running = false;
    if (this.ticker) this.ticker.stop();
    // Uçuşta olan teslimatların bitmesini bekle: ortada kesmek, kilidi
    // düşene kadar (5 dakika) o iletileri bekletir.
    const deadline = Date.now() + 30_000;
    while (this.stats.inFlight > 0 && Date.now() < deadline) await sleep(200, { unref: false });
  }

  _domainAvailable(domain) {
    const backoffUntil = this.domainBackoff.get(domain) || 0;
    if (Date.now() < backoffUntil) return false;
    const active = this.domainSlots.get(domain) || 0;
    return active < this.config.queue.perDomainConcurrency;
  }

  _acquireDomain(domain) {
    this.domainSlots.set(domain, (this.domainSlots.get(domain) || 0) + 1);
  }

  _releaseDomain(domain) {
    const active = (this.domainSlots.get(domain) || 1) - 1;
    if (active <= 0) this.domainSlots.delete(domain);
    else this.domainSlots.set(domain, active);
  }

  _backoffDomain(domain, ms) {
    const until = Date.now() + ms;
    const current = this.domainBackoff.get(domain) || 0;
    if (until > current) this.domainBackoff.set(domain, until);
  }

  /**
   * Bir kuyruk turu. TURLAR ÜST ÜSTE BİNMEZ.
   *
   * ── NEDEN KİLİT GEREKİYOR ────────────────────────────────────────────────
   * `claimDue`, satırları önce OKUYUP sonra "sending" olarak İŞARETLİYOR ve bu
   * iki adım arasında `await` var. İki tur aynı anda çalıştığında ikisi de
   * satırı "queued" görüyor, ikisi de kilitliyor ve ikisi de teslim ediyor —
   * alıcı iletiyi İKİ KEZ alıyor. Satır başına kilit bunu engellemiyor, çünkü
   * kilidin kendisi de aynı yarışın içinde konuyor.
   *
   * Ve eşzamanlılık burada istisna değil, olağan hâl: `enqueue()` beklemeden
   * bir tur başlatıyor, yoklama zamanlayıcısı da kendi turunu çeviriyor. Yeni
   * bir ileti, zamanlayıcının turuna denk geldiği anda çift teslimat oluyor.
   *
   * Turlar arası kilit, çift teslimatı tek süreç içinde tamamen kaldırıyor.
   * (Birden fazla süreçte satır kilidi hâlâ tek koruma; onun sağlamlaştırılması
   * motorda karşılaştır-değiştir desteği ister.)
   */
  async tick() {
    if (!this.running) return;
    if (this._ticking) {
      // Zaten dönen bir tur var. Yenisini başlatmak yerine onun bitmesini
      // bekle; bu arada gelen yeni iş için bir tur daha gerektiğini işaretle.
      this._tickPending = true;
      return this._ticking;
    }
    this._ticking = this._tickOnce().finally(() => {
      this._ticking = null;
      if (this._tickPending && this.running) {
        this._tickPending = false;
        // Zincirleme `await` yerine sıradaki döngü adımına bırakılıyor: uzun
        // bir tur zinciri, çağıranın beklediği sözü süresiz açık tutardı.
        setImmediate(() => this.tick().catch((err) => {
          this.logger.error({ error: err.message, msg: 'kuyruk turu hata verdi' });
        }));
      }
    });
    return this._ticking;
  }

  async _tickOnce() {
    this.stats.cycles++;
    this.stats.lastCycleAt = Date.now();

    const batchSize = this.config.queue.workers * this.config.queue.perDomainConcurrency * 4;
    // Talep etme adımı ayrı ölçülür. Kuyruğun donduğu bildirildiğinde suçlanan
    // hep teslimat oluyordu; oysa duran şey bu çağrıydı (giden kuyruğun
    // `nextAttemptAt` aralık sorgusu, veritabanı tarafında olay döngüsünü
    // dakikalarca kilitliyordu). Süresi görünür olmadan bu ayrım yapılamaz.
    const claimStartedAt = Date.now();
    const claimed = await this.stores.outbound.claimDue({
      workerId: this.workerId,
      limit: batchSize,
      lockMs: 300_000,
    });
    const claimMs = Date.now() - claimStartedAt;
    if (claimMs > 1000) {
      this.logger.warn({
        ms: claimMs, claimed: claimed.length,
        msg: 'kuyruktan iş alma yavaş — veritabanı sorgusu darboğaz olabilir',
      });
    }
    if (!claimed.length) return;

    this.logger.debug({ claimed: claimed.length, ms: claimMs, msg: 'kuyruktan iş alındı' });

    const tasks = [];
    let deferredByBackoff = 0;
    for (const item of claimed) {
      const domain = item.rcptDomain || splitAddress(item.rcptTo).domain;
      if (!this._domainAvailable(domain)) {
        // Bu tur bu alana yer yok: kilidi bırak, sıradaki turda yeniden alınır.
        //
        // BIRAKMAK, BAŞARISIZ SAYMAK DEĞİL. Burada `markFailure` çağrılıyordu
        // ve her tur bir deneme harcıyordu; `maxAttempts` dolduğunda ileti
        // kalıcı olarak başarısız işaretleniyordu — tek bir teslimat denemesi
        // bile yapılmadan. Geri çekilme penceresi bir teslimat hatası değil.
        deferredByBackoff++;
        await this.stores.outbound.release(
          item.ref, 'alan adı için eşzamanlılık/geri çekilme penceresi dolu',
        ).catch(() => {});
        continue;
      }
      this._acquireDomain(domain);
      tasks.push(this.limiter(() => this._process(item, domain)));
    }

    if (deferredByBackoff) {
      this.logger.debug({
        held: deferredByBackoff, dispatched: tasks.length,
        backoffDomains: [...this.domainBackoff.entries()]
          .filter(([, until]) => until > Date.now()).map(([d]) => d),
        msg: 'geri çekilme/eşzamanlılık nedeniyle bu tur bekletildi (deneme sayılmadı)',
      });
    }
    await Promise.allSettled(tasks);
  }

  async _process(item, domain) {
    this.stats.inFlight++;
    // Hata yolundaki kayıt satırları da süreyi bildiriyor, bu yüzden `try`
    // bloğunun DIŞINDA: blok içinde tanımlanmış bir `const`, `catch` içinden
    // okunduğunda ReferenceError verir ve gerçek teslimat hatasının üstünü
    // örterdi.
    const startedAt = Date.now();
    try {
      if (item.campaignId) {
        const rate = this._campaignRate(item.campaignId);
        await rate();
      }

      const raw = await this.stores.outbound.getRaw(item);
      if (!raw) {
        await this.stores.outbound.markFailure(item.ref, {
          error: 'ham ileti bulunamadı (blob süresi dolmuş olabilir)',
          permanent: true,
        });
        this.stats.failed++;
        return;
      }

      this.logger.debug({
        queueId: item.queueId, to: item.rcptTo, domain,
        attempt: item.attempts + 1, sizeBytes: item.sizeBytes,
        dkim: item.dkimSigned, smime: item.smimeSigned,
        msg: 'teslimat başlıyor',
      });
      const result = await deliver({
        rawMessage: raw,
        envelopeFrom: item.envelopeFrom,
        recipient: item.rcptTo,
        heloName: this.config.hostname,
        logger: this.logger,
        localAddress: this.config.smtp.outboundLocalAddress || null,
        dsnRequested: item.dsnRequested,
        ...this.deliveryOptions,
      });

      await this.stores.outbound.markSent(item.ref, {
        mx: result.mx,
        tlsUsed: result.tlsUsed,
        smtpCode: result.code,
        logEntry: {
          at: Date.now(), mx: result.mx, code: result.code,
          tls: result.tlsUsed, verified: result.tlsVerified,
          durationMs: Date.now() - startedAt,
          // Aşama süreleri kuyruk satırında da saklanır: teslimat günlerce
          // sonra incelendiğinde süreç kaydı çoktan dönmüş oluyor.
          timings: result.timings || null,
          attempts: (result.attempts || []).length,
        },
      });
      this.stats.delivered++;
      this.logger.info({
        queueId: item.queueId,
        to: item.rcptTo, mx: result.mx, code: result.code,
        response: String(result.message || '').slice(0, 120),
        tls: result.tlsUsed ? (result.tlsVerified ? 'doğrulanmış' : 'doğrulanmamış') : 'yok',
        attempt: item.attempts + 1,
        triedMx: (result.attempts || []).length,
        ms: Date.now() - startedAt,
        stages: result.timings || undefined,
        msg: 'teslim edildi',
      });
      // Başarı, alan adının geri çekilmesini temizler.
      this.domainBackoff.delete(domain);
    } catch (err) {
      const permanent = !!err.permanent;
      const outcome = await this.stores.outbound.markFailure(item.ref, {
        error: err.message,
        smtpCode: err.code || 0,
        permanent,
        mx: err.mx || '',
        logEntry: {
          at: Date.now(), error: err.message, code: err.code || 0, stage: err.stage || '',
          timings: err.timings || null,
          mxTried: (err.attempts || []).map((a) => ({ mx: a.mx, code: a.code, stage: a.stage, error: a.error })),
        },
      });

      if (permanent) {
        this.stats.failed++;
        this.logger.warn({
          queueId: item.queueId, to: item.rcptTo, mx: err.mx || '',
          code: err.code, stage: err.stage || '',
          triedMx: (err.attempts || []).length,
          ms: Date.now() - startedAt,
          error: err.message,
          msg: 'kalıcı teslimat hatası — bir daha denenmeyecek',
        });
        await this._maybeSendDsn(item, err);
      } else {
        this.stats.deferred++;
        // Geçici hata: bu alana kısa bir süre yüklenme.
        this._backoffDomain(domain, Math.min(15 * 60_000, 30_000 * Math.max(1, item.attempts + 1)));
        this.logger.info({
          queueId: item.queueId,
          to: item.rcptTo, mx: err.mx || '',
          code: err.code || 0, stage: err.stage || '',
          attempt: outcome ? outcome.attempts : 0,
          maxAttempts: this.config.queue.maxAttempts,
          nextAt: outcome && outcome.nextAttemptAt ? new Date(outcome.nextAttemptAt).toISOString() : null,
          ms: Date.now() - startedAt,
          error: err.message,
          msg: 'teslimat ertelendi',
        });
      }
    } finally {
      this._releaseDomain(domain);
      this.stats.inFlight--;
    }
  }

  /**
   * Kalıcı hatada gönderene bildirim.
   *
   * Zarf göndereni boş olan iletiler için DSN ÜRETİLMEZ: boş zarf göndereni
   * zaten bir geri dönüş iletisidir ve ona geri dönüş üretmek iki sunucu
   * arasında sonsuz döngü demektir (RFC 5321 §4.5.5).
   */
  async _maybeSendDsn(item, err) {
    if (!this.pipeline) return;
    if (!item.envelopeFrom) return;
    if (item.envelopeFrom === this.config.queue.dsnFrom) return;

    const { domain } = splitAddress(item.envelopeFrom);
    if (!this.config.isLocalDomain(domain)) {
      // Gönderen bizim değilse DSN üretmek, aktarma yaptığımız anlamına gelir
      // ve yapmıyoruz.
      return;
    }
    try {
      const raw = await this.stores.outbound.getRaw(item).catch(() => null);
      await this.pipeline.sendDsn({
        to: item.envelopeFrom,
        originalRecipient: item.rcptTo,
        originalMessageId: item.messageId,
        status: err.code >= 500 ? '5.1.1' : '4.4.1',
        diagnostic: `${err.code || ''} ${err.message}`.trim(),
        originalRaw: raw,
      });
    } catch (dsnErr) {
      this.logger.error({ error: dsnErr.message, msg: 'DSN gönderilemedi' });
    }
  }

  _campaignRate(campaignId) {
    let rate = this.campaignRates.get(campaignId);
    if (!rate) {
      rate = createRateLimiter(this.config.queue.campaignRatePerSecond);
      this.campaignRates.set(campaignId, rate);
      // Harita sonsuza kadar büyümesin: kampanya bittiğinde temizlenir, ama
      // temizlenmese de sayı sınırlı kalsın diye üst sınır var.
      if (this.campaignRates.size > 500) {
        const firstKey = this.campaignRates.keys().next().value;
        this.campaignRates.delete(firstKey);
      }
    }
    return rate;
  }

  /**
   * Toplu gönderim: kampanya oluşturur ve alıcıları yığın yığın kuyruğa alır.
   *
   * Alıcı listesi tek seferde kuyruğa yazılmaz; `campaignBatchSize` kadarlık
   * yığınlarla yazılır. 100 bin alıcıyı tek işlemde yazmak, veritabanı
   * kuyruğunu o süre boyunca kilitler ve bu arada gelen işlemsel postalar
   * bekler.
   */
  async startCampaign({
    mailbox, name, subject, text = '', html = '', recipients = [],
    attachments = [], smime = false, fromAddress = null, ratePerSecond = null,
    listUnsubscribe = null, actorSub = '', meta = null,
  }) {
    const unique = [...new Set(recipients.map((r) => String(r || '').trim().toLowerCase()).filter((r) => r.includes('@')))];
    if (!unique.length) throw new Error('geçerli alıcı yok');
    if (unique.length > this.config.queue.maxRecipientsPerCampaign) {
      throw new Error(`kampanya alıcı sınırı: ${this.config.queue.maxRecipientsPerCampaign}`);
    }

    const campaignId = await this.stores.outbound.createCampaign({
      name, ownerSub: actorSub, mailboxRef: mailbox.ref, subject,
      total: unique.length, ratePerSecond, meta, smimeSign: smime,
    });
    await this.stores.outbound.setCampaignStatus(campaignId, 'running');

    // İleti BİR KEZ kurulur ve imzalanır; alıcı başına yeniden kurmak, aynı
    // gövde için 100 bin kez DKIM imzası hesaplamak olurdu.
    const { buildMessage } = require('../mail/mime-builder');
    const sendingAddress = fromAddress || mailbox.address;
    let smimeMaterial = null;
    if (smime) {
      smimeMaterial = await this.signer.getSmimeMaterial(sendingAddress);
      if (!smimeMaterial) throw new Error(`${sendingAddress} için S/MIME sertifikası yok`);
    }

    const built = buildMessage({
      from: { address: sendingAddress, name: mailbox.displayName },
      // To başlığı listenin kendisi: alıcıların birbirini görmesi kabul
      // edilemez, bu yüzden her alıcı ayrı zarfla ama aynı gövdeyle gider.
      to: [{ address: sendingAddress, name: mailbox.displayName }],
      subject, text, html, attachments,
      campaignId,
      listUnsubscribe: listUnsubscribe || `<mailto:${this.config.queue.bounceMailbox}?subject=unsubscribe>`,
      autoSubmitted: 'auto-generated',
      extraHeaders: { Precedence: 'bulk' },
      smime: smimeMaterial,
    });
    const signed = await this.signer.signDkim(built.raw, { fromAddress: sendingAddress });

    let queuedTotal = 0;
    const batchSize = this.config.queue.campaignBatchSize;
    for (let i = 0; i < unique.length; i += batchSize) {
      const batch = unique.slice(i, i + batchSize);
      const result = await this.stores.outbound.enqueue({
        rawBuffer: signed.rawMessage,
        envelopeFrom: this.config.queue.bounceMailbox,
        recipients: batch,
        mailboxRef: mailbox.ref,
        campaignId,
        subject,
        messageId: built.messageId,
        priority: 0,
        dkimSigned: signed.signed,
        smimeSigned: built.smimeSigned,
      });
      queuedTotal += result.queued.length;
      await this.stores.outbound.bumpCampaign(campaignId, { queued: result.queued.length });
    }

    await this.stores.audit.record({
      actorSub, actorEmail: mailbox.address, action: 'campaign.start',
      targetType: 'campaign', targetId: campaignId,
      detail: { recipients: queuedTotal, subject, smime: built.smimeSigned },
    });

    this.logger.info({ campaignId, recipients: queuedTotal, msg: 'kampanya kuyruğa alındı' });
    if (this.running) setImmediate(() => this.tick().catch(() => {}));
    return { campaignId, queued: queuedTotal, messageId: built.messageId, smimeSigned: built.smimeSigned };
  }

  async pauseCampaign(campaignId) {
    await this.stores.outbound.setCampaignStatus(campaignId, 'paused');
    const items = await this.stores.outbound.listByCampaign(campaignId, { status: 'queued', limit: 100_000 });
    let cancelled = 0;
    for (const item of items) {
      if (await this.stores.outbound.cancel(item.ref, 'kampanya duraklatıldı')) cancelled++;
    }
    return { cancelled };
  }

  snapshot() {
    return {
      ...this.stats,
      running: this.running,
      activeDomains: this.domainSlots.size,
      backoffDomains: [...this.domainBackoff.entries()]
        .filter(([, until]) => until > Date.now())
        .map(([domain, until]) => ({ domain, untilMs: until - Date.now() })),
      limiter: this.limiter.stats(),
    };
  }
}

module.exports = { OutboundQueue };
