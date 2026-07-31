'use strict';

const log = require('./util/log');
const { createInterval } = require('./util/async');

/**
 * Uygulamanın kurulum noktası.
 *
 * Bağımlılık sırası bir zincir ve tek yönlü:
 *
 *   yapılandırma -> veritabanı -> depolar (+kasa) -> imzalayıcı
 *      -> sertifika yöneticisi -> kuyruk -> hat (pipeline)
 *      -> SMTP + HTTP + gerçek zamanlı
 *
 * Her katman yalnızca kendinden öncekini tanıyor. Bu, bir katmanın testte
 * tek başına kurulabilmesini sağlıyor — test yardımcısı tam olarak bunu
 * yapıyor.
 */
class MailApplication {
  constructor(config) {
    this.config = config;
    this.logger = log.child('app');
    this.startedAt = Date.now();
    this.components = {};
    this.maintenance = [];
    this.stopping = false;
  }

  async start({ withSmtp = true, withHttp = true, withQueue = true, withCerts = true, withDns = true } = {}) {
    const config = this.config;
    config.validate();
    log.configure({
      level: config.log.level,
      json: config.log.json,
      color: config.log.color,
      redactAddresses: config.log.redactAddresses,
    });

    this.logger.info({
      env: config.env,
      hostname: config.hostname,
      domains: config.domains.map((d) => d.name).join(','),
      instanceId: config.instanceId,
      msg: 'Fitfak posta sunucusu başlıyor',
    });

    /* ── veri katmanı ────────────────────────────────────────── */
    const { connect } = require('./db');
    const { createStores } = require('./db/repos');
    const db = await connect(config, { logger: log.child('db') });
    const stores = createStores(db, { config, logger: log.child('store') });
    this.components.db = db;
    this.components.stores = stores;

    // Yapılandırmadaki alan adları için sistem kutuları: postmaster ve
    // dmarc adresleri RFC gereği çalışır olmalı, ve DMARC raporlarının
    // gideceği bir yer yoksa rapor isteyen kayıt yayımlamak anlamsız.
    for (const domain of config.domains) {
      if (!domain.receive) continue;
      await stores.mailboxes.ensure(`network@${domain.name}`, { kind: 'system', displayName: 'Postmaster' });
      await stores.mailboxes.ensure(domain.dmarcRua, { kind: 'system', displayName: 'DMARC raporları' });
    }

    /* ── imzalama ────────────────────────────────────────────── */
    const { MailSigner } = require('./mail/signer');
    const signer = new MailSigner({
      vault: stores.vault, certificates: stores.certificates, config, logger: log.child('signer'),
    });
    this.components.signer = signer;

    // DKIM anahtarları açılışta hazırlanır: ilk giden postanın imzasız
    // gitmemesi için.
    for (const domain of config.domains) {
      await signer.getDkimKey(domain.name).catch((err) => {
        this.logger.error({ domain: domain.name, error: err.message, msg: 'DKIM anahtarı hazırlanamadı' });
      });
    }

    /* ── kimlik sağlayıcı ────────────────────────────────────── */
    const { IdpClient } = require('./auth/idp-client');
    const { SessionManager } = require('./auth/session-manager');
    const idp = new IdpClient({
      baseUrl: config.idp.baseUrl,
      clientId: config.idp.clientId,
      clientSecret: config.idp.clientSecret,
      redirectUri: config.redirectUri(),
      scopes: config.idp.scopes,
      logger: log.child('idp'),
      config,
    });
    const sessions = new SessionManager({ config, logger: log.child('session'), stores, idp });
    this.components.idp = idp;
    this.components.sessions = sessions;

    /* ── sertifikalar ────────────────────────────────────────── */
    let certificates = null;
    if (withCerts) {
      const { ServiceTokenProvider } = require('./auth/service-token');
      const { CertificateManager } = require('./certs/manager');
      const serviceToken = new ServiceTokenProvider({
        idp, vault: stores.vault, logger: log.child('service-token'),
      });
      certificates = new CertificateManager({
        config, logger: log.child('cert'), stores, serviceToken, signer,
      });
      this.components.certificates = certificates;
      this.components.serviceToken = serviceToken;
      if (!certificates.available) {
        this.logger.warn({ msg: '@fitfak/ssl yok — S/MIME imzalama ve sertifika verme devre dışı' });
      }
    }

    /* ── bildirim ve gerçek zamanlı ──────────────────────────── */
    const { PushService } = require('./http/push');
    const { RealtimeHub } = require('./http/realtime');
    const push = new PushService({ config, logger: log.child('push'), stores });
    const realtime = new RealtimeHub({ logger: log.child('realtime'), stores, config });
    this.components.push = push;
    this.components.realtime = realtime;
    await push.ensureVapid().catch((err) => {
      this.logger.error({ error: err.message, msg: 'VAPID anahtarı hazırlanamadı; bildirimler çalışmayacak' });
    });

    /* ── kuyruk ve hat ───────────────────────────────────────── */
    const { OutboundQueue } = require('./smtp/queue');
    const { MailPipeline } = require('./mail/pipeline');
    const queue = new OutboundQueue({ config, logger: log.child('queue'), stores, signer });
    const pipeline = new MailPipeline({
      config, logger: log.child('mail'), stores, signer, queue,
      notifier: push, realtime,
    });
    queue.pipeline = pipeline;
    this.components.queue = queue;
    this.components.pipeline = pipeline;
    if (withQueue) queue.start();

    /* ── DNS denetimi ────────────────────────────────────────── */
    let dnsAuditor = null;
    if (withDns) {
      const { DnsAuditor } = require('./dns/auditor');
      dnsAuditor = new DnsAuditor({ config, logger: log.child('dns'), stores, signer });
      this.components.dnsAuditor = dnsAuditor;
      // İlk denetim açılışı BEKLETMEZ: DNS sorguları yavaş olabilir ve
      // sunucunun posta kabul etmeye başlaması buna bağlı değil.
      setTimeout(() => {
        dnsAuditor.audit({ apply: config.dns.autoApply }).catch((err) => {
          this.logger.warn({ error: err.message, msg: 'ilk DNS denetimi başarısız' });
        });
      }, 5000).unref?.();
      dnsAuditor.start();
    }

    /* ── SMTP ────────────────────────────────────────────────── */
    if (withSmtp) {
      const { SmtpServer } = require('./smtp/server');
      const smtpServer = new SmtpServer({
        config,
        logger: log.child('smtp'),
        handlers: {
          authenticate: (args) => pipeline.authenticate(args),
          validateRecipient: (args) => pipeline.validateRecipient(args),
          handleMessage: (args) => pipeline.handleMessage(args),
        },
        // TLS malzemesi önce kasadan: sertifika yenilendiğinde dosya
        // kopyalamaya gerek kalmıyor.
        tlsProvider: async () => {
          const pair = await stores.certificates.getSigningPair('tls', config.hostname).catch(() => null);
          if (!pair) return null;
          return {
            key: pair.privateKeyPem,
            cert: pair.chainPem ? `${pair.certPem}\n${pair.chainPem}` : pair.certPem,
          };
        },
      });
      await smtpServer.start();
      this.components.smtpServer = smtpServer;
    }

    /* ── HTTP ────────────────────────────────────────────────── */
    if (withHttp) {
      const { HttpServers } = require('./http/server');
      const httpServers = new HttpServers({
        config,
        logger: log.child('http'),
        stores,
        sessions,
        pipeline,
        queue,
        push,
        realtime,
        signer,
        certificates,
        dnsAuditor,
        smtpServer: this.components.smtpServer,
        startedAt: this.startedAt,
      });
      await httpServers.start();
      this.components.httpServers = httpServers;
    }

    /* ── sertifika taraması ──────────────────────────────────── */
    if (certificates) {
      certificates.start();
      // İlk tarama gecikmeli: açılışta kimlik sağlayıcıya yüklenmemek için.
      setTimeout(() => {
        certificates.ensureAll().catch((err) => {
          this.logger.warn({ error: err.message, msg: 'ilk sertifika taraması başarısız' });
        });
      }, 15_000).unref?.();
    }

    /* ── bakım görevleri ─────────────────────────────────────── */
    this._startMaintenance();

    this.logger.info({
      smtp: !!this.components.smtpServer,
      http: this.components.httpServers ? this.components.httpServers.addresses() : null,
      queue: withQueue,
      msg: 'sunucu hazır',
    });
    return this;
  }

  /**
   * Süpürme görevleri.
   *
   * Hepsi aynı yerde, çünkü hepsinin ortak özelliği aynı: yapılmazsa sistem
   * yavaşça büyür ve haftalar sonra "neden bu kadar yer kaplıyor" sorusu
   * çıkar.
   */
  _startMaintenance() {
    const { stores } = this.components;
    const logger = log.child('maintenance');

    this.maintenance.push(createInterval(async () => {
      const results = {
        sessions: await stores.sessions.sweepExpired(),
        ephemeral: await stores.sessions.sweepEphemeral(),
        blobs: await stores.blobs.sweepExpired(),
        orphanChunks: await stores.blobs.sweepOrphans(),
        queue: await stores.outbound.sweepCompleted(),
        trash: await stores.messages.purgeTrash(),
      };
      const total = Object.values(results).reduce((sum, n) => sum + (n || 0), 0);
      if (total) logger.info({ ...results, msg: 'bakım taraması' });
    }, 60 * 60 * 1000, { immediate: false, logger, name: 'sweep' }));

    // Süresi yaklaşan sırlar için uyarı: bir DKIM anahtarının ya da TLS
    // sertifikasının sessizce sona ermesi, teslimatın bir sabah durması
    // demek.
    this.maintenance.push(createInterval(async () => {
      const expiring = await stores.vault.listExpiring(14 * 86400_000);
      for (const secret of expiring) {
        logger.warn({
          kind: secret.kind, version: secret.version,
          daysLeft: Math.floor(secret.expiresInMs / 86400_000),
          msg: 'kasadaki sırın süresi yaklaşıyor',
        });
      }
    }, 12 * 60 * 60 * 1000, { immediate: false, logger, name: 'expiry-watch' }));
  }

  async stop() {
    if (this.stopping) return;
    this.stopping = true;
    this.logger.info({ msg: 'kapanıyor' });

    for (const task of this.maintenance) task.stop();
    const { smtpServer, httpServers, queue, realtime, certificates, dnsAuditor, db } = this.components;

    // Sıra önemli: önce yeni iş kabul etmeyi bırak, sonra uçuştakini bitir,
    // en sonda veritabanını kapat.
    if (smtpServer) await smtpServer.stop().catch(() => {});
    if (httpServers) await httpServers.stop().catch(() => {});
    if (realtime) realtime.close();
    if (certificates) certificates.stop();
    if (dnsAuditor) dnsAuditor.stop();
    if (queue) await queue.stop().catch(() => {});
    if (db) await db.close().catch(() => {});

    this.logger.info({ msg: 'kapandı' });
  }

  /** Sinyal yakalama: kapanışta uçuştaki teslimatları kaybetmemek için. */
  installSignalHandlers() {
    const shutdown = async (signal) => {
      this.logger.info({ signal, msg: 'kapanma sinyali alındı' });
      const timer = setTimeout(() => {
        this.logger.error({ msg: 'kapanma zaman aşımı, süreç sonlandırılıyor' });
        process.exit(1);
      }, 30_000);
      timer.unref();
      await this.stop();
      clearTimeout(timer);
      process.exit(0);
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('unhandledRejection', (reason) => {
      // Yakalanmamış reddetme süreci öldürmez ama kayda geçer: posta
      // sunucusunun tek bir hatalı teslimat yüzünden durması, o teslimattan
      // daha büyük bir sorun.
      this.logger.error({
        error: reason instanceof Error ? reason.message : String(reason),
        stack: reason instanceof Error ? reason.stack : null,
        msg: 'yakalanmamış reddetme',
      });
    });
    process.on('uncaughtException', (err) => {
      this.logger.error({ error: err.message, stack: err.stack, msg: 'yakalanmamış istisna' });
      shutdown('uncaughtException');
    });
    return this;
  }
}

module.exports = { MailApplication };
