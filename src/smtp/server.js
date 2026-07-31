'use strict';

const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const tls = require('node:tls');

const { SmtpSession, MODE } = require('./session');
const { ConnectionCounter, FailureTracker } = require('../util/rate-limit');

/**
 * SMTP dinleyicileri: 25 (MX), 587 (submission), 465 (SMTPS).
 *
 * Üç portun ayrı olmasının nedeni yalnızca gelenek değil, farklı politika:
 *
 *   25  — dünyadan gelen posta. Kimlik doğrulama YOK (duyurulmaz bile), yalnızca
 *         yerel alanlara teslim. Aktarma (relay) kapalı.
 *   587 — kendi kullanıcılarımızın gönderimi. STARTTLS + AUTH zorunlu.
 *   465 — aynı politika, ama TLS bağlantının başından itibaren (implicit).
 *
 * 25'te AUTH duyurmamak bilinçli: duyurulan her AUTH, sözlük saldırısı için
 * bir hedeftir ve MX portunda kimsenin kimlik doğrulamasına ihtiyacı yok.
 */
class SmtpServer {
  /**
   * @param {object} p
   * @param {object} p.config
   * @param {object} p.logger
   * @param {object} p.handlers  { authenticate, validateRecipient, handleMessage }
   * @param {function} [p.tlsProvider] async () => { key, cert, ca } | null
   */
  constructor({ config, logger, handlers, tlsProvider = null }) {
    this.config = config;
    this.logger = logger;
    this.handlers = handlers;
    this.tlsProvider = tlsProvider;
    this.servers = [];
    this.tlsOptions = null;
    this.connections = new ConnectionCounter({
      maxPerKey: config.smtp.maxConnectionsPerIp,
      maxTotal: config.smtp.maxConnections,
    });
    this.authFailures = new FailureTracker({
      threshold: config.smtp.maxAuthFailures,
      windowMs: config.smtp.authWindowMs,
    });
    this.activeSessions = new Set();
    this.stats = {
      connections: 0, rejected: 0, messagesAccepted: 0, messagesRejected: 0,
      authFailures: 0, authSuccesses: 0, startedAt: Date.now(),
    };
    this._sweeper = setInterval(() => {
      this.authFailures.sweep();
    }, 300_000);
    if (this._sweeper.unref) this._sweeper.unref();
  }

  /** TLS malzemesi: önce sağlayıcıdan (kasa), sonra diskten. */
  async loadTls() {
    if (this.tlsProvider) {
      try {
        const material = await this.tlsProvider();
        if (material && material.key && material.cert) {
          this.tlsOptions = {
            key: material.key,
            cert: material.cert,
            ...(material.ca ? { ca: material.ca } : {}),
            minVersion: 'TLSv1.2',
            // Şifre sırası sunucu tarafından belirlenir; istemcinin en zayıf
            // ortak şifreyi seçmesine izin vermemek için.
            honorCipherOrder: true,
          };
          this.logger.info({ source: 'vault', msg: 'TLS malzemesi yüklendi' });
          return this.tlsOptions;
        }
      } catch (err) {
        this.logger.warn({ error: err.message, msg: 'kasadan TLS malzemesi alınamadı, diske bakılıyor' });
      }
    }

    const candidates = [
      { key: 'privkey.pem', cert: 'fullchain.pem' },
      { key: 'server.key', cert: 'server.crt' },
      { key: `${this.config.hostname}.key`, cert: `${this.config.hostname}.crt` },
    ];
    for (const candidate of candidates) {
      const keyPath = path.join(this.config.certDir, candidate.key);
      const certPath = path.join(this.config.certDir, candidate.cert);
      if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) continue;
      this.tlsOptions = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
        minVersion: 'TLSv1.2',
        honorCipherOrder: true,
      };
      this.logger.info({ source: certPath, msg: 'TLS malzemesi yüklendi' });
      return this.tlsOptions;
    }

    // TLS yoksa 465 hiç açılmaz ve 587 STARTTLS duyurmaz. Sessizce düz metin
    // kimlik doğrulamaya izin vermek, parolaları ağa yazmak olurdu.
    this.logger.warn({ certDir: this.config.certDir, msg: 'TLS sertifikası bulunamadı — 465 kapalı, 587 üzerinde AUTH devre dışı' });
    return null;
  }

  _sessionOptions(mode, { secure, allowStarttls, allowAuth }) {
    return {
      mode,
      secure,
      allowStarttls,
      allowAuth,
      tlsOptions: this.tlsOptions,
      config: this.config,
      logger: this.logger,
      handlers: {
        ...this.handlers,
        isAuthBlocked: (ip) => this.authFailures.isLocked(ip),
        authenticate: async (args) => {
          const result = await this.handlers.authenticate(args);
          if (result && result.ok) {
            this.authFailures.recordSuccess(args.ip);
            this.stats.authSuccesses++;
            return result;
          }
          const failure = this.authFailures.recordFailure(args.ip);
          this.stats.authFailures++;
          return { ...(result || {}), ok: false, blocked: failure.locked };
        },
        handleMessage: async (args) => {
          const result = await this.handlers.handleMessage(args);
          const replies = [].concat(result && result.reply ? result.reply : []);
          if (replies.some((r) => /^[45]/.test(String(r)))) this.stats.messagesRejected++;
          else this.stats.messagesAccepted++;
          return result;
        },
      },
      onClose: (session) => {
        this.activeSessions.delete(session);
        if (!session.handedOff) this.connections.release(session.remoteAddress);
      },
      onHandoff: (from, to) => {
        // Devredilen bağlantı sayacı yeni oturuma geçer; eski oturum
        // kapanışta sayacı düşürmez.
        this.activeSessions.delete(from);
        this.activeSessions.add(to);
      },
    };
  }

  _accept(socket, mode, sessionOpts) {
    this.stats.connections++;
    const ip = String(socket.remoteAddress || '').replace(/^::ffff:/, '');
    const slot = this.connections.tryAcquire(ip);
    if (!slot.ok) {
      this.stats.rejected++;
      this.logger.warn({ peer: ip, reason: slot.reason, msg: 'bağlantı sınırı, reddedildi' });
      try {
        socket.write('421 4.7.0 Çok fazla eşzamanlı bağlantı\r\n');
        socket.end();
      } catch { /* yok say */ }
      return;
    }
    // Nagle kapalı: SMTP küçük satırlarla konuşur ve gecikme birikir.
    socket.setNoDelay(true);
    const session = new SmtpSession(socket, sessionOpts);
    this.activeSessions.add(session);
    if (this.config.smtp.greetingDelayMs > 0 && mode === MODE.MX) {
      // Karşılama gecikmesi: kural tanımayan gönderenler karşılamayı
      // beklemeden komut yazar. Gecikme sırasında veri gelirse bu güçlü bir
      // spam göstergesidir (RFC 5321 §4.3.1 bunu açıkça yasaklar).
      const timer = setTimeout(() => session.greet(), this.config.smtp.greetingDelayMs);
      if (timer.unref) timer.unref();
    } else {
      session.greet();
    }
  }

  async start() {
    await this.loadTls();
    const bind = this.config.smtp.bind;

    const mxPort = this.config.smtp.ports.mx;
    if (mxPort) {
      const opts = this._sessionOptions(MODE.MX, {
        secure: false, allowStarttls: !!this.tlsOptions, allowAuth: false,
      });
      const server = net.createServer((socket) => this._accept(socket, MODE.MX, opts));
      await this._listen(server, mxPort, bind, 'MX');
    }

    const subPort = this.config.smtp.ports.submission;
    if (subPort) {
      const opts = this._sessionOptions(MODE.SUBMISSION, {
        secure: false, allowStarttls: !!this.tlsOptions, allowAuth: true,
      });
      const server = net.createServer((socket) => this._accept(socket, MODE.SUBMISSION, opts));
      await this._listen(server, subPort, bind, 'SUBMISSION');
    }

    const smtpsPort = this.config.smtp.ports.smtps;
    if (smtpsPort && this.tlsOptions) {
      const opts = this._sessionOptions(MODE.SUBMISSION, {
        secure: true, allowStarttls: false, allowAuth: true,
      });
      const server = tls.createServer(this.tlsOptions, (socket) => this._accept(socket, MODE.SUBMISSION, opts));
      server.on('tlsClientError', (err) => {
        this.logger.debug({ error: err.message, msg: 'TLS istemci hatası (465)' });
      });
      await this._listen(server, smtpsPort, bind, 'SMTPS');
    } else if (smtpsPort) {
      this.logger.warn({ port: smtpsPort, msg: '465 açılmadı: TLS malzemesi yok' });
    }

    return this;
  }

  _listen(server, port, host, label) {
    return new Promise((resolve, reject) => {
      server.on('error', (err) => {
        if (err.code === 'EACCES') {
          this.logger.error({ port, msg: `${port} portu için yetki yok (ayrıcalıklı port) — CAP_NET_BIND_SERVICE ya da yeniden yönlendirme gerekir` });
        } else if (err.code === 'EADDRINUSE') {
          this.logger.error({ port, msg: `${port} portu kullanımda` });
        } else {
          this.logger.error({ port, error: err.message, msg: 'dinleyici hatası' });
        }
        reject(err);
      });
      server.listen(port, host, () => {
        this.servers.push({ server, port, label });
        const actual = server.address();
        this.logger.info({ port: actual.port, host: actual.address, mode: label, msg: 'SMTP dinleniyor' });
        resolve(server);
      });
    });
  }

  async stop() {
    clearInterval(this._sweeper);
    for (const session of this.activeSessions) {
      try { session.write('421 4.3.2 Sunucu kapanıyor'); session.end(); } catch { /* yok say */ }
    }
    await Promise.all(this.servers.map(({ server }) => new Promise((resolve) => server.close(resolve))));
    this.servers = [];
  }

  snapshot() {
    return {
      ...this.stats,
      uptimeMs: Date.now() - this.stats.startedAt,
      activeSessions: this.activeSessions.size,
      connectionStats: this.connections.stats(),
      listeners: this.servers.map(({ port, label }) => ({ port, mode: label })),
      tls: !!this.tlsOptions,
    };
  }
}

module.exports = { SmtpServer };
