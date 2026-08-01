'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

/**
 * Test yardımcıları.
 *
 * Testler @fitfak/database olmadan da çalışmak zorunda: aksi hâlde doğruluk
 * denetimi, yayımlanmamış bir pakete ve ayakta bir gRPC sunucusuna bağımlı
 * olurdu. Bu yüzden dosya sürücüsü kullanılıyor — ve o sürücü motorun
 * tuhaflıklarını (BigInt `_id`) bilerek taklit ediyor.
 */

const created = [];

async function makeTempDir(prefix = 'fitmail-test-') {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), prefix));
  created.push(dir);
  return dir;
}

async function cleanupAll() {
  for (const dir of created.splice(0)) {
    await fsp.rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

/** Kullanılabilir bir port bulur. Sabit port, paralel testlerde çakışır. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/**
 * Yalıtılmış bir uygulama bağlamı kurar.
 * Her çağrı kendi veri dizinini ve kendi sırlarını kullanır.
 */
async function createContext({
  smtp = false, domains = null, inboundChecks = false, enforceDmarc = false,
  driver = 'file', liveQueue = false,
} = {}) {
  const dir = await makeTempDir();

  // config tek örnek (singleton) olduğu için ortam değişkenleri ayarlanıp
  // önbellek temizlenir; testler arası sızıntı olmaması için.
  const env = {
    NODE_ENV: 'test',
    FITFAK_MAIL_DATA_DIR: dir,
    FITFAK_MAIL_CERT_DIR: path.join(dir, 'certs'),
    FITFAK_MAIL_DB_DRIVER: driver,
    // `db.remoteTarget` öntanımlı olarak DOLU (https://localhost:51572), yani
    // `fitfak` sürücüsü boş bırakılırsa uzak/mTLS yolunu seçer. Test gömülü
    // motoru istiyor: hedefi açıkça boşaltmak, bu seçimi yapmanın tek yolu.
    FITFAK_MAIL_DB_TARGET: '',
    FITFAK_MAIL_VAULT_SECRET: crypto.randomBytes(32).toString('base64'),
    FITFAK_MAIL_DB_ROOT_SECRET: crypto.randomBytes(32).toString('base64'),
    FITFAK_MAIL_PUBLIC_IP: '203.0.113.10',
    FITFAK_SMTP_BIND: '127.0.0.1',
    FITFAK_SMTP_INBOUND_CHECKS: inboundChecks ? '1' : '0',
    FITFAK_SMTP_ENFORCE_DMARC: enforceDmarc ? '1' : '0',
    FITFAK_SMTP_REQUIRE_TLS_FOR_AUTH: '0',
    FITFAK_MAIL_CLIENT_ID: 'test-client',
    FITFAK_MAIL_CLIENT_SECRET: 'test-secret',
    LOG_LEVEL: process.env.TEST_LOG_LEVEL || 'silent',
  };
  if (smtp) {
    env.FITFAK_SMTP_PORT_MX = String(await freePort());
    env.FITFAK_SMTP_PORT_SUBMISSION = String(await freePort());
    env.FITFAK_SMTP_PORT_SMTPS = '0';
  }
  const previous = {};
  for (const [key, value] of Object.entries(env)) {
    previous[key] = process.env[key];
    process.env[key] = value;
  }

  // Modül önbelleğini temizle: config açılışta okunuyor.
  for (const key of Object.keys(require.cache)) {
    if (key.includes(`${path.sep}smtp${path.sep}src${path.sep}`)) delete require.cache[key];
  }

  const config = require('../src/config');
  if (domains) {
    // Alanlar `parseDomains()`in ürettiği biçime tamamlanır: eksik bir
    // `sign`/`manageDns`, üretimde öntanımlı olan davranışı testte
    // `undefined` yapardı ve test, gerçekte olmayan bir yapılandırmayı
    // doğrulamış olurdu.
    const normalized = domains.map((d) => ({
      sign: true,
      manageDns: true,
      receive: true,
      dkimSelector: 'mail',
      dmarcRua: `dmarc@${d.name}`,
      ...d,
    }));
    config.domains.length = 0;
    config.domains.push(...normalized);
    config.receiveDomains.length = 0;
    config.receiveDomains.push(...normalized.filter((d) => d.receive !== false).map((d) => d.name));
    config.dnsManagedDomains.length = 0;
    config.dnsManagedDomains.push(...normalized.filter((d) => d.manageDns !== false));
  }

  const log = require('../src/util/log');
  log.configure({ level: env.LOG_LEVEL === 'silent' ? 'silent' : env.LOG_LEVEL });
  const logger = log.child('test');

  const { connect } = require('../src/db');
  const { createStores } = require('../src/db/repos');
  const { MailSigner } = require('../src/mail/signer');
  const { MailPipeline } = require('../src/mail/pipeline');
  const { OutboundQueue } = require('../src/smtp/queue');

  const db = await connect(config, { logger });
  const stores = createStores(db, { config, logger });
  const signer = new MailSigner({
    vault: stores.vault, certificates: stores.certificates, config, logger,
  });

  const sentMail = [];
  const notifications = [];
  const realtimeEvents = [];

  const queue = new OutboundQueue({ config, logger, stores, signer });
  if (liveQueue) {
    // `tick()` ilk satırında `if (!this.running) return` diyor, bu yüzden
    // bayrak kalkmadan elle çevrilen turlar sessizce hiçbir şey yapmaz —
    // ve testler "hata yok" diye geçerdi. `start()` çağrılmıyor: o, kendi
    // zamanlayıcısını kuruyor ve testin elle çevirdiği turlarla yarışıyor.
    queue.running = true;
  } else {
    // Gerçek teslimat yapılmaz: test ortamı dışa posta göndermemeli. Kuyruğa
    // yazılanlar burada toplanır.
    //
    // `liveQueue: true` bu kısıtlamayı kaldırır ve GERÇEK kuyruk turunu
    // çalıştırır. Dışarıya çıkmaması, teslimatın yerel bir sahte MX'e
    // yönlendirilmesiyle sağlanır (`queue.deliveryOptions`), motoru taklit
    // ederek değil.
    queue.start = () => queue;
    queue.tick = async () => {};
  }

  const pipeline = new MailPipeline({
    config, logger, stores, signer, queue,
    notifier: {
      notifyNewMail: async (args) => { notifications.push(args); },
    },
    realtime: {
      publishMessage: (mailboxRef, message) => { realtimeEvents.push({ mailboxRef, message }); },
    },
  });

  const context = {
    dir, config, logger, db, stores, signer, queue, pipeline,
    sentMail, notifications, realtimeEvents,
    async close() {
      if (context.smtpServer) await context.smtpServer.stop();
      await queue.stop();
      await db.close();
      for (const [key, value] of Object.entries(previous)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    },
  };

  if (smtp) {
    const { SmtpServer } = require('../src/smtp/server');
    context.smtpServer = new SmtpServer({
      config, logger,
      handlers: {
        authenticate: (args) => pipeline.authenticate(args),
        validateRecipient: (args) => pipeline.validateRecipient(args),
        handleMessage: (args) => pipeline.handleMessage(args),
      },
    });
    await context.smtpServer.start();
    context.ports = {
      mx: Number(env.FITFAK_SMTP_PORT_MX),
      submission: Number(env.FITFAK_SMTP_PORT_SUBMISSION),
    };
  }

  return context;
}

/** Basit SMTP istemcisi — testler protokolü elle konuşur. */
class TestSmtpClient {
  constructor({ port, host = '127.0.0.1' }) {
    this.port = port;
    this.host = host;
    this.buffer = '';
    this.pending = null;
    this.lines = [];
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.connect(this.port, this.host);
      this.socket.setEncoding('latin1');
      this.socket.on('data', (chunk) => this._onData(chunk));
      this.socket.once('error', reject);
      this.socket.once('connect', () => resolve(this.read()));
    });
  }

  _onData(chunk) {
    this.buffer += chunk;
    let idx;
    while ((idx = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, idx).replace(/\r$/, '');
      this.buffer = this.buffer.slice(idx + 1);
      const m = line.match(/^(\d{3})([ -])(.*)$/);
      this.lines.push(line);
      if (m && m[2] === ' ' && this.pending) {
        const { resolve, timer } = this.pending;
        clearTimeout(timer);
        this.pending = null;
        const collected = this.lines.slice();
        this.lines = [];
        resolve({ code: Number(m[1]), lines: collected, text: collected.join('\n') });
      }
    }
  }

  read(timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending = null; reject(new Error('istemci okuma zaman aşımı')); }, timeoutMs);
      this.pending = { resolve, reject, timer };
    });
  }

  async send(line, timeoutMs = 5000) {
    const p = this.read(timeoutMs);
    this.socket.write(`${line}\r\n`);
    return p;
  }

  async sendData(raw, timeoutMs = 10_000) {
    const p = this.read(timeoutMs);
    const text = Buffer.isBuffer(raw) ? raw.toString('latin1') : String(raw);
    const stuffed = text.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
    this.socket.write(`${stuffed}\r\n.\r\n`);
    return p;
  }

  close() { try { this.socket.destroy(); } catch { /* yok say */ } }
}

/* ── minik doğrulama çatısı ─────────────────────────────────── */

class TestRunner {
  constructor(name) {
    this.name = name;
    this.tests = [];
    this.passed = 0;
    this.failed = 0;
  }

  test(description, fn) { this.tests.push({ description, fn }); }

  async run() {
    process.stdout.write(`\n${this.name}\n`);
    for (const { description, fn } of this.tests) {
      try {
        await fn();
        this.passed++;
        process.stdout.write(`  [32m✓[0m ${description}\n`);
      } catch (err) {
        this.failed++;
        process.stdout.write(`  [31m✗[0m ${description}\n    ${err.message}\n`);
        if (process.env.TEST_VERBOSE) process.stdout.write(`    ${err.stack}\n`);
      }
    }
    process.stdout.write(`  ${this.passed} geçti, ${this.failed} başarısız\n`);
    return this.failed === 0;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'doğrulama başarısız');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || 'eşit değil'}: beklenen ${JSON.stringify(expected)}, gelen ${JSON.stringify(actual)}`);
  }
}

function assertMatch(actual, pattern, message) {
  if (!pattern.test(String(actual))) {
    throw new Error(`${message || 'desen uyuşmadı'}: ${pattern} <- ${String(actual).slice(0, 200)}`);
  }
}

async function assertThrows(fn, pattern, message) {
  try {
    await fn();
  } catch (err) {
    if (pattern && !pattern.test(err.message)) {
      throw new Error(`${message || 'yanlış hata'}: ${pattern} <- ${err.message}`);
    }
    return err;
  }
  throw new Error(message || 'hata beklendi ama atılmadı');
}

/** Test için S/MIME sertifikası üretir (kök CA + yaprak). */
function issueTestSmimeCert(address, displayName = '') {
  const ssl = require('@fitfak/ssl');
  const { createSmimeRequest } = require('../src/certs/csr');
  const root = ssl.generateEcRootCA({ curveName: 'P-256' });
  const request = createSmimeRequest({ address, displayName: displayName || address });
  const issued = ssl.issueCertificateFromCSR(request.csrPem, root, { profile: 'email', validityDays: 365 });
  return {
    rootPem: root.certPem,
    certPem: issued.pem || issued.certPem,
    privateKeyPem: request.privateKeyPem,
    csrPem: request.csrPem,
  };
}

module.exports = {
  createContext, cleanupAll, makeTempDir, freePort,
  TestSmtpClient, TestRunner,
  assert, assertEqual, assertMatch, assertThrows,
  issueTestSmimeCert,
};
