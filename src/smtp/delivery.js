'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');
const tls = require('node:tls');

const { splitAddress } = require('../util/encoding');

/**
 * Giden SMTP istemcisi.
 *
 * Önceki sürümdeki teslimat kodu tek bir MX'e bağlanıyor ve yanıtları
 * satır satır bir durum makinesiyle okuyordu. İki sorun:
 *
 *   1. ÇOK SATIRLI YANIT. `250-` ile başlayan satırlar yalnızca EHLO
 *      aşamasında ele alınıyordu; başka bir aşamada çok satırlı yanıt gelirse
 *      (ki gelir — birçok sunucu RCPT'ye çok satırlı yanıt verir) durum
 *      makinesi ilk satırla ilerliyor ve kalan satırları bir sonraki aşamanın
 *      yanıtı sanıyordu.
 *   2. TEK MX. En yüksek öncelikli MX yanıt vermiyorsa teslimat başarısız
 *      sayılıyordu, oysa MX listesi tam olarak bu yüzden var.
 *
 * Buradaki istemci yanıtları TAM olarak okur (çok satırlı dâhil) ve MX
 * listesini öncelik sırasıyla dener.
 *
 * TLS kararı: fırsatçı (opportunistic). Sertifika doğrulaması BAŞARISIZ olsa
 * bile şifreli devam edilir, çünkü seçenek düz metindir — internet postasında
 * doğrulanmamış TLS, hiç TLS'ten iyidir. Doğrulama sonucu kayda yazılır;
 * `requireTls` ile katı davranış istenebilir.
 */

const DEFAULT_TIMEOUTS = {
  connect: 30_000,
  greeting: 60_000,
  command: 60_000,
  data: 300_000,
};

class SmtpReply {
  constructor(code, lines) {
    this.code = code;
    this.lines = lines;
    this.text = lines.join(' ');
  }

  get ok() { return this.code >= 200 && this.code < 400; }
  get temporary() { return this.code >= 400 && this.code < 500; }
  get permanent() { return this.code >= 500; }

  /** Gelişmiş durum kodu (RFC 3463), varsa. */
  get enhanced() {
    const m = this.lines[0] && this.lines[0].match(/^\s*([245]\.\d{1,3}\.\d{1,3})\b/);
    return m ? m[1] : null;
  }
}

class DeliveryError extends Error {
  constructor(message, { code = 0, permanent = false, stage = '', mx = '' } = {}) {
    super(message);
    this.code = code;
    this.permanent = permanent;
    this.stage = stage;
    this.mx = mx;
  }
}

/** Bir SMTP bağlantısı üzerinde satır tabanlı konuşma. */
class SmtpClientConnection {
  constructor(socket, { timeouts, logger, label }) {
    this.socket = socket;
    this.timeouts = timeouts;
    this.logger = logger;
    this.label = label;
    this.buffer = Buffer.alloc(0);
    this.pending = null;
    this.closedError = null;
    this.lines = [];

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('error', (err) => this._fail(err));
    socket.on('close', () => this._fail(new Error('bağlantı beklenmedik şekilde kapandı')));
  }

  _fail(err) {
    this.closedError = err;
    if (this.pending) {
      const { reject, timer } = this.pending;
      clearTimeout(timer);
      this.pending = null;
      reject(err);
    }
  }

  _onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const idx = this.buffer.indexOf(0x0a);
      if (idx === -1) break;
      let line = this.buffer.subarray(0, idx);
      this.buffer = this.buffer.subarray(idx + 1);
      if (line.length && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
      this._onLine(line.toString('latin1'));
    }
  }

  _onLine(line) {
    if (this.logger) this.logger.debug({ mx: this.label, msg: `< ${line.slice(0, 200)}` });
    const m = line.match(/^(\d{3})([ -]?)(.*)$/);
    if (!m) { this.lines.push(line); return; }
    this.lines.push(m[3]);
    // Devam işareti '-' ise yanıt sürüyor. Boşluk (ya da hiç) son satır.
    if (m[2] === '-') return;
    const reply = new SmtpReply(Number(m[1]), this.lines);
    this.lines = [];
    if (this.pending) {
      const { resolve, timer } = this.pending;
      clearTimeout(timer);
      this.pending = null;
      resolve(reply);
    }
  }

  /** Tam bir yanıt bekler. */
  readReply(timeoutMs) {
    if (this.closedError) return Promise.reject(this.closedError);
    if (this.pending) return Promise.reject(new Error('eşzamanlı okuma'));
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending = null;
        reject(new Error(`yanıt zaman aşımı (${timeoutMs}ms)`));
      }, timeoutMs);
      this.pending = { resolve, reject, timer };
    });
  }

  async command(line, timeoutMs = this.timeouts.command) {
    if (this.logger) this.logger.debug({ mx: this.label, msg: `> ${line.slice(0, 200)}` });
    this.socket.write(`${line}\r\n`);
    return this.readReply(timeoutMs);
  }

  /** Ham iletiyi nokta doldurma (dot-stuffing) ile yazar. */
  async sendData(rawMessage, timeoutMs = this.timeouts.data) {
    const buf = Buffer.isBuffer(rawMessage) ? rawMessage : Buffer.from(String(rawMessage), 'utf8');
    const out = [];
    let lineStart = 0;
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] !== 0x0a) continue;
      let line = buf.subarray(lineStart, i);
      if (line.length && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
      // Satır başındaki nokta ikiye çıkarılır; yoksa istemci onu ileti sonu
      // sanır ve iletinin geri kalanı komut olarak yorumlanır.
      if (line.length && line[0] === 0x2e) out.push(Buffer.from([0x2e]));
      out.push(line, Buffer.from('\r\n', 'latin1'));
      lineStart = i + 1;
    }
    if (lineStart < buf.length) {
      let line = buf.subarray(lineStart);
      if (line.length && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
      if (line.length && line[0] === 0x2e) out.push(Buffer.from([0x2e]));
      out.push(line, Buffer.from('\r\n', 'latin1'));
    }
    out.push(Buffer.from('.\r\n', 'latin1'));

    this.socket.write(Buffer.concat(out));
    return this.readReply(timeoutMs);
  }

  close() {
    this.socket.removeAllListeners('close');
    this.socket.removeAllListeners('error');
    try { this.socket.destroy(); } catch { /* yok say */ }
  }
}

/** Alan adı için MX listesi; MX yoksa A/AAAA kaydına düşer (RFC 5321 §5.1). */
async function resolveMailExchangers(domain, { resolver = dns, logger = null } = {}) {
  try {
    const rows = await resolver.resolveMx(domain);
    if (rows && rows.length) {
      // Null MX (RFC 7505): "." tek MX ise alan posta kabul etmiyor demektir.
      if (rows.length === 1 && (rows[0].exchange === '' || rows[0].exchange === '.')) {
        const err = new DeliveryError(`${domain} posta kabul etmiyor (null MX)`, { permanent: true, code: 556 });
        throw err;
      }
      return rows
        .filter((r) => r.exchange && r.exchange !== '.')
        .sort((a, b) => a.priority - b.priority || a.exchange.localeCompare(b.exchange))
        .map((r) => ({ host: r.exchange.replace(/\.$/, ''), priority: r.priority }));
    }
  } catch (err) {
    if (err instanceof DeliveryError) throw err;
    if (err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
      throw new DeliveryError(`MX çözümlenemedi: ${err.code || err.message}`, { permanent: false });
    }
  }
  // MX yok: alan adının kendisi örtük MX'tir.
  try {
    const a = await resolver.resolve4(domain).catch(() => []);
    const aaaa = a.length ? [] : await resolver.resolve6(domain).catch(() => []);
    if (a.length || aaaa.length) return [{ host: domain, priority: 0, implicit: true }];
  } catch { /* aşağıda hata */ }
  throw new DeliveryError(`${domain} için MX ya da A kaydı yok`, { permanent: true, code: 550 });
}

/**
 * Bir iletiyi bir alıcıya teslim eder.
 *
 * @param {object} p
 * @param {Buffer} p.rawMessage
 * @param {string} p.envelopeFrom
 * @param {string} p.recipient
 * @param {string} p.heloName
 * @returns {Promise<{code, message, mx, tlsUsed, tlsVerified, attempts}>}
 */
async function deliver({
  rawMessage, envelopeFrom, recipient, heloName,
  resolver = dns, logger = null, timeouts = {}, localAddress = null,
  requireTls = false, port = 25, mxOverride = null, dsnRequested = false,
}) {
  const t = { ...DEFAULT_TIMEOUTS, ...timeouts };
  const { domain } = splitAddress(recipient);
  if (!domain) throw new DeliveryError(`geçersiz alıcı: ${recipient}`, { permanent: true, code: 550 });

  const exchangers = mxOverride
    ? [{ host: mxOverride, priority: 0 }]
    : await resolveMailExchangers(domain, { resolver, logger });

  const attempts = [];
  let lastError = null;

  for (const mx of exchangers.slice(0, 5)) {
    const attempt = { mx: mx.host, startedAt: Date.now() };
    try {
      const result = await deliverToHost({
        host: mx.host, port, rawMessage, envelopeFrom, recipient, heloName,
        logger, timeouts: t, localAddress, requireTls, dsnRequested,
      });
      attempt.result = 'sent';
      attempt.code = result.code;
      attempt.tlsUsed = result.tlsUsed;
      attempts.push(attempt);
      return { ...result, mx: mx.host, attempts };
    } catch (err) {
      attempt.result = 'error';
      attempt.error = err.message;
      attempt.code = err.code || 0;
      attempt.permanent = !!err.permanent;
      attempts.push(attempt);
      lastError = err;
      // Kalıcı hata (5xx) sıradaki MX'te de aynı olacaktır: aynı alanın
      // ikinci MX'i "böyle kullanıcı yok" kararını değiştirmez. Denemeye
      // devam etmek yalnızca itibar harcar.
      if (err.permanent) break;
      if (logger) logger.debug({ mx: mx.host, error: err.message, msg: 'MX denemesi başarısız, sıradakine geçiliyor' });
    }
  }

  const error = lastError || new DeliveryError('teslim edilemedi', { permanent: false });
  error.attempts = attempts;
  throw error;
}

async function deliverToHost({
  host, port, rawMessage, envelopeFrom, recipient, heloName,
  logger, timeouts, localAddress, requireTls, dsnRequested,
}) {
  const socket = await connectSocket({ host, port, timeout: timeouts.connect, localAddress });
  let conn = new SmtpClientConnection(socket, { timeouts, logger, label: host });
  let tlsUsed = false;
  let tlsVerified = false;

  const fail = (reply, stage) => {
    throw new DeliveryError(`${stage}: ${reply.code} ${reply.text}`.trim(), {
      code: reply.code, permanent: reply.permanent, stage, mx: host,
    });
  };

  try {
    const greeting = await conn.readReply(timeouts.greeting);
    if (!greeting.ok) fail(greeting, 'karşılama');

    let ehlo = await conn.command(`EHLO ${heloName}`);
    if (!ehlo.ok) {
      // EHLO'yu anlamayan (çok eski) sunucu: HELO ile devam.
      const helo = await conn.command(`HELO ${heloName}`);
      if (!helo.ok) fail(helo, 'HELO');
      ehlo = helo;
    }

    let capabilities = parseCapabilities(ehlo.lines);

    if (capabilities.has('STARTTLS')) {
      const starttls = await conn.command('STARTTLS');
      if (starttls.ok) {
        const upgraded = await upgradeToTls({ socket, host, requireTls });
        tlsUsed = true;
        tlsVerified = upgraded.verified;
        conn.socket.removeAllListeners('data');
        conn.socket.removeAllListeners('error');
        conn.socket.removeAllListeners('close');
        conn = new SmtpClientConnection(upgraded.socket, { timeouts, logger, label: `${host}(tls)` });
        // TLS sonrası EHLO tekrar edilir: yetenek listesi değişebilir ve
        // RFC 3207 §4.2 bunu zorunlu kılar.
        const ehlo2 = await conn.command(`EHLO ${heloName}`);
        if (!ehlo2.ok) fail(ehlo2, 'TLS sonrası EHLO');
        capabilities = parseCapabilities(ehlo2.lines);
      } else if (requireTls) {
        fail(starttls, 'STARTTLS');
      }
    } else if (requireTls) {
      throw new DeliveryError(`${host} STARTTLS duyurmuyor ve TLS zorunlu`, { permanent: false, mx: host });
    }

    const mailParams = [];
    if (capabilities.has('8BITMIME')) mailParams.push('BODY=8BITMIME');
    if (capabilities.has('SIZE')) mailParams.push(`SIZE=${rawMessage.length}`);
    if (dsnRequested && capabilities.has('DSN')) mailParams.push('RET=HDRS');

    const mail = await conn.command(`MAIL FROM:<${envelopeFrom}>${mailParams.length ? ` ${mailParams.join(' ')}` : ''}`);
    if (!mail.ok) fail(mail, 'MAIL FROM');

    const rcptParams = dsnRequested && capabilities.has('DSN') ? ' NOTIFY=FAILURE,DELAY' : '';
    const rcpt = await conn.command(`RCPT TO:<${recipient}>${rcptParams}`);
    if (!rcpt.ok) fail(rcpt, 'RCPT TO');

    const dataReply = await conn.command('DATA');
    if (dataReply.code !== 354) fail(dataReply, 'DATA');

    const accepted = await conn.sendData(rawMessage, timeouts.data);
    if (!accepted.ok) fail(accepted, 'ileti gövdesi');

    // QUIT yanıtı beklenir ama sonucu teslimatı etkilemez: sunucu 250 dedikten
    // sonra ileti kabul edilmiştir, QUIT'te kopan bağlantı bunu geri almaz.
    await conn.command('QUIT', 10_000).catch(() => {});

    return {
      code: accepted.code,
      message: accepted.text,
      enhanced: accepted.enhanced,
      tlsUsed,
      tlsVerified,
    };
  } finally {
    conn.close();
  }
}

function connectSocket({ host, port, timeout, localAddress }) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({
      host, port,
      ...(localAddress ? { localAddress } : {}),
    });
    socket.setTimeout(timeout);
    const onError = (err) => {
      socket.destroy();
      reject(new DeliveryError(`bağlanılamadı ${host}:${port}: ${err.code || err.message}`, {
        permanent: err.code === 'ENOTFOUND', mx: host,
      }));
    };
    socket.once('error', onError);
    socket.once('timeout', () => onError(new Error('bağlantı zaman aşımı')));
    socket.once('connect', () => {
      socket.removeListener('error', onError);
      socket.setTimeout(0);
      socket.setNoDelay(true);
      resolve(socket);
    });
  });
}

function upgradeToTls({ socket, host, requireTls }) {
  return new Promise((resolve, reject) => {
    const tlsSocket = tls.connect({
      socket,
      servername: host,
      minVersion: 'TLSv1.2',
      // Doğrulama isteniyorsa katı; istenmiyorsa el sıkışma tamamlanır ve
      // doğrulama sonucu ayrıca bildirilir. İkisini karıştırmamak önemli:
      // "TLS kullandık" ile "karşı tarafı doğruladık" farklı ifadeler.
      rejectUnauthorized: !!requireTls,
    });
    const onError = (err) => {
      tlsSocket.destroy();
      reject(new DeliveryError(`TLS el sıkışması başarısız (${host}): ${err.message}`, {
        permanent: false, mx: host,
      }));
    };
    tlsSocket.once('error', onError);
    tlsSocket.once('secureConnect', () => {
      tlsSocket.removeListener('error', onError);
      resolve({ socket: tlsSocket, verified: tlsSocket.authorized === true });
    });
  });
}

function parseCapabilities(lines) {
  const set = new Set();
  for (const line of lines) {
    const token = String(line).trim().split(/\s+/)[0];
    if (token) set.add(token.toUpperCase());
  }
  return set;
}

module.exports = { deliver, resolveMailExchangers, SmtpReply, DeliveryError, SmtpClientConnection };
