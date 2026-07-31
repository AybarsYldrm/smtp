'use strict';

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

/**
 * Gerçek zamanlı yayın: WebSocket ve SSE.
 *
 * İki taşıma da destekleniyor çünkü ihtiyaçları farklı: webmail arayüzü çift
 * yönlü konuşuyor (WS), durum API'sini kullanan bir betik ise yalnızca
 * dinliyor (SSE, tek yönlü ve ara sunuculardan daha kolay geçiyor).
 *
 * KAÇIRILAN İLETİ SORUNU. Bir istemci bağlantısını kaybettiğinde o aradaki
 * iletiler yayınlanmış olur. Bu yüzden her ileti kutu içi bir SIRA NUMARASI
 * (seq) taşıyor ve istemci yeniden bağlanırken son gördüğü numarayı
 * bildiriyor; sunucu aradakileri gönderiyor. Zaman damgasıyla yapmak, aynı
 * milisaniyede gelen iki iletiden birini kaybettirirdi.
 */

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME_BYTES = 1 * 1024 * 1024;
const PING_INTERVAL_MS = 30_000;

class RealtimeHub extends EventEmitter {
  constructor({ logger, stores, config }) {
    super();
    this.logger = logger;
    this.stores = stores;
    this.config = config;
    // mailboxRef -> Set<client>
    this.subscriptions = new Map();
    this.clients = new Set();
    this.stats = { connected: 0, totalConnections: 0, published: 0, dropped: 0 };

    this.pinger = setInterval(() => this._pingAll(), PING_INTERVAL_MS);
    if (this.pinger.unref) this.pinger.unref();
  }

  /* ── yayın ────────────────────────────────────────────────── */

  publishMessage(mailboxRef, message) {
    this.publish(mailboxRef, { type: 'message', message });
  }

  publishUpdate(mailboxRef, update) {
    this.publish(mailboxRef, { type: 'update', ...update });
  }

  publish(mailboxRef, payload) {
    const targets = this.subscriptions.get(String(mailboxRef));
    if (!targets || !targets.size) return 0;
    const frame = JSON.stringify({ ...payload, mailboxRef: String(mailboxRef), at: Date.now() });
    let sent = 0;
    for (const client of targets) {
      if (client.send(frame)) sent++;
    }
    this.stats.published += sent;
    return sent;
  }

  /** Bir kimliğin bütün kutularına yayın (ör. güvenlik uyarısı). */
  publishToSession(idpSub, payload) {
    const frame = JSON.stringify({ ...payload, at: Date.now() });
    let sent = 0;
    for (const client of this.clients) {
      if (client.idpSub === idpSub && client.send(frame)) sent++;
    }
    return sent;
  }

  _subscribe(client, mailboxRefs) {
    for (const ref of mailboxRefs) {
      const key = String(ref);
      if (!this.subscriptions.has(key)) this.subscriptions.set(key, new Set());
      this.subscriptions.get(key).add(client);
    }
    client.mailboxRefs = mailboxRefs.map(String);
  }

  _unsubscribe(client) {
    for (const ref of client.mailboxRefs || []) {
      const set = this.subscriptions.get(ref);
      if (!set) continue;
      set.delete(client);
      if (!set.size) this.subscriptions.delete(ref);
    }
    this.clients.delete(client);
    this.stats.connected = this.clients.size;
  }

  _pingAll() {
    const now = Date.now();
    for (const client of this.clients) {
      // Yanıt vermeyen bağlantı kapatılır: TCP bir bağlantının karşı tarafı
      // yok olduğunda bunu kendiliğinden fark etmiyor ve soket sonsuza kadar
      // açık kalıyor.
      if (client.lastSeenAt && now - client.lastSeenAt > PING_INTERVAL_MS * 3) {
        this.logger.debug({ msg: 'yanıtsız istemci kapatıldı' });
        client.close();
        continue;
      }
      client.ping();
    }
  }

  /* ── WebSocket ────────────────────────────────────────────── */

  /**
   * HTTP upgrade isteğini karşılar.
   * @param {object} p
   * @param {object} p.session   çözülmüş oturum (yoksa bağlantı reddedilir)
   */
  handleUpgrade({ req, socket, head, session }) {
    if (!session) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return null;
    }
    const key = req.headers['sec-websocket-key'];
    if (!key || String(req.headers.upgrade || '').toLowerCase() !== 'websocket') {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return null;
    }

    const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
    socket.write([
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${accept}`,
      '', '',
    ].join('\r\n'));
    socket.setNoDelay(true);

    const client = new WebSocketClient({ socket, session, hub: this, logger: this.logger });
    this.clients.add(client);
    this.stats.connected = this.clients.size;
    this.stats.totalConnections++;

    const mailboxRefs = (session.mailboxes || []).map((m) => m.ref);
    this._subscribe(client, mailboxRefs);

    client.send(JSON.stringify({
      type: 'hello',
      mailboxes: session.mailboxes || [],
      email: session.idpEmail,
      isAdmin: !!session.isAdmin,
      at: Date.now(),
    }));

    return client;
  }

  /** İstemciden gelen komutlar. */
  async handleClientMessage(client, raw) {
    let msg;
    try { msg = JSON.parse(raw); }
    catch { return; }
    client.lastSeenAt = Date.now();

    if (msg.type === 'ping') { client.send(JSON.stringify({ type: 'pong', at: Date.now() })); return; }

    if (msg.type === 'subscribe') {
      // Yalnızca oturumun erişebildiği kutulara abone olunabilir: istemcinin
      // istediği kutuya abone etmek, başkasının postasını yayınlamak olur.
      const allowed = new Set((client.session.mailboxes || []).map((m) => m.ref));
      const requested = [].concat(msg.mailboxRefs || []).map(String).filter((r) => allowed.has(r));
      this._unsubscribe(client);
      this.clients.add(client);
      this._subscribe(client, requested);
      client.send(JSON.stringify({ type: 'subscribed', mailboxRefs: requested }));
      return;
    }

    if (msg.type === 'catchup') {
      const allowed = (client.session.mailboxes || []).find((m) => m.ref === String(msg.mailboxRef));
      if (!allowed) return;
      const missed = await this.stores.messages.since({
        mailboxRef: msg.mailboxRef,
        seq: Number(msg.sinceSeq || 0),
        limit: 200,
      });
      client.send(JSON.stringify({
        type: 'catchup',
        mailboxRef: String(msg.mailboxRef),
        messages: missed,
        // İstemci bir sonraki yeniden bağlanmada bu numaradan devam eder.
        lastSeq: missed.length ? missed[missed.length - 1].seq : Number(msg.sinceSeq || 0),
      }));
    }
  }

  /* ── SSE ──────────────────────────────────────────────────── */

  /**
   * Sunucu gönderimli olaylar. Durum API'sini kullanan betikler için:
   * WebSocket el sıkışması gerektirmez, yeniden bağlanmayı tarayıcı yapar.
   */
  handleSse(ctx, session) {
    const { res } = ctx;
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      // Ters proxy'nin tamponlaması olayları biriktirip toplu gönderir ve
      // "gerçek zamanlı" olmaktan çıkarır.
      'x-accel-buffering': 'no',
    });
    ctx.responded = true;

    const client = new SseClient({ res, session, hub: this });
    this.clients.add(client);
    this.stats.connected = this.clients.size;
    this.stats.totalConnections++;
    this._subscribe(client, (session.mailboxes || []).map((m) => m.ref));

    client.send(JSON.stringify({ type: 'hello', mailboxes: session.mailboxes || [], at: Date.now() }));

    ctx.req.on('close', () => { this._unsubscribe(client); });
    return client;
  }

  close() {
    clearInterval(this.pinger);
    for (const client of [...this.clients]) client.close();
  }

  snapshot() {
    return {
      ...this.stats,
      subscriptions: this.subscriptions.size,
      clients: [...this.clients].map((c) => ({ kind: c.kind, mailboxes: (c.mailboxRefs || []).length })),
    };
  }
}

class WebSocketClient {
  constructor({ socket, session, hub, logger }) {
    this.kind = 'ws';
    this.socket = socket;
    this.session = session;
    this.idpSub = session.idpSub;
    this.hub = hub;
    this.logger = logger;
    this.buffer = Buffer.alloc(0);
    this.closed = false;
    this.lastSeenAt = Date.now();
    this.mailboxRefs = [];

    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('close', () => this._onClose());
    socket.on('error', () => this._onClose());
  }

  _onClose() {
    if (this.closed) return;
    this.closed = true;
    this.hub._unsubscribe(this);
  }

  _onData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (!this.closed) {
      const frame = decodeFrame(this.buffer);
      if (!frame) break;
      if (frame.error) { this.close(); return; }
      this.buffer = frame.rest;

      if (frame.opcode === 0x8) { this.close(); return; }
      if (frame.opcode === 0x9) { this._writeFrame(0xa, frame.payload); this.lastSeenAt = Date.now(); continue; }
      if (frame.opcode === 0xa) { this.lastSeenAt = Date.now(); continue; }
      if (frame.opcode === 0x1 || frame.opcode === 0x0) {
        this.hub.handleClientMessage(this, frame.payload.toString('utf8')).catch((err) => {
          this.logger.debug({ error: err.message, msg: 'WS istemci iletisi işlenemedi' });
        });
      }
    }
  }

  send(text) {
    if (this.closed) return false;
    return this._writeFrame(0x1, Buffer.from(text, 'utf8'));
  }

  ping() { if (!this.closed) this._writeFrame(0x9, Buffer.alloc(0)); }

  _writeFrame(opcode, payload) {
    if (this.closed) return false;
    try {
      this.socket.write(encodeFrame(opcode, payload));
      return true;
    } catch {
      this.close();
      return false;
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    try { this.socket.destroy(); } catch { /* yok say */ }
    this.hub._unsubscribe(this);
  }
}

class SseClient {
  constructor({ res, session, hub }) {
    this.kind = 'sse';
    this.res = res;
    this.session = session;
    this.idpSub = session.idpSub;
    this.hub = hub;
    this.closed = false;
    this.lastSeenAt = Date.now();
    this.mailboxRefs = [];
    this.eventId = 0;
  }

  send(text) {
    if (this.closed) return false;
    try {
      this.res.write(`id: ${++this.eventId}\ndata: ${text}\n\n`);
      return true;
    } catch {
      this.close();
      return false;
    }
  }

  ping() {
    if (this.closed) return;
    // SSE yorum satırı: bağlantıyı canlı tutar, istemcide olay üretmez.
    try { this.res.write(': ping\n\n'); this.lastSeenAt = Date.now(); }
    catch { this.close(); }
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    try { this.res.end(); } catch { /* yok say */ }
    this.hub._unsubscribe(this);
  }
}

/* ── WebSocket çerçeveleme (RFC 6455) ──────────────────────── */

function encodeFrame(opcode, payload) {
  const length = payload.length;
  let header;
  if (length < 126) {
    header = Buffer.alloc(2);
    header[1] = length;
  } else if (length < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }
  header[0] = 0x80 | opcode; // FIN + opcode
  return Buffer.concat([header, payload]);
}

function decodeFrame(buffer) {
  if (buffer.length < 2) return null;
  const masked = (buffer[1] & 0x80) !== 0;
  // İstemciden gelen her çerçeve maskeli OLMAK ZORUNDA (RFC 6455 §5.1);
  // maskesiz çerçeve protokol hatasıdır ve ara sunucu zehirlenmesine karşı
  // koruma tam olarak buradan gelir.
  if (!masked) return { error: 'unmasked' };

  const opcode = buffer[0] & 0x0f;
  let length = buffer[1] & 0x7f;
  let offset = 2;

  if (length === 126) {
    if (buffer.length < 4) return null;
    length = buffer.readUInt16BE(2);
    offset = 4;
  } else if (length === 127) {
    if (buffer.length < 10) return null;
    const big = buffer.readBigUInt64BE(2);
    if (big > BigInt(MAX_FRAME_BYTES)) return { error: 'too_large' };
    length = Number(big);
    offset = 10;
  }
  if (length > MAX_FRAME_BYTES) return { error: 'too_large' };
  if (buffer.length < offset + 4 + length) return null;

  const mask = buffer.subarray(offset, offset + 4);
  const payload = Buffer.allocUnsafe(length);
  buffer.copy(payload, 0, offset + 4, offset + 4 + length);
  for (let i = 0; i < length; i++) payload[i] ^= mask[i & 3];

  return { opcode, payload, rest: buffer.subarray(offset + 4 + length) };
}

module.exports = { RealtimeHub, encodeFrame, decodeFrame };
