'use strict';

const crypto = require('node:crypto');
const net = require('node:net');
const tls = require('node:tls');

const { normalizeAddress, splitAddress, asciiFold } = require('../util/encoding');

/**
 * SMTP oturum durum makinesi (RFC 5321).
 *
 * Önceki sürüme göre değişen ve her biri gerçek bir hataya karşılık gelen
 * noktalar:
 *
 *   1. VERİ BAYT OLARAK OKUNUYOR. Önceki sürüm soketi
 *      `setEncoding('utf8')` ile açıyordu; bu, base64 olmayan (8bit) ekleri
 *      ve UTF-8 dışı gövdeleri diske yazılmadan önce bozuyordu. Kayıp geri
 *      alınamaz çünkü bozulma ayrıştırmadan önce oluyor.
 *
 *   2. ÇOK ALICI. Önceki sürümde `sess.rcptTo = rcpt` her RCPT TO'da üzerine
 *      yazıyordu: üç alıcıya gönderilen bir ileti yalnızca son alıcıya
 *      teslim ediliyor, diğer ikisi 250 yanıtı almış olmasına rağmen sessizce
 *      kayboluyordu. Alıcılar artık liste.
 *
 *   3. NOKTA AÇMA (dot-unstuffing). Satır başındaki fazladan nokta
 *      kaldırılmazsa, gövdesinde "." ile başlayan satır olan her ileti bozuk
 *      teslim edilir — ve DKIM gövde özeti de bozulur.
 *
 *   4. PROXY PROTOKOLÜ YALNIZCA GÜVENİLEN KAYNAKTAN. Önceki sürüm ilk satır
 *      "PROXY " ile başlıyorsa istemcinin bildirdiği IP'yi kabul ediyordu:
 *      herhangi bir istemci böylece IP tabanlı her kısıtlamayı (ban listesi,
 *      SPF değerlendirmesi) atlatabilirdi.
 *
 *   5. SATIR UZUNLUĞU SINIRI. RFC 5321 §4.5.3.1.6: komut satırı 512, metin
 *      satırı 1000 sekizli. Sınırsız satır, tek bağlantıyla belleği
 *      tüketmenin en kolay yolu.
 */

const MAX_COMMAND_LINE = 512;
const MAX_TEXT_LINE = 4096; // hoşgörülü: bazı istemciler uzun başlık satırı yazar
const MAX_UNRECOGNIZED_COMMANDS = 10;
const MAX_RSET = 30;

const MODE = { MX: 'mx', SUBMISSION: 'submission' };

class SmtpSession {
  /**
   * @param {net.Socket|tls.TLSSocket} socket
   * @param {object} opts
   * @param {string} opts.mode                 'mx' | 'submission'
   * @param {boolean} opts.secure              bağlantı zaten TLS mi
   * @param {boolean} opts.allowStarttls
   * @param {boolean} opts.allowAuth
   * @param {object} opts.handlers             { authenticate, validateRecipient, handleMessage }
   * @param {object} opts.config
   * @param {object} opts.logger
   */
  constructor(socket, opts) {
    this.socket = socket;
    this.opts = opts;
    this.config = opts.config;
    this.logger = opts.logger;
    this.handlers = opts.handlers;
    this.id = crypto.randomBytes(6).toString('hex');

    this.mode = opts.mode;
    this.secure = !!opts.secure;
    this.tlsCipher = socket.getCipher ? (socket.getCipher() || null) : null;

    this.remoteAddress = normalizeIp(socket.remoteAddress);
    this.remotePort = socket.remotePort;
    this.proxiedFrom = null;

    this.heloName = '';
    this.esmtp = false;
    this.authenticated = false;
    this.authUser = '';
    this.authMailbox = null;

    this.mailFrom = null;
    this.recipients = [];
    this.declaredSize = 0;
    this.smtpUtf8 = false;
    this.bodyType = '7BIT';

    this.dataMode = false;
    this.dataChunks = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;

    this.authStage = null;
    this.buffer = Buffer.alloc(0);
    this.closed = false;
    this.processing = false
    this.firstLineSeen = false;
    this.unrecognizedCount = 0;
    this.rsetCount = 0;
    this.messageCount = 0;
    this.startedAt = Date.now();

    this._bindSocket();
  }

  get peerIp() { return this.proxiedFrom ? this.proxiedFrom.ip : this.remoteAddress; }
  get peerLabel() { return `${this.peerIp}:${this.proxiedFrom ? this.proxiedFrom.port : this.remotePort}`; }

  _bindSocket() {
    // Kodlama AYARLANMIYOR: gelen veri Buffer olarak kalmalı.
    this.socket.setTimeout(this.config.smtp.commandTimeoutMs);
    this.socket.on('data', (chunk) => this._onData(chunk));
    this.socket.on('timeout', () => {
      this.write('421 4.4.2 Zaman aşımı, bağlantı kapatılıyor');
      this.end();
    });
    this.socket.on('error', (err) => {
      // ECONNRESET sıradan: istemciler QUIT yazmadan kapatır.
      if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
        this.logger.debug({ session: this.id, peer: this.peerLabel, error: err.message, msg: 'soket hatası' });
      }
      this.closed = true;
    });
    this.socket.on('close', () => {
      this.closed = true;
      if (this.opts.onClose) this.opts.onClose(this);
      this.logger.debug({
        session: this.id, peer: this.peerLabel, messages: this.messageCount,
        durationMs: Date.now() - this.startedAt, msg: 'bağlantı kapandı',
      });
    });
  }

  write(line) {
    if (this.closed) return;
    // Tele ASCII verilir: SMTP yanıt metni ASCII'dir ve UTF-8 yazmak,
    // istemcinin yanıtı latin1 çözüp bozuk göstermesine yol açar.
    const wire = asciiFold(line);
    this.logger.debug({ session: this.id, msg: `> ${wire}` });
    try { this.socket.write(`${wire}\r\n`, 'latin1'); } catch { /* kapanmış soket */ }
  }

  writeMulti(lines) {
    lines.forEach((line, i) => {
      const last = i === lines.length - 1;
      const code = line.slice(0, 3);
      const rest = line.slice(3).trim();
      this.write(`${code}${last ? ' ' : '-'}${rest}`);
    });
  }

  end() {
    if (this.closed) return;
    try { this.socket.end(); } catch { /* yok say */ }
  }

  greet() {
    this.write(`220 ${this.config.hostname} ESMTP Fitfak; ${new Date().toUTCString()}`);
  }

  async _onData(chunk) {
    if (this.closed) return;
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;

    // Eğer halihazırda bir komut işleniyorsa, yeni gelen paketi sadece buffer'a ekle ve çık.
    // İşlemi biten döngü, buffer'daki yeni veriyi görüp kaldığı yerden devam edecektir.
    if (this.processing) return;
    this.processing = true;

    try {
      while (!this.closed) {
        const idx = this.buffer.indexOf(0x0a);
        if (idx === -1) break;
        let line = this.buffer.subarray(0, idx);
        this.buffer = this.buffer.subarray(idx + 1);
        if (line.length && line[line.length - 1] === 0x0d) line = line.subarray(0, line.length - 1);
        
        // Komutların asenkron işlemlerinin birbirini beklemesini SAĞLADIK
        if (this.dataMode) await this._onDataLine(line);
        else await this._onCommandLine(line);
        
        if (this.handedOff) return;
      }
      
      const limit = this.dataMode ? MAX_TEXT_LINE * 4 : MAX_COMMAND_LINE * 4;
      if (this.buffer.length > limit) {
        this.write(this.dataMode ? '500 5.5.2 Sat ok uzun' : '500 5.5.2 Komut sat ok uzun');
        this.buffer = Buffer.alloc(0);
        this.end();
      }
    } finally {
      this.processing = false;
    }
  }

  async _onDataLine(lineBuf) {
    if (lineBuf.length === 1 && lineBuf[0] === 0x2e) {
      await this._finishData();
      return;
    }
    // Nokta açma: satır başındaki fazladan nokta kaldırılır (RFC 5321 §4.5.2).
    const body = (lineBuf.length && lineBuf[0] === 0x2e) ? lineBuf.subarray(1) : lineBuf;
    const withCrlf = Buffer.concat([body, Buffer.from('\r\n', 'latin1')]);
    this.dataBytes += withCrlf.length;

    if (this.dataBytes > this.config.smtp.maxMessageBytes) {
      // Bağlantı hemen kesilmez: istemci noktayı gönderene kadar okumaya
      // devam edip sonra 552 döndürmek, istemcinin hatayı anlamasını sağlar.
      // Baytlar biriktirilmez.
      this.dataTooLarge = true;
      return;
    }
    this.dataChunks.push(withCrlf);
  }

  async _finishData() {
    this.dataMode = false;
    this.socket.setTimeout(this.config.smtp.commandTimeoutMs);
    const chunks = this.dataChunks;
    const bytes = this.dataBytes;
    const tooLarge = this.dataTooLarge;
    this.dataChunks = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;

    if (tooLarge) {
      this.write(`552 5.3.4 İleti çok büyük (en fazla ${this.config.smtp.maxMessageBytes} bayt)`);
      this._resetTransaction();
      return;
    }

    const raw = Buffer.concat(chunks);
    const envelope = {
      mailFrom: this.mailFrom,
      recipients: this.recipients.slice(),
      sizeBytes: bytes,
      heloName: this.heloName,
      remoteIp: this.peerIp,
      secure: this.secure,
      tlsCipher: this.tlsCipher,
      authenticated: this.authenticated,
      authUser: this.authUser,
      authMailbox: this.authMailbox,
      mode: this.mode,
      sessionId: this.id,
      receivedAt: Date.now(),
      smtpUtf8: this.smtpUtf8,
      bodyType: this.bodyType,
    };
    this._resetTransaction();

    // Soket duraklatılır: işleme sırasında gelen boru hattı komutları,
    // sonucu yazmadan önce işlenmeye başlamamalı.
    this.socket.pause();
    try {
      const result = await this.handlers.handleMessage({ raw, envelope, session: this });
      const lines = [].concat(result && result.reply ? result.reply : '250 2.0.0 Kabul edildi');
      this.writeMulti(lines);
    } catch (err) {
      this.logger.error({ session: this.id, error: err.message, stack: err.stack, msg: 'ileti işlenemedi' });
      this.write('451 4.3.0 Geçici hata, lütfen tekrar deneyin');
    } finally {
      this.socket.resume();
    }
  }

  _resetTransaction() {
    this.mailFrom = null;
    this.recipients = [];
    this.declaredSize = 0;
    this.smtpUtf8 = false;
    this.bodyType = '7BIT';
    this.dataMode = false;
    this.dataChunks = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
  }

  async _onCommandLine(lineBuf) {
    const line = lineBuf.toString('latin1');

    if (!this.firstLineSeen) {
      this.firstLineSeen = true;
      if (line.startsWith('PROXY ')) {
        this._handleProxyLine(line);
        return;
      }
    }

    // AUTH alt diyaloğu, komut ayrıştırmasından ÖNCE: base64 verisi bir
    // komut gibi görünebilir.
    if (this.authStage) { await this._handleAuthContinuation(line); return; }

    if (line.length > MAX_COMMAND_LINE) { this.write('500 5.5.2 Komut satırı çok uzun'); return; }
    this.logger.debug({ session: this.id, msg: `< ${line.slice(0, 200)}` });

    const spaceIdx = line.indexOf(' ');
    const verb = (spaceIdx === -1 ? line : line.slice(0, spaceIdx)).toUpperCase();
    const rest = spaceIdx === -1 ? '' : line.slice(spaceIdx + 1);

    switch (verb) {
      case 'EHLO': return this._handleEhlo(rest, true);
      case 'HELO': return this._handleEhlo(rest, false);
      case 'STARTTLS': return this._handleStarttls();
      case 'AUTH': return this._handleAuth(rest);
      case 'MAIL': return this._handleMail(rest);
      case 'RCPT': return this._handleRcpt(rest);
      case 'DATA': return this._handleDataCommand();
      case 'RSET':
        if (++this.rsetCount > MAX_RSET) { this.write('421 4.7.0 Çok fazla RSET'); return this.end(); }
        this._resetTransaction();
        return this.write('250 2.0.0 Sıfırlandı');
      case 'NOOP': return this.write('250 2.0.0 Tamam');
      case 'QUIT':
        this.write(`221 2.0.0 ${this.config.hostname} kapanıyor`);
        return this.end();
      case 'VRFY':
        // Adres doğrulama KAPALI: bir adresin var olup olmadığını söylemek,
        // spam gönderene ücretsiz adres doğrulama hizmeti vermektir.
        return this.write('252 2.5.2 Adres doğrulanamaz ama iletiyi kabul etmeyi denerim');
      case 'EXPN':
        return this.write('502 5.5.1 EXPN desteklenmiyor');
      case 'HELP':
        return this.write(`214 2.0.0 ${this.config.hostname} — desteklenen komutlar: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT${this.opts.allowAuth ? ' AUTH' : ''}${this.opts.allowStarttls && !this.secure ? ' STARTTLS' : ''}`);
      default:
        if (++this.unrecognizedCount >= MAX_UNRECOGNIZED_COMMANDS) {
          this.write('421 4.7.0 Çok fazla tanınmayan komut');
          return this.end();
        }
        return this.write('500 5.5.1 Komut tanınmadı');
    }
  }

  _handleProxyLine(line) {
    const trusted = this.config.smtp.trustedProxies.includes(this.remoteAddress);
    if (!trusted) {
      // Güvenilmeyen kaynaktan PROXY: bağlantı kesilir. Yok sayıp devam
      // etmek, istemcinin ilk komutunun kaybolmasına yol açardı.
      this.logger.warn({ session: this.id, peer: this.remoteAddress, msg: 'güvenilmeyen kaynaktan PROXY başlığı' });
      this.write('421 4.7.0 PROXY başlığı kabul edilmiyor');
      this.end();
      return;
    }
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 6 && (parts[1] === 'TCP4' || parts[1] === 'TCP6')) {
      this.proxiedFrom = { ip: normalizeIp(parts[2]), port: Number(parts[4]) || 0 };
      this.logger.debug({ session: this.id, peer: this.peerLabel, msg: 'PROXY başlığı kabul edildi' });
    }
  }

  _handleEhlo(rest, esmtp) {
    const name = String(rest || '').trim();
    if (!name) { this.write('501 5.5.4 EHLO bir alan adı gerektirir'); return; }
    this.heloName = name;
    this.esmtp = esmtp;
    this._resetTransaction();

    if (!esmtp) { this.write(`250 ${this.config.hostname}`); return; }

    const lines = [
      `250 ${this.config.hostname} merhaba ${this.peerIp}`,
      `250 SIZE ${this.config.smtp.maxMessageBytes}`,
      '250 8BITMIME',
      '250 PIPELINING',
      '250 ENHANCEDSTATUSCODES',
      '250 SMTPUTF8',
      '250 CHUNKING-NOT-SUPPORTED',
    ].filter((l) => !l.includes('CHUNKING-NOT'));

    if (this.opts.allowStarttls && !this.secure) lines.push('250 STARTTLS');
    // AUTH yalnızca TLS altında duyurulur: düz metin bir kanalda AUTH
    // duyurmak, istemcinin parolasını açık ağa yazmasını davet etmektir.
    if (this.opts.allowAuth && (this.secure || !this.config.smtp.requireTlsForAuth)) {
      lines.push('250 AUTH PLAIN LOGIN');
    }
    lines.push('250 DSN');
    this.writeMulti(lines);
  }

  _handleStarttls() {
    if (!this.opts.allowStarttls || this.secure || !this.opts.tlsOptions) {
      this.write('454 4.7.0 TLS şu anda kullanılamıyor');
      return;
    }
    this.write('220 2.0.0 TLS el sıkışmasına hazır');

    // Devir teslim: bu örnek soketi bırakır, yeni bir oturum TLS soketini
    // devralır. TLS sonrası durum SIFIRLANIR (RFC 3207 §4.2) — kimlik
    // doğrulama ve zarf dâhil. Taşımak, TLS öncesi yapılmış bir
    // doğrulamanın TLS sonrası geçerli sayılması olurdu.
    this.handedOff = true;
    this.socket.removeAllListeners('data');
    this.socket.removeAllListeners('timeout');
    this.socket.removeAllListeners('error');
    this.socket.removeAllListeners('close');
    this.socket.setTimeout(0);

    const tlsSocket = new tls.TLSSocket(this.socket, {
      isServer: true,
      secureContext: tls.createSecureContext(this.opts.tlsOptions),
    });
    tlsSocket.on('error', (err) => {
      this.logger.debug({ session: this.id, error: err.message, msg: 'STARTTLS el sıkışması başarısız' });
    });
    tlsSocket.once('secure', () => {
      this.logger.debug({ session: this.id, cipher: tlsSocket.getCipher()?.name, msg: 'STARTTLS tamamlandı' });
    });

    const next = new SmtpSession(tlsSocket, {
      ...this.opts,
      secure: true,
      allowStarttls: false,
      // Devredilen bağlantı sayacı zaten alınmış; kapanışta iki kez
      // düşürülmemesi için yalnızca yeni oturum bildirir.
      onClose: this.opts.onClose,
    });
    next.proxiedFrom = this.proxiedFrom;
    next.heloName = '';
    this.opts.onHandoff?.(this, next);
  }

  async _handleAuth(rest) {
    if (!this.opts.allowAuth) { this.write('503 5.5.1 Bu portta kimlik doğrulama yok'); return; }
    if (this.config.smtp.requireTlsForAuth && !this.secure) {
      this.write('538 5.7.11 Kimlik doğrulama için şifreli kanal gerekli (STARTTLS)');
      return;
    }
    if (this.authenticated) { this.write('503 5.5.1 Zaten kimlik doğrulandı'); return; }

    const banned = await this.handlers.isAuthBlocked?.(this.peerIp);
    if (banned) {
      this.write('421 4.7.0 Çok fazla başarısız deneme, sonra tekrar deneyin');
      this.end();
      return;
    }

    const parts = String(rest || '').trim().split(/\s+/);
    const mechanism = (parts[0] || '').toUpperCase();

    if (mechanism === 'PLAIN') {
      if (parts[1]) return this._verifyPlain(parts[1]);
      this.authStage = { type: 'PLAIN' };
      this.write('334 ');
      return;
    }
    if (mechanism === 'LOGIN') {
      this.authStage = { type: 'LOGIN', step: 'username' };
      this.write(`334 ${Buffer.from('Username:').toString('base64')}`);
      return;
    }
    this.write('504 5.5.4 Desteklenmeyen kimlik doğrulama yöntemi');
  }

  async _handleAuthContinuation(line) {
    const stage = this.authStage;
    const trimmed = line.trim();
    if (trimmed === '*') { this.authStage = null; this.write('501 5.7.0 Kimlik doğrulama iptal edildi'); return; }

    if (stage.type === 'PLAIN') {
      this.authStage = null;
      return this._verifyPlain(trimmed);
    }
    if (stage.type === 'LOGIN') {
      if (stage.step === 'username') {
        stage.username = safeB64(trimmed);
        stage.step = 'password';
        this.write(`334 ${Buffer.from('Password:').toString('base64')}`);
        return;
      }
      const username = stage.username;
      const password = safeB64(trimmed);
      this.authStage = null;
      return this._completeAuth(username, password);
    }
    this.authStage = null;
    this.write('501 5.5.4 Kimlik doğrulama akışı bozuk');
  }

  _verifyPlain(token) {
    const decoded = safeB64(token);
    // authzid \0 authcid \0 passwd
    const segments = decoded.split('\0');
    if (segments.length < 3) { this.write('501 5.5.4 Bozuk AUTH PLAIN verisi'); return; }
    return this._completeAuth(segments[1], segments[2]);
  }

  async _completeAuth(username, password) {
    const result = await this.handlers.authenticate({
      username, password, ip: this.peerIp, session: this,
    });
    if (result && result.ok) {
      this.authenticated = true;
      this.authUser = result.username || username;
      this.authMailbox = result.mailbox || null;
      this.logger.info({ session: this.id, peer: this.peerIp, authUser: this.authUser, msg: 'kimlik doğrulandı' });
      this.write('235 2.7.0 Kimlik doğrulama başarılı');
      return;
    }
    const blocked = result && result.blocked;
    this.logger.warn({
      session: this.id, peer: this.peerIp, authUser: username,
      reason: result ? result.reason : 'unknown', msg: 'kimlik doğrulama başarısız',
    });
    if (blocked) {
      this.write('421 4.7.0 Çok fazla başarısız deneme, bağlantı kapatılıyor');
      this.end();
      return;
    }
    // Sebep AYRIŞTIRILMIYOR: "böyle kullanıcı yok" ile "parola yanlış"ı
    // ayırmak, geçerli adres listesi çıkarmayı mümkün kılar.
    this.write('535 5.7.8 Kimlik bilgileri geçersiz');
  }

  _handleMail(rest) {
    if (!this.heloName) { this.write('503 5.5.1 Önce EHLO gönderin'); return; }
    if (this.mailFrom) { this.write('503 5.5.1 MAIL komutu zaten verildi'); return; }

    const m = String(rest || '').match(/^FROM:\s*(<[^>]*>|[^\s]+)(.*)$/i);
    if (!m) { this.write('501 5.5.4 MAIL FROM sözdizimi hatalı'); return; }

    const address = parsePath(m[1]);
    if (address === null) { this.write('501 5.1.7 Gönderen adresi geçersiz'); return; }
    const params = parseParams(m[2]);

    if (params.SIZE) {
      const declared = Number(params.SIZE);
      if (Number.isFinite(declared) && declared > this.config.smtp.maxMessageBytes) {
        // Boyut önceden bildirilmişse iletiyi hiç almadan reddetmek, hem
        // bant genişliği hem de istemciye net bir hata anlamına gelir.
        this.write(`552 5.3.4 Bildirilen boyut sınırı aşıyor (en fazla ${this.config.smtp.maxMessageBytes})`);
        return;
      }
      this.declaredSize = declared;
    }
    if (params.SMTPUTF8 !== undefined) this.smtpUtf8 = true;
    if (params.BODY) this.bodyType = String(params.BODY).toUpperCase();

    if (this.mode === MODE.SUBMISSION && !this.authenticated) {
      this.write('530 5.7.0 Kimlik doğrulama gerekli');
      return;
    }

    this.mailFrom = address;
    this.recipients = [];
    this.write('250 2.1.0 Gönderen kabul edildi');
  }

  async _handleRcpt(rest) {
    if (!this.mailFrom) { this.write('503 5.5.1 Önce MAIL FROM gönderin'); return; }
    if (this.recipients.length >= this.config.smtp.maxRecipients) {
      this.write(`452 4.5.3 Alıcı sayısı sınırı (${this.config.smtp.maxRecipients})`);
      return;
    }
    const m = String(rest || '').match(/^TO:\s*(<[^>]*>|[^\s]+)(.*)$/i);
    if (!m) { this.write('501 5.5.4 RCPT TO sözdizimi hatalı'); return; }

    const address = parsePath(m[1]);
    if (!address) { this.write('501 5.1.3 Alıcı adresi geçersiz'); return; }
    const params = parseParams(m[2]);

    const verdict = await this.handlers.validateRecipient({
      address, session: this, params,
    });
    if (!verdict.accept) {
      this.write(verdict.reply || '550 5.1.1 Böyle bir alıcı yok');
      return;
    }
    if (this.recipients.some((r) => r.address === address)) {
      // Aynı alıcı iki kez: kabul edilir ama tek kez teslim edilir. Reddetmek
      // gereksiz; iki kopya teslim etmek ise yanlış.
      this.write('250 2.1.5 Alıcı zaten listede');
      return;
    }
    this.recipients.push({
      address,
      mailbox: verdict.mailbox || null,
      local: !!verdict.local,
      dsn: params.NOTIFY ? String(params.NOTIFY) : null,
      orcpt: params.ORCPT ? String(params.ORCPT) : null,
    });
    this.write('250 2.1.5 Alıcı kabul edildi');
  }

  _handleDataCommand() {
    if (!this.mailFrom) { this.write('503 5.5.1 Önce MAIL FROM gönderin'); return; }
    if (!this.recipients.length) { this.write('503 5.5.1 Alıcı yok'); return; }
    this.write('354 Veriyi girin, <CRLF>.<CRLF> ile bitirin');
    this.dataMode = true;
    this.dataChunks = [];
    this.dataBytes = 0;
    this.dataTooLarge = false;
    this.socket.setTimeout(this.config.smtp.dataTimeoutMs);
  }
}

/** `<a@b>` ya da `a@b` -> normalize adres. Boş yol (`<>`) '' döner. */
function parsePath(token) {
  let s = String(token || '').trim();
  if (s === '<>') return '';
  if (s.startsWith('<') && s.endsWith('>')) s = s.slice(1, -1);
  s = s.trim();
  if (!s) return '';
  // Kaynak yönlendirme (@a,@b:c@d) tarihsel ve kötüye kullanılıyor: yalnızca
  // son adres alınır (RFC 5321 §4.1.1.3 bunu önerir).
  const colon = s.lastIndexOf(':');
  if (s.startsWith('@') && colon > 0) s = s.slice(colon + 1);
  const normalized = normalizeAddress(s);
  if (!normalized.includes('@')) return null;
  const { localPart, domain } = splitAddress(normalized);
  if (!localPart || !domain || !domain.includes('.')) return null;
  if (/[\s<>",;\\]/.test(normalized)) return null;
  return normalized;
}

function parseParams(rest) {
  const out = {};
  for (const token of String(rest || '').trim().split(/\s+/).filter(Boolean)) {
    const eq = token.indexOf('=');
    if (eq === -1) out[token.toUpperCase()] = undefined;
    else out[token.slice(0, eq).toUpperCase()] = token.slice(eq + 1);
  }
  return out;
}

function safeB64(s) {
  try { return Buffer.from(String(s || ''), 'base64').toString('utf8'); }
  catch { return ''; }
}

function normalizeIp(ip) {
  const s = String(ip || '').trim();
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

module.exports = { SmtpSession, MODE, parsePath, parseParams, normalizeIp };
