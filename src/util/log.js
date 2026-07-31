'use strict';

/**
 * Bağımlılıksız yapılandırılmış kayıt (log).
 *
 * Üç kip aynı çağrıdan beslenir:
 *
 *   - GELİŞTİRME: renkli, bileşen etiketli, tek satır. Okunabilirlik önce
 *     gelir; bir posta sunucusunda hata ayıklamanın büyük kısmı "hangi
 *     bileşen ne dedi" seviyesindedir.
 *   - ÜRETİM: tek satır JSON. Toplayıcıya (journald/loki) giden biçim bu.
 *   - İZLEME (trace): protokol seviyesi. SMTP komutları, IdP istek/yanıtları,
 *     DKIM imza girdisi. Bu seviye varsayılan olarak KAPALI, çünkü açıkken
 *     jeton ve ileti içeriği kayda düşebilir.
 *
 * Neden ayrı bir seviye: önceki sürümde IdP istemcisi ve sertifika yöneticisi
 * kendi `console.log('\x1b[92m...')` bloklarını taşıyordu. Bunlar seviyeye
 * bakmıyor, JSON kipinde satırı bozuyor, maskeleme uygulamıyor ve üretimde
 * jetonları düz metin yazıyordu. Aynı bilgi burada `trace` olarak, aynı
 * maskeleme kurallarından geçerek veriliyor.
 */

const LEVELS = {
  trace: 5, debug: 10, info: 20, warn: 30, error: 40, silent: 99,
};

const LEVEL_COLOR = {
  trace: '\x1b[90m',
  debug: '\x1b[36m',
  info: '\x1b[32m',
  warn: '\x1b[33m',
  error: '\x1b[31m',
};

const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

let currentLevel = 'info';
let jsonMode = false;
let redactAddresses = false;
let colorEnabled = !!process.stdout.isTTY && process.env.NO_COLOR !== '1';

/**
 * @param {object} opts
 * @param {string} [opts.level]            trace|debug|info|warn|error|silent
 * @param {boolean} [opts.json]
 * @param {boolean} [opts.color]
 * @param {boolean} [opts.redactAddresses]
 */
function configure({ level, json, color, redactAddresses: redact } = {}) {
  if (level && LEVELS[String(level).toLowerCase()] != null) currentLevel = String(level).toLowerCase();
  if (json != null) jsonMode = !!json;
  if (redact != null) redactAddresses = !!redact;
  // Renk JSON kipinde her zaman kapalı: kaçış dizileri JSON'un içine girerse
  // toplayıcı satırı ayrıştıramaz.
  if (color != null) colorEnabled = !!color;
  if (jsonMode) colorEnabled = false;
  return { level: currentLevel, json: jsonMode, color: colorEnabled, redactAddresses };
}

function level() { return currentLevel; }

function enabled(lvl) {
  return (LEVELS[lvl] ?? 0) >= (LEVELS[currentLevel] ?? LEVELS.info);
}

function c(code) { return colorEnabled ? code : ''; }

/* ── maskeleme ─────────────────────────────────────────────── */

// Adres maskesi: bir kayıt satırı hangi kutuya ne geldiğini göstermeye yeter
// olmalı, kimin yazdığını göstermeye değil. İlk iki karakter + alan adı,
// destek için ayırt edici; günlük dosyasını okuyan biri için adres listesi
// değil.
function maskAddress(addr) {
  const s = String(addr || '');
  const at = s.indexOf('@');
  if (at <= 0) return s ? `${s.slice(0, 2)}***` : s;
  const local = s.slice(0, at);
  const domain = s.slice(at + 1);
  const head = local.slice(0, Math.min(2, local.length));
  return `${head}${local.length > 2 ? '***' : ''}@${domain}`;
}

const ADDR_KEYS = new Set([
  'from', 'to', 'rcpt', 'recipient', 'sender', 'mailbox', 'address', 'email',
  'envelopeFrom', 'envelopeTo', 'fromAddr', 'toAddr', 'mailFrom', 'rcptTo', 'authUser',
  'idpEmail', 'actorEmail', 'externalEmail', 'subjectAddress',
]);

// Bu adları taşıyan hiçbir değer kayda GİRMEZ — seviyeden bağımsız olarak.
// "yalnızca trace'te yazıyoruz" yeterli bir koruma değil: trace'i açan kişi
// genellikle bir sorunu kovalıyor ve o kaydı bir yere yapıştırıyor.
const SECRET_KEY_RE = /(secret|password|passwd|token|authorization|cookie|privatekey|apikey|api_key|clientsecret)/i;

function maskSecret(value) {
  const s = String(value == null ? '' : value);
  if (!s) return '';
  if (s.length <= 8) return '***';
  return `${s.slice(0, 4)}…${s.slice(-4)} (${s.length}b)`;
}

function redactValue(key, value) {
  if (SECRET_KEY_RE.test(key)) {
    if (value && typeof value === 'object' && !Buffer.isBuffer(value)) return '[gizli]';
    return maskSecret(value);
  }
  if (!redactAddresses) return value;
  if (typeof value === 'string' && ADDR_KEYS.has(key)) return maskAddress(value);
  if (Array.isArray(value) && ADDR_KEYS.has(key)) {
    return value.map((v) => (typeof v === 'string' ? maskAddress(v) : v));
  }
  return value;
}

function normalizeFields(fields) {
  if (fields == null) return null;
  if (fields instanceof Error) return { error: fields.message, stack: fields.stack };
  if (typeof fields === 'string') return { msg: fields };
  if (Buffer.isBuffer(fields)) return { bytes: fields.length };
  const out = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    if (v instanceof Error) { out[k] = v.message; continue; }
    out[k] = redactValue(k, v);
  }
  return out;
}

/* ── biçimlendirme ─────────────────────────────────────────── */

function bufferReplacer(_key, value) {
  if (Buffer.isBuffer(value)) {
    const head = value.toString('hex').slice(0, 48);
    return `<Buffer ${value.length}B 0x${head}${value.length > 24 ? '…' : ''}>`;
  }
  if (typeof value === 'bigint') return value.toString();
  return value;
}

function safeJson(o) {
  try { return JSON.stringify(o, bufferReplacer); } catch { return String(o); }
}

function stringify(fields) {
  const parts = [];
  for (const [k, v] of Object.entries(fields)) {
    if (k === 'msg') continue;
    if (v === null) { parts.push(`${k}=null`); continue; }
    if (Buffer.isBuffer(v)) { parts.push(`${k}=<${v.length}B>`); continue; }
    if (typeof v === 'object') { parts.push(`${k}=${safeJson(v)}`); continue; }
    const s = String(v);
    parts.push(/[\s"=]/.test(s) ? `${k}="${s.replace(/"/g, '\\"')}"` : `${k}=${s}`);
  }
  return parts.join(' ');
}

function timestamp() {
  return new Date().toISOString().slice(11, 23); // HH:MM:SS.mmm
}

/**
 * Onaltılık döküm. "Hangi bayt nereye gitti" seviyesindeki sorular —
 * DKIM imza girdisi, SMTP tel baytları, DER kodlanmış CSR — başka türlü
 * cevaplanamıyor.
 */
function hexDump(buf, { width = 16, indent = '  ', maxBytes = 512 } = {}) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return `${indent}<boş>`;
  const view = buf.length > maxBytes ? buf.subarray(0, maxBytes) : buf;
  const out = [];
  for (let i = 0; i < view.length; i += width) {
    const slice = view.subarray(i, i + width);
    const hex = [...slice].map((b) => b.toString(16).padStart(2, '0'))
      .join(' ').padEnd(width * 3 - 1, ' ');
    const ascii = [...slice].map((b) => ((b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.')).join('');
    out.push(`${indent}${c(DIM)}${i.toString(16).padStart(6, '0')}${c(RESET)}  ${hex}  ${c(DIM)}|${ascii}|${c(RESET)}`);
  }
  if (buf.length > maxBytes) out.push(`${indent}${c(DIM)}… ${buf.length - maxBytes} bayt daha${c(RESET)}`);
  return out.join('\n');
}

function emit(lvl, tag, fields) {
  if (!enabled(lvl)) return;
  const norm = normalizeFields(fields) || {};
  const stream = (lvl === 'error' || lvl === 'warn') ? process.stderr : process.stdout;

  if (jsonMode) {
    stream.write(`${safeJson({ ts: new Date().toISOString(), level: lvl, tag, ...norm })}\n`);
    return;
  }

  const color = c(LEVEL_COLOR[lvl] || '');
  const head = `${c(DIM)}${timestamp()}${c(RESET)} `
    + `${color}${c(BOLD)}${lvl.toUpperCase().padEnd(5)}${c(RESET)} `
    + `${color}[${tag}]${c(RESET)}`;
  const message = norm.msg != null ? ` ${norm.msg}` : '';
  const rest = stringify(norm);
  stream.write(`${head}${message}${rest ? ` ${c(DIM)}${rest}${c(RESET)}` : ''}\n`);
}

/**
 * Çağrı biçimleri:
 *   logger.info({ msg: 'hazır', port: 25 })
 *   logger.info('hazır', { port: 25 })
 *   logger.error(err)
 */
function coerce(a, b) {
  if (typeof a === 'string') return { msg: a, ...(b && typeof b === 'object' ? b : {}) };
  if (a instanceof Error) return { error: a.message, stack: a.stack, ...(b && typeof b === 'object' ? b : {}) };
  return a;
}

function child(tag) {
  const self = {
    trace: (a, b) => emit('trace', tag, coerce(a, b)),
    debug: (a, b) => emit('debug', tag, coerce(a, b)),
    info: (a, b) => emit('info', tag, coerce(a, b)),
    warn: (a, b) => emit('warn', tag, coerce(a, b)),
    error: (a, b) => emit('error', tag, coerce(a, b)),
    child: (sub) => child(`${tag}:${sub}`),
    enabled: (lvl) => enabled(lvl),

    /** Onaltılık döküm — yalnızca trace açıkken. */
    hex: (label, buf, opts) => {
      if (!enabled('trace')) return;
      emit('trace', tag, { msg: label, bytes: Buffer.isBuffer(buf) ? buf.length : 0 });
      process.stdout.write(`${hexDump(buf, opts)}\n`);
    },

    /**
     * Sunucudan sunucuya HTTP çağrılarının izi.
     *
     * Başlıklar ve gövde MASKELENEREK yazılır: bir jetonun tamamını kayda
     * yazmak, o kaydı okuyabilen herkese jetonu vermektir. Yine de ilk/son
     * dört karakter kalır — "doğru jetonu mu gönderdik" sorusu bununla
     * cevaplanabiliyor.
     */
    http: (direction, detail) => {
      if (!enabled('trace')) return;
      emit('trace', tag, { msg: `http ${direction}`, ...detail });
    },

    /** Süre ölçer: `const done = logger.timer('dkim'); … done({ ok: true })` */
    timer: (label) => {
      const startedAt = process.hrtime.bigint();
      return (fields = {}) => {
        const ms = Number(process.hrtime.bigint() - startedAt) / 1e6;
        emit('debug', tag, { msg: label, ms: Math.round(ms * 100) / 100, ...fields });
      };
    },
  };
  return self;
}

/** Nesnedeki başlıkları kayda uygun hâle getirir (Authorization vb. maskeli). */
function safeHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k] = SECRET_KEY_RE.test(k) ? maskSecret(v) : v;
  }
  return out;
}

/** Gövdeyi kayda uygun uzunluğa indirir. */
function snippet(value, max = 500) {
  const s = Buffer.isBuffer(value) ? value.toString('utf8') : String(value == null ? '' : value);
  if (s.length <= max) return s;
  return `${s.slice(0, max)}… (+${s.length - max} karakter)`;
}

module.exports = {
  configure,
  level,
  child,
  maskAddress,
  maskSecret,
  safeHeaders,
  snippet,
  hexDump,
  levels: LEVELS,
  trace: (tag, f) => emit('trace', tag, f),
  debug: (tag, f) => emit('debug', tag, f),
  info: (tag, f) => emit('info', tag, f),
  warn: (tag, f) => emit('warn', tag, f),
  error: (tag, f) => emit('error', tag, f),
};
