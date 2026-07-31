'use strict';

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 99 };

let currentLevel = 'info';
let jsonMode = false;
let redactAddresses = false;

function configure({ level, json, redactAddresses: redact } = {}) {
  if (level && LEVELS[level] != null) currentLevel = level;
  if (json != null) jsonMode = !!json;
  if (redact != null) redactAddresses = !!redact;
}

function enabled(level) {
  return (LEVELS[level] ?? 0) >= (LEVELS[currentLevel] ?? 20);
}

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
]);

function redactValue(key, value) {
  if (!redactAddresses) return value;
  if (typeof value === 'string' && ADDR_KEYS.has(key)) return maskAddress(value);
  if (Array.isArray(value) && ADDR_KEYS.has(key)) return value.map((v) => (typeof v === 'string' ? maskAddress(v) : v));
  return value;
}

function normalizeFields(fields) {
  if (fields == null) return null;
  if (fields instanceof Error) return { error: fields.message, stack: fields.stack };
  if (typeof fields === 'string') return { msg: fields };
  const out = {};
  for (const [k, v] of Object.entries(fields)) {
    if (v === undefined) continue;
    out[k] = v instanceof Error ? v.message : redactValue(k, v);
  }
  return out;
}

function stringify(fields) {
  const parts = [];
  for (const [k, v] of Object.entries(fields)) {
    if (v === null) { parts.push(`${k}=null`); continue; }
    if (typeof v === 'object') { parts.push(`${k}=${safeJson(v)}`); continue; }
    const s = String(v);
    parts.push(/[\s"=]/.test(s) ? `${k}="${s.replace(/"/g, '\\"')}"` : `${k}=${s}`);
  }
  return parts.join(' ');
}

function safeJson(o) {
  try { return JSON.stringify(o); } catch { return String(o); }
}

function emit(level, tag, fields) {
  if (!enabled(level)) return;
  const norm = normalizeFields(fields) || {};
  if (jsonMode) {
    const line = safeJson({ ts: new Date().toISOString(), level, tag, ...norm });
    (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
    return;
  }
  const ts = new Date().toISOString().slice(11, 23);
  const body = stringify(norm);
  const line = `${ts} ${level.toUpperCase().padEnd(5)} [${tag}]${body ? ' ' + body : ''}`;
  (level === 'error' || level === 'warn' ? process.stderr : process.stdout).write(line + '\n');
}

function child(tag) {
  return {
    debug: (fields) => emit('debug', tag, fields),
    info: (fields) => emit('info', tag, fields),
    warn: (fields) => emit('warn', tag, fields),
    error: (fields) => emit('error', tag, fields),
    child: (sub) => child(`${tag}:${sub}`),
  };
}

module.exports = {
  configure,
  child,
  maskAddress,
  levels: LEVELS,
  debug: (tag, f) => emit('debug', tag, f),
  info: (tag, f) => emit('info', tag, f),
  warn: (tag, f) => emit('warn', tag, f),
  error: (tag, f) => emit('error', tag, f),
};
