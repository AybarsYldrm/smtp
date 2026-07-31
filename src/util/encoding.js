'use strict';

const crypto = require('node:crypto');

/* ── base64 / base64url ─────────────────────────────────────── */

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlDecode(str) {
  let s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

// Satır uzunluğu 76: RFC 2045 §6.8 sınırı. Aşan satırları bazı eski MTA'lar
// bölerek imzayı bozar.
function b64Wrap(buf, width = 76, eol = '\r\n') {
  const s = Buffer.from(buf).toString('base64');
  const lines = [];
  for (let i = 0; i < s.length; i += width) lines.push(s.slice(i, i + width));
  return lines.join(eol);
}

/* ── quoted-printable ───────────────────────────────────────── */

function decodeQuotedPrintable(input) {
  const s = String(input || '');
  // Soft line break önce kaldırılır, sonra =XX çözülür: ters sırada yapılması
  // "=3D\r\n" gibi dizileri yanlış çözer.
  const unfolded = s.replace(/=\r?\n/g, '');
  const out = [];
  for (let i = 0; i < unfolded.length; i++) {
    const c = unfolded[i];
    if (c === '=' && i + 2 < unfolded.length && /^[0-9A-Fa-f]{2}$/.test(unfolded.slice(i + 1, i + 3))) {
      out.push(parseInt(unfolded.slice(i + 1, i + 3), 16));
      i += 2;
    } else {
      const code = c.charCodeAt(0);
      if (code > 255) { for (const b of Buffer.from(c, 'utf8')) out.push(b); }
      else out.push(code);
    }
  }
  return Buffer.from(out);
}

function encodeQuotedPrintable(buf, { eol = '\r\n', maxLine = 76 } = {}) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), 'utf8');
  let line = '';
  const lines = [];
  const flush = (soft) => { lines.push(soft ? line + '=' : line); line = ''; };

  const push = (token) => {
    if (line.length + token.length > maxLine - 1) flush(true);
    line += token;
  };

  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0x0d && bytes[i + 1] === 0x0a) { flush(false); i++; continue; }
    if (b === 0x0a) { flush(false); continue; }
    const isLast = i === bytes.length - 1 || bytes[i + 1] === 0x0d || bytes[i + 1] === 0x0a;
    // Satır sonundaki boşluk/tab kodlanmak ZORUNDA: aksi hâlde aktarımda
    // kırpılır ve gövde özeti (dolayısıyla DKIM imzası) değişir.
    if ((b === 0x20 || b === 0x09) && isLast) { push('=' + b.toString(16).toUpperCase().padStart(2, '0')); continue; }
    if (b === 0x3d) { push('=3D'); continue; }
    if (b >= 0x21 && b <= 0x7e) { push(String.fromCharCode(b)); continue; }
    if (b === 0x20 || b === 0x09) { push(String.fromCharCode(b)); continue; }
    push('=' + b.toString(16).toUpperCase().padStart(2, '0'));
  }
  if (line.length) lines.push(line);
  return lines.join(eol);
}

/* ── RFC 2047 kodlu başlıklar ───────────────────────────────── */

const CHARSET_ALIASES = {
  'utf-8': 'utf8', utf8: 'utf8', 'us-ascii': 'latin1', ascii: 'latin1',
  'iso-8859-1': 'latin1', 'iso-8859-9': 'latin1', latin1: 'latin1',
  'windows-1252': 'latin1', 'windows-1254': 'latin1', 'cp1252': 'latin1',
};

function decodeCharset(buf, charset) {
  const enc = CHARSET_ALIASES[String(charset || '').toLowerCase()] || 'utf8';
  try { return buf.toString(enc); } catch { return buf.toString('utf8'); }
}

function decodeMimeWords(input) {
  let s = String(input || '');
  if (!s.includes('=?')) return s;
  // Ardışık kodlu sözcükler arasındaki boşluk YOK SAYILIR (RFC 2047 §6.2):
  // çok baytlı bir karakter iki sözcüğe bölünmüşse aradaki boşluğu korumak
  // onu bozar. Bu yüzden çözmeden önce sözcükleri birleştiriyoruz — aynı
  // karakter kümesindeki parçaların baytları da böylece yan yana gelir.
  s = s.replace(/(=\?[^?]+\?[BbQq]\?[^?]*\?=)\s+(?==\?[^?]+\?[BbQq]\?)/g, '$1');
  const rx = /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g;
  let out = '';
  let last = 0;
  let m;
  let pending = null; // { charset, chunks[] } — aynı charset'te ardışık sözcükler
  const flush = () => {
    if (!pending) return;
    out += decodeCharset(Buffer.concat(pending.chunks), pending.charset);
    pending = null;
  };
  while ((m = rx.exec(s)) !== null) {
    const between = s.slice(last, m.index);
    if (between) { flush(); out += between; }
    const [, charset, enc, text] = m;
    let raw;
    try {
      raw = enc.toUpperCase() === 'B'
        ? Buffer.from(text, 'base64')
        : decodeQuotedPrintable(text.replace(/_/g, ' '));
    } catch { flush(); out += m[0]; last = m.index + m[0].length; continue; }
    if (pending && pending.charsetKey === String(charset).toLowerCase()) pending.chunks.push(raw);
    else { flush(); pending = { charset, charsetKey: String(charset).toLowerCase(), chunks: [raw] }; }
    last = m.index + m[0].length;
  }
  flush();
  out += s.slice(last);
  return out;
}

function needsEncoding(s) { return /[^\x20-\x7e]/.test(String(s || '')); }

// Kodlanmış sözcük başına 75 karakter sınırı vardır; UTF-8 karakterlerini
// bölmemek için base64'e karakter karakter veri ekleyip sınıra bakıyoruz.
function encodeMimeWord(str, maxWord = 63) {
  const chars = Array.from(String(str || ''));
  const words = [];
  let cur = '';
  for (const ch of chars) {
    const candidate = cur + ch;
    if (Buffer.byteLength(candidate, 'utf8') * 4 / 3 > maxWord && cur) { words.push(cur); cur = ch; }
    else cur = candidate;
  }
  if (cur) words.push(cur);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w, 'utf8').toString('base64')}?=`).join('\r\n ');
}

function encodeHeaderValue(value) {
  const s = String(value == null ? '' : value).replace(/[\r\n]+/g, ' ');
  return needsEncoding(s) ? encodeMimeWord(s) : s;
}

// Görünen ad + adres. Ad ASCII dışıysa kodlanır, ASCII ama özel karakter
// içeriyorsa alıntılanır.
function encodeAddress(address, displayName) {
  const addr = String(address || '').trim();
  const name = String(displayName || '').trim();
  if (!name) return `<${addr}>`;
  if (needsEncoding(name)) return `${encodeMimeWord(name)} <${addr}>`;
  if (/[()<>@,;:\\".[\]]/.test(name)) return `"${name.replace(/([\\"])/g, '\\$1')}" <${addr}>`;
  return `${name} <${addr}>`;
}

// Uzun başlıkları katlar (RFC 5322 §2.2.3). Katlama noktası boşluktur; imza
// hesabı katlanmış hâli görmemeli diye bu yalnızca gönderim anında uygulanır.
function foldHeader(name, value, maxLen = 78) {
  const prefix = `${name}: `;
  const v = String(value == null ? '' : value);
  if (prefix.length + v.length <= maxLen || /\r\n/.test(v)) return prefix + v;
  const tokens = v.split(' ');
  const lines = [];
  let line = prefix;
  for (const t of tokens) {
    if (line.length + t.length + 1 > maxLen && line.trim() !== prefix.trim()) {
      lines.push(line.replace(/\s+$/, ''));
      line = ' ' + t;
    } else {
      line += (line.endsWith(' ') || line === prefix ? '' : ' ') + t;
    }
  }
  if (line.trim()) lines.push(line.replace(/\s+$/, ''));
  return lines.join('\r\n');
}

/* ── adres ayrıştırma ───────────────────────────────────────── */

// Basit ama alıntı ve yorum farkında olan bir adres listesi ayrıştırıcısı.
// "a, b" <x@y> gibi başlıklarda virgülden bölmek yanlış sonuç verir.
function splitAddressList(input) {
  const s = String(input || '');
  const out = [];
  let cur = '';
  let inQuote = false;
  let depthAngle = 0;
  let depthParen = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inQuote) {
      cur += c;
      if (c === '\\' && i + 1 < s.length) { cur += s[++i]; continue; }
      if (c === '"') inQuote = false;
      continue;
    }
    if (c === '"') { inQuote = true; cur += c; continue; }
    if (c === '<') { depthAngle++; cur += c; continue; }
    if (c === '>') { depthAngle = Math.max(0, depthAngle - 1); cur += c; continue; }
    if (c === '(') { depthParen++; cur += c; continue; }
    if (c === ')') { depthParen = Math.max(0, depthParen - 1); cur += c; continue; }
    if ((c === ',' || c === ';') && !depthAngle && !depthParen) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const ADDR_RX = /[^\s<>@,;:"]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

function parseAddress(entry) {
  const s = decodeMimeWords(String(entry || '').trim());
  const angle = s.match(/<([^>]*)>/);
  if (angle) {
    const address = angle[1].trim();
    let name = s.slice(0, angle.index).trim().replace(/^"(.*)"$/, '$1').replace(/\\(.)/g, '$1');
    if (!name) {
      const comment = s.match(/\(([^)]*)\)/);
      if (comment) name = comment[1].trim();
    }
    return { address, name, raw: s };
  }
  const bare = s.match(ADDR_RX);
  return { address: bare ? bare[0] : '', name: '', raw: s };
}

function parseAddressList(input) {
  return splitAddressList(input).map(parseAddress).filter((a) => a.address);
}

function extractAddress(input) { return parseAddress(input).address; }

/* ── adres normalizasyonu ───────────────────────────────────── */

function normalizeAddress(addr) {
  const s = String(addr || '').trim().replace(/^<|>$/g, '');
  const at = s.lastIndexOf('@');
  if (at <= 0) return s.toLowerCase();
  // Yerel kısmın büyük/küçük harfi teoride anlamlıdır, pratikte hiçbir
  // sağlayıcı ayırt etmez ve ayırt etmek "Network@" ile "network@" için iki
  // ayrı kutu demek olurdu.
  return `${s.slice(0, at).toLowerCase()}@${s.slice(at + 1).toLowerCase()}`;
}

// Etiket ("+tag") ve noktaları temizleyerek asıl kutuyu bulur. Yalnızca
// yerel kutulara yönlendirme yaparken kullanılır; harici adreslerde
// dokunulmaz, çünkü nokta kaldırmak Gmail dışında adresi bozar.
function canonicalLocalPart(localPart, { stripDots = false } = {}) {
  let lp = String(localPart || '').toLowerCase();
  const plus = lp.indexOf('+');
  if (plus > 0) lp = lp.slice(0, plus);
  if (stripDots) lp = lp.replace(/\./g, '');
  return lp;
}

function splitAddress(addr) {
  const norm = normalizeAddress(addr);
  const at = norm.lastIndexOf('@');
  if (at <= 0) return { localPart: norm, domain: '', address: norm };
  return { localPart: norm.slice(0, at), domain: norm.slice(at + 1), address: norm };
}

/* ── metin yardımcıları ─────────────────────────────────────── */

function clip(str, max) {
  const s = String(str == null ? '' : str);
  return s.length <= max ? s : s.slice(0, max);
}

function htmlEscape(str) {
  return String(str == null ? '' : str).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function htmlToText(html) {
  return String(html || '')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<head[\s\S]*?<\/head>/gi, ' ')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/[ \t]+/g, ' ')
    .replace(/\n\s*\n\s*\n+/g, '\n\n')
    .trim();
}

function makePreview(text, max = 240) {
  return clip(String(text || '').replace(/\s+/g, ' ').trim(), max);
}

function safeFileName(name, fallback = 'dosya.bin') {
  const base = String(name || '').split(/[\\/]/).pop() || '';
  // Tehlikeli olanı at, geri kalanı KORU.
  //
  // Önceki hâli ASCII dışındaki her karakteri `_` yapıyordu; bu, "çözüm.pdf"
  // adlı bir eki "__z_m.pdf" olarak kaydetmek demekti. Türkçe dosya adı
  // sıradan bir durum, güvenlik sorunu değil. Asıl tehlike üç şeyde:
  // yol ayırıcı (zaten yukarıda atıldı), kontrol karakterleri ve Unicode
  // yön değiştirme işaretleri (RTL override ile "resim‮gpj.exe" numarası).
  const cleaned = base
    .replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
    .replace(/[<>:"|?*\\/]/g, '_')
    .replace(/^[.\s]+/, '')
    .replace(/\s+/g, ' ')
    .trim();
  const finalName = cleaned || fallback;
  return clip(finalName, 180);
}

const ASCII_FOLD_MAP = {
  ç: 'c', Ç: 'C', ğ: 'g', Ğ: 'G', ı: 'i', İ: 'I', ö: 'o', Ö: 'O',
  ş: 's', Ş: 'S', ü: 'u', Ü: 'U', â: 'a', Â: 'A', î: 'i', Î: 'I', û: 'u', Û: 'U',
};

/**
 * Türkçe karakterleri ASCII karşılıklarına indirger.
 *
 * SMTP yanıt metni ASCII'dir (RFC 5321 §4.2.1); UTF-8 yanıt için SMTPUTF8
 * uzantısının pazarlıkla açılması gerekir. Kaynakta Türkçe yazıp tele ASCII
 * vermek, hem okunur kod hem de her istemcinin doğru okuduğu yanıt demek —
 * yoksa istemci yanıtı latin1 çözer ve kullanıcı "gÃ¶nderme" görür.
 */
function asciiFold(str) {
  let out = '';
  for (const ch of String(str == null ? '' : str)) {
    if (ASCII_FOLD_MAP[ch]) { out += ASCII_FOLD_MAP[ch]; continue; }
    out += ch.charCodeAt(0) > 126 ? '?' : ch;
  }
  return out;
}

/**
 * Baytları UTF-8 olarak çözer, geçerli UTF-8 değilse latin1'e düşer.
 *
 * Başlıklar kural olarak ASCII'dir ve ASCII dışı içerik RFC 2047 ile
 * kodlanır. Ama 8BITMIME ile ham UTF-8 başlık gönderen istemci çok yaygın;
 * onu latin1 okumak konuyu "Ä°kili" diye göstermek olur. Geçerli UTF-8'i
 * UTF-8 olarak okumak, kodlanmamış başlıkları da doğru gösteriyor ve
 * gerçekten latin1 olanları bozmuyor (latin1 metin çoğunlukla geçersiz
 * UTF-8'dir).
 */
function decodeMaybeUtf8(buf) {
  const bytes = Buffer.isBuffer(buf) ? buf : Buffer.from(String(buf), 'latin1');
  if (!bytes.some((b) => b > 0x7f)) return bytes.toString('latin1');
  const asUtf8 = bytes.toString('utf8');
  // Kayıp karakter (U+FFFD) varsa bayt dizisi geçerli UTF-8 değildi.
  return asUtf8.includes('�') ? bytes.toString('latin1') : asUtf8;
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function sha256Hex(buf) { return sha256(buf).toString('hex'); }

function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a == null ? '' : a), 'utf8');
  const bb = Buffer.from(String(b == null ? '' : b), 'utf8');
  // Uzunluk farkı da sabit zamanda: doğrudan false dönmek, doğru parolanın
  // uzunluğunu ölçülebilir hâle getirir.
  const len = Math.max(ba.length, bb.length, 1);
  const pa = Buffer.alloc(len);
  const pb = Buffer.alloc(len);
  ba.copy(pa); bb.copy(pb);
  return crypto.timingSafeEqual(pa, pb) && ba.length === bb.length;
}

function randomId(bytes = 16) { return crypto.randomBytes(bytes).toString('hex'); }

function newMessageId(domain) {
  return `<${crypto.randomBytes(16).toString('hex')}.${Date.now().toString(36)}@${domain}>`;
}

function toCrlf(input) {
  const s = Buffer.isBuffer(input) ? input.toString('binary') : String(input);
  return s.replace(/\r\n|\r|\n/g, '\r\n');
}

function bufToCrlf(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b === 0x0d) {
      out.push(0x0d, 0x0a);
      if (buf[i + 1] === 0x0a) i++;
    } else if (b === 0x0a) {
      out.push(0x0d, 0x0a);
    } else out.push(b);
  }
  return Buffer.from(out);
}

module.exports = {
  b64url, b64urlDecode, b64Wrap,
  decodeQuotedPrintable, encodeQuotedPrintable,
  decodeMimeWords, encodeMimeWord, encodeHeaderValue, encodeAddress, foldHeader,
  decodeCharset, needsEncoding,
  splitAddressList, parseAddress, parseAddressList, extractAddress,
  normalizeAddress, canonicalLocalPart, splitAddress,
  clip, htmlEscape, htmlToText, makePreview, safeFileName, asciiFold, decodeMaybeUtf8,
  sha256, sha256Hex, timingSafeEqualStr, randomId, newMessageId,
  toCrlf, bufToCrlf,
};
