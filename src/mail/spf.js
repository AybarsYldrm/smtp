'use strict';

const dnsModule = require('node:dns');
const net = require('node:net');

/**
 * SPF değerlendirmesi (RFC 7208).
 *
 * Gelen postada SPF'e bakmanın somut faydası: zarf gönderenini (MAIL FROM)
 * taklit eden bir bağlantıyı, iletiyi hiç kabul etmeden ayırt etmek. Tek
 * başına yetmez — SPF ileti başlığındaki From'u değil zarfı doğrular, bu
 * yüzden DMARC hizalaması olmadan "SPF geçti" bir kimlik kanıtı değildir.
 * Bu yüzden bu modül karar VERMEZ, yalnızca sonuç üretir; kararı DMARC verir.
 *
 * İki sınır bilinçli olarak sıkı:
 *
 *   - DNS sorgu sayısı 10 ile sınırlı (§4.6.4). Bu sınır olmadan, saldırgan
 *     iç içe `include` zincirleriyle bizi kendi seçtiği hedeflere karşı bir
 *     DNS yükseltme aracına çevirebilir.
 *   - Boş dönen sorgu (void lookup) 2 ile sınırlı. Aynı saldırının daha
 *     sessiz biçimi budur.
 */

const MAX_DNS_LOOKUPS = 10;
const MAX_VOID_LOOKUPS = 2;
const MAX_MX_RECORDS = 10;
const MAX_PTR_RECORDS = 10;
const MAX_RECURSION = 10;

const RESULT = {
  NONE: 'none',
  NEUTRAL: 'neutral',
  PASS: 'pass',
  FAIL: 'fail',
  SOFTFAIL: 'softfail',
  TEMPERROR: 'temperror',
  PERMERROR: 'permerror',
};

const QUALIFIER_RESULT = { '+': RESULT.PASS, '-': RESULT.FAIL, '~': RESULT.SOFTFAIL, '?': RESULT.NEUTRAL };

class SpfPermError extends Error {}
class SpfTempError extends Error {}

/** Değerlendirme durumu: sorgu sayaçları burada, çünkü sınırlar bütün
 *  değerlendirme boyunca ortaktır — her `include` kendi sayacını tutarsa
 *  sınır hiç dolmaz. */
class Evaluation {
  constructor({ resolver, ip, sender, heloDomain, timeoutMs }) {
    this.resolver = resolver;
    this.ip = ip;
    this.ipVersion = net.isIPv6(ip) ? 6 : 4;
    this.ipBytes = ipToBytes(ip);
    this.sender = sender;
    this.heloDomain = heloDomain;
    this.timeoutMs = timeoutMs;
    this.lookups = 0;
    this.voidLookups = 0;
    this.log = [];
  }

  countLookup() {
    if (++this.lookups > MAX_DNS_LOOKUPS) {
      throw new SpfPermError(`DNS sorgu sınırı aşıldı (${MAX_DNS_LOOKUPS})`);
    }
  }

  countVoid() {
    if (++this.voidLookups > MAX_VOID_LOOKUPS) {
      throw new SpfPermError(`boş DNS sorgusu sınırı aşıldı (${MAX_VOID_LOOKUPS})`);
    }
  }

  async resolveTxt(name) {
    this.countLookup();
    try {
      const records = await this.resolver.resolveTxt(name);
      if (!records || !records.length) this.countVoid();
      // TXT parçaları birleştirilir: 255 baytı aşan kayıtlar bölünür ve
      // birleştirmeden okumak politikayı yarıda keser.
      return (records || []).map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
    } catch (err) {
      if (isNotFound(err)) { this.countVoid(); return []; }
      throw new SpfTempError(`TXT ${name}: ${err.code || err.message}`);
    }
  }

  async resolveAddresses(name) {
    this.countLookup();
    const out = [];
    try {
      if (this.ipVersion === 4) {
        const v4 = await this.resolver.resolve4(name).catch((e) => { if (isNotFound(e)) return []; throw e; });
        out.push(...v4);
      } else {
        const v6 = await this.resolver.resolve6(name).catch((e) => { if (isNotFound(e)) return []; throw e; });
        out.push(...v6);
      }
    } catch (err) {
      if (!isNotFound(err)) throw new SpfTempError(`A/AAAA ${name}: ${err.code || err.message}`);
    }
    if (!out.length) this.countVoid();
    return out;
  }

  async resolveMx(name) {
    this.countLookup();
    try {
      const rows = await this.resolver.resolveMx(name);
      if (!rows || !rows.length) this.countVoid();
      return (rows || []).slice(0, MAX_MX_RECORDS);
    } catch (err) {
      if (isNotFound(err)) { this.countVoid(); return []; }
      throw new SpfTempError(`MX ${name}: ${err.code || err.message}`);
    }
  }

  async resolvePtr(ip) {
    this.countLookup();
    try { return (await this.resolver.reverse(ip)).slice(0, MAX_PTR_RECORDS); }
    catch (err) {
      if (isNotFound(err)) { this.countVoid(); return []; }
      throw new SpfTempError(`PTR ${ip}: ${err.code || err.message}`);
    }
  }
}

function isNotFound(err) {
  return err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA' || err.code === 'NXDOMAIN');
}

function ipToBytes(ip) {
  if (net.isIPv4(ip)) return Buffer.from(ip.split('.').map(Number));
  if (!net.isIPv6(ip)) return null;
  // IPv6 genişletme: "::" kısaltması ve gömülü IPv4 ("::ffff:1.2.3.4").
  let text = ip;
  const v4Match = text.match(/(\d+\.\d+\.\d+\.\d+)$/);
  let tail = [];
  if (v4Match) {
    tail = v4Match[1].split('.').map(Number);
    text = text.slice(0, v4Match.index).replace(/:$/, '') + ':';
  }
  const [headPart, tailPart = ''] = text.split('::');
  const head = headPart ? headPart.split(':').filter(Boolean) : [];
  const rest = tailPart ? tailPart.split(':').filter(Boolean) : [];
  const groupsNeeded = 8 - (tail.length ? 1 : 0) * 2 / 2;
  const total = tail.length ? 6 : 8;
  const missing = total - head.length - rest.length;
  const groups = [...head, ...Array(Math.max(0, missing)).fill('0'), ...rest];
  const bytes = [];
  for (const g of groups.slice(0, total)) {
    const v = parseInt(g || '0', 16);
    bytes.push((v >> 8) & 0xff, v & 0xff);
  }
  while (bytes.length < 16 - tail.length) bytes.push(0);
  bytes.push(...tail);
  return Buffer.from(bytes.slice(0, 16));
}

function cidrMatch(ipBytes, targetIp, prefixLength, version) {
  const target = ipToBytes(targetIp);
  if (!target || !ipBytes) return false;
  if (target.length !== ipBytes.length) return false;
  const maxBits = version === 6 ? 128 : 32;
  const bits = prefixLength == null ? maxBits : Math.min(prefixLength, maxBits);
  const fullBytes = Math.floor(bits / 8);
  for (let i = 0; i < fullBytes; i++) if (ipBytes[i] !== target[i]) return false;
  const remaining = bits % 8;
  if (!remaining) return true;
  const mask = 0xff << (8 - remaining) & 0xff;
  return (ipBytes[fullBytes] & mask) === (target[fullBytes] & mask);
}

/** SPF makro genişletme (§7). Yalnızca gerçekten kullanılan makrolar. */
function expandMacros(text, evaluation, domain) {
  const senderParts = String(evaluation.sender || '').split('@');
  const localPart = senderParts.length > 1 ? senderParts[0] : 'postmaster';
  const senderDomain = senderParts.length > 1 ? senderParts[1] : senderParts[0];

  return String(text).replace(/%\{([slodipvhcrt])(\d*)(r?)([.\-+,/_=]*)\}|%%|%_|%-/gi, (match, letter, digits, reverse, delimiters) => {
    if (match === '%%') return '%';
    if (match === '%_') return ' ';
    if (match === '%-') return '%20';
    let value;
    switch (String(letter).toLowerCase()) {
      case 's': value = evaluation.sender || `postmaster@${domain}`; break;
      case 'l': value = localPart; break;
      case 'o': value = senderDomain; break;
      case 'd': value = domain; break;
      case 'i': value = evaluation.ipVersion === 4 ? evaluation.ip : nibbleForm(evaluation.ipBytes); break;
      case 'p': value = 'unknown'; break; // p= (PTR) makrosu kullanımı önerilmez
      case 'v': value = evaluation.ipVersion === 4 ? 'in-addr' : 'ip6'; break;
      case 'h': value = evaluation.heloDomain || domain; break;
      case 'c': value = evaluation.ip; break;
      case 'r': value = 'unknown'; break;
      case 't': value = String(Math.floor(Date.now() / 1000)); break;
      default: return match;
    }
    const delimiterSet = delimiters && delimiters.length ? delimiters.split('') : ['.'];
    let parts = String(value).split(new RegExp(`[${delimiterSet.map((d) => `\\${d}`).join('')}]`));
    if (reverse) parts = parts.reverse();
    if (digits) {
      const n = Number(digits);
      if (n > 0 && n < parts.length) parts = parts.slice(parts.length - n);
    }
    return parts.join('.');
  });
}

function nibbleForm(bytes) {
  return [...bytes].map((b) => `${(b >> 4).toString(16)}.${(b & 0xf).toString(16)}`).join('.');
}

function parseRecord(text) {
  const terms = String(text).trim().split(/\s+/).filter(Boolean);
  if (!/^v=spf1$/i.test(terms[0] || '')) return null;
  const mechanisms = [];
  const modifiers = {};
  for (const term of terms.slice(1)) {
    const modMatch = term.match(/^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$/);
    if (modMatch) {
      const key = modMatch[1].toLowerCase();
      // Aynı değiştirici iki kez: kayıt geçersiz (§6). Hangisinin geçerli
      // olduğuna karar vermek yerine reddetmek doğru olan.
      if (key === 'redirect' || key === 'exp') {
        if (modifiers[key] != null) throw new SpfPermError(`yinelenen değiştirici: ${key}`);
        modifiers[key] = modMatch[2];
      }
      continue;
    }
    const m = term.match(/^([+\-~?]?)([A-Za-z][A-Za-z0-9_.-]*)((?::|\/)?.*)$/);
    if (!m) throw new SpfPermError(`ayrıştırılamayan terim: ${term}`);
    const qualifier = m[1] || '+';
    const name = m[2].toLowerCase();
    let rest = m[3] || '';
    let value = null;
    let prefix4 = null;
    let prefix6 = null;

    if (rest.startsWith(':')) {
      rest = rest.slice(1);
      const slash = rest.indexOf('/');
      if (slash >= 0) { value = rest.slice(0, slash); rest = rest.slice(slash); }
      else { value = rest; rest = ''; }
    }
    const cidr = rest.match(/^\/(\d+)?(?:\/\/(\d+))?$/);
    if (cidr) {
      if (cidr[1] != null) prefix4 = Number(cidr[1]);
      if (cidr[2] != null) prefix6 = Number(cidr[2]);
    } else if (rest) {
      const dual = rest.match(/^\/\/(\d+)$/);
      if (dual) prefix6 = Number(dual[1]);
      else throw new SpfPermError(`geçersiz CIDR: ${term}`);
    }
    mechanisms.push({ qualifier, name, value, prefix4, prefix6, raw: term });
  }
  return { mechanisms, modifiers };
}

async function fetchRecord(evaluation, domain) {
  const records = await evaluation.resolveTxt(domain);
  const spfRecords = records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  // İkiden fazla SPF kaydı: hangisinin geçerli olduğu belirsiz, permerror
  // (§4.5). Birini seçmek, alan sahibinin niyetini tahmin etmek olurdu.
  if (spfRecords.length > 1) throw new SpfPermError(`${domain}: birden fazla SPF kaydı`);
  return spfRecords[0] || null;
}

async function evaluateDomain(evaluation, domain, depth = 0) {
  if (depth > MAX_RECURSION) throw new SpfPermError('özyineleme sınırı aşıldı');

  const recordText = await fetchRecord(evaluation, domain);
  if (!recordText) return { result: RESULT.NONE, matched: null, domain };

  const parsed = parseRecord(recordText);
  if (!parsed) return { result: RESULT.NONE, matched: null, domain };

  for (const mech of parsed.mechanisms) {
    const matched = await matchMechanism(evaluation, domain, mech, depth);
    if (!matched) continue;
    evaluation.log.push({ domain, mechanism: mech.raw, result: QUALIFIER_RESULT[mech.qualifier] });
    return { result: QUALIFIER_RESULT[mech.qualifier], matched: mech.raw, domain, record: recordText };
  }

  if (parsed.modifiers.redirect != null) {
    const target = expandMacros(parsed.modifiers.redirect, evaluation, domain);
    // redirect, `all` yokken devreye girer ve sonucu OLDUĞU GİBİ devralır;
    // include'un aksine "eşleşmedi" durumu neutral değil permerror üretir.
    const redirected = await evaluateDomain(evaluation, target, depth + 1);
    if (redirected.result === RESULT.NONE) throw new SpfPermError(`redirect hedefi SPF kaydı taşımıyor: ${target}`);
    return { ...redirected, redirectedFrom: domain };
  }

  return { result: RESULT.NEUTRAL, matched: null, domain, record: recordText };
}

async function matchMechanism(evaluation, domain, mech, depth) {
  const targetDomain = mech.value ? expandMacros(mech.value, evaluation, domain) : domain;

  switch (mech.name) {
    case 'all':
      return true;

    case 'ip4': {
      if (evaluation.ipVersion !== 4) return false;
      if (!mech.value) throw new SpfPermError('ip4 adres gerektirir');
      const [addr, len] = String(mech.value).split('/');
      const prefix = mech.prefix4 != null ? mech.prefix4 : (len != null ? Number(len) : 32);
      if (!net.isIPv4(addr)) throw new SpfPermError(`geçersiz ip4: ${mech.value}`);
      return cidrMatch(evaluation.ipBytes, addr, prefix, 4);
    }

    case 'ip6': {
      if (evaluation.ipVersion !== 6) return false;
      if (!mech.value) throw new SpfPermError('ip6 adres gerektirir');
      const slash = String(mech.value).lastIndexOf('/');
      const addr = slash > 0 ? mech.value.slice(0, slash) : mech.value;
      const prefix = mech.prefix6 != null ? mech.prefix6
        : (slash > 0 ? Number(mech.value.slice(slash + 1)) : 128);
      if (!net.isIPv6(addr)) throw new SpfPermError(`geçersiz ip6: ${mech.value}`);
      return cidrMatch(evaluation.ipBytes, addr, prefix, 6);
    }

    case 'a': {
      const addresses = await evaluation.resolveAddresses(targetDomain);
      const prefix = evaluation.ipVersion === 4 ? mech.prefix4 : mech.prefix6;
      return addresses.some((addr) => cidrMatch(evaluation.ipBytes, addr, prefix, evaluation.ipVersion));
    }

    case 'mx': {
      const mxRows = await evaluation.resolveMx(targetDomain);
      const prefix = evaluation.ipVersion === 4 ? mech.prefix4 : mech.prefix6;
      for (const row of mxRows) {
        const addresses = await evaluation.resolveAddresses(row.exchange);
        if (addresses.some((addr) => cidrMatch(evaluation.ipBytes, addr, prefix, evaluation.ipVersion))) return true;
      }
      return false;
    }

    case 'ptr': {
      // PTR mekanizması RFC 7208 §5.5'te kullanımı ÖNERİLMEZ olarak
      // işaretli: yavaş ve güvenilmez. Yine de destekliyoruz çünkü eski
      // kayıtlarda var; desteklememek onları sessizce fail yapar.
      const names = await evaluation.resolvePtr(evaluation.ip);
      for (const name of names) {
        const lower = String(name).toLowerCase().replace(/\.$/, '');
        const target = String(targetDomain).toLowerCase().replace(/\.$/, '');
        if (lower !== target && !lower.endsWith(`.${target}`)) continue;
        const forward = await evaluation.resolveAddresses(lower);
        if (forward.some((addr) => addr === evaluation.ip)) return true;
      }
      return false;
    }

    case 'exists': {
      if (!mech.value) throw new SpfPermError('exists alan adı gerektirir');
      evaluation.countLookup();
      try {
        const rows = await evaluation.resolver.resolve4(targetDomain);
        if (!rows || !rows.length) { evaluation.countVoid(); return false; }
        return true;
      } catch (err) {
        if (isNotFound(err)) { evaluation.countVoid(); return false; }
        throw new SpfTempError(`exists ${targetDomain}: ${err.code || err.message}`);
      }
    }

    case 'include': {
      if (!mech.value) throw new SpfPermError('include alan adı gerektirir');
      const inner = await evaluateDomain(evaluation, targetDomain, depth + 1);
      // include YALNIZCA pass ise eşleşir (§5.2). Hedefte kayıt yoksa bu
      // permerror'dur — sessizce "eşleşmedi" saymak, yazım hatası olan bir
      // include'u fark edilmez kılar.
      if (inner.result === RESULT.NONE) throw new SpfPermError(`include hedefi SPF kaydı taşımıyor: ${targetDomain}`);
      if (inner.result === RESULT.TEMPERROR) throw new SpfTempError(`include geçici hata: ${targetDomain}`);
      if (inner.result === RESULT.PERMERROR) throw new SpfPermError(`include kalıcı hata: ${targetDomain}`);
      return inner.result === RESULT.PASS;
    }

    default:
      throw new SpfPermError(`bilinmeyen mekanizma: ${mech.name}`);
  }
}

/**
 * SPF denetimi.
 *
 * @param {object} p
 * @param {string} p.ip           bağlanan istemcinin IP'si
 * @param {string} p.sender       MAIL FROM (boşsa HELO adı kullanılır)
 * @param {string} p.heloDomain
 * @param {object} [p.resolver]   node:dns.promises uyumlu (test için değiştirilebilir)
 * @returns {Promise<{result, domain, explanation, mechanism, lookups}>}
 */
async function check({ ip, sender = '', heloDomain = '', resolver = dnsModule.promises, timeoutMs = 8000 }) {
  const normalizedIp = String(ip || '').replace(/^::ffff:/i, '');
  if (!net.isIP(normalizedIp)) {
    return { result: RESULT.PERMERROR, domain: '', explanation: 'geçersiz IP', mechanism: null, lookups: 0 };
  }

  // Zarf gönderen boşsa (bounce iletileri) SPF, HELO adı üzerinden yapılır
  // (§2.3). Bunu atlamak, tüm geri dönüş iletilerini denetimsiz bırakır.
  const effectiveSender = sender || (heloDomain ? `postmaster@${heloDomain}` : '');
  const domain = String(effectiveSender).split('@').pop().toLowerCase().replace(/\.$/, '');
  if (!domain || !domain.includes('.')) {
    return { result: RESULT.NONE, domain, explanation: 'değerlendirilebilir alan adı yok', mechanism: null, lookups: 0 };
  }

  const evaluation = new Evaluation({ resolver, ip: normalizedIp, sender: effectiveSender, heloDomain, timeoutMs });

  try {
    const outcome = await evaluateDomain(evaluation, domain);
    return {
      result: outcome.result,
      // ── BİLDİRİLEN HATA: her Gmail iletisi dmarc=fail ───────────────────
      //
      // Burası `outcome.domain` döndürüyordu: mekanizmanın EŞLEŞTİĞİ alan
      // adı. gmail.com'un kaydı `redirect=_spf.google.com` olduğu için
      // eşleşme orada oluyor ve sonuç `_spf.google.com` diye dönüyordu.
      // Başlıkta da öyle görünüyordu:
      //
      //     spf=pass smtp.mailfrom=_spf.google.com
      //
      // DMARC hizalaması ise From alan adını SPF'in doğruladığı KİMLİĞİN
      // alan adıyla karşılaştırır (RFC 7489 §3.1.1) — o kimlik MAIL FROM'dur,
      // yani `gmail.com`. `_spf.google.com` ile karşılaştırıldığında hizalama
      // hiçbir zaman tutmuyor, SPF geçmiş olmasına rağmen DMARC düşüyordu.
      // Bu yalnızca Gmail'i değil, `redirect`/`include` kullanan HER büyük
      // sağlayıcıyı (Outlook, Yahoo, Amazon SES…) etkiliyordu.
      //
      // Doğrusu: doğrulanan kimliğin alan adı, yani başlangıçta sorulan alan.
      domain,
      // Eşleşmenin nerede olduğu tanı için değerli, ama HİZALAMA için değil.
      matchedDomain: outcome.domain,
      redirectedFrom: outcome.redirectedFrom || null,
      identity: sender ? 'mailfrom' : 'helo',
      mechanism: outcome.matched,
      explanation: outcome.record || '',
      lookups: evaluation.lookups,
      trace: evaluation.log,
    };
  } catch (err) {
    const result = err instanceof SpfTempError ? RESULT.TEMPERROR : RESULT.PERMERROR;
    return {
      result,
      domain,
      matchedDomain: null,
      redirectedFrom: null,
      identity: sender ? 'mailfrom' : 'helo',
      mechanism: null,
      explanation: err.message,
      lookups: evaluation.lookups,
      trace: evaluation.log,
    };
  }
}

/** Received-SPF başlığı (RFC 7208 §9.1). */
function receivedSpfHeader({ result, domain, ip, sender, helo, hostname }) {
  const comment = `${hostname}: ${result === RESULT.PASS
    ? `domain of ${sender || helo} designates ${ip} as permitted sender`
    : `${ip} is not a permitted sender for ${domain}`}`;
  const parts = [`${result} (${comment})`];
  if (ip) parts.push(`client-ip=${ip}`);
  if (helo) parts.push(`helo=${helo}`);
  if (sender) parts.push(`envelope-from=${sender}`);
  return `Received-SPF: ${parts.join('; ')}`;
}

module.exports = { check, RESULT, parseRecord, expandMacros, ipToBytes, cidrMatch, receivedSpfHeader };
