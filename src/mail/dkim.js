'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns').promises;

/**
 * DKIM imzalama ve doğrulama (RFC 6376).
 *
 * ── Bildirilen hata ve sebebi ────────────────────────────────────────────
 * Önceki sürümde 465/587 üzerinden bir posta istemcisiyle bağlanıp
 * gönderilen iletide DKIM imzası görünmüyordu. Sebep, imzanın hiç
 * atılmamasıydı: `sendMail()` (yani panelin kendi gönderimi) imzalıyor, ama
 * istemciden gelen ileti `relayRawMail()` yolundan geçiyordu ve o yol ham
 * baytları olduğu gibi karşı tarafa aktarıyordu. Yani imza "kayboluyor"
 * değildi, o kod yolunda hiç üretilmiyordu.
 *
 * İkinci ve daha sinsi sorun: imza, GÖNDERİLEN başlıklar üzerinden değil,
 * yeniden kurulmuş bir başlık kümesi üzerinden hesaplanıyordu. Bu, imza
 * atılsa bile doğrulamanın başarısız olması demek — çünkü doğrulayan tarafın
 * gördüğü baytlar imzalananla aynı değil.
 *
 * Buradaki çözüm tek bir kurala dayanıyor: İMZA, TELE VERİLECEK BAYTLAR
 * ÜZERİNDEN HESAPLANIR. `signMessage` ham iletiyi alır, kendi ayrıştırır,
 * imzayı üretir ve başlığı ham iletinin BAŞINA ekler. Aradaki hiçbir katman
 * başlıkları yeniden yazmaz.
 *
 * ── Kanoniklik seçimi ────────────────────────────────────────────────────
 * relaxed/relaxed kullanıyoruz. `simple` gövde kanonikliği tek bir boşluk
 * değişikliğinde imzayı bozar; posta listeleri, virüs tarayıcıları ve bazı
 * MTA'lar gövdeye dokunur. relaxed, anlamı değiştirmeyen boşluk
 * dönüşümlerine dayanır — pratikte doğrulanabilirlik farkı budur.
 */

const CRLF = '\r\n';

// İmzalanacak başlıklar. From ZORUNLU (RFC 6376 §5.4).
//
// Listeye almadığımız bir başlık, aradaki biri tarafından EKLENEBİLİR ve imza
// hâlâ geçerli görünür. Bu yüzden alıcının gördüğü ve anlam taşıyan her başlık
// listede: Subject olmadan imzalamak, konuyu değiştirmeye izin vermek olur.
const DEFAULT_SIGNED_HEADERS = [
  'from', 'to', 'cc', 'subject', 'date', 'message-id',
  'mime-version', 'content-type', 'content-transfer-encoding',
  'reply-to', 'in-reply-to', 'references',
  'list-id', 'list-unsubscribe',
];

const ALGORITHMS = {
  'rsa-sha256': { keyType: 'rsa', hash: 'sha256' },
  'ed25519-sha256': { keyType: 'ed25519', hash: 'sha256' },
};

/* ── ileti bölme ───────────────────────────────────────────── */

/**
 * Ham iletiyi başlık satırlarına ve gövdeye ayırır.
 *
 * Katlanmış (folded) başlıklar TEK satır olarak birleştirilir ama HAM hâli
 * korunur: kanoniklik hesabı ham hâlden türetilir.
 */
function splitMessage(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString('binary') : String(raw);
  const match = text.match(/\r?\n\r?\n/);
  const headerBlock = match ? text.slice(0, match.index) : text;
  const body = match ? text.slice(match.index + match[0].length) : '';

  const headers = [];
  let current = null;
  for (const line of headerBlock.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && current) {
      current.raw += CRLF + line;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    current = { name: line.slice(0, colon).trim().toLowerCase(), raw: line };
    headers.push(current);
  }
  return { headers, body, headerBlock };
}

/* ── kanoniklik ────────────────────────────────────────────── */

/** relaxed başlık kanonikliği (RFC 6376 §3.4.2). */
function canonicalizeHeaderRelaxed(rawLine) {
  const colon = rawLine.indexOf(':');
  const name = rawLine.slice(0, colon).trim().toLowerCase();
  let value = rawLine.slice(colon + 1);
  // Katlamayı aç, boşluk dizilerini tek boşluğa indir, baş/son boşluğu at.
  value = value.replace(/\r?\n[ \t]+/g, ' ').replace(/[ \t]+/g, ' ').trim();
  return `${name}:${value}`;
}

/** simple başlık kanonikliği — başlık olduğu gibi, yalnızca CRLF eklenir. */
function canonicalizeHeaderSimple(rawLine) {
  return rawLine.replace(/\r?\n/g, CRLF);
}

/** relaxed gövde kanonikliği (RFC 6376 §3.4.4). */
function canonicalizeBodyRelaxed(body) {
  let text = String(body).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = text.split('\n').map((line) => line.replace(/[ \t]+/g, ' ').replace(/[ \t]+$/, ''));
  // Sondaki boş satırlar silinir.
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (!lines.length) return '';
  return lines.join(CRLF) + CRLF;
}

/** simple gövde kanonikliği (RFC 6376 §3.4.3). */
function canonicalizeBodySimple(body) {
  let text = String(body).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const lines = text.split('\n');
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  if (!lines.length) return CRLF; // gövdesiz ileti tek CRLF'e kanonikleşir
  return lines.join(CRLF) + CRLF;
}

function canonicalizeBody(body, mode, lengthLimit = null) {
  const canonical = mode === 'simple' ? canonicalizeBodySimple(body) : canonicalizeBodyRelaxed(body);
  if (lengthLimit == null) return canonical;
  return canonical.slice(0, lengthLimit);
}

function bodyHash(body, { canon = 'relaxed', hash = 'sha256', lengthLimit = null } = {}) {
  const canonical = canonicalizeBody(body, canon, lengthLimit);
  return crypto.createHash(hash).update(Buffer.from(canonical, 'binary')).digest('base64');
}

/* ── imzalama ──────────────────────────────────────────────── */

/**
 * Bir DKIM-Signature başlığı üretir ve ham iletinin başına ekler.
 *
 * @param {object} p
 * @param {Buffer|string} p.rawMessage  tele verilecek ham ileti
 * @param {string} p.domain             d=
 * @param {string} p.selector           s=
 * @param {string} p.privateKeyPem
 * @param {string[]} [p.headers]        imzalanacak başlık adları
 * @param {string} [p.algorithm='rsa-sha256']
 * @param {string} [p.headerCanon='relaxed']
 * @param {string} [p.bodyCanon='relaxed']
 * @param {string} [p.identity]         i= (yoksa yazılmaz)
 * @param {number} [p.expiresInMs]      x=
 * @returns {{signatureHeader: string, rawMessage: Buffer}}
 */
function signMessage({
  rawMessage, domain, selector, privateKeyPem,
  headers = DEFAULT_SIGNED_HEADERS, algorithm = 'rsa-sha256',
  headerCanon = 'relaxed', bodyCanon = 'relaxed',
  identity = null, expiresInMs = null, timestamp = null,
  oversignFrom = true,
}) {
  const spec = ALGORITHMS[algorithm];
  if (!spec) throw new Error(`[dkim] desteklenmeyen algoritma: ${algorithm}`);
  if (!domain || !selector) throw new Error('[dkim] domain ve selector zorunlu');

  const rawBuf = Buffer.isBuffer(rawMessage) ? rawMessage : Buffer.from(String(rawMessage), 'utf8');
  const { headers: headerList, body } = splitMessage(rawBuf);

  const present = new Set(headerList.map((h) => h.name));
  const wanted = headers.map((h) => h.toLowerCase()).filter((h) => present.has(h));
  if (!wanted.includes('from')) {
    throw new Error('[dkim] From başlığı yok — imzalanamaz');
  }

  // From'u iki kez listelemek ("oversigning"), aradaki birinin ikinci bir
  // From ekleyip imzayı hâlâ geçerli göstermesini engeller: doğrulayan,
  // listede iki From beklerken tek From bulursa imzayı reddeder.
  const hList = oversignFrom ? [...wanted, 'from'] : wanted;

  const bh = bodyHash(body, { canon: bodyCanon, hash: spec.hash });

  const tags = [
    'v=1',
    `a=${algorithm}`,
    `c=${headerCanon}/${bodyCanon}`,
    `d=${domain}`,
    `s=${selector}`,
    `t=${Math.floor((timestamp || Date.now()) / 1000)}`,
    ...(expiresInMs ? [`x=${Math.floor((Date.now() + expiresInMs) / 1000)}`] : []),
    ...(identity ? [`i=${identity}`] : []),
    `h=${hList.join(':')}`,
    `bh=${bh}`,
    'b=',
  ];
  const unsignedHeader = `DKIM-Signature: ${tags.join('; ')}`;

  // Aynı başlık birden fazla varsa ALTTAN başlayarak tüketilir (RFC 6376
  // §5.4.2): üstteki eklenmiş olabilir, alttaki özgün olandır.
  const remaining = new Map();
  for (const h of headerList) {
    if (!remaining.has(h.name)) remaining.set(h.name, []);
    remaining.get(h.name).push(h);
  }
  for (const list of remaining.values()) list.reverse();

  const canonHeader = headerCanon === 'simple' ? canonicalizeHeaderSimple : canonicalizeHeaderRelaxed;
  const signedParts = [];
  for (const name of hList) {
    const list = remaining.get(name);
    if (!list || !list.length) {
      // Listede olup iletide olmayan başlık: boş olarak kanonikleşir. Bu,
      // oversigning'in çalışma biçimi.
      signedParts.push(headerCanon === 'simple' ? '' : `${name}:`);
      continue;
    }
    signedParts.push(canonHeader(list.shift().raw));
  }
  // İmzalanan son öğe, b= değeri BOŞ olan DKIM-Signature başlığının kendisi
  // ve sonunda CRLF YOKTUR (§3.7).
  signedParts.push(canonHeader(unsignedHeader));

  const signingInput = Buffer.from(signedParts.join(CRLF), 'binary');
  const keyObject = crypto.createPrivateKey(privateKeyPem);
  if (keyObject.asymmetricKeyType !== spec.keyType) {
    throw new Error(`[dkim] anahtar türü ${keyObject.asymmetricKeyType}, algoritma ${algorithm} bekliyor`);
  }

  const signature = spec.keyType === 'ed25519'
    ? crypto.sign(null, signingInput, keyObject)
    : crypto.sign(spec.hash, signingInput, keyObject);

  const b64 = signature.toString('base64');
  const signatureHeader = foldSignature(`DKIM-Signature: ${tags.slice(0, -1).join('; ')}; b=${b64}`);

  return {
    signatureHeader,
    rawMessage: Buffer.concat([Buffer.from(signatureHeader + CRLF, 'binary'), rawBuf]),
    bodyHash: bh,
    signedHeaders: hList,
  };
}

/** İmza başlığını 78 sütuna katlar. b= değeri satırlara bölünebilir. */
function foldSignature(header, maxLen = 78) {
  const lines = [];
  let line = '';
  for (const token of header.split(' ')) {
    if (line && line.length + token.length + 1 > maxLen) { lines.push(line); line = ' ' + token; }
    else line += (line ? ' ' : '') + token;
  }
  if (line) lines.push(line);
  // b= değeri tek başına uzunsa onu da böl.
  return lines.map((l) => (l.length <= maxLen ? l : l.replace(/(.{70})/g, `$1${CRLF}  `))).join(CRLF);
}

/* ── doğrulama ─────────────────────────────────────────────── */

function parseTagList(value) {
  const out = {};
  for (const part of String(value).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    const key = part.slice(0, eq).trim();
    // Etiket değerlerinden boşluk temizlenir; b= ve bh= base64 olduğu için
    // içindeki katlama boşlukları tamamen atılmalı.
    const val = part.slice(eq + 1).trim();
    out[key] = /^(b|bh)$/.test(key) ? val.replace(/\s+/g, '') : val;
  }
  return out;
}

async function defaultKeyLookup(selector, domain, { resolver = dns } = {}) {
  const name = `${selector}._domainkey.${domain}`;
  const records = await resolver.resolveTxt(name);
  // TXT kayıtları 255 baytlık parçalara bölünür; birleştirmeden anahtar
  // eksik okunur.
  return records.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
}

/**
 * Bir iletideki DKIM imzalarını doğrular.
 *
 * @returns {Promise<{results: Array, overall: string}>}
 *   overall: 'pass' | 'fail' | 'none' | 'temperror' | 'permerror'
 */
async function verifyMessage(rawMessage, {
  keyLookup = null, resolver = dns, maxSignatures = 5, now = Date.now(), diagnostics = false,
} = {}) {
  const rawBuf = Buffer.isBuffer(rawMessage) ? rawMessage : Buffer.from(String(rawMessage), 'utf8');
  const { headers: headerList, body } = splitMessage(rawBuf);
  const lookup = keyLookup || ((s, d) => defaultKeyLookup(s, d, { resolver }));

  const signatures = headerList.filter((h) => h.name === 'dkim-signature').slice(0, maxSignatures);
  if (!signatures.length) {
    return { results: [], overall: 'none', reason: 'iletide DKIM-Signature başlığı yok' };
  }

  const results = [];
  for (const sigHeader of signatures) {
    const colon = sigHeader.raw.indexOf(':');
    const tags = parseTagList(sigHeader.raw.slice(colon + 1));
    const entry = {
      domain: tags.d || '',
      selector: tags.s || '',
      algorithm: tags.a || '',
      identity: tags.i || '',
      result: 'permerror',
      reason: null,
      bodyHashMatch: false,
    };
    // Tanı bilgisi: bir imza neden geçmedi sorusu, "fail" kelimesiyle
    // cevaplanamıyor. Gövde özeti mi tutmadı, imza mı tutmadı, anahtar mı
    // bulunamadı — üçü tamamen farklı sorunlar ve farklı yerlere bakmayı
    // gerektiriyorlar.
    const detail = {
      canonicalization: tags.c || 'simple/simple',
      signedHeaders: [],
      declaredBodyHash: tags.bh || '',
      computedBodyHash: '',
      bodyLengthTag: tags.l != null ? Number(tags.l) : null,
      dnsName: tags.s && tags.d ? `${tags.s}._domainkey.${tags.d}` : '',
      dnsRecordFound: false,
      signingInputBytes: 0,
      timestamp: tags.t ? Number(tags.t) : null,
      expires: tags.x ? Number(tags.x) : null,
    };
    if (diagnostics) entry.detail = detail;

    try {
      if (tags.v !== '1') throw failPerm('sürüm 1 değil');
      const spec = ALGORITHMS[tags.a];
      if (!spec) throw failPerm(`desteklenmeyen algoritma: ${tags.a}`);
      if (!tags.d || !tags.s || !tags.b || !tags.bh || !tags.h) throw failPerm('eksik etiket');
      if (tags.x && Number(tags.x) * 1000 < now) throw failPerm('imza süresi dolmuş');
      // x= her zaman t='den SONRA olmalı (§3.5). Tersi, imzalayanın kendi
      // imzasını doğmadan geçersiz ilan etmesi demek ve kayıt bozuktur.
      if (tags.x && tags.t && Number(tags.x) < Number(tags.t)) throw failPerm('x= etiketi t= değerinden küçük');

      // i= etiketi d= alanının altında olmak zorunda; olmazsa imza başka bir
      // alan adına ait bir kimliği iddia ediyor.
      if (tags.i) {
        const at = tags.i.lastIndexOf('@');
        const idDomain = at >= 0 ? tags.i.slice(at + 1).toLowerCase() : '';
        const d = tags.d.toLowerCase();
        if (idDomain && idDomain !== d && !idDomain.endsWith(`.${d}`)) throw failPerm('i= etiketi d= altında değil');
      }

      const [headerCanon = 'simple', bodyCanon = 'simple'] = String(tags.c || 'simple/simple').split('/');
      const lengthLimit = tags.l != null && tags.l !== '' ? Number(tags.l) : null;

      // `l=` gövdenin YALNIZCA ilk n sekizlisinin imzalandığını söyler. Bildirilen
      // uzunluk gerçek gövdeden büyükse imza doğrulanamaz (§3.7): aradaki fark,
      // imzalanmış ama teslim edilmemiş bayt demektir ve neyin imzalandığı
      // belirsizleşir. Kısaltıp geçmek, eksik gövdeyi imzalı saymak olurdu.
      const canonicalBody = canonicalizeBody(body, bodyCanon);
      if (lengthLimit != null && lengthLimit > canonicalBody.length) {
        throw failFail(`l= etiketi gövdeden uzun (${lengthLimit} > ${canonicalBody.length})`);
      }

      const computedBh = bodyHash(body, { canon: bodyCanon, hash: spec.hash, lengthLimit });
      detail.computedBodyHash = computedBh;
      entry.bodyHashMatch = computedBh === tags.bh;
      if (!entry.bodyHashMatch) {
        throw failFail(
          `gövde özeti uyuşmuyor (beklenen ${String(tags.bh).slice(0, 12)}…, `
          + `hesaplanan ${computedBh.slice(0, 12)}…, kanoniklik ${bodyCanon}, `
          + `${canonicalBody.length} bayt) — gövde aktarım sırasında değişmiş olabilir`,
        );
      }

      const hNames = String(tags.h).toLowerCase().split(':').map((s) => s.trim()).filter(Boolean);
      if (!hNames.includes('from')) throw failPerm('h= listesinde from yok');
      detail.signedHeaders = hNames;

      const remaining = new Map();
      for (const h of headerList) {
        if (!remaining.has(h.name)) remaining.set(h.name, []);
        remaining.get(h.name).push(h);
      }
      for (const list of remaining.values()) list.reverse();

      const canonHeader = headerCanon === 'simple' ? canonicalizeHeaderSimple : canonicalizeHeaderRelaxed;
      const parts = [];
      for (const name of hNames) {
        const list = remaining.get(name);
        if (!list || !list.length) { parts.push(headerCanon === 'simple' ? '' : `${name}:`); continue; }
        parts.push(canonHeader(list.shift().raw));
      }
      // Doğrulanan DKIM-Signature'ın kendisi, b= değeri boşaltılmış hâlde.
      const selfRaw = sigHeader.raw.replace(/([;\s]b=)[^;]*/i, '$1');
      parts.push(canonHeader(selfRaw));

      const signingInput = Buffer.from(parts.join(CRLF), 'binary');
      detail.signingInputBytes = signingInput.length;

      const txtRecords = await lookup(tags.s, tags.d).catch((err) => {
        throw failTemp(`${detail.dnsName} sorgulanamadı: ${err.code || err.message}`);
      });
      if (!txtRecords || !txtRecords.length) {
        throw failPerm(`${detail.dnsName} için TXT kaydı yok — imzalayan alan anahtarı yayımlamıyor`);
      }
      detail.dnsRecordFound = true;

      const keyRecord = pickKeyRecord(txtRecords, tags.a);
      if (!keyRecord) {
        throw failPerm(
          `${detail.dnsName} kaydında ${tags.a} ile kullanılabilir anahtar yok `
          + `(${txtRecords.length} kayıt bulundu)`,
        );
      }
      // Anahtar kaydı hangi özet algoritmalarına izin verdiğini yazabilir
      // (h=sha256). Listede olmayan bir özetle üretilmiş imza reddedilir:
      // alan sahibi sha1'i kapatmışsa ona uymak gerekir.
      if (keyRecord.h) {
        const allowed = String(keyRecord.h).toLowerCase().split(':').map((s) => s.trim()).filter(Boolean);
        if (allowed.length && !allowed.includes(spec.hash)) {
          throw failPerm(`anahtar kaydı ${spec.hash} özetine izin vermiyor (h=${keyRecord.h})`);
        }
      }

      const publicKey = buildPublicKey(keyRecord, spec.keyType);
      if (!publicKey) throw failPerm('DNS kaydındaki açık anahtar okunamadı (p= bozuk olabilir)');

      const sigBytes = Buffer.from(tags.b, 'base64');
      const ok = spec.keyType === 'ed25519'
        ? crypto.verify(null, signingInput, publicKey, sigBytes)
        : crypto.verify(spec.hash, signingInput, publicKey, sigBytes);

      entry.result = ok ? 'pass' : 'fail';
      entry.testMode = String(keyRecord.t || '').split(':').includes('y');
      if (!ok) {
        // Gövde özeti tuttu ama imza tutmadı: değişen şey BAŞLIKLARDA.
        // Bu ayrım önemli, çünkü ikisinin sebepleri farklı — gövdeyi bir
        // tarayıcı bozar, başlığı aradaki bir liste sunucusu yeniden yazar.
        entry.reason = `imza uyuşmuyor — gövde özeti doğru, imzalanan başlıklardan biri değişmiş `
          + `(h=${hNames.join(':')})`;
      }
    } catch (err) {
      entry.result = err.dkimResult || 'permerror';
      entry.reason = err.message;
    }
    results.push(entry);
  }

  // Bir tanesinin geçmesi yeter (RFC 6376 §6.1): farklı alan adları farklı
  // seçicilerle imzalayabilir.
  const overall = results.some((r) => r.result === 'pass') ? 'pass'
    : results.some((r) => r.result === 'temperror') ? 'temperror'
      : results.some((r) => r.result === 'fail') ? 'fail' : 'permerror';

  const failing = results.find((r) => r.result !== 'pass');
  return {
    results,
    overall,
    reason: overall === 'pass' ? null : (failing ? failing.reason : null),
  };
}

function failPerm(msg) { const e = new Error(msg); e.dkimResult = 'permerror'; return e; }
function failFail(msg) { const e = new Error(msg); e.dkimResult = 'fail'; return e; }
function failTemp(msg) { const e = new Error(msg); e.dkimResult = 'temperror'; return e; }

function pickKeyRecord(txtRecords, algorithm) {
  for (const record of txtRecords) {
    const tags = parseTagList(record);
    if (tags.v && tags.v.toUpperCase() !== 'DKIM1') continue;
    // g= (granularity) ve t=y (test kipi) burada reddetmeye yol açmaz: test
    // kipindeki bir imza geçerlidir, yalnızca alıcı ona göre karar vermez.
    const keyType = (tags.k || 'rsa').toLowerCase();
    const expected = algorithm === 'ed25519-sha256' ? 'ed25519' : 'rsa';
    if (keyType !== expected) continue;
    if (!tags.p) continue; // p= boş: anahtar iptal edilmiş
    return { ...tags, keyType };
  }
  return null;
}

function buildPublicKey(keyRecord, keyType) {
  const der = Buffer.from(String(keyRecord.p).replace(/\s+/g, ''), 'base64');
  try {
    if (keyType === 'ed25519') {
      // DKIM'de Ed25519 açık anahtarı HAM 32 bayt olarak yayımlanır; Node
      // SPKI ister, o yüzden başına sabit önek konur.
      if (der.length === 32) {
        const prefix = Buffer.from('302a300506032b6570032100', 'hex');
        return crypto.createPublicKey({ key: Buffer.concat([prefix, der]), format: 'der', type: 'spki' });
      }
      return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    }
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    try { return crypto.createPublicKey({ key: der, format: 'der', type: 'pkcs1' }); }
    catch { return null; }
  }
}

/* ── anahtar üretimi ve DNS kaydı ──────────────────────────── */

/**
 * DKIM anahtar çifti üretir.
 * RSA-2048 öntanımlı: Ed25519 daha küçük ve hızlı ama doğrulayan tarafların
 * bir kısmı hâlâ desteklemiyor ve desteklemeyen taraf imzayı "yok" sayar.
 * İkisini birden yayımlamak mümkün (farklı seçiciler) ve `algorithm` bunu
 * seçmek için var.
 */
function generateKeyPair({ algorithm = 'rsa', modulusLength = 2048 } = {}) {
  if (algorithm === 'ed25519') {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const spki = publicKey.export({ type: 'spki', format: 'der' });
    return {
      algorithm: 'ed25519-sha256',
      privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
      // Son 32 bayt ham anahtar; DKIM kaydı bunu bekler.
      dnsPublicKey: spki.subarray(spki.length - 32).toString('base64'),
      keyTag: 'k=ed25519',
    };
  }
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength });
  return {
    algorithm: 'rsa-sha256',
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    dnsPublicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    keyTag: 'k=rsa',
  };
}

/** Yayımlanacak TXT kaydının değeri. */
function dnsRecordValue({ dnsPublicKey, algorithm = 'rsa-sha256', testMode = false }) {
  const k = algorithm === 'ed25519-sha256' ? 'ed25519' : 'rsa';
  return `v=DKIM1; k=${k}; ${testMode ? 't=y; ' : ''}p=${dnsPublicKey}`;
}

/** Var olan bir özel anahtardan DNS kaydı üretir (anahtar kasadan geldiğinde). */
function dnsRecordFromPrivateKey(privateKeyPem, { testMode = false } = {}) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const pub = crypto.createPublicKey(key);
  if (key.asymmetricKeyType === 'ed25519') {
    const spki = pub.export({ type: 'spki', format: 'der' });
    return dnsRecordValue({
      dnsPublicKey: spki.subarray(spki.length - 32).toString('base64'),
      algorithm: 'ed25519-sha256',
      testMode,
    });
  }
  return dnsRecordValue({
    dnsPublicKey: pub.export({ type: 'spki', format: 'der' }).toString('base64'),
    algorithm: 'rsa-sha256',
    testMode,
  });
}

function algorithmForKey(privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  return key.asymmetricKeyType === 'ed25519' ? 'ed25519-sha256' : 'rsa-sha256';
}

module.exports = {
  signMessage, verifyMessage, bodyHash,
  splitMessage, canonicalizeHeaderRelaxed, canonicalizeBodyRelaxed,
  canonicalizeHeaderSimple, canonicalizeBodySimple,
  generateKeyPair, dnsRecordValue, dnsRecordFromPrivateKey, algorithmForKey,
  parseTagList, DEFAULT_SIGNED_HEADERS, ALGORITHMS,
};
