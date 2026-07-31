'use strict';

const crypto = require('node:crypto');

const {
  decodeMimeWords, decodeQuotedPrintable, decodeCharset,
  parseAddress, parseAddressList, htmlToText, makePreview, safeFileName, decodeMaybeUtf8,
} = require('../util/encoding');

/**
 * MIME ayrıştırıcı.
 *
 * Üç şeyi doğru yapmak zorunda ve önceki sürüm üçünde de hatalıydı:
 *
 *   1. SINIR (boundary) YAPISI İÇ İÇEDİR. Önceki sürüm iletideki bütün
 *      boundary değerlerini tek bir regex'e toplayıp iletiyi hepsine göre
 *      bölüyordu. multipart/mixed içinde multipart/alternative olan sıradan
 *      bir iletide bu, parçaları yanlış yerlerden keser: ek olarak gönderilen
 *      bir görselin baytları metin gövdesinin içine karışır. Ayrıştırma
 *      özyinelemeli olmak zorunda.
 *
 *   2. BAYTLAR METİN DEĞİLDİR. Önceki sürüm soketi `setEncoding('utf8')` ile
 *      okuyup ham iletiyi bir dizge olarak taşıyordu. base64 çözülünce bu
 *      sorun çıkarmıyor ama 8bit taşınan ekler ve karakter kümesi UTF-8
 *      olmayan gövdeler bozuluyor — geri dönüşü olmayan biçimde, çünkü
 *      bozulma diske yazılmadan önce oluyor.
 *
 *   3. S/MIME İMZASI HAM BAYTLAR ÜZERİNDEN DOĞRULANIR. multipart/signed'ın
 *      imzalanan parçası yeniden kurulamaz; başlık sırası ya da satır sonu
 *      değişirse imza bozulur. Bu yüzden o parçanın ham dilimi (`signedContent`)
 *      olduğu gibi saklanıyor.
 */

const DEFAULT_LIMITS = {
  maxAttachmentsPerMessage: 25,
  maxAttachmentBytes: 25 * 1024 * 1024,
  maxTotalAttachmentBytes: 35 * 1024 * 1024,
  maxBodyBytes: 2 * 1024 * 1024,
  maxMimeParts: 200,
  maxMimeDepth: 20,
  allowedAttachmentTypes: null, // null = hepsi
  blockedAttachmentExtensions: [],
};

/** Dosya türü imzaları. Beyan edilen türle çelişki, eki güvenilmez yapar. */
const MAGIC = [
  { type: 'image/png', bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: 'image/jpeg', bytes: [0xff, 0xd8, 0xff] },
  { type: 'image/gif', bytes: [0x47, 0x49, 0x46, 0x38] },
  { type: 'application/pdf', bytes: [0x25, 0x50, 0x44, 0x46, 0x2d] },
  { type: 'application/zip', bytes: [0x50, 0x4b, 0x03, 0x04] },
  { type: 'application/gzip', bytes: [0x1f, 0x8b] },
  { type: 'application/x-msdownload', bytes: [0x4d, 0x5a] }, // PE/EXE
  { type: 'application/x-elf', bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { type: 'application/x-rar', bytes: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07] },
  { type: 'application/x-7z', bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
];

function sniffType(buf) {
  if (!buf || buf.length < 4) return '';
  for (const sig of MAGIC) {
    if (buf.length < sig.bytes.length) continue;
    let ok = true;
    for (let i = 0; i < sig.bytes.length; i++) if (buf[i] !== sig.bytes[i]) { ok = false; break; }
    if (ok) return sig.type;
  }
  // RIFF tabanlı (WEBP, WAV) ve ISO-BMFF (MP4) ayrı: dört bayt öteye bakmak gerekir.
  if (buf.length >= 12) {
    const head = buf.subarray(0, 4).toString('latin1');
    const brand = buf.subarray(8, 12).toString('latin1');
    if (head === 'RIFF' && brand === 'WEBP') return 'image/webp';
    if (head === 'RIFF' && brand === 'WAVE') return 'audio/wav';
    if (buf.subarray(4, 8).toString('latin1') === 'ftyp') {
      if (/^(isom|iso2|mp41|mp42|avc1|dash|M4V )/.test(brand)) return 'video/mp4';
      if (/^qt/.test(brand)) return 'video/quicktime';
      if (/^(heic|heix|mif1)/.test(brand)) return 'image/heic';
    }
    if (head === 'OggS') return 'audio/ogg';
    if (buf.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))) return 'video/x-matroska';
  }
  return '';
}

/** Beyan edilen tür ile içerik çelişiyor mu? */
function typesConflict(declared, sniffed) {
  if (!sniffed || !declared) return false;
  const d = declared.toLowerCase();
  const s = sniffed.toLowerCase();
  if (d === s) return false;
  // Çalıştırılabilir bir içerik başka bir tür olarak beyan edilmişse çelişki
  // kesin. Bu, "image/png" diyip .exe göndermenin yakalandığı yer.
  if (s === 'application/x-msdownload' || s === 'application/x-elf') return true;
  // OOXML dosyaları zip'tir; zip olarak koklanması çelişki değil.
  if (s === 'application/zip' && /(officedocument|opendocument|zip|epub|jar|apk)/.test(d)) return false;
  if (s === 'application/gzip' && /(gzip|tar|tgz)/.test(d)) return false;
  // Aynı üst tür içinde kalan uyuşmazlık (image/jpeg <-> image/png) yalnızca
  // yanlış etiketlemedir; içeriği türüne göre yeniden adlandırmak yeterli.
  if (d.split('/')[0] === s.split('/')[0]) return false;
  return true;
}

function parseHeaderBlock(text) {
  const headers = {};
  const list = [];
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && current) {
      current.value += ' ' + line.trim();
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    current = { name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() };
    list.push(current);
  }
  for (const entry of list) {
    const key = entry.name.toLowerCase();
    // Aynı başlık birden fazlaysa hepsi korunur ama okuma yolu İLKİNİ
    // kullanır. Received gibi çoklu başlıklarda liste, From gibi tekil
    // olması gerekenlerde ise ilki anlamlıdır — sonrakini kullanmak
    // başlık enjeksiyonuna kapı açar.
    if (headers[key] == null) headers[key] = entry.value;
    else if (Array.isArray(headers[key])) headers[key].push(entry.value);
    else headers[key] = [headers[key], entry.value];
  }
  return { headers, list };
}

/** `Content-Type: text/plain; charset=utf-8; name="a b"` -> {type, params} */
function parseContentType(value) {
  const raw = String(value || '').trim();
  if (!raw) return { type: '', params: {} };
  const semi = raw.indexOf(';');
  const type = (semi >= 0 ? raw.slice(0, semi) : raw).trim().toLowerCase();
  const params = {};
  if (semi >= 0) Object.assign(params, parseParameters(raw.slice(semi + 1)));
  return { type, params };
}

/**
 * Parametre ayrıştırma; RFC 2231 sürekli/kodlu parametreleri dâhil.
 * `filename*0*=utf-8''%C3%A7` biçimini anlamamak, Türkçe adlı ekleri
 * "undefined" diye kaydetmek olurdu.
 */
function parseParameters(text) {
  const out = {};
  const continuations = {};
  const rx = /([^=;\s]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^;]*))/g;
  let m;
  while ((m = rx.exec(text)) !== null) {
    const rawKey = m[1].trim().toLowerCase();
    const value = m[2] != null ? m[2].replace(/\\(.)/g, '$1') : String(m[3] || '').trim();
    const cont = rawKey.match(/^([^*]+)\*(\d+)(\*)?$/);
    if (cont) {
      const base = cont[1];
      continuations[base] = continuations[base] || [];
      continuations[base][Number(cont[2])] = { value, encoded: !!cont[3] };
      continue;
    }
    if (rawKey.endsWith('*')) {
      out[rawKey.slice(0, -1)] = decodeExtendedParameter(value);
      continue;
    }
    if (out[rawKey] == null) out[rawKey] = value;
  }
  for (const [base, parts] of Object.entries(continuations)) {
    let joined = '';
    let anyEncoded = false;
    for (const part of parts) {
      if (!part) continue;
      joined += part.value;
      if (part.encoded) anyEncoded = true;
    }
    out[base] = anyEncoded ? decodeExtendedParameter(joined) : joined;
  }
  return out;
}

function decodeExtendedParameter(value) {
  const m = String(value).match(/^([^']*)'([^']*)'(.*)$/);
  const charset = m ? m[1] : 'utf-8';
  const encoded = m ? m[3] : String(value);
  const bytes = [];
  for (let i = 0; i < encoded.length; i++) {
    if (encoded[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(encoded.slice(i + 1, i + 3))) {
      bytes.push(parseInt(encoded.slice(i + 1, i + 3), 16));
      i += 2;
    } else bytes.push(encoded.charCodeAt(i));
  }
  return decodeCharset(Buffer.from(bytes), charset);
}

function decodePartBody(buf, encoding) {
  const enc = String(encoding || '').trim().toLowerCase();
  if (enc === 'base64') {
    // base64 dışı karakterler atılır: bazı gönderenler satır sonlarını ve
    // boşlukları serbestçe koyar.
    return Buffer.from(buf.toString('latin1').replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
  }
  if (enc === 'quoted-printable') return decodeQuotedPrintable(buf.toString('latin1'));
  // 7bit / 8bit / binary: dokunulmaz.
  return buf;
}

/** Bir multipart gövdesini sınır dizgesine göre ham dilimlere böler. */
function splitMultipart(body, boundary) {
  const marker = Buffer.from(`--${boundary}`, 'latin1');
  const parts = [];
  let searchFrom = 0;
  let firstIndex = -1;

  const positions = [];
  while (true) {
    const idx = body.indexOf(marker, searchFrom);
    if (idx === -1) break;
    // Sınır yalnızca satır başında geçerli. Gövdenin içinde geçen aynı diziyi
    // sınır saymak, iletiyi yanlış yerden keser.
    const atLineStart = idx === 0 || body[idx - 1] === 0x0a || (body[idx - 1] === 0x0d);
    if (atLineStart) positions.push(idx);
    searchFrom = idx + marker.length;
  }

  for (let i = 0; i < positions.length; i++) {
    const start = positions[i];
    const afterMarker = start + marker.length;
    const isClosing = body[afterMarker] === 0x2d && body[afterMarker + 1] === 0x2d;
    if (firstIndex === -1) { firstIndex = start; }
    if (isClosing) break;
    // Sınır satırının sonuna kadar atla (CRLF).
    let contentStart = afterMarker;
    while (contentStart < body.length && body[contentStart] !== 0x0a) contentStart++;
    contentStart++;
    const nextStart = positions[i + 1];
    if (nextStart == null) {
      parts.push(body.subarray(contentStart));
      break;
    }
    // Sonraki sınırdan önceki CRLF sınır işaretçisine aittir, içeriğe değil.
    let end = nextStart;
    if (end > contentStart && body[end - 1] === 0x0a) end--;
    if (end > contentStart && body[end - 1] === 0x0d) end--;
    parts.push(body.subarray(contentStart, end));
  }
  return parts;
}

function extensionOf(fileName) {
  const m = String(fileName || '').match(/(\.[A-Za-z0-9]{1,12})$/);
  return m ? m[1].toLowerCase() : '';
}

/**
 * Bir eki politikaya göre değerlendirir.
 * Ret sebebi kayda yazılır ve kullanıcıya gösterilir: sessizce düşen bir ek,
 * "gelmedi" olarak değil "hiç gönderilmedi" olarak algılanır ve destek
 * tarafında bulunamaz.
 */
function screenAttachment({ fileName, contentType, content, limits, state }) {
  const size = content ? content.length : 0;
  const ext = extensionOf(fileName);
  const sniffed = sniffType(content);

  if (state.attachmentCount >= limits.maxAttachmentsPerMessage) {
    return { scanStatus: 'rejected_count', rejectedReason: `ek sayısı sınırı (${limits.maxAttachmentsPerMessage})`, sniffed };
  }
  if (size > limits.maxAttachmentBytes) {
    return { scanStatus: 'rejected_size', rejectedReason: `ek boyutu sınırı (${formatBytes(limits.maxAttachmentBytes)})`, sniffed };
  }
  if (state.totalAttachmentBytes + size > limits.maxTotalAttachmentBytes) {
    return { scanStatus: 'rejected_size', rejectedReason: `toplam ek boyutu sınırı (${formatBytes(limits.maxTotalAttachmentBytes)})`, sniffed };
  }
  if (ext && limits.blockedAttachmentExtensions.includes(ext)) {
    return { scanStatus: 'rejected_extension', rejectedReason: `uzantı kabul edilmiyor: ${ext}`, sniffed };
  }
  if (typesConflict(contentType, sniffed)) {
    return { scanStatus: 'rejected_type', rejectedReason: `beyan edilen tür (${contentType}) içerikle çelişiyor (${sniffed})`, sniffed };
  }
  if (limits.allowedAttachmentTypes && limits.allowedAttachmentTypes.length) {
    const allowed = limits.allowedAttachmentTypes.includes(contentType)
      || (sniffed && limits.allowedAttachmentTypes.includes(sniffed));
    if (!allowed) {
      return { scanStatus: 'rejected_type', rejectedReason: `tür kabul edilmiyor: ${contentType}`, sniffed };
    }
  }
  return { scanStatus: 'accepted', rejectedReason: '', sniffed };
}

function formatBytes(n) {
  if (n >= 1024 * 1024) return `${Math.round(n / (1024 * 1024))} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
}

/**
 * Ham iletiyi ayrıştırır.
 *
 * @param {Buffer} raw
 * @param {object} [opts]
 * @param {object} [opts.limits]
 * @returns {object} ayrıştırılmış ileti
 */
function parseMessage(raw, { limits: limitsInput = {}, keepPartRaw = true } = {}) {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw), 'utf8');
  const limits = { ...DEFAULT_LIMITS, ...limitsInput };

  const state = {
    partCount: 0,
    attachmentCount: 0,
    totalAttachmentBytes: 0,
    bodyBytes: 0,
    bodyTruncated: false,
  };

  const root = parseEntity(buf, { limits, state, depth: 0, partId: '1', keepPartRaw });

  const textParts = [];
  const htmlParts = [];
  const attachments = [];
  const flatParts = [];
  let signedContent = null;
  let signaturePart = null;
  let encrypted = false;

  walk(root, (part) => {
    flatParts.push({ partId: part.partId, contentType: part.contentType, sizeBytes: part.sizeBytes });
    if (part.smimeSignedContent) signedContent = part.smimeSignedContent;
    if (part.smimeSignature) signaturePart = part.smimeSignature;
    if (part.smimeEncrypted) encrypted = true;
    if (part.isAttachment) { attachments.push(part.attachment); return; }
    if (part.contentType === 'text/plain' && part.text != null) textParts.push(part.text);
    else if (part.contentType === 'text/html' && part.text != null) htmlParts.push(part.text);
  });

  const { headers, list } = root.headerInfo;
  const from = parseAddress(firstValue(headers.from));
  const subject = decodeMimeWords(firstValue(headers.subject) || '');

  const text = textParts.join('\n\n').trim();
  const html = htmlParts.join('\n<hr>\n').trim();

  return {
    headers,
    headerList: list.map((h) => [h.name, h.value]),
    from,
    to: parseAddressList(firstValue(headers.to)),
    cc: parseAddressList(firstValue(headers.cc)),
    bcc: parseAddressList(firstValue(headers.bcc)),
    replyTo: parseAddress(firstValue(headers['reply-to'])).address || '',
    subject,
    date: firstValue(headers.date) || '',
    messageId: (firstValue(headers['message-id']) || '').trim(),
    inReplyTo: (firstValue(headers['in-reply-to']) || '').trim(),
    references: String(firstValue(headers.references) || '').split(/\s+/).filter(Boolean),
    listId: (firstValue(headers['list-id']) || '').trim(),
    autoSubmitted: (firstValue(headers['auto-submitted']) || '').trim(),
    precedence: (firstValue(headers.precedence) || '').trim(),
    contentType: root.contentType,
    text,
    html,
    preview: makePreview(text || htmlToText(html)),
    attachments,
    parts: flatParts,
    signedContent,
    signaturePart,
    encrypted,
    sizeBytes: buf.length,
    bodyTruncated: state.bodyTruncated,
    partCount: state.partCount,
  };
}

function firstValue(v) { return Array.isArray(v) ? v[0] : v; }

function walk(part, visit) {
  visit(part);
  for (const child of part.children || []) walk(child, visit);
}

function parseEntity(buf, { limits, state, depth, partId, keepPartRaw, inheritedHeaders = null }) {
  state.partCount++;

  let headerInfo;
  let body;
  if (inheritedHeaders) {
    headerInfo = inheritedHeaders;
    body = buf;
  } else {
    const sep = findHeaderSeparator(buf);
    const headerText = decodeMaybeUtf8(sep.index >= 0 ? buf.subarray(0, sep.index) : buf);
    headerInfo = parseHeaderBlock(headerText);
    body = sep.index >= 0 ? buf.subarray(sep.index + sep.length) : Buffer.alloc(0);
  }

  const { headers } = headerInfo;
  const ct = parseContentType(firstValue(headers['content-type']) || 'text/plain');
  const encoding = firstValue(headers['content-transfer-encoding']) || '7bit';
  const disposition = parseContentType(firstValue(headers['content-disposition']) || '');
  const contentId = String(firstValue(headers['content-id']) || '').replace(/[<>\s]/g, '');

  const part = {
    partId,
    headerInfo,
    contentType: ct.type || 'text/plain',
    params: ct.params,
    encoding,
    disposition: disposition.type || '',
    contentId,
    sizeBytes: body.length,
    children: [],
    isAttachment: false,
  };

  // Derinlik ve parça sayısı sınırı: iç içe binlerce multipart taşıyan bir
  // ileti, ayrıştırıcıyı yığın taşmasına ya da bellek tükenmesine
  // sürükleyebilir. Sınıra takılan parça ham hâliyle ek gibi saklanır —
  // atılmaz, çünkü içinde gerçek veri olabilir.
  if (depth >= limits.maxMimeDepth || state.partCount > limits.maxMimeParts) {
    part.isAttachment = true;
    part.attachment = {
      partId,
      fileName: safeFileName(ct.params.name || 'ic-ice-parca.bin'),
      contentType: 'application/octet-stream',
      content: body,
      sizeBytes: body.length,
      contentId,
      disposition: 'attachment',
      isInline: false,
      scanStatus: 'truncated',
      rejectedReason: depth >= limits.maxMimeDepth ? 'MIME derinlik sınırı' : 'MIME parça sayısı sınırı',
      declaredType: ct.type,
      sniffedType: '',
    };
    return part;
  }

  if (part.contentType.startsWith('multipart/')) {
    const boundary = ct.params.boundary;
    if (!boundary) {
      // Sınırı olmayan multipart bozuktur; gövdeyi düz metin gibi ele almak,
      // hiç göstermemekten iyidir.
      part.contentType = 'text/plain';
      part.text = decodeText(decodePartBody(body, encoding), ct.params.charset);
      return part;
    }
    const rawParts = splitMultipart(body, boundary);

    // multipart/signed: İLK parça imzalanan içerik, ikincisi imza. İmzalanan
    // parçanın ham dilimi olduğu gibi tutulur; yeniden kurmak imzayı bozar.
    const isSigned = part.contentType === 'multipart/signed';

    rawParts.forEach((slice, i) => {
      const child = parseEntity(slice, {
        limits, state, depth: depth + 1, partId: `${partId}.${i + 1}`, keepPartRaw,
      });
      if (isSigned && i === 0 && keepPartRaw) {
        // CRLF'e normalize: imza CRLF üzerinden hesaplanmıştır ve taşıma
        // sırasında satır sonu değişmiş olabilir.
        part.smimeSignedContent = normalizeCrlf(slice);
      }
      if (isSigned && i === 1) {
        const sigBytes = decodePartBody(slice.subarray(findHeaderSeparator(slice).index + findHeaderSeparator(slice).length), child.encoding);
        part.smimeSignature = sigBytes;
        // İmza parçası ek olarak listelenmez: kullanıcıya "smime.p7s" diye
        // bir dosya göstermek gürültüdür, imza durumu ayrı alanda taşınıyor.
        child.isAttachment = false;
        child.suppressed = true;
      }
      part.children.push(child);
    });
    return part;
  }

  if (part.contentType === 'application/pkcs7-mime' || part.contentType === 'application/x-pkcs7-mime') {
    const smimeType = String(ct.params['smime-type'] || '').toLowerCase();
    const decoded = decodePartBody(body, encoding);
    if (smimeType === 'enveloped-data') part.smimeEncrypted = true;
    else part.smimeSignature = decoded; // opak imza
    part.isAttachment = false;
    return part;
  }

  const decoded = decodePartBody(body, encoding);
  const fileNameRaw = disposition.params.filename || ct.params.name || '';
  const fileName = fileNameRaw ? safeFileName(decodeMimeWords(fileNameRaw)) : '';
  const isInline = part.disposition === 'inline' || (!!contentId && !fileName);
  const looksLikeAttachment = part.disposition === 'attachment' || !!fileName
    || (!!contentId && !part.contentType.startsWith('text/'));

  if (looksLikeAttachment) {
    const verdict = screenAttachment({
      fileName: fileName || `ek-${partId}`,
      contentType: part.contentType,
      content: decoded,
      limits,
      state,
    });
    if (verdict.scanStatus === 'accepted') {
      state.attachmentCount++;
      state.totalAttachmentBytes += decoded.length;
    }
    part.isAttachment = true;
    part.attachment = {
      partId,
      fileName: fileName || defaultNameFor(part.contentType, partId),
      contentType: part.contentType,
      // Reddedilen ek baytları TAŞINMAZ: sınırı aşan bir eki saklamak,
      // sınırın amacını ortadan kaldırır. Üstverisi kalır, içeriği kalmaz.
      content: verdict.scanStatus === 'accepted' ? decoded : null,
      sizeBytes: decoded.length,
      contentId,
      disposition: part.disposition || 'attachment',
      isInline,
      scanStatus: verdict.scanStatus,
      rejectedReason: verdict.rejectedReason,
      declaredType: part.contentType,
      sniffedType: verdict.sniffed,
      sha256Hex: verdict.scanStatus === 'accepted' ? crypto.createHash('sha256').update(decoded).digest('hex') : '',
    };
    return part;
  }

  if (part.contentType.startsWith('text/')) {
    let textBuf = decoded;
    if (state.bodyBytes + textBuf.length > limits.maxBodyBytes) {
      textBuf = textBuf.subarray(0, Math.max(0, limits.maxBodyBytes - state.bodyBytes));
      state.bodyTruncated = true;
    }
    state.bodyBytes += textBuf.length;
    part.text = decodeText(textBuf, ct.params.charset);
    return part;
  }

  // Ne metin ne ek: adı olmayan bir ikili parça. Ek gibi ele alınır, çünkü
  // gösterilemez ama var.
  const verdict = screenAttachment({
    fileName: defaultNameFor(part.contentType, partId),
    contentType: part.contentType,
    content: decoded,
    limits,
    state,
  });
  if (verdict.scanStatus === 'accepted') {
    state.attachmentCount++;
    state.totalAttachmentBytes += decoded.length;
  }
  part.isAttachment = true;
  part.attachment = {
    partId,
    fileName: defaultNameFor(part.contentType, partId),
    contentType: part.contentType,
    content: verdict.scanStatus === 'accepted' ? decoded : null,
    sizeBytes: decoded.length,
    contentId,
    disposition: 'attachment',
    isInline: false,
    scanStatus: verdict.scanStatus,
    rejectedReason: verdict.rejectedReason,
    declaredType: part.contentType,
    sniffedType: verdict.sniffed,
    sha256Hex: verdict.scanStatus === 'accepted' ? crypto.createHash('sha256').update(decoded).digest('hex') : '',
  };
  return part;
}

function defaultNameFor(contentType, partId) {
  const sub = String(contentType || '').split('/')[1] || 'bin';
  const ext = { jpeg: 'jpg', quicktime: 'mov', 'x-matroska': 'mkv', 'x-msvideo': 'avi', plain: 'txt' }[sub] || sub;
  return `ek-${partId}.${ext.replace(/[^a-z0-9]/gi, '')}`;
}

function decodeText(buf, charset) {
  return decodeCharset(buf, charset || 'utf-8');
}

function findHeaderSeparator(buf) {
  for (let i = 0; i < buf.length - 1; i++) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      return { index: i, length: 4 };
    }
    if (buf[i] === 0x0a && buf[i + 1] === 0x0a) return { index: i, length: 2 };
  }
  return { index: -1, length: 0 };
}

function normalizeCrlf(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x0d) {
      out.push(0x0d, 0x0a);
      if (buf[i + 1] === 0x0a) i++;
    } else if (buf[i] === 0x0a) out.push(0x0d, 0x0a);
    else out.push(buf[i]);
  }
  return Buffer.from(out);
}

module.exports = {
  parseMessage, parseContentType, parseParameters, parseHeaderBlock,
  splitMultipart, sniffType, typesConflict, screenAttachment, decodePartBody,
  DEFAULT_LIMITS,
};
