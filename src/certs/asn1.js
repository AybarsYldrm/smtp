'use strict';

/**
 * Küçük bir DER kodlayıcı/çözücü.
 *
 * @fitfak/ssl'in `src/asn1.js` modülüyle AYNI yüzeyi sunuyor (readTLV,
 * readChildren, SEQ, OID, OCT, INT, NULL, CTX) — çünkü PKCS#12 kodu ondan
 * türedi ve iki uygulamanın ayrışması, aynı hatayı iki yerde ayrı ayrı
 * aramak demek olurdu.
 *
 * Kendi kopyası olmasının nedeni bağımlılık: @fitfak/ssl ZORUNLU olmayan
 * (peer) bir paket ve kurulu olmadığında S/MIME üretimi devre dışı kalıyor.
 * Bir .pfx'i AÇMAK ya da OLUŞTURMAK ise sertifika üretmekten bağımsız bir
 * ihtiyaç: dışarıda üretilmiş bir anahtarı içeri almak ya da kasadakini
 * dışarı vermek, tam da @fitfak/ssl yokken gerekiyor olabilir.
 *
 * Kapsam BİLİNÇLİ olarak dar: yalnızca PKCS#12 ve PKCS#8 için gereken
 * yapılar. Genel amaçlı bir ASN.1 kütüphanesi değil.
 */

const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  BMP_STRING: 0x1e,
};

/* ── çözücü ─────────────────────────────────────────────────── */

/**
 * Bir TLV (tag-length-value) okur.
 * @returns {{tag:number, headerLen:number, length:number, content:Buffer, totalLen:number}}
 */
function readTLV(buf, offset = 0) {
  if (offset >= buf.length) throw new Error('[asn1] tampon bitti');
  const tag = buf[offset];
  let pos = offset + 1;
  if (pos >= buf.length) throw new Error('[asn1] uzunluk baytı yok');

  let length = buf[pos++];
  if (length & 0x80) {
    const count = length & 0x7f;
    // Belirsiz uzunluk (0x80) BER'dedir, DER'de yasaktır. Desteklemek,
    // kabul ettiğimiz biçimi belirsizleştirir.
    if (count === 0) throw new Error('[asn1] belirsiz uzunluk (BER) desteklenmiyor');
    if (count > 4) throw new Error(`[asn1] çok uzun uzunluk alanı: ${count} bayt`);
    length = 0;
    for (let i = 0; i < count; i++) {
      if (pos >= buf.length) throw new Error('[asn1] uzunluk alanı kesilmiş');
      length = (length << 8) | buf[pos++];
    }
  }
  if (pos + length > buf.length) {
    throw new Error(`[asn1] içerik tamponu aşıyor (tag=0x${tag.toString(16)}, len=${length})`);
  }
  return {
    tag,
    headerLen: pos - offset,
    length,
    content: buf.subarray(pos, pos + length),
    totalLen: pos - offset + length,
  };
}

/** Bir yapısal düğümün çocuklarını sırayla okur. */
function readChildren(content) {
  const out = [];
  let offset = 0;
  while (offset < content.length) {
    const node = readTLV(content, offset);
    node.raw = content.subarray(offset, offset + node.totalLen);
    out.push(node);
    offset += node.totalLen;
  }
  return out;
}

function derIntToBigInt(content) {
  let value = 0n;
  for (const byte of content) value = (value << 8n) | BigInt(byte);
  // İlk bit 1 ise sayı negatiftir (ikiye tümleyen). PKCS#12'de negatif tamsayı
  // beklemiyoruz ama sessizce yanlış okumaktansa doğru okumak daha ucuz.
  if (content.length && (content[0] & 0x80)) value -= 1n << BigInt(content.length * 8);
  return value;
}

/** OID içeriğinin onaltılık gösteriminden noktalı biçime. */
function decodeOidHex(hex) {
  return decodeOid(Buffer.from(String(hex), 'hex'));
}

function decodeOid(content) {
  if (!content.length) return '';
  const parts = [Math.floor(content[0] / 40), content[0] % 40];
  let value = 0n;
  for (let i = 1; i < content.length; i++) {
    value = (value << 7n) | BigInt(content[i] & 0x7f);
    if (!(content[i] & 0x80)) { parts.push(value.toString()); value = 0n; }
  }
  return parts.join('.');
}

/* ── kodlayıcı ──────────────────────────────────────────────── */

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let value = n;
  while (value > 0) { bytes.unshift(value & 0xff); value >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Ham TLV üretir. */
function tlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

function SEQ(...children) { return tlv(TAG.SEQUENCE, Buffer.concat(children.map(asBuffer))); }
function SET(...children) { return tlv(TAG.SET, Buffer.concat(children.map(asBuffer))); }
function OCT(content) { return tlv(TAG.OCTET_STRING, asBuffer(content)); }
function NULL() { return Buffer.from([TAG.NULL, 0x00]); }

function INT(value) {
  let v = typeof value === 'bigint' ? value : BigInt(value);
  if (v === 0n) return Buffer.from([TAG.INTEGER, 0x01, 0x00]);
  if (v < 0n) throw new Error('[asn1] negatif tamsayı kodlaması gerekmiyor');
  const bytes = [];
  while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
  // En anlamlı bit 1 ise başa 0x00 konur, yoksa değer negatif okunur.
  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return tlv(TAG.INTEGER, Buffer.from(bytes));
}

function OID(dotted) {
  const parts = String(dotted).split('.').map(Number);
  if (parts.length < 2 || parts.some((n) => !Number.isFinite(n))) {
    throw new Error(`[asn1] geçersiz OID: ${dotted}`);
  }
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let value = part;
    do { chunk.unshift(value & 0x7f); value >>>= 7; } while (value > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    bytes.push(...chunk);
  }
  return tlv(TAG.OID, Buffer.from(bytes));
}

/**
 * Bağlam etiketi.
 *
 * `explicit: true` (öntanımlı) içeriği OLDUĞU GİBİ sarar — verilen değer
 * zaten tam bir TLV olmalıdır. `explicit: false` ise IMPLICIT etiketlemedir
 * ve içeriğin ETİKETİ DEĞİŞTİRİLİR, sarılmaz.
 *
 * Bu ayrım PKCS#12'de bir hata kaynağıydı: `EncryptedContentInfo` içindeki
 * `encryptedContent` alanı **[0] IMPLICIT OCTET STRING**'tir. Onu EXPLICIT
 * sarmak (yani `A0 04 …`) yapıyı sözdizimsel olarak geçerli ama anlamca
 * yanlış kılar; OpenSSL da Windows da böyle bir .pfx'i açamaz, üstelik hata
 * "parola yanlış" gibi görünür.
 */
function CTX(number, content, { explicit = true, constructed = null } = {}) {
  const body = asBuffer(content);
  if (explicit) {
    return tlv(0xa0 | (number & 0x1f), body);
  }
  const isConstructed = constructed == null ? false : constructed;
  return tlv((isConstructed ? 0xa0 : 0x80) | (number & 0x1f), body);
}

/** UTF-16BE (BMPString) — PKCS#12 dostu ad ve parola gösterimi. */
function BMP(text) {
  const s = String(text == null ? '' : text);
  const buf = Buffer.alloc(s.length * 2);
  for (let i = 0; i < s.length; i++) buf.writeUInt16BE(s.charCodeAt(i), i * 2);
  return tlv(TAG.BMP_STRING, buf);
}

function asBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  throw new Error('[asn1] Buffer bekleniyor');
}

/* ── PEM köprüsü ────────────────────────────────────────────── */

function derToPem(der, label) {
  const b64 = der.toString('base64').match(/.{1,64}/g);
  return `-----BEGIN ${label}-----\n${(b64 || []).join('\n')}\n-----END ${label}-----\n`;
}

function pemToDer(pem) {
  const text = String(pem);
  const body = text.includes('-----BEGIN')
    ? text.split('\n').filter((l) => l && !l.startsWith('-----')).join('')
    : text;
  const der = Buffer.from(body.replace(/\s+/g, ''), 'base64');
  if (!der.length) throw new Error('[asn1] PEM gövdesi boş ya da çözülemedi');
  return der;
}

module.exports = {
  TAG,
  readTLV, readChildren, derIntToBigInt, decodeOid, decodeOidHex,
  tlv, SEQ, SET, OCT, NULL, INT, OID, CTX, BMP,
  derToPem, pemToDer,
};
