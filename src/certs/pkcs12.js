'use strict';

const crypto = require('node:crypto');

/**
 * PKCS#12 (.pfx / .p12) üretme ve okuma — RFC 7292.
 *
 * Posta istemcileri (Outlook, Apple Mail, Thunderbird) S/MIME kimliğini PEM
 * çifti olarak değil, tek bir parola korumalı kap olarak istiyor. Sertifikayı
 * ve özel anahtarı ayrı ayrı indirtip kullanıcıya `openssl pkcs12 -export`
 * komutunu yazdırmak, bu akışın en çok terk edilen adımı.
 *
 * ── NEDEN KENDİ ASN.1'İMİZ ──────────────────────────────────────────────
 * Bu modül `@fitfak/ssl`e BAĞLI DEĞİL. Gereken DER kodlaması yüz satırın
 * altında ve bağımsız olması iki şey kazandırıyor: paket S/MIME olmadan da
 * kurulabiliyor, ve bu dosya kendi başına test edilebiliyor. PKI'nin geri
 * kalanı (CSR, imzalama, profiller) `@fitfak/ssl`de kalıyor.
 *
 * ── YAPI ────────────────────────────────────────────────────────────────
 * OpenSSL'in ürettiğiyle aynı yerleşim kullanılıyor; en geniş uyumluluk
 * bunda:
 *
 *   PFX
 *   ├── version 3
 *   ├── authSafe (data) -> AuthenticatedSafe
 *   │   ├── ContentInfo(encryptedData)  -> certBag'ler   (PBES2/AES-256-CBC)
 *   │   └── ContentInfo(data)           -> shroudedKeyBag (PBES2/AES-256-CBC)
 *   └── macData  (HMAC-SHA256, PKCS#12 KDF)
 *
 * MacData ZORUNLU sayılmalı: onsuz üretilen dosyayı Windows sertifika
 * deposu ve macOS Anahtar Zinciri reddediyor — "geçersiz parola" diye, ki
 * parola doğru olduğu için teşhisi çok zor bir hata. Önceki taslakta bu
 * katman eksikti.
 *
 * `localKeyId` özniteliği de öyle: sertifika ile anahtarı eşleştiren şey o.
 * Olmadığında bazı istemciler kabı açıyor ama "bu sertifikanın özel anahtarı
 * yok" diyor.
 */

/* ── DER kodlayıcı ──────────────────────────────────────────── */

const TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  UTF8: 0x0c,
  SEQUENCE: 0x30,
  SET: 0x31,
  BMP_STRING: 0x1e,
};

function derLength(length) {
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  let n = length;
  while (n > 0) { bytes.unshift(n & 0xff); n >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const seq = (...parts) => tlv(TAG.SEQUENCE, parts.flat());
const set = (...parts) => tlv(TAG.SET, parts.flat());
const octet = (buf) => tlv(TAG.OCTET_STRING, buf);
const nullValue = () => Buffer.from([TAG.NULL, 0x00]);
/** [n] EXPLICIT — içeriği bir başka TLV olan bağlam etiketi. */
const explicit = (n, ...parts) => tlv(0xa0 | n, parts.flat());
/** [n] IMPLICIT OCTET STRING — etiketi değişmiş, içeriği ham. */
const implicitOctet = (n, buf) => tlv(0x80 | n, buf);

function integer(value) {
  let bytes = [];
  let n = BigInt(value);
  if (n === 0n) bytes = [0];
  else {
    while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
    // En yüksek bit 1 ise başa 0x00: DER tamsayıları işaretlidir ve aksi
    // hâlde değer negatif okunur.
    if (bytes[0] & 0x80) bytes.unshift(0);
  }
  return tlv(TAG.INTEGER, Buffer.from(bytes));
}

function oid(dotted) {
  const parts = String(dotted).split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    if (part < 0x80) { bytes.push(part); continue; }
    const chunk = [];
    let n = part;
    while (n > 0) { chunk.unshift((n & 0x7f) | 0x80); n >>= 7; }
    chunk[chunk.length - 1] &= 0x7f;
    bytes.push(...chunk);
  }
  return tlv(TAG.OID, Buffer.from(bytes));
}

/** BMPString: UTF-16BE. PKCS#12'de kolay adlar bu tipte taşınır. */
function bmpString(text) {
  const chars = String(text);
  const buf = Buffer.alloc(chars.length * 2);
  for (let i = 0; i < chars.length; i++) buf.writeUInt16BE(chars.charCodeAt(i), i * 2);
  return tlv(TAG.BMP_STRING, buf);
}

/* ── DER çözücü ─────────────────────────────────────────────── */

function readTLV(buf, offset = 0) {
  const tag = buf[offset];
  let pos = offset + 1;
  let length = buf[pos++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error('[pkcs12] desteklenmeyen uzunluk kodlaması');
    length = 0;
    for (let i = 0; i < count; i++) length = (length << 8) | buf[pos++];
  }
  return { tag, content: buf.subarray(pos, pos + length), end: pos + length };
}

function readChildren(buf) {
  const out = [];
  let offset = 0;
  while (offset < buf.length) {
    const node = readTLV(buf, offset);
    out.push(node);
    offset = node.end;
  }
  return out;
}

function decodeOid(content) {
  const first = content[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (const byte of content.subarray(1)) {
    value = (value << 7) | (byte & 0x7f);
    if (!(byte & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

function derToPem(der, label) {
  const body = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function pemToDer(pem) {
  const body = String(pem).split(/\r?\n/).filter((l) => l && !l.startsWith('-----')).join('');
  return Buffer.from(body, 'base64');
}

/* ── OID'ler ────────────────────────────────────────────────── */

const OIDS = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  certBag: '1.2.840.113549.1.12.10.1.3',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  friendlyName: '1.2.840.113549.1.9.20',
  localKeyId: '1.2.840.113549.1.9.21',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  hmacSha256: '1.2.840.113549.2.9',
  hmacSha1: '1.2.840.113549.2.7',
  hmacSha384: '1.2.840.113549.2.10',
  hmacSha512: '1.2.840.113549.2.11',
  aes256cbc: '2.16.840.1.101.3.4.1.42',
  aes128cbc: '2.16.840.1.101.3.4.1.2',
  des3cbc: '1.2.840.113549.3.7',
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
};

const PRF_HASH = {
  [OIDS.hmacSha1]: 'sha1',
  [OIDS.hmacSha256]: 'sha256',
  [OIDS.hmacSha384]: 'sha384',
  [OIDS.hmacSha512]: 'sha512',
};

const CIPHERS = {
  [OIDS.aes256cbc]: { alg: 'aes-256-cbc', keyLength: 32 },
  [OIDS.aes128cbc]: { alg: 'aes-128-cbc', keyLength: 16 },
  [OIDS.des3cbc]: { alg: 'des-ede3-cbc', keyLength: 24 },
};

const MAC_HASH = { [OIDS.sha1]: 'sha1', [OIDS.sha256]: 'sha256' };

/* ── PKCS#12 anahtar türetme (RFC 7292 Ek B.2) ──────────────── */

/**
 * MAC anahtarı PBKDF2 ile DEĞİL, PKCS#12'nin kendi türetmesiyle üretilir.
 * İkisini karıştırmak, doğru parolayla üretilmiş bir dosyanın her istemcide
 * "parola yanlış" demesine yol açar — ve hata mesajı sebebi göstermez.
 *
 * Parola BMPString olarak, sonunda iki sıfır baytla kodlanır.
 */
function pkcs12Derive(password, salt, id, iterations, length, hashName = 'sha256') {
  const u = crypto.createHash(hashName).digest().length;
  const v = hashName === 'sha512' || hashName === 'sha384' ? 128 : 64;

  const passwordBytes = Buffer.alloc((String(password).length + 1) * 2);
  for (let i = 0; i < String(password).length; i++) {
    passwordBytes.writeUInt16BE(String(password).charCodeAt(i), i * 2);
  }

  const D = Buffer.alloc(v, id);
  const S = fillRepeat(salt, v);
  const P = fillRepeat(passwordBytes, v);
  let I = Buffer.concat([S, P]);

  const blocks = [];
  const needed = Math.ceil(length / u);
  for (let i = 0; i < needed; i++) {
    let A = Buffer.concat([D, I]);
    for (let j = 0; j < iterations; j++) A = crypto.createHash(hashName).update(A).digest();
    blocks.push(A);

    if (i + 1 < needed) {
      const B = fillRepeat(A, v);
      const next = Buffer.alloc(I.length);
      for (let offset = 0; offset < I.length; offset += v) {
        // I_j = (I_j + B + 1) mod 2^v — v baytlık büyük-endian toplama.
        let carry = 1;
        for (let k = v - 1; k >= 0; k--) {
          const sum = I[offset + k] + B[k] + carry;
          next[offset + k] = sum & 0xff;
          carry = sum >> 8;
        }
      }
      I = next;
    }
  }
  return Buffer.concat(blocks).subarray(0, length);
}

/** Bir tamponu, uzunluğu `blockSize`ın katı olacak şekilde tekrarlar. */
function fillRepeat(source, blockSize) {
  if (!source.length) return Buffer.alloc(0);
  const total = Math.ceil(source.length / blockSize) * blockSize;
  const out = Buffer.alloc(total);
  for (let i = 0; i < total; i++) out[i] = source[i % source.length];
  return out;
}

/* ── PBES2 ──────────────────────────────────────────────────── */

function encryptPbes2(plaintext, password, { iterations = 100_000 } = {}) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(16);
  const key = crypto.pbkdf2Sync(String(password), salt, iterations, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  const algorithm = seq(
    oid(OIDS.pbes2),
    seq(
      seq(oid(OIDS.pbkdf2), seq(octet(salt), integer(iterations), seq(oid(OIDS.hmacSha256), nullValue()))),
      seq(oid(OIDS.aes256cbc), octet(iv)),
    ),
  );
  return { algorithm, ciphertext };
}

function decryptPbes2(algorithmNode, ciphertext, password) {
  const [schemeOid, parameters] = readChildren(algorithmNode.content);
  if (decodeOid(schemeOid.content) !== OIDS.pbes2) {
    throw new Error('[pkcs12] yalnızca PBES2 destekleniyor (dosya eski RC2/40-bit şifreleme kullanıyor olabilir)');
  }
  const [kdfNode, encNode] = readChildren(parameters.content);

  const kdfParts = readChildren(kdfNode.content);
  const pbkdf2Params = readChildren(kdfParts[1].content);
  const salt = pbkdf2Params[0].content;
  const iterations = Number(bufferToBigInt(pbkdf2Params[1].content));
  let hashName = 'sha1';
  for (const node of pbkdf2Params.slice(2)) {
    if (node.tag !== TAG.SEQUENCE) continue;
    hashName = PRF_HASH[decodeOid(readChildren(node.content)[0].content)] || 'sha1';
  }

  const encParts = readChildren(encNode.content);
  const cipherInfo = CIPHERS[decodeOid(encParts[0].content)];
  if (!cipherInfo) throw new Error('[pkcs12] desteklenmeyen şifreleme algoritması');
  const iv = encParts[1].content;

  const key = crypto.pbkdf2Sync(String(password), salt, iterations, cipherInfo.keyLength, hashName);
  const decipher = crypto.createDecipheriv(cipherInfo.alg, key, iv);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function bufferToBigInt(buf) {
  let value = 0n;
  for (const byte of buf) value = (value << 8n) | BigInt(byte);
  return value;
}

/* ── üretme ─────────────────────────────────────────────────── */

/**
 * Sertifika + özel anahtardan .pfx üretir.
 *
 * @param {object} p
 * @param {string} p.certPem       sahip sertifikası
 * @param {string} p.privateKeyPem
 * @param {string} p.password      kabı açacak parola
 * @param {string[]} [p.chainPems] ara sertifikalar (zincir tamamlansın diye)
 * @param {string} [p.friendlyName]
 * @returns {Buffer} DER kodlu PFX
 */
function build({ certPem, privateKeyPem, password, chainPems = [], friendlyName = '' }) {
  if (!certPem || !privateKeyPem) throw new Error('[pkcs12] sertifika ve özel anahtar zorunlu');
  if (password == null || password === '') throw new Error('[pkcs12] parola zorunlu');

  // Anahtarı PKCS#8'e normalleştiriyoruz: PKCS#12 shroudedKeyBag içinde
  // PrivateKeyInfo bekliyor, SEC1 ("EC PRIVATE KEY") ya da PKCS#1
  // ("RSA PRIVATE KEY") değil. Node bu dönüşümü zaten yapabiliyor.
  const pkcs8Der = crypto.createPrivateKey(privateKeyPem).export({ type: 'pkcs8', format: 'der' });

  // Sertifika ile anahtarı EŞLEŞTİREN kimlik. İstemciler kabı bununla
  // okuyor; olmadığında "özel anahtarı olmayan sertifika" olarak içe
  // aktarılıyor ve imzalama sessizce çalışmıyor.
  const localKeyId = crypto.randomBytes(20);
  const attributes = (extra = []) => set(
    seq(oid(OIDS.localKeyId), set(octet(localKeyId))),
    ...(friendlyName ? [seq(oid(OIDS.friendlyName), set(bmpString(friendlyName)))] : []),
    ...extra,
  );

  const certBagFor = (pem, withAttributes) => seq(
    oid(OIDS.certBag),
    explicit(0, seq(oid(OIDS.x509Certificate), explicit(0, octet(pemToDer(pem))))),
    ...(withAttributes ? [attributes()] : []),
  );

  // Sahip sertifikası önce, sonra zincir. Zincir halkalarına localKeyId
  // KONMAZ: o kimlik yalnızca anahtarın sahibine ait.
  const certBags = [
    certBagFor(certPem, true),
    ...chainPems.filter(Boolean).map((pem) => seq(
      oid(OIDS.certBag),
      explicit(0, seq(oid(OIDS.x509Certificate), explicit(0, octet(pemToDer(pem))))),
    )),
  ];
  const encryptedCerts = encryptPbes2(seq(...certBags), password);
  const certContentInfo = seq(
    oid(OIDS.encryptedData),
    explicit(0, seq(
      integer(0),
      seq(oid(OIDS.data), encryptedCerts.algorithm, implicitOctet(0, encryptedCerts.ciphertext)),
    )),
  );

  const encryptedKey = encryptPbes2(pkcs8Der, password);
  const keyBag = seq(
    oid(OIDS.pkcs8ShroudedKeyBag),
    explicit(0, seq(encryptedKey.algorithm, octet(encryptedKey.ciphertext))),
    attributes(),
  );
  const keyContentInfo = seq(oid(OIDS.data), explicit(0, octet(seq(keyBag))));

  const authenticatedSafe = seq(certContentInfo, keyContentInfo);

  // MacData: bütünlük VE parola doğrulaması. Anahtarı PKCS#12 KDF üretir.
  const macSalt = crypto.randomBytes(20);
  const macIterations = 2048;
  const macKey = pkcs12Derive(password, macSalt, 3, macIterations, 32, 'sha256');
  const mac = crypto.createHmac('sha256', macKey).update(authenticatedSafe).digest();

  return seq(
    integer(3),
    seq(oid(OIDS.data), explicit(0, octet(authenticatedSafe))),
    seq(seq(seq(oid(OIDS.sha256), nullValue()), octet(mac)), octet(macSalt), integer(macIterations)),
  );
}

/* ── okuma ──────────────────────────────────────────────────── */

/**
 * .pfx okur ve içindekileri PEM olarak döndürür.
 *
 * MAC varsa DOĞRULANIR. Doğrulamamak, yanlış parolayla açılan bir dosyanın
 * anlamsız baytları "anahtar" diye kabul ettirmesine kapı bırakırdı;
 * kullanıcı da hatayı çok sonra, imza tutmadığında görürdü.
 *
 * @returns {{certificates: string[], privateKeys: string[], macVerified: boolean}}
 */
function parse(pfxDer, password) {
  const buf = Buffer.isBuffer(pfxDer) ? pfxDer : Buffer.from(pfxDer);
  const root = readChildren(readTLV(buf, 0).content);
  const authSafeInfo = readChildren(root[1].content);
  const authenticatedSafe = readTLV(authSafeInfo[1].content, 0).content;

  let macVerified = false;
  if (root[2]) {
    const [digestInfo, macSaltNode, iterNode] = readChildren(root[2].content);
    const [algNode, digestNode] = readChildren(digestInfo.content);
    const hashName = MAC_HASH[decodeOid(readChildren(algNode.content)[0].content)] || 'sha1';
    const iterations = iterNode ? Number(bufferToBigInt(iterNode.content)) : 1;
    const length = crypto.createHash(hashName).digest().length;
    const key = pkcs12Derive(password, macSaltNode.content, 3, iterations, length, hashName);
    const expected = crypto.createHmac(hashName, key).update(authenticatedSafe).digest();
    if (!crypto.timingSafeEqual(expected, digestNode.content)) {
      throw new Error('[pkcs12] parola yanlış ya da dosya bozulmuş (MAC doğrulanmadı)');
    }
    macVerified = true;
  }

  const results = { certificates: [], privateKeys: [], macVerified };
  for (const contentInfo of readChildren(readTLV(authenticatedSafe, 0).content)) {
    const parts = readChildren(contentInfo.content);
    const contentType = decodeOid(parts[0].content);

    if (contentType === OIDS.encryptedData) {
      const encrypted = readChildren(readTLV(parts[1].content, 0).content);
      const info = readChildren(encrypted[1].content);
      extractBags(decryptPbes2(info[1], info[2].content, password), password, results);
    } else if (contentType === OIDS.data) {
      extractBags(readTLV(parts[1].content, 0).content, password, results);
    }
  }
  return results;
}

function extractBags(safeContentsDer, password, results) {
  for (const bag of readChildren(readTLV(safeContentsDer, 0).content)) {
    const parts = readChildren(bag.content);
    const bagType = decodeOid(parts[0].content);
    const value = parts[1];

    if (bagType === OIDS.certBag) {
      const certBag = readChildren(readTLV(value.content, 0).content);
      results.certificates.push(derToPem(readTLV(certBag[1].content, 0).content, 'CERTIFICATE'));
    } else if (bagType === OIDS.pkcs8ShroudedKeyBag) {
      const encrypted = readChildren(readTLV(value.content, 0).content);
      const pkcs8 = decryptPbes2(encrypted[0], encrypted[1].content, password);
      results.privateKeys.push(derToPem(pkcs8, 'PRIVATE KEY'));
    } else if (bagType === OIDS.keyBag) {
      const node = readTLV(value.content, 0);
      results.privateKeys.push(derToPem(value.content.subarray(0, node.end), 'PRIVATE KEY'));
    }
  }
}

/**
 * Bir özel anahtarın bir sertifikaya AİT olduğunu kanıtlar.
 *
 * Açık anahtarları karşılaştırmak yetmez: bazı kodlamalar aynı anahtarı
 * farklı baytlarla yazar. Bir imza atıp doğrulamak, soruyu doğrudan
 * cevaplıyor — eşleşmeyen bir çifti kabul etmek, imzalayamayan bir kimlik
 * kaydetmek olurdu.
 */
function keyMatchesCertificate(privateKeyPem, certPem) {
  try {
    const probe = crypto.randomBytes(32);
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    const publicKey = new crypto.X509Certificate(certPem).publicKey;
    if (privateKey.asymmetricKeyType !== publicKey.asymmetricKeyType) return false;
    const signature = crypto.sign('sha256', probe, privateKey);
    return crypto.verify('sha256', probe, publicKey, signature);
  } catch {
    return false;
  }
}

module.exports = {
  build,
  parse,
  keyMatchesCertificate,
  derToPem,
  pemToDer,
  pkcs12Derive,
  OIDS,
};
