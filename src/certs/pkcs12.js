'use strict';

const crypto = require('node:crypto');

const {
  readTLV, readChildren, derIntToBigInt, decodeOidHex,
  SEQ, SET, OID, OCT, INT, NULL, CTX, BMP, derToPem, pemToDer,
} = require('./asn1');

/**
 * PKCS#12 (.pfx) okuma ve yazma.
 *
 * ── NEDEN VAR ────────────────────────────────────────────────────────────
 * İki yönlü bir ihtiyacın karşılığı:
 *
 *   DIŞARI: kasadaki S/MIME sertifikası ve özel anahtarı, Thunderbird,
 *           Outlook, Apple Mail ya da bir donanım anahtarına aktarmak. Bu
 *           istemcilerin hepsi .pfx okur; ayrı ayrı .crt + .key kabul eden
 *           yok denecek kadar az.
 *   İÇERİ:  başka bir yerde (ör. bir kurumsal CA'da) üretilmiş bir anahtar
 *           çiftini posta sunucusuna tanıtmak. Anahtarı kasaya almanın
 *           taşınabilir tek biçimi yine .pfx.
 *
 * ── KULLANICININ pfx.js'İNDEN FARKLAR ────────────────────────────────────
 * Bu modül kullanıcının paylaştığı `pfx.js`ten türedi. Ayrıştırma tarafı
 * neredeyse aynı; ÜRETME tarafında üç şey düzeltildi ve üçü de "dosya
 * yazıldı ama hiçbir istemci açamıyor" sonucunu veriyordu:
 *
 *   1. `encryptedContent` alanı **[0] IMPLICIT OCTET STRING**'tir. Özgün kod
 *      onu EXPLICIT sarıyordu (`A0 04 …`), yani şifreli metnin başına bir
 *      OCTET STRING başlığı daha giriyordu. Çözen taraf o başlığı da şifreli
 *      metnin parçası sanıp çözmeye çalışıyor ve dolgu (padding) hatası
 *      alıyor — hata "parola yanlış" gibi görünüyor.
 *
 *   2. MacData YOKTU. Özgün kodun kendi notu da bunu söylüyordu
 *      ("DİKKAT: MacData katmanı eksiktir"). OpenSSL onsuz dosyayı
 *      `mac absent` diye okuyabiliyor ama Windows ve macOS anahtar
 *      zincirleri bütünlük katmanı olmayan bir .pfx'i doğrudan reddediyor.
 *      Artık RFC 7292 Ek B'deki PKCS#12 anahtar türetmesiyle üretiliyor.
 *
 *   3. `localKeyId` ve `friendlyName` öznitelikleri yoktu. Onlar olmadan
 *      içe aktaran taraf sertifika ile özel anahtarı EŞLEŞTİREMİYOR:
 *      sertifika görünüyor, "özel anahtarı yok" diyor.
 *
 * Ayrıca parola BMPString olarak (UTF-16BE + sonda çift sıfır) türetiliyor;
 * PKCS#12 anahtar türetmesi bunu şart koşuyor ve ASCII varsayan bir uygulama
 * yalnızca ASCII parolalarda çalışır.
 */

const OIDS = {
  data: '1.2.840.113549.1.7.1',
  encryptedData: '1.2.840.113549.1.7.6',
  certBag: '1.2.840.113549.1.12.10.1.3',
  pkcs8ShroudedKeyBag: '1.2.840.113549.1.12.10.1.2',
  keyBag: '1.2.840.113549.1.12.10.1.1',
  x509Certificate: '1.2.840.113549.1.9.22.1',
  friendlyName: '1.2.840.113549.1.9.20',
  localKeyId: '1.2.840.113549.1.9.21',
  pbes2: '1.2.840.113549.1.5.13',
  pbkdf2: '1.2.840.113549.1.5.12',
  hmacSha256: '1.2.840.113549.2.9',
  aes256Cbc: '2.16.840.1.101.3.4.1.42',
};

const HASH_OIDS = {
  '1.2.840.113549.2.7': 'sha1',
  '1.2.840.113549.2.8': 'sha224',
  '1.2.840.113549.2.9': 'sha256',
  '1.2.840.113549.2.10': 'sha384',
  '1.2.840.113549.2.11': 'sha512',
};

const DIGEST_OIDS = {
  sha1: '1.3.14.3.2.26',
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
};

const CIPHER_OIDS = {
  '2.16.840.1.101.3.4.1.42': { alg: 'aes-256-cbc', keyLen: 32 },
  '2.16.840.1.101.3.4.1.2': { alg: 'aes-128-cbc', keyLen: 16 },
  '1.2.840.113549.3.7': { alg: 'des-ede3-cbc', keyLen: 24 },
};

const HASH_BLOCK_BYTES = { sha1: 64, sha256: 64, sha384: 128, sha512: 128 };

/**
 * PKCS#12 anahtar türetmesi (RFC 7292 Ek B.2).
 *
 * PBKDF2 DEĞİLDİR ve yerine geçmez: bütünlük katmanının (MacData) anahtarı
 * bu yöntemle türetilmek zorunda, çünkü doğrulayan taraf da onu böyle
 * türetiyor. Şifreleme tarafında modern PBES2/PBKDF2 kullanılıyor — orada
 * seçim bizde.
 *
 * @param {Buffer} password  BMPString kodlanmış parola (sonda 0x0000 dâhil)
 * @param {Buffer} salt
 * @param {number} id        1=anahtar, 2=IV, 3=MAC anahtarı
 * @param {number} iterations
 * @param {number} size      istenen bayt sayısı
 * @param {string} hashName
 */
function pkcs12Derive(password, salt, id, iterations, size, hashName = 'sha256') {
  const u = crypto.createHash(hashName).digest().length;
  const v = HASH_BLOCK_BYTES[hashName] || 64;

  const D = Buffer.alloc(v, id);
  const S = fillRepeating(salt, v);
  const P = fillRepeating(password, v);
  let I = Buffer.concat([S, P]);

  const blocks = Math.ceil(size / u);
  const out = Buffer.alloc(blocks * u);

  for (let i = 0; i < blocks; i++) {
    let A = Buffer.concat([D, I]);
    for (let r = 0; r < iterations; r++) A = crypto.createHash(hashName).update(A).digest();
    A.copy(out, i * u);
    if (i === blocks - 1) break;

    // I'nin her v baytlık bloğuna (B + 1) eklenir; toplama v baytlık
    // büyük-endian tamsayı aritmetiğidir ve taşma yok sayılır.
    const B = fillRepeating(A, v);
    for (let j = 0; j < I.length; j += v) {
      let carry = 1;
      for (let k = v - 1; k >= 0; k--) {
        const sum = I[j + k] + B[k] + carry;
        I[j + k] = sum & 0xff;
        carry = sum >> 8;
      }
    }
  }
  return out.subarray(0, size);
}

function fillRepeating(source, blockSize) {
  if (!source.length) return Buffer.alloc(0);
  const length = Math.ceil(source.length / blockSize) * blockSize;
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i++) out[i] = source[i % source.length];
  return out;
}

/** Parolanın PKCS#12 gösterimi: UTF-16BE + sonda iki sıfır bayt. */
function bmpPassword(password) {
  const text = String(password == null ? '' : password);
  const buf = Buffer.alloc(text.length * 2 + 2);
  for (let i = 0; i < text.length; i++) buf.writeUInt16BE(text.charCodeAt(i), i * 2);
  return buf;
}

class PKCS12 {
  /**
   * @param {string} password
   * @param {object} [opts]
   * @param {number} [opts.iterations=100000] PBKDF2 tur sayısı (şifreleme)
   * @param {number} [opts.macIterations=2048]
   * @param {string} [opts.macAlgorithm='sha256']
   */
  constructor(password = '', { iterations = 100_000, macIterations = 2048, macAlgorithm = 'sha256' } = {}) {
    this.password = String(password == null ? '' : password);
    this.iterations = iterations;
    this.macIterations = macIterations;
    this.macAlgorithm = macAlgorithm;
    this.OIDS = OIDS;
  }

  static derToPem(der, label) { return derToPem(der, label); }
  static pemToDer(pem) { return pemToDer(pem); }
  static getHashName(oid) { return HASH_OIDS[oid] || 'sha1'; }

  /* ══════════════════════════════════════════════════════════════
     AYRIŞTIRMA
     ══════════════════════════════════════════════════════════════ */

  /**
   * Bir .pfx içeriğini açar.
   * @param {Buffer} pfxDer
   * @returns {{certificates: string[], privateKeys: string[], macVerified: boolean|null}}
   */
  parse(pfxDer) {
    const results = { certificates: [], privateKeys: [], macVerified: null };
    const pfxTlv = readTLV(pfxDer, 0);
    const pfxChildren = readChildren(pfxTlv.content);

    const authSafeNode = pfxChildren[1];
    if (!authSafeNode) throw new Error('[pkcs12] authSafe bulunamadı');
    const authSafeChildren = readChildren(authSafeNode.content);
    const authSafeContentCtx = authSafeChildren[1];
    if (!authSafeContentCtx) throw new Error('[pkcs12] authSafe içeriği yok');

    const octetNode = readTLV(authSafeContentCtx.content, 0);
    const authenticatedSafeDer = octetNode.content;

    // Bütünlük ÖNCE denetlenir. Doğrulamadan içerik açmak, saldırganın
    // değiştirdiği bir çantayı işlemek demek — ve MacData'nın var olma
    // sebebi tam olarak bu.
    if (pfxChildren[2]) {
      results.macVerified = this._verifyMac(pfxChildren[2], authenticatedSafeDer);
      if (!results.macVerified) {
        throw new Error(
          '[pkcs12] bütünlük denetimi başarısız: parola yanlış ya da dosya değiştirilmiş',
        );
      }
    }

    const authSafeSeq = readTLV(authenticatedSafeDer, 0);
    const safeContents = readChildren(authSafeSeq.content);

    safeContents.forEach((contentInfo) => {
      const ciChildren = readChildren(contentInfo.content);
      const bagOid = decodeOidHex(ciChildren[0].content.toString('hex'));
      const ctx0 = ciChildren[1];

      if (bagOid === OIDS.encryptedData) {
        const encryptedDataSeq = readTLV(ctx0.content, 0);
        const edChildren = readChildren(encryptedDataSeq.content);

        const eciChildren = readChildren(edChildren[1].content);
        const encryptionAlgNode = eciChildren[1];
        const cipherText = PKCS12._encryptedContentBytes(eciChildren[2]);

        const decryptedData = this._decryptPBES2(encryptionAlgNode, cipherText);
        this._extractBags(decryptedData, results);
      } else if (bagOid === OIDS.data) {
        const octetDataNode = readTLV(ctx0.content, 0);
        this._extractBags(octetDataNode.content, results);
      }
    });

    return results;
  }

  /**
   * `encryptedContent` [0] alanının baytları.
   *
   * Şemaya göre IMPLICIT'tir (tag 0x80, ilkel) ve içerik doğrudan şifreli
   * metindir. Ama EXPLICIT yazan üreticiler var (0xA0 + içeride bir OCTET
   * STRING) — bizim eski üretecimiz de öyle yazıyordu. İkisi de okunuyor;
   * yazarken YALNIZCA doğrusu üretiliyor.
   */
  static _encryptedContentBytes(node) {
    if (!node) throw new Error('[pkcs12] şifreli içerik yok');
    if ((node.tag & 0x20) === 0) return node.content; // ilkel: IMPLICIT
    const inner = readTLV(node.content, 0);
    return inner.tag === 0x04 ? inner.content : node.content;
  }

  _verifyMac(macDataNode, authenticatedSafeDer) {
    const macChildren = readChildren(macDataNode.content);
    const digestInfo = readChildren(macChildren[0].content);
    const algId = readChildren(digestInfo[0].content);
    const digestOid = decodeOidHex(algId[0].content.toString('hex'));
    const hashName = Object.keys(DIGEST_OIDS).find((k) => DIGEST_OIDS[k] === digestOid) || 'sha1';
    const expected = digestInfo[1].content;
    const salt = macChildren[1].content;
    const iterations = macChildren[2] ? Number(derIntToBigInt(macChildren[2].content)) : 1;

    const keyLen = crypto.createHash(hashName).digest().length;
    const key = pkcs12Derive(bmpPassword(this.password), salt, 3, iterations, keyLen, hashName);
    const actual = crypto.createHmac(hashName, key).update(authenticatedSafeDer).digest();
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }

  _extractBags(safeContentsDer, results) {
    const seq = readTLV(safeContentsDer, 0);
    const bags = readChildren(seq.content);

    bags.forEach((bagNode) => {
      const bagChildren = readChildren(bagNode.content);
      const bagOid = decodeOidHex(bagChildren[0].content.toString('hex'));
      const ctx0 = bagChildren[1];

      if (bagOid === OIDS.certBag) {
        const certBagSeq = readTLV(ctx0.content, 0);
        const certBagChildren = readChildren(certBagSeq.content);
        const certOctet = readTLV(certBagChildren[1].content, 0);
        results.certificates.push(derToPem(certOctet.content, 'CERTIFICATE'));
      } else if (bagOid === OIDS.pkcs8ShroudedKeyBag) {
        const encPrivKeyInfo = readTLV(ctx0.content, 0);
        const epkiChildren = readChildren(encPrivKeyInfo.content);
        const pkcs8Der = this._decryptPBES2(epkiChildren[0], epkiChildren[1].content);
        results.privateKeys.push(derToPem(pkcs8Der, 'PRIVATE KEY'));
      } else if (bagOid === OIDS.keyBag) {
        const privKeyInfoSeq = readTLV(ctx0.content, 0);
        const pkDer = ctx0.content.subarray(0, privKeyInfoSeq.totalLen);
        results.privateKeys.push(derToPem(pkDer, 'PRIVATE KEY'));
      }
    });
  }

  _decryptPBES2(algNode, cipherText) {
    const algChildren = readChildren(algNode.content);
    const schemeOid = decodeOidHex(algChildren[0].content.toString('hex'));
    if (schemeOid !== OIDS.pbes2) {
      // Eski .pfx'ler pbeWithSHAAnd40BitRC2-CBC gibi PKCS#12 şemaları
      // kullanıyor. Desteklememek bir eksiklik ama SESSİZ bir yanlış
      // çözümden iyi: hangi şemanın gerektiği açıkça söyleniyor.
      throw new Error(
        `[pkcs12] desteklenmeyen şifreleme şeması: ${schemeOid}. `
        + 'Dosyayı PBES2 ile yeniden üretin: '
        + 'openssl pkcs12 -export -keypbe AES-256-CBC -certpbe AES-256-CBC …',
      );
    }

    const pbes2Params = readChildren(algChildren[1].content);
    const kdfChildren = readChildren(pbes2Params[0].content);
    const pbkdf2Params = readChildren(kdfChildren[1].content);

    const salt = pbkdf2Params[0].content;
    const iterations = Number(derIntToBigInt(pbkdf2Params[1].content));

    let hashName = 'sha1';
    for (let i = 2; i < pbkdf2Params.length; i++) {
      if (pbkdf2Params[i].tag === 0x30) {
        const prfChildren = readChildren(pbkdf2Params[i].content);
        hashName = PKCS12.getHashName(decodeOidHex(prfChildren[0].content.toString('hex')));
      }
    }

    const encChildren = readChildren(pbes2Params[1].content);
    const encOid = decodeOidHex(encChildren[0].content.toString('hex'));
    const iv = encChildren[1].content;

    const cipherInfo = CIPHER_OIDS[encOid];
    if (!cipherInfo) throw new Error(`[pkcs12] desteklenmeyen şifre: ${encOid}`);

    const key = crypto.pbkdf2Sync(this.password, salt, iterations, cipherInfo.keyLen, hashName);
    const decipher = crypto.createDecipheriv(cipherInfo.alg, key, iv);
    try {
      return Buffer.concat([decipher.update(cipherText), decipher.final()]);
    } catch (cause) {
      const err = new Error('[pkcs12] içerik çözülemedi — parola yanlış olabilir');
      err.cause = cause;
      throw err;
    }
  }

  /* ══════════════════════════════════════════════════════════════
     ÜRETME
     ══════════════════════════════════════════════════════════════ */

  /** PBES2 + AES-256-CBC ile şifreler ve ASN.1 parçalarını döner. */
  _encryptPBES2(plainTextDer) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const key = crypto.pbkdf2Sync(this.password, salt, this.iterations, 32, 'sha256');

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    const cipherText = Buffer.concat([cipher.update(plainTextDer), cipher.final()]);

    const pbkdf2Params = SEQ(OCT(salt), INT(BigInt(this.iterations)), SEQ(OID(OIDS.hmacSha256), NULL()));
    const kdf = SEQ(OID(OIDS.pbkdf2), pbkdf2Params);
    const encScheme = SEQ(OID(OIDS.aes256Cbc), OCT(iv));
    const algId = SEQ(OID(OIDS.pbes2), SEQ(kdf, encScheme));

    return {
      algId,
      // [0] IMPLICIT OCTET STRING — sarmalanmaz, etiketi değişir.
      cipherTextCtx: CTX(0, cipherText, { explicit: false }),
      cipherText,
    };
  }

  /**
   * Sertifika ve özel anahtardan .pfx üretir.
   *
   * @param {string} certPem
   * @param {string} keyPem       PKCS#8 ya da PKCS#1/SEC1 (Node dönüştürür)
   * @param {object} [opts]
   * @param {string} [opts.friendlyName]
   * @param {string[]} [opts.chainPem] ara sertifikalar
   * @returns {Buffer}
   */
  build(certPem, keyPem, { friendlyName = '', chainPem = [] } = {}) {
    const certDer = pemToDer(certPem);

    // Anahtar HER ZAMAN PKCS#8'e normalleştirilir. SEC1 ("EC PRIVATE KEY")
    // ya da PKCS#1 ("RSA PRIVATE KEY") bir PKCS#12 anahtar çantasına
    // doğrudan konamaz: çantanın içeriği PrivateKeyInfo olmak zorunda.
    const keyObject = crypto.createPrivateKey(keyPem);
    const keyDer = keyObject.export({ type: 'pkcs8', format: 'der' });

    // localKeyId: sertifika ile anahtarı EŞLEŞTİREN bağ. İçe aktaran taraf
    // bu olmadan ikisini ilişkilendiremiyor ve "özel anahtar yok" diyor.
    const localKeyId = crypto.createHash('sha1')
      .update(crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'der' }))
      .digest();

    const attributes = (extra = []) => SET(
      SEQ(OID(OIDS.localKeyId), SET(OCT(localKeyId))),
      ...(friendlyName ? [SEQ(OID(OIDS.friendlyName), SET(BMP(friendlyName)))] : []),
      ...extra,
    );

    // 1. Sertifika çantaları (yaprak + zincir).
    const certBags = [certPem, ...[].concat(chainPem || []).filter(Boolean)].map((pem, index) => {
      const der = pemToDer(pem);
      // Zincir sertifikalarına localKeyId KONMAZ: o bağ yalnızca anahtarın
      // sahibi olan sertifikaya aittir. Zincire de koymak, içe aktaran
      // tarafın hangisinin sahip olduğunu bulamamasına yol açar.
      const attrs = index === 0
        ? attributes()
        : (friendlyName ? SET(SEQ(OID(OIDS.friendlyName), SET(BMP(`${friendlyName} (zincir ${index})`)))) : null);
      return SEQ(
        OID(OIDS.certBag),
        CTX(0, SEQ(OID(OIDS.x509Certificate), CTX(0, OCT(der)))),
        ...(attrs ? [attrs] : []),
      );
    });
    const certSafeContents = SEQ(...certBags);

    // 2. Anahtar çantası — şifreli (pkcs8ShroudedKeyBag).
    //
    // Anahtarı ŞİFRESİZ (keyBag) koymak da mümkündü ve özgün kod öyle
    // yapıyordu: dış katman şifreliydi ama anahtar çantanın içinde düz
    // duruyordu. İki katmanı da parolaya bağlamak, dosyanın herhangi bir
    // katmanı sıyrılsa bile anahtarın açıkta kalmamasını sağlıyor.
    const encryptedKey = this._encryptPBES2(keyDer);
    const shroudedKeyBag = SEQ(
      OID(OIDS.pkcs8ShroudedKeyBag),
      CTX(0, SEQ(encryptedKey.algId, OCT(encryptedKey.cipherText))),
      attributes(),
    );
    const keySafeContents = SEQ(shroudedKeyBag);

    // 3. Sertifika çantası dış katmanda da şifrelenir.
    const encryptedCerts = this._encryptPBES2(certSafeContents);
    const encryptedCertContentInfo = SEQ(
      OID(OIDS.encryptedData),
      CTX(0, SEQ(
        INT(0n),
        SEQ(OID(OIDS.data), encryptedCerts.algId, encryptedCerts.cipherTextCtx),
      )),
    );

    const keyContentInfo = SEQ(OID(OIDS.data), CTX(0, OCT(keySafeContents)));

    const authenticatedSafe = SEQ(encryptedCertContentInfo, keyContentInfo);

    // 4. Bütünlük katmanı (MacData). Özgün kodda EKSİKTİ ve Windows/macOS
    //    onsuz dosyayı reddediyor.
    const macSalt = crypto.randomBytes(20);
    const hashName = this.macAlgorithm;
    const macKeyLen = crypto.createHash(hashName).digest().length;
    const macKey = pkcs12Derive(
      bmpPassword(this.password), macSalt, 3, this.macIterations, macKeyLen, hashName,
    );
    const mac = crypto.createHmac(hashName, macKey).update(authenticatedSafe).digest();
    const macData = SEQ(
      SEQ(SEQ(OID(DIGEST_OIDS[hashName]), NULL()), OCT(mac)),
      OCT(macSalt),
      INT(BigInt(this.macIterations)),
    );

    return SEQ(
      INT(3n),
      SEQ(OID(OIDS.data), CTX(0, OCT(authenticatedSafe))),
      macData,
    );
  }
}

module.exports = { PKCS12, pkcs12Derive, bmpPassword, OIDS };
