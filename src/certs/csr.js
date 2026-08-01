'use strict';

const crypto = require('node:crypto');

/**
 * Anahtar üretimi ve PKCS#10 isteği — @fitfak/ssl üzerine ince bir katman.
 *
 * ASN.1, OID kayıt defteri, CSR kodlama ve sertifika profilleri zaten
 * @fitfak/ssl içinde var (src/asn1.js, src/oid.js, src/pki.js,
 * src/profiles.js). Buradaki iş yalnızca "bir posta adresi için S/MIME
 * isteği" biçimini kurmak: hangi ad öznitelikleri, hangi SAN, hangi profil.
 * Bu modül bilerek küçük; ikinci bir PKI uygulaması olmak niyetinde değil.
 *
 * S/MIME için kritik ayrıntı: adres SAN'da rfc822Name olarak bulunmak
 * ZORUNDA. İstemciler imzalayanın adresini CN'den değil SAN'dan doğrular;
 * yalnızca CN koymak sertifikanın kabul edilip imzanın "adres eşleşmiyor"
 * denerek reddedilmesine yol açar.
 */

let cachedSsl = null;
let sslLoadError = null;

function loadSsl() {
  if (cachedSsl) return cachedSsl;
  if (sslLoadError) throw sslLoadError;
  try {
    cachedSsl = require('@fitfak/ssl');
    return cachedSsl;
  } catch (err) {
    sslLoadError = new Error(
      '[certs] @fitfak/ssl yüklü değil. Sertifika üretimi ve S/MIME imzalama '
      + 'bu paketi gerektirir: npm run link:deps (ya da FITFAK_SSL_PATH).',
    );
    sslLoadError.cause = err;
    throw sslLoadError;
  }
}

function isAvailable() {
  try { loadSsl(); return true; }
  catch { return false; }
}

/** @fitfak/ssl'in `keyInfo` biçimi + Node'un anlayacağı PEM'ler. */
function generateKeyMaterial({ algorithm = 'ec', curveName = 'P-256', modulusLength = 3072 } = {}) {
  const ssl = loadSsl();

  if (algorithm === 'rsa') {
    const kp = ssl.generateRsaKeyPair(modulusLength);
    const privateKeyPem = ssl.rsaPrivToPem(kp);
    const keyObject = crypto.createPrivateKey(privateKeyPem);
    return {
      keyInfo: { keyType: 'rsa', n: kp.n, e: kp.e, d: kp.d, p: kp.p, q: kp.q, dp: kp.dp, dq: kp.dq, qInv: kp.qInv },
      privateKeyPem,
      publicKeyPem: crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'pem' }),
      keyObject,
      keyType: 'rsa',
      algorithmLabel: `rsa-${modulusLength}`,
    };
  }

  const kp = ssl.generateEcKeyPair(curveName);
  // @fitfak/ssl özel anahtarı SKALER (BigInt) tutar; Node ise KeyObject ister.
  // İkisi arasındaki köprü PEM: paketin `ecPrivToPem`i SEC1 üretir, Node onu
  // okur.
  const privateKeyPem = ssl.ecPrivToPem(kp);
  const keyObject = crypto.createPrivateKey(privateKeyPem);
  return {
    keyInfo: { keyType: 'ec', curveName, privateKey: kp.privateKey, publicKeyBuf: kp.publicKeyBuf },
    privateKeyPem,
    publicKeyPem: crypto.createPublicKey(keyObject).export({ type: 'spki', format: 'pem' }),
    keyObject,
    keyType: 'ec',
    algorithmLabel: `ec-${curveName}`,
  };
}

/**
 * Bir posta adresi için S/MIME anahtarı ve isteği üretir.
 *
 * @param {object} p
 * @param {string} p.address        sertifikanın ait olduğu posta adresi
 * @param {string} [p.displayName]  CN olarak kullanılacak ad
 * @param {string} [p.organization]
 * @param {Array}  [p.extraAltNames] ek SAN girdileri ({type,value})
 * @returns {{csrPem, privateKeyPem, publicKeyPem, keyType, algorithmLabel}}
 */
function createSmimeRequest({
  address, displayName = '', organization = 'Fitfak', organizationalUnit = '',
  country = '', algorithm = 'ec', curveName = 'P-256', extraAltNames = [],
}) {
  const ssl = loadSsl();
  const { OIDs } = ssl.oid || ssl;
  const pki = require('@fitfak/ssl/src/pki');

  const addr = String(address || '').trim().toLowerCase();
  if (!addr.includes('@')) throw new Error(`[certs] geçersiz posta adresi: ${address}`);

  const material = generateKeyMaterial({ algorithm, curveName });

  // Ad öznitelikleri @fitfak/ssl'in kayıt defterindeki adlarla: `orgName`,
  // `orgUnit`, `pkcs9EmailAddress`. Kendi adlarımızı uydurmak, OID
  // tanımsız gelince "normalizeOid: dizge bekleniyor" gibi ilgisiz bir
  // hataya dönüşüyor.
  const nameAttrs = [
    [OIDs.commonName, displayName || addr],
    ...(organizationalUnit ? [[OIDs.orgUnit, organizationalUnit]] : []),
    ...(organization ? [[OIDs.orgName, organization]] : []),
    ...(country ? [[OIDs.country, country]] : []),
    // emailAddress DN'in sonunda: geleneksel sıra bu ve bazı CA'lar sırayı
    // olduğu gibi kopyalar.
    [OIDs.pkcs9EmailAddress, addr],
  ];

  const sans = [{ type: 'email', value: addr }, ...extraAltNames];
  const csrPem = pki.generateCSR(material.keyInfo, nameAttrs, sans);

  return {
    csrPem,
    privateKeyPem: material.privateKeyPem,
    publicKeyPem: material.publicKeyPem,
    keyType: material.keyType,
    algorithmLabel: material.algorithmLabel,
    address: addr,
    sans,
  };
}

/**
 * mTLS istemci kimliği için istek (veritabanı enrolment'ı gibi durumlar).
 * @fitfak/database kendi `createFitfakSslCsrProvider`ını sunuyor ve uzak
 * veritabanı yolunda o kullanılıyor; bu yalnızca doğrudan ihtiyaç duyan
 * yerler için.
 */
function createClientRequest({ commonName, altNames = [], algorithm = 'ec', curveName = 'P-256' }) {
  const ssl = loadSsl();
  const { OIDs } = ssl.oid || ssl;
  const pki = require('@fitfak/ssl/src/pki');
  const material = generateKeyMaterial({ algorithm, curveName });
  const csrPem = pki.generateCSR(material.keyInfo, [[OIDs.commonName, commonName]], altNames);
  return {
    csrPem,
    privateKeyPem: material.privateKeyPem,
    publicKeyPem: material.publicKeyPem,
    keyType: material.keyType,
  };
}

/** İsteği geri okur ve imzasını doğrular (anahtar sahipliği kanıtı). */
function inspectRequest(csrPem) {
  const ssl = loadSsl();
  const parsed = ssl.parseCSR(csrPem);
  const signatureValid = ssl.verifyCSR(csrPem) === true;
  const emails = (parsed.sans || []).filter((s) => s.type === 'email').map((s) => s.value);
  const cnAttr = (parsed.subjectAttrs || []).find((a) => /^(2\.5\.4\.3|CN)$/i.test(String(a.oid || a.type || a.name || '')));
  return {
    commonName: cnAttr ? (cnAttr.value || '') : '',
    subject: parsed.subject || '',
    emails,
    sans: parsed.sans || [],
    signatureValid,
    publicKey: parsed.publicKey,
  };
}

/* ── @fitfak/ssl olmadan PKCS#10 ──────────────────────────────── */

/**
 * @fitfak/database'in CsrProvider arayüzünü YALNIZCA Node'un kendi crypto'suyla
 * karşılar.
 *
 * ── NEDEN GEREKLİ ────────────────────────────────────────────────────────
 * `db/driver-fitfak.js` uzak (mTLS) yolda @fitfak/ssl yoksa buraya düşüyor ve
 * bunu bilerek yapıyor: "tek bir paketin eksikliği sistemi başlatılamaz hâle
 * getirmemeli". Ama çağırdığı `createLocalCsrProvider` HİÇ YAZILMAMIŞTI, yani
 * o yol ilk satırında `createLocalCsrProvider is not a function` ile
 * düşüyordu. Sonuç, tam olarak engellenmek istenen şeydi: @fitfak/ssl kurulu
 * değilken uzak veritabanına bağlanan bir posta sunucusu AÇILAMIYORDU.
 *
 * Sağlayıcının sözleşmesi (csr-provider.js):
 *   generateKeyPair()                        -> { privateKeyPem, publicKeyPem, … }
 *   createCsr({ keyPair, subject, altNames }) -> csrPem
 *
 * Bu ikinci bir PKI değil: yalnızca bir CertificationRequest kodlar ve imzalar.
 * Sertifika üretmiyor, doğrulamıyor, profil uygulamıyor — onlar @fitfak/ssl'in
 * işi ve orada kalıyor.
 */
function createLocalCsrProvider({ algorithm = 'ec', namedCurve = 'prime256v1', modulusLength = 2048 } = {}) {
  const { SEQ, SET, OID, CTX, INT, NULL, tlv, TAG, derToPem } = require('./asn1');

  // PKCS#10, imzalanan yapıyı (CertificationRequestInfo) DER olarak istiyor;
  // Node bize SPKI verdiği için açık anahtar oraya olduğu gibi gömülüyor.
  const SUBJECT_OIDS = {
    CN: '2.5.4.3', C: '2.5.4.6', ST: '2.5.4.8', L: '2.5.4.7',
    O: '2.5.4.10', OU: '2.5.4.11', emailAddress: '1.2.840.113549.1.9.1',
  };
  const SIG_OIDS = {
    // ecdsa-with-SHA256 — EC'de parametre alanı BULUNMAZ (NULL bile değil);
    // NULL koymak bazı doğrulayıcılarda imzayı geçersiz kılıyor.
    ec: { oid: '1.2.840.10045.4.3.2', params: null },
    // sha256WithRSAEncryption — RSA'da parametre alanı NULL olmak ZORUNDA.
    rsa: { oid: '1.2.840.113549.1.1.11', params: 'null' },
  };

  const IA5_STRING = 0x16; // asn1.js'in TAG tablosunda yok; PKCS#9 emailAddress bunu ister.
  function utf8(text) { return tlv(TAG.UTF8_STRING, Buffer.from(String(text), 'utf8')); }
  function ia5(text) { return tlv(IA5_STRING, Buffer.from(String(text), 'utf8')); }

  function subjectName(subject) {
    const rdns = [];
    for (const [key, value] of Object.entries(subject || {})) {
      const oid = SUBJECT_OIDS[key];
      if (!oid || value == null || value === '') continue;
      // emailAddress tarihsel olarak IA5String; diğerleri UTF8String.
      const encoded = key === 'emailAddress' ? ia5(value) : utf8(value);
      rdns.push(SET(SEQ(OID(oid), encoded)));
    }
    return SEQ(...rdns);
  }

  function generalNames(altNames) {
    const entries = [];
    for (const raw of altNames || []) {
      const value = String(raw || '').trim();
      if (!value) continue;
      if (value.includes('@')) {
        entries.push(CTX(1, Buffer.from(value, 'utf8'), { explicit: false })); // rfc822Name
      } else if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
        entries.push(CTX(7, Buffer.from(value.split('.').map(Number)), { explicit: false })); // iPAddress
      } else {
        entries.push(CTX(2, Buffer.from(value, 'utf8'), { explicit: false })); // dNSName
      }
    }
    return entries.length ? SEQ(...entries) : null;
  }

  return {
    name: 'local-pkcs10',

    async generateKeyPair() {
      if (algorithm === 'rsa') {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength });
        return {
          keyType: 'rsa',
          privateKey,
          publicKey,
          privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
          publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
          publicKeySpkiDer: publicKey.export({ type: 'spki', format: 'der' }),
        };
      }
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve });
      return {
        keyType: 'ec',
        privateKey,
        publicKey,
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
        publicKeySpkiDer: publicKey.export({ type: 'spki', format: 'der' }),
      };
    },

    async createCsr({ keyPair, subject = {}, altNames = [] }) {
      const keyType = keyPair.keyType === 'rsa' ? 'rsa' : 'ec';
      const spki = keyPair.publicKeySpkiDer
        || crypto.createPublicKey(keyPair.publicKeyPem).export({ type: 'spki', format: 'der' });

      // attributes [0] IMPLICIT SET OF Attribute.
      //
      // IMPLICIT olduğu için [0] etiketi SET'in YERİNE geçer, onu sarmaz —
      // içeriğe ayrıca bir SET (ya da SEQUENCE) koymak, OpenSSL'in
      // "wrong tag / nested asn1 error" ile reddettiği fazladan bir katman
      // üretiyor. Bu yüzden Attribute doğrudan [0]'ın içinde duruyor.
      const sanNames = generalNames(altNames);
      const attributes = sanNames
        ? CTX(0, SEQ(                     // Attribute
          OID('1.2.840.113549.1.9.14'),   // extensionRequest
          SET(SEQ(SEQ(                    // SET { Extensions { Extension } }
            OID('2.5.29.17'),             // subjectAltName
            tlv(TAG.OCTET_STRING, sanNames),
          ))),
        ), { explicit: false, constructed: true })
        : CTX(0, Buffer.alloc(0), { explicit: false, constructed: true });

      const requestInfo = SEQ(
        INT(0n),                 // version v1
        subjectName(subject),
        spki,                    // SubjectPublicKeyInfo, already a complete SEQUENCE
        attributes,
      );

      const privateKey = keyPair.privateKey || crypto.createPrivateKey(keyPair.privateKeyPem);
      const signature = crypto.sign('sha256', requestInfo, keyType === 'ec'
        ? { key: privateKey, dsaEncoding: 'der' }
        : privateKey);

      const sig = SIG_OIDS[keyType];
      const algId = sig.params === 'null' ? SEQ(OID(sig.oid), NULL()) : SEQ(OID(sig.oid));

      const csrDer = SEQ(
        requestInfo,
        algId,
        // BIT STRING: ilk bayt kullanılmayan bit sayısı, imzada her zaman 0.
        tlv(TAG.BIT_STRING, Buffer.concat([Buffer.from([0x00]), signature])),
      );
      return derToPem(csrDer, 'CERTIFICATE REQUEST');
    },
  };
}

module.exports = {
  isAvailable, loadSsl, generateKeyMaterial,
  createSmimeRequest, createClientRequest, inspectRequest,
  createLocalCsrProvider,
};
