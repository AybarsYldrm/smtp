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

module.exports = {
  isAvailable, loadSsl, generateKeyMaterial,
  createSmimeRequest, createClientRequest, inspectRequest,
};
