'use strict';

const crypto = require('node:crypto');

const { loadSsl } = require('./csr');

/**
 * S/MIME imzalama ve doğrulama (RFC 8551 / CMS RFC 5652).
 *
 * Yapı @fitfak/ssl'in ASN.1 ilkelleriyle kuruluyor — paketin kendi TSA
 * modülü (src/tsa.js) CMS SignedData'yı aynı şekilde kuruyor, yani bu bir
 * ikinci uygulama değil aynı temelin ikinci kullanımı. Buradaki fark
 * yalnızca içerik: TSA'da imzalanan şey bir TSTInfo, burada bir MIME parçası
 * ve içerik AYRIK (detached) — yani imza içeriğin kopyasını taşımıyor,
 * yalnızca özetini.
 *
 * Ayrık imza şart, çünkü multipart/signed'ın anlamı bu: imzayı anlamayan bir
 * istemci de iletiyi okuyabilmeli. Opak biçim (application/pkcs7-mime) de
 * destekleniyor ama öntanımlı değil; onu okuyamayan istemci iletiyi hiç
 * göremez.
 *
 * ÜÇ AYRINTI, üçü de "imza geçersiz" olarak görünen ve sebebi görünmeyen
 * hatalar üretir:
 *
 *   1. İmzalanan baytlar, imzalanan parçanın başlıkları DÂHİL tam hâli ve
 *      satır sonları CRLF olmak zorunda. Gövdeyi tek başına ya da LF ile
 *      imzalamak, alıcının yeniden kodladığından farklı bayt dizisi verir.
 *   2. signedAttrs, SignerInfo içinde [0] IMPLICIT olarak kodlanır ama imza
 *      AÇIK SET OF (0x31) etiketiyle hesaplanır (RFC 5652 §5.4).
 *   3. SET OF üyeleri DER kodlamalarına göre sıralı olmak zorundadır.
 *
 * İkincisi ve üçüncüsü @fitfak/ssl'in TSA modülünde de açıkça not edilmiş;
 * aynı tuzaklar burada da geçerli.
 */

const OID_DATA = '1.2.840.113549.1.7.1';
const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_ATTR_CONTENT_TYPE = '1.2.840.113549.1.9.3';
const OID_ATTR_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_ATTR_SIGNING_TIME = '1.2.840.113549.1.9.5';
const OID_ATTR_SMIME_CAPABILITIES = '1.2.840.113549.1.9.15';
const OID_ATTR_SIGNING_CERT_V2 = '1.2.840.113549.1.9.16.2.47';

const DIGEST_OIDS = {
  sha256: '2.16.840.1.101.3.4.2.1',
  sha384: '2.16.840.1.101.3.4.2.2',
  sha512: '2.16.840.1.101.3.4.2.3',
};
const DIGEST_BY_OID = Object.fromEntries(Object.entries(DIGEST_OIDS).map(([k, v]) => [v, k]));

/**
 * SignerInfo.signatureAlgorithm için tanınan OID'ler.
 *
 * `hash: null` "özeti buradan okuma, `digestAlgorithm` alanından al" demek —
 * ve bu, kaçınılabilir bir uyumsuzluğun kaynağıydı: OpenSSL (ve onu kullanan
 * pek çok istemci) RSA imzalarında signatureAlgorithm olarak
 * `sha256WithRSAEncryption` DEĞİL, düz `rsaEncryption` (1.2.840.113549.1.1.1)
 * yazıyor; özet zaten ayrı alanda bildiriliyor. Bu OID listede olmadığı için
 * gelen S/MIME imzaları "bilinmeyen imza algoritması" ile reddediliyordu —
 * yani dışarıdan gelen imzaların büyük kısmı hiç doğrulanamıyordu.
 *
 * Aynı gerekçe EC tarafında `id-ecPublicKey` için de geçerli.
 */
const SIGNATURE_ALG_BY_OID = {
  '1.2.840.113549.1.1.1': { keyType: 'rsa', hash: null },   // rsaEncryption (OpenSSL öntanımlısı)
  '1.2.840.113549.1.1.11': { keyType: 'rsa', hash: 'sha256' },
  '1.2.840.113549.1.1.12': { keyType: 'rsa', hash: 'sha384' },
  '1.2.840.113549.1.1.13': { keyType: 'rsa', hash: 'sha512' },
  '1.2.840.10045.2.1': { keyType: 'ec', hash: null },       // id-ecPublicKey
  '1.2.840.10045.4.3.2': { keyType: 'ec', hash: 'sha256' },
  '1.2.840.10045.4.3.3': { keyType: 'ec', hash: 'sha384' },
  '1.2.840.10045.4.3.4': { keyType: 'ec', hash: 'sha512' },
  '1.3.101.112': { keyType: 'ed25519', hash: null },
};

const CURVE_FOR_HASH = { sha256: 'P-256', sha384: 'P-384', sha512: 'P-521' };

/**
 * ASN.1 ilkelleri.
 *
 * ÜRETME tarafı @fitfak/ssl'i gerektiriyor (sertifika profilleri, OID kayıt
 * defteri). DOĞRULAMA tarafı gerektirmiyor: yaptığı tek şey DER okumak ve
 * Node'un kendi `crypto.verify`'ını çağırmak — ikisi de burada zaten var
 * (`./asn1`).
 *
 * Buna rağmen doğrulama da aynı `require` üzerinden gidiyordu, yani
 * @fitfak/ssl kurulu değilken gelen bir S/MIME imzasını DOĞRULAMAK da
 * imkânsızdı. İmza doğrulamak, imza üretmekten farklı bir yetenek ve daha az
 * şey gerektiriyor; eksik bir paket yüzünden kapanmamalı.
 */
function asn1() {
  try { return require('@fitfak/ssl/src/asn1'); }
  catch { return require('./asn1'); }
}

/**
 * Bir düğümün TAM TLV baytları (etiket + uzunluk + içerik).
 *
 * İki ASN.1 uygulaması bunu farklı veriyor: @fitfak/ssl `contentOff` ile
 * konumu bildiriyor, buradaki `readChildren` ise dilimi `raw` olarak hazır
 * veriyor. Fark gözetilmezse biri `undefined - number = NaN` üretir ve
 * `subarray(NaN, NaN)` sessizce BOŞ bir tampon döndürür — imzalayan
 * sertifikası "ekli değil" görünür.
 */
function fullTlv(node, parentContent) {
  if (node.raw) return node.raw;
  const start = node.contentOff - node.headerLen;
  return parentContent.subarray(start, start + node.totalLen);
}

/** İçerik uzunluğu — `len` (@fitfak/ssl) ya da `length` (yerel). */
function nodeLength(node) {
  return node.len != null ? node.len : node.length;
}

function pemToDer(pem, label = 'CERTIFICATE') {
  const rx = new RegExp(`-----BEGIN [^-]*${label}[^-]*-----([\\s\\S]*?)-----END [^-]*${label}[^-]*-----`);
  const m = String(pem).match(rx);
  if (!m) throw new Error(`[smime] PEM bloğu bulunamadı (${label})`);
  return Buffer.from(m[1].replace(/[^A-Za-z0-9+/=]/g, ''), 'base64');
}

function pemToDerAll(pem, label = 'CERTIFICATE') {
  const out = [];
  const rx = new RegExp(`-----BEGIN [^-]*${label}[^-]*-----([\\s\\S]*?)-----END [^-]*${label}[^-]*-----`, 'g');
  let m;
  while ((m = rx.exec(String(pem))) !== null) {
    out.push(Buffer.from(m[1].replace(/[^A-Za-z0-9+/=]/g, ''), 'base64'));
  }
  return out;
}

/** IssuerAndSerialNumber için sertifikadan issuer DER'i ve seri numarasını çeker. */
function parseIssuerAndSerial(certDer) {
  const { readTLV, readChildren } = asn1();
  const cert = readTLV(certDer, 0);
  const tbs = readTLV(cert.content, 0);
  const children = readChildren(tbs.content);
  // [0] EXPLICIT version isteğe bağlıdır; varsa alanlar bir kayar.
  const i = children[0].tag === 0xa0 ? 1 : 0;
  const serialNode = children[i];
  const issuerNode = children[i + 2];
  return {
    issuerDer: fullTlv(issuerNode, tbs.content),
    serialContent: serialNode.content,
  };
}

/**
 * S/MIME yetenek beyanı: alıcının bize hangi algoritmayla şifreleyebileceğini
 * söyler. Bunu koymamak, karşı tarafın 3DES gibi en düşük ortak paydaya
 * düşmesine yol açar.
 */
function buildSmimeCapabilities() {
  const { SEQ, OID, INT } = asn1();
  return SEQ(
    SEQ(OID('2.16.840.1.101.3.4.1.46')), // aes256-GCM
    SEQ(OID('2.16.840.1.101.3.4.1.42')), // aes256-CBC
    SEQ(OID('2.16.840.1.101.3.4.1.2')), // aes128-CBC
    SEQ(OID('1.2.840.113549.3.7'), INT(128n)), // 3DES — yalnızca son çare olarak
  );
}

/** ESSCertIDv2 (RFC 5035): imzalayanın hangi sertifika olduğunu bağlar. */
function buildSigningCertificateV2(leafDer, hash) {
  const { SEQ, OID, OCT, CTX, tlv } = asn1();
  const certHash = crypto.createHash(hash).update(leafDer).digest();
  const { issuerDer, serialContent } = parseIssuerAndSerial(leafDer);
  const generalNames = SEQ(CTX(4, issuerDer)); // directoryName [4] EXPLICIT
  const issuerSerial = SEQ(generalNames, tlv(0x02, serialContent));
  // sha256 öntanımlı olduğunda algoritma alanı atlanabilir; açıkça yazmak
  // farklı özet kullanıldığında doğrulayanın tahmin etmesini önler.
  const algPart = hash === 'sha256' ? null : SEQ(OID(DIGEST_OIDS[hash]));
  return SEQ(SEQ(SEQ(...[algPart, OCT(certHash), issuerSerial].filter(Boolean))));
}

function buildSignedAttributes({ contentDigest, leafDer, hash, signingTime, includeCapabilities = true }) {
  const { SEQ, SET, OID, OCT, GenTime, tlv } = asn1();
  const attrs = [
    SEQ(OID(OID_ATTR_CONTENT_TYPE), SET(OID(OID_DATA))),
    SEQ(OID(OID_ATTR_MESSAGE_DIGEST), SET(OCT(contentDigest))),
  ];
  if (signingTime) attrs.push(SEQ(OID(OID_ATTR_SIGNING_TIME), SET(GenTime(signingTime))));
  if (includeCapabilities) attrs.push(SEQ(OID(OID_ATTR_SMIME_CAPABILITIES), SET(buildSmimeCapabilities())));
  attrs.push(SEQ(OID(OID_ATTR_SIGNING_CERT_V2), SET(buildSigningCertificateV2(leafDer, hash))));

  // SET OF: DER'de bileşenler kodlanmış hâllerine göre sıralı olmak ZORUNDA.
  const sorted = attrs.slice().sort(Buffer.compare);
  return tlv(0x31, Buffer.concat(sorted));
}

function signatureAlgIdFor(keyObject, hash) {
  const { SEQ, OID, NULL } = asn1();
  const type = keyObject.asymmetricKeyType;
  if (type === 'rsa' || type === 'rsa-pss') {
    const oids = {
      sha256: '1.2.840.113549.1.1.11',
      sha384: '1.2.840.113549.1.1.12',
      sha512: '1.2.840.113549.1.1.13',
    };
    if (!oids[hash]) throw new Error(`[smime] RSA için desteklenmeyen özet: ${hash}`);
    return SEQ(OID(oids[hash]), NULL());
  }
  if (type === 'ec') {
    const oids = {
      sha256: '1.2.840.10045.4.3.2',
      sha384: '1.2.840.10045.4.3.3',
      sha512: '1.2.840.10045.4.3.4',
    };
    if (!oids[hash]) throw new Error(`[smime] ECDSA için desteklenmeyen özet: ${hash}`);
    return SEQ(OID(oids[hash]));
  }
  if (type === 'ed25519') return SEQ(OID('1.3.101.112'));
  throw new Error(`[smime] desteklenmeyen anahtar türü: ${type}`);
}

function signBytes(data, keyObject, hash) {
  if (keyObject.asymmetricKeyType === 'ed25519') return crypto.sign(null, data, keyObject);
  // ECDSA imzası CMS'de DER kodlu SEQUENCE{r,s} olmak zorunda. 'ieee-p1363'
  // (JWT biçimi) burada sessizce doğrulanamayan bir imza üretir.
  return crypto.sign(hash, data, keyObject.asymmetricKeyType === 'ec'
    ? { key: keyObject, dsaEncoding: 'der' }
    : keyObject);
}

/**
 * Ayrık (detached) CMS SignedData üretir.
 *
 * @param {object} p
 * @param {Buffer} p.content      imzalanacak baytlar (CRLF'e normalize EDİLMİŞ olmalı)
 * @param {string} p.certPem      imzalayanın sertifikası
 * @param {string} p.privateKeyPem
 * @param {string} [p.chainPem]   ara sertifikalar
 * @param {string} [p.hash='sha256']
 * @returns {Buffer} DER
 */
function signDetached({ content, certPem, privateKeyPem, chainPem = '', hash = 'sha256', signingTime = new Date() }) {
  loadSsl(); // @fitfak/ssl yoksa burada, anlaşılır bir hatayla dur
  const { SEQ, SET, OID, OCT, INT, CTX, tlv } = asn1();
  if (!DIGEST_OIDS[hash]) throw new Error(`[smime] desteklenmeyen özet: ${hash}`);

  const body = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
  const leafDer = pemToDer(certPem, 'CERTIFICATE');
  const chainDers = chainPem ? pemToDerAll(chainPem, 'CERTIFICATE') : [];
  const keyObject = crypto.createPrivateKey(privateKeyPem);

  const contentDigest = crypto.createHash(hash).update(body).digest();
  const signedAttrs = buildSignedAttributes({ contentDigest, leafDer, hash, signingTime });
  const signature = signBytes(signedAttrs, keyObject, hash);

  const { issuerDer, serialContent } = parseIssuerAndSerial(leafDer);
  const signerIdentifier = SEQ(issuerDer, tlv(0x02, serialContent));
  const digestAlgId = SEQ(OID(DIGEST_OIDS[hash]));

  const signerInfo = SEQ(
    INT(1n), // issuerAndSerialNumber kullanıldığında sürüm 1
    signerIdentifier,
    digestAlgId,
    // signedAttrs [0] IMPLICIT — SET etiketi bağlam etiketiyle DEĞİŞTİRİLİR
    tlv(0xa0, asn1().readTLV(signedAttrs, 0).content),
    signatureAlgIdFor(keyObject, hash),
    OCT(signature),
  );

  // Ayrık imza: encapContentInfo'da eContent YOK, yalnızca tür.
  const encapContentInfo = SEQ(OID(OID_DATA));
  const certificates = tlv(0xa0, Buffer.concat([leafDer, ...chainDers]));

  const signedData = SEQ(
    INT(1n),
    SET(digestAlgId),
    encapContentInfo,
    certificates,
    SET(signerInfo),
  );

  return SEQ(OID(OID_SIGNED_DATA), CTX(0, signedData));
}

/**
 * multipart/signed gövdesi kurar (RFC 1847 + RFC 8551 §3.5).
 *
 * `contentPart` imzalanan parçanın TAM hâlidir: kendi başlıkları, boş satır,
 * gövde. Burada HİÇBİR dönüşüm yapılmaz ve yapılmamalı — çağıran, imzaladığı
 * baytların aynısını vermek zorunda.
 *
 * Buradaki tek kural ve en kolay kaçırılan ayrıntı: parçanın sonundaki CRLF
 * sınır işaretçisine (`--boundary`) AİTTİR, içeriğe değil (RFC 2046 §5.1.1).
 * Dolayısıyla imzalanan baytlar sondaki CRLF'i İÇERMEZ. Bunu burada kırpmak
 * ile imzalamadan önce kırpmak arasındaki fark, "imza geçersiz" olarak
 * görünen ve sebebi görünmeyen bir hataydı: imza sondaki CRLF dâhil
 * hesaplanıyor, tele CRLF'siz hâli veriliyordu. Kırpma artık çağıranın
 * sorumluluğunda ve `canonicalizeSignedPart` tam olarak bunun için var.
 */
function canonicalizeSignedPart(contentPart) {
  return String(contentPart).replace(/\r?\n/g, '\r\n').replace(/(\r\n)+$/, '');
}

function buildMultipartSigned({ contentPart, signatureDer, boundary = null, micalg = 'sha-256' }) {
  const bnd = boundary || `----=_fitfak_smime_${crypto.randomBytes(12).toString('hex')}`;
  const sigB64 = Buffer.from(signatureDer).toString('base64').replace(/(.{76})/g, '$1\r\n');
  const headers = [
    `Content-Type: multipart/signed; protocol="application/pkcs7-signature"; micalg=${micalg}; boundary="${bnd}"`,
  ];
  const body = [
    `--${bnd}`,
    contentPart,
    `--${bnd}`,
    'Content-Type: application/pkcs7-signature; name="smime.p7s"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="smime.p7s"',
    'Content-Description: S/MIME Cryptographic Signature',
    '',
    sigB64,
    `--${bnd}--`,
    '',
  ].join('\r\n');
  return { headers, body, boundary: bnd };
}

/** Opak biçim (application/pkcs7-mime). Yalnızca açıkça istendiğinde. */
function buildOpaqueSigned({ signatureDer }) {
  const sigB64 = Buffer.from(signatureDer).toString('base64').replace(/(.{76})/g, '$1\r\n');
  return {
    headers: [
      'Content-Type: application/pkcs7-mime; smime-type=signed-data; name="smime.p7m"',
      'Content-Transfer-Encoding: base64',
      'Content-Disposition: attachment; filename="smime.p7m"',
    ],
    body: sigB64,
  };
}

/* ── doğrulama ─────────────────────────────────────────────── */

function decodeOid(content) {
  if (!content.length) return '';
  const parts = [Math.floor(content[0] / 40), content[0] % 40];
  let acc = 0;
  for (let i = 1; i < content.length; i++) {
    acc = acc * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) { parts.push(acc); acc = 0; }
  }
  return parts.join('.');
}

/**
 * Ayrık imzayı doğrular.
 *
 * Döndürülen `valid`, YALNIZCA kriptografik doğruluğu ifade eder: imza bu
 * içerik ve bu sertifika ile tutarlı. Sertifikanın GÜVENİLİR olup olmadığı
 * (zincir, süre, adres eşleşmesi) ayrı alanlarda döner ve çağıran ikisini
 * ayrı ayrı değerlendirmek zorunda — "imza geçerli" deyip güvenilmeyen bir
 * kök kabul etmek, imzanın hiç olmamasından daha kötü, çünkü kullanıcıya
 * yanlış bir güvence verir.
 */
function verifyDetached({ content, signatureDer, trustedCaPems = [], expectedAddress = null, at = new Date() }) {
  const { readTLV, readChildren } = asn1();
  const result = {
    valid: false,
    reason: null,
    digestMatch: false,
    signer: null,
    certs: [],
    chainTrusted: false,
    addressMatch: null,
    timeValid: false,
  };

  let contentInfo;
  try { contentInfo = readTLV(Buffer.from(signatureDer), 0); }
  catch (err) { result.reason = `ayrıştırılamadı: ${err.message}`; return result; }

  let signedData;
  try {
    const ciChildren = readChildren(contentInfo.content);
    if (decodeOid(ciChildren[0].content) !== OID_SIGNED_DATA) {
      result.reason = 'içerik türü signedData değil';
      return result;
    }
    signedData = readTLV(ciChildren[1].content, 0);
  } catch (err) { result.reason = `signedData okunamadı: ${err.message}`; return result; }

  const sdChildren = readChildren(signedData.content);
  // version, digestAlgorithms, encapContentInfo, [certificates], [crls], signerInfos
  let idx = 3;
  let certsNode = null;
  let signerInfosNode = null;
  for (let i = idx; i < sdChildren.length; i++) {
    const node = sdChildren[i];
    if (node.tag === 0xa0) certsNode = node;
    else if (node.tag === 0x31) signerInfosNode = node;
  }
  if (!signerInfosNode) { result.reason = 'signerInfos yok'; return result; }

  const certDers = certsNode
    ? readChildren(certsNode.content).map((n) => fullTlv(n, certsNode.content))
    : [];

  const certs = [];
  for (const der of certDers) {
    try { certs.push({ der, x509: new crypto.X509Certificate(der) }); }
    catch { /* okunamayan sertifika atlanır */ }
  }
  result.certs = certs.map((c) => describeCert(c.x509));

  const signerInfos = readChildren(signerInfosNode.content);
  if (!signerInfos.length) { result.reason = 'imzalayan yok'; return result; }

  // Birden fazla imzalayan olabilir; bir tanesinin doğrulanması yeterli
  // sayılmaz — hangisinin doğrulandığı bildirilmeli. İlk geçerli olanı
  // döndürüyoruz ve hangisi olduğunu `signer` alanında söylüyoruz.
  for (const siNode of signerInfos) {
    const si = readChildren(siNode.content);
    let p = 1; // sürüm atlandı
    const sid = si[p++];
    const digestAlg = si[p++];
    let signedAttrsNode = null;
    if (si[p] && si[p].tag === 0xa0) signedAttrsNode = si[p++];
    const sigAlg = si[p++];
    const sigNode = si[p++];

    const digestOid = decodeOid(readChildren(digestAlg.content)[0].content);
    const hash = DIGEST_BY_OID[digestOid];
    if (!hash) { result.reason = `bilinmeyen özet algoritması: ${digestOid}`; continue; }

    const sigAlgOid = decodeOid(readChildren(sigAlg.content)[0].content);
    const sigSpec = SIGNATURE_ALG_BY_OID[sigAlgOid];
    if (!sigSpec) { result.reason = `bilinmeyen imza algoritması: ${sigAlgOid}`; continue; }

    // İmzalayanı issuer+serial ile bul.
    const sidChildren = readChildren(sid.content);
    const wantIssuer = sidChildren[0];
    const wantSerial = sidChildren[1];
    const wantIssuerDer = fullTlv(wantIssuer, sid.content);

    const match = certs.find((c) => {
      try {
        const { issuerDer, serialContent } = parseIssuerAndSerial(c.der);
        return issuerDer.equals(wantIssuerDer) && stripLeadingZero(serialContent).equals(stripLeadingZero(wantSerial.content));
      } catch { return false; }
    });
    if (!match) { result.reason = 'imzalayan sertifikası ekli değil'; continue; }

    const body = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    const contentDigest = crypto.createHash(hash).update(body).digest();

    let signedBytes;
    if (signedAttrsNode) {
      // İmza AÇIK SET OF etiketiyle hesaplanır; kayıtta [0] IMPLICIT durur.
      signedBytes = Buffer.concat([Buffer.from([0x31]), encodeLength(nodeLength(signedAttrsNode)), signedAttrsNode.content]);
      // messageDigest özniteliği içerikle uyuşmalı: imza doğru olsa bile
      // özet başka bir içeriğe aitse imza bu iletiyi kanıtlamaz.
      const attrs = readChildren(signedAttrsNode.content);
      for (const attr of attrs) {
        const ac = readChildren(attr.content);
        if (decodeOid(ac[0].content) !== OID_ATTR_MESSAGE_DIGEST) continue;
        const declared = readChildren(ac[1].content)[0];
        result.digestMatch = Buffer.compare(declared.content, contentDigest) === 0;
      }
    } else {
      // signedAttrs yoksa imza doğrudan içerik üzerindedir.
      signedBytes = body;
      result.digestMatch = true;
    }

    let cryptoOk = false;
    try {
      const publicKey = match.x509.publicKey;
      const sigBytes = sigNode.content;
      if (sigSpec.keyType === 'ed25519') cryptoOk = crypto.verify(null, signedBytes, publicKey, sigBytes);
      else {
        // signatureAlgorithm özeti bildirmiyorsa (rsaEncryption /
        // id-ecPublicKey) özet, digestAlgorithm alanından gelir.
        const effectiveHash = sigSpec.hash || hash;
        cryptoOk = crypto.verify(effectiveHash, signedBytes, {
          key: publicKey,
          ...(sigSpec.keyType === 'ec' ? { dsaEncoding: 'der' } : {}),
        }, sigBytes);
      }
    } catch (err) { result.reason = `imza doğrulanamadı: ${err.message}`; }

    if (!cryptoOk) { result.reason = result.reason || 'imza uyuşmuyor'; continue; }
    if (!result.digestMatch) { result.reason = 'içerik özeti uyuşmuyor'; continue; }

    const signerDesc = describeCert(match.x509);
    result.signer = signerDesc;
    result.valid = true;
    result.reason = null;

    const now = at instanceof Date ? at.getTime() : Date.now();
    result.timeValid = signerDesc.notBefore <= now && now <= signerDesc.notAfter;

    if (expectedAddress) {
      const want = String(expectedAddress).toLowerCase();
      result.addressMatch = signerDesc.emails.includes(want);
    }

    if (trustedCaPems.length) {
      result.chainTrusted = verifyChainAgainst(match, certs, trustedCaPems);
    }
    break;
  }

  return result;
}

function encodeLength(len) {
  if (len < 0x80) return Buffer.from([len]);
  const bytes = [];
  let n = len;
  while (n > 0) { bytes.unshift(n & 0xff); n >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function stripLeadingZero(buf) {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i++;
  return buf.subarray(i);
}

function describeCert(x509) {
  const emails = [];
  if (x509.subjectAltName) {
    for (const part of String(x509.subjectAltName).split(',')) {
      const t = part.trim();
      if (/^email:/i.test(t)) emails.push(t.slice(6).trim().toLowerCase());
    }
  }
  const cnEmail = String(x509.subject || '').match(/emailAddress=([^\s,\n]+)/i);
  if (cnEmail && !emails.includes(cnEmail[1].toLowerCase())) emails.push(cnEmail[1].toLowerCase());
  return {
    subject: String(x509.subject || '').replace(/\n/g, ', '),
    issuer: String(x509.issuer || '').replace(/\n/g, ', '),
    serialNumber: String(x509.serialNumber || '').toLowerCase(),
    fingerprint: String(x509.fingerprint256 || '').replace(/:/g, '').toLowerCase(),
    notBefore: new Date(x509.validFrom).getTime() || 0,
    notAfter: new Date(x509.validTo).getTime() || 0,
    emails,
    keyType: x509.publicKey ? x509.publicKey.asymmetricKeyType : '',
  };
}

/**
 * Zincir doğrulaması. @fitfak/ssl'in `verifyChain`i varsa o kullanılır
 * (OCSP/CRL ve politika denetimleri onda), yoksa Node'un `verify`si ile
 * yaprak-ara-kök yürüyüşü yapılır.
 */
function verifyChainAgainst(leaf, allCerts, trustedCaPems) {
  try {
    const ssl = loadSsl();
    if (typeof ssl.verifyChain === 'function') {
      const chainPems = [leaf, ...allCerts.filter((c) => c !== leaf)].map((c) => derToPem(c.der));
      const res = ssl.verifyChain(chainPems, trustedCaPems);
      if (typeof res === 'boolean') return res;
      if (res && typeof res === 'object') return res.valid === true || res.ok === true;
    }
  } catch { /* aşağıdaki yedek yola düş */ }

  const anchors = [];
  for (const pem of trustedCaPems) {
    for (const der of pemToDerAll(pem, 'CERTIFICATE')) {
      try { anchors.push(new crypto.X509Certificate(der)); } catch { /* atla */ }
    }
  }
  if (!anchors.length) return false;

  let current = leaf.x509;
  const pool = allCerts.map((c) => c.x509).filter((x) => x !== current);
  for (let depth = 0; depth < 8; depth++) {
    const anchor = anchors.find((a) => { try { return current.verify(a.publicKey); } catch { return false; } });
    if (anchor) return true;
    const parent = pool.find((p) => { try { return current.verify(p.publicKey); } catch { return false; } });
    if (!parent) return false;
    current = parent;
  }
  return false;
}

function derToPem(der, label = 'CERTIFICATE') {
  const b64 = Buffer.from(der).toString('base64').replace(/(.{64})/g, '$1\n');
  return `-----BEGIN ${label}-----\n${b64}${b64.endsWith('\n') ? '' : '\n'}-----END ${label}-----\n`;
}

/**
 * Gelen iletide S/MIME imzası varsa doğrular.
 *
 * `parsedMessage` MIME ayrıştırıcısının çıktısıdır; multipart/signed
 * yapısında imzalanan parçanın HAM baytları korunmuş olmak zorunda —
 * ayrıştırıcı onu yeniden kurarsa (başlık sırası, satır sonu) imza bozulur.
 */
function verifyMessageSignature(parsedMessage, { trustedCaPems = [], expectedAddress = null } = {}) {
  const signedPart = parsedMessage.signedContent;
  const signaturePart = parsedMessage.signaturePart;
  if (!signedPart || !signaturePart) return { status: 'none' };

  const verdict = verifyDetached({
    content: signedPart,
    signatureDer: signaturePart,
    trustedCaPems,
    expectedAddress,
  });

  let status = 'signed-invalid';
  if (verdict.valid) {
    if (trustedCaPems.length && !verdict.chainTrusted) status = 'signed-untrusted';
    else if (expectedAddress && verdict.addressMatch === false) status = 'signed-address-mismatch';
    else if (!verdict.timeValid) status = 'signed-expired';
    else status = 'signed-valid';
  }
  return { status, ...verdict };
}

module.exports = {
  signDetached, buildMultipartSigned, buildOpaqueSigned, canonicalizeSignedPart,
  verifyDetached, verifyMessageSignature,
  parseIssuerAndSerial, describeCert, pemToDer, pemToDerAll, derToPem,
  DIGEST_OIDS, OID_DATA, OID_SIGNED_DATA,
};
