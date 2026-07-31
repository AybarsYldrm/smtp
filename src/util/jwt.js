'use strict';

const crypto = require('node:crypto');
const { b64url, b64urlDecode } = require('./encoding');

// Kompakt JWS. İki kullanım var ve ikisi de farklı:
//
//   1. Kendi ürettiğimiz kısa ömürlü yetkiler (ek indirme bağlantısı, API
//      anahtarı) — HS256, anahtar kasadan gelir.
//   2. IdP'nin verdiği erişim jetonları — RS256/ES256, anahtar JWKS'ten gelir.
//
// (1) için anahtarın SÜREKLİ olması gerekir. Önceki sürüm her açılışta
// `crypto.randomBytes(48)` ile yeni bir sır üretiyordu: sunucu yeniden
// başladığı anda kullanıcının açık duran e-postasındaki bütün ek bağlantıları
// 403 vermeye başlıyordu ve neden olduğu görünmüyordu. Anahtar artık kasada.

const ALG_HMAC = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };
const ALG_ASYM = {
  RS256: { hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PADDING },
  RS384: { hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PADDING },
  RS512: { hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PADDING },
  PS256: { hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
  ES256: { hash: 'sha256', dsaEncoding: 'ieee-p1363' },
  ES384: { hash: 'sha384', dsaEncoding: 'ieee-p1363' },
  ES512: { hash: 'sha512', dsaEncoding: 'ieee-p1363' },
};

function signHs(payload, key, { alg = 'HS256', kid = null, expiresInMs = null } = {}) {
  const hash = ALG_HMAC[alg];
  if (!hash) throw new Error(`jwt: desteklenmeyen algoritma ${alg}`);
  const header = { alg, typ: 'JWT' };
  if (kid) header.kid = kid;
  const body = { ...payload };
  if (expiresInMs != null && body.exp == null) body.exp = Math.floor((Date.now() + expiresInMs) / 1000);
  if (body.iat == null) body.iat = Math.floor(Date.now() / 1000);
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(body)))}`;
  const sig = crypto.createHmac(hash, key).update(signingInput).digest();
  return `${signingInput}.${b64url(sig)}`;
}

function decode(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  try {
    return {
      header: JSON.parse(b64urlDecode(parts[0]).toString('utf8')),
      payload: JSON.parse(b64urlDecode(parts[1]).toString('utf8')),
      signature: parts[2],
      signingInput: `${parts[0]}.${parts[1]}`,
    };
  } catch { return null; }
}

function checkTime(payload, clockSkewSec) {
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp != null && now > Number(payload.exp) + clockSkewSec) return 'expired';
  if (payload.nbf != null && now + clockSkewSec < Number(payload.nbf)) return 'not_yet_valid';
  return null;
}

/**
 * HS* doğrulaması. `keyResolver(kid)` birden fazla anahtar döndürebilir —
 * anahtar döndürme sırasında hem eski hem yeni anahtarın kabul edilmesi
 * gerekir, yoksa rotasyon anında verilmiş her jeton geçersizleşir.
 */
function verifyHs(token, keyResolver, { clockSkewSec = 30, requiredClaims = [] } = {}) {
  const parsed = decode(token);
  if (!parsed) return { ok: false, reason: 'malformed' };
  const { header, payload, signature, signingInput } = parsed;
  const hash = ALG_HMAC[header.alg];
  if (!hash) return { ok: false, reason: 'alg_not_allowed' };

  const keys = [].concat(typeof keyResolver === 'function' ? keyResolver(header.kid) || [] : keyResolver);
  if (!keys.length) return { ok: false, reason: 'no_key' };

  const provided = b64urlDecode(signature);
  let matched = false;
  for (const key of keys) {
    if (!key) continue;
    const expected = crypto.createHmac(hash, key).update(signingInput).digest();
    if (expected.length === provided.length && crypto.timingSafeEqual(expected, provided)) { matched = true; break; }
  }
  if (!matched) return { ok: false, reason: 'bad_signature' };

  const timeErr = checkTime(payload, clockSkewSec);
  if (timeErr) return { ok: false, reason: timeErr };
  for (const claim of requiredClaims) {
    if (payload[claim] == null) return { ok: false, reason: `missing_claim:${claim}` };
  }
  return { ok: true, header, payload };
}

/** JWKS anahtarıyla asimetrik doğrulama (IdP jetonları). */
function verifyAsym(token, jwk, { clockSkewSec = 60, issuer = null, audience = null } = {}) {
  const parsed = decode(token);
  if (!parsed) return { ok: false, reason: 'malformed' };
  const { header, payload, signature, signingInput } = parsed;
  const spec = ALG_ASYM[header.alg];
  // "none" ve HS* burada kabul EDİLMEZ: JWKS'ten gelen açık anahtarı HMAC
  // sırrı olarak kullanan klasik algoritma karıştırma saldırısı tam olarak
  // bunun açık bırakılmasıyla çalışır.
  if (!spec) return { ok: false, reason: 'alg_not_allowed' };

  let keyObject;
  try { keyObject = crypto.createPublicKey({ key: jwk, format: 'jwk' }); }
  catch (err) { return { ok: false, reason: `bad_key:${err.message}` }; }

  const verifier = crypto.createVerify(spec.hash);
  verifier.update(signingInput);
  verifier.end();
  const opts = { key: keyObject };
  if (spec.padding) opts.padding = spec.padding;
  if (spec.saltLength) opts.saltLength = spec.saltLength;
  if (spec.dsaEncoding) opts.dsaEncoding = spec.dsaEncoding;

  let ok = false;
  try { ok = verifier.verify(opts, b64urlDecode(signature)); } catch { ok = false; }
  if (!ok) return { ok: false, reason: 'bad_signature' };

  const timeErr = checkTime(payload, clockSkewSec);
  if (timeErr) return { ok: false, reason: timeErr };
  if (issuer && payload.iss !== issuer) return { ok: false, reason: 'bad_issuer' };
  if (audience) {
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!auds.includes(audience)) return { ok: false, reason: 'bad_audience' };
  }
  return { ok: true, header, payload };
}

module.exports = { signHs, verifyHs, verifyAsym, decode };
