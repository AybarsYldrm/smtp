'use strict';

const crypto = require('node:crypto');

const { normalizeAddress } = require('../../util/encoding');

/**
 * Sertifika kaydı (S/MIME ve TLS).
 *
 * Özel anahtar burada DEĞİL kasada; kayıtta yalnızca göndergesi var. İkisini
 * aynı satırda tutmak, sertifikayı okumak için verilen bir yetkinin özel
 * anahtarı da vermesi anlamına gelirdi — oysa sertifika açık veridir,
 * anahtar değil.
 *
 * Sürümler üzerine yazılmaz: yeni sertifika `pending` olarak girer, terfi
 * ettirilir, eskisi `retired` olur. S/MIME'de bu şart: eski anahtarla
 * imzalanmış postaların doğrulanabilmesi için eski sertifikanın kalması
 * gerekir.
 */
class CertificateRepo {
  constructor(db, { vault, logger = null } = {}) {
    this.db = db;
    this.vault = vault;
    this.logger = logger;
  }

  get certs() { return this.db.collection('certificates'); }

  static certKey(usage, subject) { return `${usage}|${normalizeAddress(subject)}`; }

  static shape(row) {
    if (!row) return null;
    return {
      ref: String(row._id),
      usage: row.usage,
      subjectAddress: row.subjectAddress,
      mailboxRef: row.mailboxRef || '',
      serialHex: row.serialHex || '',
      skidHex: row.skidHex || '',
      fingerprint: row.fingerprintSha256 || '',
      certPem: row.certPem || '',
      chainPem: row.chainPem || '',
      privateKeySecretRef: row.privateKeySecretRef || '',
      notBefore: Number(row.notBefore || 0),
      notAfter: Number(row.notAfter || 0),
      status: row.status,
      issuedVia: row.issuedVia || '',
      issuedAt: Number(row.issuedAt || 0),
      revokedAt: Number(row.revokedAt || 0),
      revocationReason: row.revocationReason || '',
      keyAlgorithm: row.keyAlgorithm || '',
      version: Number(row.version || 1),
      renewAfter: Number(row.renewAfter || 0),
      issuerDn: row.issuerDn || '',
      subjectDn: row.subjectDn || '',
      san: parseJson(row.sanJson, []),
    };
  }

  /**
   * Sertifikayı ve özel anahtarını kaydeder.
   * Anahtar kasaya yazılır; kayıt yalnızca adı taşır.
   */
  async store({
    usage, subjectAddress, mailboxRef = '', certPem, chainPem = '', privateKeyPem = null,
    issuedVia = '', keyAlgorithm = '', requestedBySub = '', renewAtRatio = 0.66, activate = true,
  }) {
    const address = normalizeAddress(subjectAddress);
    const parsed = parseCertificate(certPem);
    const version = (await this._highestVersion(usage, address)) + 1;

    let privateKeySecretRef = '';
    if (privateKeyPem) {
      privateKeySecretRef = `cert/${usage}/${address}/v${version}`;
      await this.vault.put({
        kind: `${usage}-key`,
        name: privateKeySecretRef,
        value: privateKeyPem,
        contentType: 'application/x-pem-file',
        notAfter: parsed.notAfter,
        meta: { usage, subjectAddress: address, serialHex: parsed.serialHex },
        createdBySub: requestedBySub,
      });
    }

    const lifetime = Math.max(0, parsed.notAfter - parsed.notBefore);
    const renewAfter = lifetime ? parsed.notBefore + Math.floor(lifetime * renewAtRatio) : 0;
    const now = Date.now();

    const record = {
      certKey: CertificateRepo.certKey(usage, address),
      usage,
      subjectAddress: address,
      mailboxRef: String(mailboxRef || ''),
      serialHex: parsed.serialHex,
      skidHex: parsed.skidHex,
      fingerprintSha256: parsed.fingerprint,
      certPem,
      chainPem,
      privateKeySecretRef,
      notBefore: parsed.notBefore,
      notAfter: parsed.notAfter,
      status: activate ? 'active' : 'pending',
      issuedVia,
      issuedAt: now,
      revokedAt: 0,
      revocationReason: '',
      keyAlgorithm: keyAlgorithm || parsed.keyAlgorithm,
      requestedBySub,
      version,
      renewAfter,
      issuerDn: parsed.issuer,
      subjectDn: parsed.subject,
      sanJson: JSON.stringify(parsed.san),
    };

    // `certKey` tekil olduğu için etkin sertifika tek satırda tutulur; eski
    // sürümler `${certKey}#v${n}` anahtarıyla ayrı satırlarda arşivlenir.
    const existing = await this.certs.findOne('certKey', record.certKey);
    if (existing) {
      await this.certs.insert({
        ...CertificateRepo.rowFrom(existing),
        certKey: `${existing.certKey}#v${existing.version}`,
        status: existing.status === 'active' ? 'retired' : existing.status,
      });
      await this.certs.update(String(existing._id), record);
      return { ref: String(existing._id), version, replaced: true };
    }
    const ref = await this.certs.insert(record);
    return { ref, version, replaced: false };
  }

  static rowFrom(row) {
    const out = { ...row };
    delete out._id;
    return out;
  }

  // Etkin satır her zaman en yüksek sürümü taşır; arşiv satırları
  // (`certKey#vN`) yalnızca geçmiş için durur. Bu yüzden sürüm numarasını
  // bulmak için arşivi taramak gerekmiyor — tarama, kör dizinli bir alanda
  // zaten mümkün değil.
  async _highestVersion(usage, address) {
    const current = await this.certs.findOne('certKey', CertificateRepo.certKey(usage, address));
    return current ? Number(current.version || 0) : 0;
  }

  async getActive(usage, subjectAddress) {
    const row = await this.certs.findOne('certKey', CertificateRepo.certKey(usage, subjectAddress));
    if (!row) return null;
    if (row.status !== 'active') return null;
    if (Number(row.notAfter || 0) && Number(row.notAfter) < Date.now()) return null;
    return CertificateRepo.shape(row);
  }

  async get(usage, subjectAddress) {
    return CertificateRepo.shape(await this.certs.findOne('certKey', CertificateRepo.certKey(usage, subjectAddress)));
  }

  /** Sertifika + özel anahtar birlikte — imzalamak için gereken çift. */
  async getSigningPair(usage, subjectAddress) {
    const cert = await this.getActive(usage, subjectAddress);
    if (!cert || !cert.privateKeySecretRef) return null;
    const secret = await this.vault.get(`${usage}-key`, cert.privateKeySecretRef);
    if (!secret) return null;
    return { ...cert, privateKeyPem: secret.value.toString('utf8') };
  }

  async listByUsage(usage) {
    const rows = await this.certs.find('usage', usage);
    return rows
      .filter((r) => !String(r.certKey || '').includes('#v'))
      .map(CertificateRepo.shape);
  }

  async findBySerial(serialHex) {
    const rows = await this.certs.find('serialHex', String(serialHex || '').toLowerCase());
    return rows.map(CertificateRepo.shape);
  }

  async findByFingerprint(fingerprint) {
    const rows = await this.certs.find('fingerprintSha256', String(fingerprint || '').toLowerCase());
    return rows.map(CertificateRepo.shape);
  }

  /** Yenilenmesi gerekenler: `renewAfter` geçmiş ve hâlâ etkin olanlar. */
  async listNeedingRenewal({ now = Date.now() } = {}) {
    const rows = await this.certs.find('status', 'active');
    return rows
      .filter((r) => !String(r.certKey || '').includes('#v'))
      .filter((r) => Number(r.renewAfter || 0) && Number(r.renewAfter) <= now)
      .map(CertificateRepo.shape);
  }

  async listExpiring(withinMs) {
    const rows = await this.certs.findRange('notAfter', Date.now(), Date.now() + withinMs);
    return rows.map(CertificateRepo.shape);
  }

  async revoke(usage, subjectAddress, reason = 'unspecified') {
    const row = await this.certs.findOne('certKey', CertificateRepo.certKey(usage, subjectAddress));
    if (!row) return false;
    await this.certs.update(String(row._id), {
      status: 'revoked', revokedAt: Date.now(), revocationReason: String(reason),
    });
    // Anahtar da ele geçmiş sayılır: iptal gerekçesi ne olursa olsun o
    // anahtarla bir daha imzalanmamalı.
    if (row.privateKeySecretRef) {
      const secret = await this.vault.get(`${usage}-key`, row.privateKeySecretRef).catch(() => null);
      if (secret) {
        await this.vault.markCompromised(`${usage}-key`, row.privateKeySecretRef, secret.version, `cert_revoked:${reason}`).catch(() => {});
      }
    }
    if (this.logger) this.logger.warn({ usage, subject: subjectAddress, reason, msg: 'sertifika iptal edildi' });
    return true;
  }
}

/** Sertifikadan üstveri çıkarır. Çağıranın verdiği değerlere GÜVENMEZ:
 *  bitiş tarihini parametre olarak almak, o tarihi yazmayı unutan bir çağrı
 *  yüzünden hiç süresi dolmayan bir sertifika kaydı bırakır. */
function parseCertificate(certPem) {
  const x = new crypto.X509Certificate(certPem);
  const der = x.raw;
  const skid = extractSubjectKeyId(der);
  const san = [];
  if (x.subjectAltName) {
    for (const part of String(x.subjectAltName).split(',')) {
      const t = part.trim();
      const idx = t.indexOf(':');
      if (idx > 0) san.push({ type: t.slice(0, idx), value: t.slice(idx + 1) });
    }
  }
  return {
    serialHex: String(x.serialNumber || '').toLowerCase(),
    fingerprint: String(x.fingerprint256 || '').replace(/:/g, '').toLowerCase(),
    subject: String(x.subject || '').replace(/\n/g, ', '),
    issuer: String(x.issuer || '').replace(/\n/g, ', '),
    notBefore: new Date(x.validFrom).getTime() || 0,
    notAfter: new Date(x.validTo).getTime() || 0,
    keyAlgorithm: x.publicKey ? x.publicKey.asymmetricKeyType : '',
    skidHex: skid,
    san,
  };
}

/** SubjectKeyIdentifier uzantısını (OID 2.5.29.14) DER içinden çeker. */
function extractSubjectKeyId(der) {
  const target = Buffer.from([0x06, 0x03, 0x55, 0x1d, 0x0e]); // OID 2.5.29.14
  const idx = der.indexOf(target);
  if (idx < 0) return '';
  let p = idx + target.length;
  if (der[p] === 0x01) p += 3; // isteğe bağlı BOOLEAN critical
  if (der[p] !== 0x04) return ''; // OCTET STRING (extnValue)
  p++;
  const outer = readLength(der, p);
  if (!outer) return '';
  p = outer.next;
  if (der[p] !== 0x04) return '';
  p++;
  const inner = readLength(der, p);
  if (!inner) return '';
  return der.subarray(inner.next, inner.next + inner.length).toString('hex');
}

function readLength(buf, p) {
  if (p >= buf.length) return null;
  const first = buf[p];
  if (first < 0x80) return { length: first, next: p + 1 };
  const n = first & 0x7f;
  if (n === 0 || n > 4 || p + n >= buf.length) return null;
  let len = 0;
  for (let i = 0; i < n; i++) len = (len << 8) | buf[p + 1 + i];
  return { length: len, next: p + 1 + n };
}

function parseJson(s, fallback) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

module.exports = { CertificateRepo, parseCertificate };
