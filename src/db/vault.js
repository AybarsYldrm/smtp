'use strict';

const crypto = require('node:crypto');

/**
 * Anahtar kasası: sertifikalar, özel anahtarlar, DKIM ve VAPID anahtarları,
 * bildirim sırları, IdP jetonları.
 *
 * Veritabanı zaten kayıtları şifreliyor. Bu ikinci sarma katmanı, veritabanı
 * OTURUMU ele geçse bile (ör. bir gRPC istemcisi olarak yetkili bir süreç)
 * özel anahtarların düz metin dönmemesini sağlar: kasa anahtarı ayrı bir
 * ortam değişkeninde durur ve veritabanı sunucusu onu hiç görmez.
 *
 * Bunun bir HSM OLMADIĞI açıkça söylenmeli: bir anahtar okunduğu anda süreç
 * belleğinde düz metin olur. Tehdit modeli canlı sürecin bellek dökümünü
 * içeriyorsa cevap TPM/HSM destekli bir imzalayıcıdır, başka bir veritabanı
 * değil.
 *
 * Sürümler ÜZERİNE YAZILMAZ. Yeni sürüm `pending` olarak yazılır, terfi
 * edilir, eskisi `retired` olur. Bir DKIM anahtarını doğrudan değiştirmek,
 * DNS'teki açık anahtar yayılana kadar giden her postanın imzasını
 * doğrulanamaz yapardı; `pending` tam olarak o pencereyi yönetmek için var.
 */

const STATUS = { PENDING: 'pending', ACTIVE: 'active', RETIRED: 'retired', COMPROMISED: 'compromised' };

class KeyVault {
  /**
   * @param {object} db      sürücü bağımsız veritabanı yüzeyi
   * @param {Buffer} secret  kasa kök sırrı (>=32 bayt)
   */
  constructor(db, secret, { logger = null } = {}) {
    if (!secret || secret.length < 32) throw new Error('[vault] kasa sırrı en az 32 bayt olmalı');
    this.db = db;
    this.logger = logger;
    // Sarma anahtarı doğrudan kök sır DEĞİL: kök sırrın başka bir amaçla da
    // kullanılması hâlinde iki kullanım aynı anahtarı paylaşmasın.
    this.wrapKey = Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.alloc(32), Buffer.from('fitmail-vault-wrap-v1'), 32));
    // Anahtar kimliği: hangi kasa anahtarıyla sarıldığını kayıtta tutarız, ki
    // kasa sırrı döndürüldüğünde hangi kayıtların yeniden sarılması gerektiği
    // bilinsin.
    this.wrapKeyId = crypto.createHash('sha256').update(this.wrapKey).digest('hex').slice(0, 16);
  }

  get collection() { return this.db.collection('secrets'); }

  _wrap(plaintext, aad) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.wrapKey, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ct]);
  }

  /**
   * @param {Buffer} envelope
   * @param {string} aad
   * @param {string} [wrapKeyId] kaydın sarıldığı anahtarın kimliği
   */
  _unwrap(envelope, aad, wrapKeyId = null) {
    const buf = Buffer.isBuffer(envelope) ? envelope : Buffer.from(envelope);
    if (buf.length < 29) throw new Error('[vault] bozuk zarf');

    // Anahtar uyuşmazlığı ÖNCE denetlenir. Aksi hâlde AES-GCM'in
    // "Unsupported state or unable to authenticate data" hatası çıkar ve o
    // hata "veri bozuk" gibi okunur; oysa veri sağlam, yanlış anahtarla
    // açılmaya çalışılıyor. İkisi çok farklı sorunlar: biri yedekten geri
    // dönmeyi, diğeri doğru sırrı bulmayı gerektirir.
    if (wrapKeyId && wrapKeyId !== this.wrapKeyId) {
      throw new Error(
        `[vault] bu sır başka bir kasa anahtarıyla sarılmış `
        + `(kayıt: ${wrapKeyId}, şu anki: ${this.wrapKeyId}). `
        + 'FITFAK_MAIL_VAULT_SECRET değişmiş olabilir; eski sır olmadan bu kayıt açılamaz.',
      );
    }

    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const ct = buf.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.wrapKey, iv);
    // AAD sır adını ve sürümünü bağlar: bir kaydın şifreli gövdesini başka
    // bir kaydın satırına taşımak doğrulamayı bozar.
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  }

  static aadFor(kind, name, version) { return `${kind}|${name}|v${version}`; }
  static keyFor(kind, name, version) { return `${kind}|${name}|v${version}`; }

  /** Bir adın en yüksek sürüm numarasını bulur. */
  async _highestVersion(kind, name) {
    const rows = await this.collection.find('name', name);
    let max = 0;
    for (const row of rows) {
      if (row.kind !== kind) continue;
      const v = Number(row.version || 0);
      if (v > max) max = v;
    }
    return max;
  }

  /**
   * Yeni sürüm yazar.
   * @param {object} p
   * @param {string} p.kind      dkim-key | vapid-key | smime-key | tls-key | token | generic ...
   * @param {string} p.name      mantıksal ad (ör. "fitfak.net/mail")
   * @param {Buffer|string} p.value
   * @param {boolean} [p.activate=true]  doğrudan etkinleştir (false ise pending)
   * @param {number} [p.notAfter]
   */
  async put({ kind, name, value, activate = true, notAfter = 0, contentType = 'application/octet-stream', meta = null, createdBySub = '' }) {
    if (!kind || !name) throw new Error('[vault] kind ve name zorunlu');
    const plaintext = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
    const version = (await this._highestVersion(kind, name)) + 1;
    const secretKey = KeyVault.keyFor(kind, name, version);
    const now = Date.now();

    const record = {
      secretKey,
      kind,
      name,
      version,
      status: activate ? STATUS.ACTIVE : STATUS.PENDING,
      ciphertext: this._wrap(plaintext, KeyVault.aadFor(kind, name, version)),
      wrapAlg: 'AES-256-GCM/HKDF-SHA256',
      wrapKeyId: this.wrapKeyId,
      contentType,
      createdAt: now,
      notAfter: Number(notAfter) || 0,
      rotatedAt: 0,
      retiredAt: 0,
      metaJson: meta ? JSON.stringify(meta) : '',
      sha256Hex: crypto.createHash('sha256').update(plaintext).digest('hex'),
      createdBySub: createdBySub || '',
      compromisedAt: 0,
      compromiseReason: '',
    };
    const id = await this.collection.insert(record);

    if (activate) await this._retireOthers(kind, name, version);
    if (this.logger) this.logger.info({ kind, version, msg: 'kasaya sır yazıldı' });
    return { id, version, status: record.status };
  }

  async _retireOthers(kind, name, keepVersion) {
    const rows = await this.collection.find('name', name);
    const now = Date.now();
    for (const row of rows) {
      if (row.kind !== kind) continue;
      if (Number(row.version) === Number(keepVersion)) continue;
      if (row.status !== STATUS.ACTIVE && row.status !== STATUS.PENDING) continue;
      // Silinmez, `retired` olur: yükünü henüz yenilemeyen bir tüketicinin
      // doğrulayabileceği gerçek bir şey kalmalı.
      await this.collection.update(String(row._id), { status: STATUS.RETIRED, retiredAt: now });
    }
  }

  /** `pending` bir sürümü etkinleştirir; eski etkin sürüm `retired` olur. */
  async promote(kind, name, version) {
    const row = await this._row(kind, name, version);
    if (!row) throw new Error(`[vault] sır yok: ${kind}/${name} v${version}`);
    await this.collection.update(String(row._id), { status: STATUS.ACTIVE, rotatedAt: Date.now() });
    await this._retireOthers(kind, name, version);
    return true;
  }

  async _row(kind, name, version) {
    const key = KeyVault.keyFor(kind, name, version);
    return this.collection.findOne('secretKey', key);
  }

  /** Etkin sürümü döndürür (yoksa null). */
  async get(kind, name, { version = null, allowRetired = false } = {}) {
    let row;
    if (version != null) {
      row = await this._row(kind, name, version);
    } else {
      const rows = (await this.collection.find('name', name)).filter((r) => r.kind === kind);
      const usable = rows.filter((r) => r.status === STATUS.ACTIVE
        || (allowRetired && r.status === STATUS.RETIRED));
      usable.sort((a, b) => Number(b.version) - Number(a.version));
      row = usable[0] || null;
    }
    if (!row) return null;
    if (row.status === STATUS.COMPROMISED) {
      throw new Error(`[vault] sır ele geçmiş olarak işaretli: ${kind}/${name} v${row.version}`);
    }
    const value = this._unwrap(row.ciphertext, KeyVault.aadFor(row.kind, row.name, Number(row.version)), row.wrapKeyId);
    return {
      id: String(row._id),
      kind: row.kind,
      name: row.name,
      version: Number(row.version),
      status: row.status,
      value,
      contentType: row.contentType,
      createdAt: Number(row.createdAt || 0),
      notAfter: Number(row.notAfter || 0),
      meta: row.metaJson ? safeParse(row.metaJson) : null,
    };
  }

  /** Etkin + geri çekilmiş tüm sürümler — doğrulama için (imza kontrolü). */
  async getAllVersions(kind, name) {
    const rows = (await this.collection.find('name', name)).filter((r) => r.kind === kind);
    rows.sort((a, b) => Number(b.version) - Number(a.version));
    const out = [];
    for (const row of rows) {
      if (row.status === STATUS.COMPROMISED) continue;
      try {
        out.push({
          version: Number(row.version),
          status: row.status,
          value: this._unwrap(row.ciphertext, KeyVault.aadFor(row.kind, row.name, Number(row.version)), row.wrapKeyId),
          createdAt: Number(row.createdAt || 0),
        });
      } catch (err) {
        if (this.logger) this.logger.error({ kind, version: row.version, error: err.message, msg: 'sır açılamadı' });
      }
    }
    return out;
  }

  /**
   * Anahtar üretip kasaya yazan yardımcı: yoksa üretir, varsa döndürür.
   * Bu, "ilk açılışta DKIM anahtarı üret" gibi işlerin her yerde aynı
   * biçimde yapılmasını sağlar.
   */
  async getOrCreate(kind, name, generator, { contentType = 'application/octet-stream', meta = null, notAfter = 0 } = {}) {
    const existing = await this.get(kind, name);
    if (existing) return { ...existing, created: false };
    const value = await generator();
    const { version } = await this.put({ kind, name, value, contentType, meta, notAfter });
    const fresh = await this.get(kind, name, { version });
    return { ...fresh, created: true };
  }

  /** Süresi `withinMs` içinde dolacak etkin sırlar. */
  async listExpiring(withinMs) {
    const now = Date.now();
    const limit = now + withinMs;
    const rows = await this.collection.findRange('notAfter', 1, limit);
    return rows
      .filter((r) => r.status === STATUS.ACTIVE || r.status === STATUS.PENDING)
      .map((r) => ({
        kind: r.kind, name: r.name, version: Number(r.version), status: r.status,
        notAfter: Number(r.notAfter), expiresInMs: Number(r.notAfter) - now,
      }));
  }

  /** Türe göre listeleme — ADA göre listeleme YOKTUR (ad kör dizinde). */
  async listByKind(kind) {
    const rows = await this.collection.find('kind', kind);
    return rows.map((r) => ({
      kind: r.kind, version: Number(r.version), status: r.status,
      createdAt: Number(r.createdAt || 0), notAfter: Number(r.notAfter || 0),
      sha256Hex: r.sha256Hex, meta: r.metaJson ? safeParse(r.metaJson) : null,
    }));
  }

  /**
   * Ele geçmiş olarak işaretler. SİLMEZ: olay müdahalesinin neyin açığa
   * çıktığını bilmesi gerekir. Bu yalnızca yerel yarısıdır; CA'da iptal
   * etmek CA'nın işi.
   */
  async markCompromised(kind, name, version, reason) {
    const row = await this._row(kind, name, version);
    if (!row) return false;
    await this.collection.update(String(row._id), {
      status: STATUS.COMPROMISED,
      compromisedAt: Date.now(),
      compromiseReason: String(reason || 'belirtilmedi'),
    });
    if (this.logger) this.logger.warn({ kind, version, reason, msg: 'sır ele geçmiş olarak işaretlendi' });
    return true;
  }

  /**
   * Kasa sırrı döndürüldüğünde: eski anahtarla açıp yenisiyle sar.
   *
   * DİKKAT: Bu çağrı yalnızca veritabanındaki kayıtları ve BU örneğin
   * bellek içi anahtarını değiştirir. Yeni sırrı ortama (FITFAK_MAIL_VAULT_SECRET)
   * yazmak çağıranın sorumluluğudur; yazılmazsa süreç yeniden başladığında
   * kasadaki hiçbir kayıt açılamaz. `_unwrap` bu durumu artık anlaşılır bir
   * hatayla bildiriyor ama önlemiyor — önleyecek olan, sırrı kalıcı yazmak.
   */
  async rewrapAll(newSecret) {
    const nextKey = Buffer.from(crypto.hkdfSync('sha256', newSecret, Buffer.alloc(32), Buffer.from('fitmail-vault-wrap-v1'), 32));
    const nextKeyId = crypto.createHash('sha256').update(nextKey).digest('hex').slice(0, 16);
    if (nextKeyId === this.wrapKeyId) return { rewrapped: 0, unchanged: true };

    let rewrapped = 0;
    for await (const row of this.collection.scan()) {
      if (row.wrapKeyId === nextKeyId) continue;
      const aad = KeyVault.aadFor(row.kind, row.name, Number(row.version));
      const plaintext = this._unwrap(row.ciphertext, aad, row.wrapKeyId);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', nextKey, iv);
      cipher.setAAD(Buffer.from(aad, 'utf8'));
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      await this.collection.update(String(row._id), {
        ciphertext: Buffer.concat([iv, cipher.getAuthTag(), ct]),
        wrapKeyId: nextKeyId,
        rotatedAt: Date.now(),
      });
      rewrapped++;
    }
    this.wrapKey = nextKey;
    this.wrapKeyId = nextKeyId;
    return { rewrapped, unchanged: false };
  }
}

function safeParse(s) { try { return JSON.parse(s); } catch { return null; } }

module.exports = { KeyVault, VAULT_STATUS: STATUS };
