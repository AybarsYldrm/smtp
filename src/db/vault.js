'use strict';

const crypto = require('node:crypto');

const { toBuffer, tryDecodeBase64 } = require('../util/bytes');

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

/**
 * Zarf başlığı: `FMV1` || iv(12) || tag(16) || şifreli metin.
 *
 * ── BİLDİRİLEN HATA ──────────────────────────────────────────────────────
 *   Error: Unsupported state or unable to authenticate data
 *       at Decipheriv.final (node:internal/crypto/cipher)
 *       at KeyVault._unwrap  ->  MailSigner.getDkimKey  ->  pipeline.send
 *
 * Yani DKIM anahtarı kasaya YAZILIYOR ama GERİ OKUNAMIYOR ve giden her posta
 * 500 ile düşüyordu. AES-GCM'in bu hatası üç ayrı nedene çıkar ve üçünün
 * çözümü farklıdır:
 *
 *   a) Kasa sırrı değişti  -> eski sır olmadan kayıt açılamaz.
 *   b) Şifreli metin BOZULDU -> yedekten dönmek gerekir.
 *   c) Şifreli metin SAĞLAM ama sürücüden FARKLI BİR ŞEKİLDE geri geldi
 *      (Buffer yerine base64 dizge, ya da base64 metnin baytları) -> hiçbir
 *      şey kaybolmamıştır, yalnızca doğru okunmamıştır.
 *
 * Uygulamada gerçekleşen (c) idi ve (b) gibi görünüyordu. Ayrım, tahminle
 * yapılamaz — bu yüzden zarf artık KENDİNİ TANITIYOR: 4 baytlık `FMV1`
 * imzası, değerin hangi şekilde geri geldiğinden bağımsız olarak "bu bir
 * kasa zarfıdır ve şuradan başlar" diyor. İmza bulunamazsa değer bir kez de
 * base64 metni olarak çözülüp tekrar bakılıyor; hâlâ yoksa kayıt eski
 * biçimdedir ve doğrudan iv||tag||ct olarak okunuyor.
 *
 * (a) ve (b) ise artık BİRBİRİNDEN AYRI hata mesajları veriyor.
 */
const ENVELOPE_MAGIC = Buffer.from('FMV1', 'latin1');
const IV_BYTES = 12;
const TAG_BYTES = 16;

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
    const iv = crypto.randomBytes(IV_BYTES);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.wrapKey, iv);
    cipher.setAAD(Buffer.from(aad, 'utf8'));
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([ENVELOPE_MAGIC, iv, cipher.getAuthTag(), ct]);
  }

  /**
   * Sürücüden dönen değerden zarfın GÖVDESİNİ (iv||tag||ct) çıkarır.
   *
   * Üç şekil de aynı zarfı taşıyabilir ve üçü de burada aynı sonuca iner:
   *   - Buffer/Uint8Array olarak `FMV1...`         (beklenen)
   *   - base64 DİZGE olarak `"Rk1WMQ..."`          (JSON köprüsü)
   *   - base64 metnin BAYTLARI `0x52 0x6b 0x31...` (dizge -> bytes çeviren sürücü)
   */
  static _envelopeBody(value) {
    const direct = toBuffer(value);
    if (direct.length >= ENVELOPE_MAGIC.length
      && direct.subarray(0, ENVELOPE_MAGIC.length).equals(ENVELOPE_MAGIC)) {
      return { body: direct.subarray(ENVELOPE_MAGIC.length), legacy: false, reencoded: false };
    }

    const decoded = tryDecodeBase64(direct);
    if (decoded && decoded.length >= ENVELOPE_MAGIC.length
      && decoded.subarray(0, ENVELOPE_MAGIC.length).equals(ENVELOPE_MAGIC)) {
      return { body: decoded.subarray(ENVELOPE_MAGIC.length), legacy: false, reencoded: true };
    }

    // İmza yok: `FMV1` öncesi yazılmış kayıt. Gövdenin kendisi zarftır.
    // Dizge olarak gelmişse base64 çözümü eski davranışla aynı kalır.
    if (typeof value === 'string') {
      const asBase64 = Buffer.from(value, 'base64');
      if (asBase64.length >= IV_BYTES + TAG_BYTES + 1) {
        return { body: asBase64, legacy: true, reencoded: true };
      }
    }
    return { body: direct, legacy: true, reencoded: false };
  }

  /**
   * @param {Buffer|string|object} envelope
   * @param {string} aad
   * @param {string} [wrapKeyId] kaydın sarıldığı anahtarın kimliği
   * @param {object} [context]   hata mesajına yazılacak kayıt bilgisi
   */
  _unwrap(envelope, aad, wrapKeyId = null, context = {}) {
    const where = context.label ? ` (${context.label})` : '';

    // Anahtar uyuşmazlığı ÖNCE denetlenir. Aksi hâlde AES-GCM'in
    // "Unsupported state or unable to authenticate data" hatası çıkar ve o
    // hata "veri bozuk" gibi okunur; oysa veri sağlam, yanlış anahtarla
    // açılmaya çalışılıyor. İkisi çok farklı sorunlar: biri yedekten geri
    // dönmeyi, diğeri doğru sırrı bulmayı gerektirir.
    if (wrapKeyId && wrapKeyId !== this.wrapKeyId) {
      const err = new Error(
        `[vault] bu sır başka bir kasa anahtarıyla sarılmış${where} `
        + `(kayıt: ${wrapKeyId}, şu anki: ${this.wrapKeyId}). `
        + 'FITFAK_MAIL_VAULT_SECRET değişmiş olabilir; eski sır olmadan bu kayıt açılamaz. '
        + 'Eski sır elinizdeyse `rewrapAll` ile yeniden sarın, yoksa bu sır yeniden üretilmelidir.',
      );
      err.code = 'VAULT_KEY_MISMATCH';
      throw err;
    }

    const { body, legacy } = KeyVault._envelopeBody(envelope);
    if (body.length < IV_BYTES + TAG_BYTES + 1) {
      const err = new Error(`[vault] bozuk zarf${where}: ${body.length} bayt, en az ${IV_BYTES + TAG_BYTES + 1} bekleniyor`);
      err.code = 'VAULT_ENVELOPE_INVALID';
      throw err;
    }

    const iv = body.subarray(0, IV_BYTES);
    const tag = body.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const ct = body.subarray(IV_BYTES + TAG_BYTES);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.wrapKey, iv);

    // AAD sır adını ve sürümünü bağlar: bir kaydın şifreli gövdesini başka
    // bir kaydın satırına taşımak doğrulamayı bozar.
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    try {
      return Buffer.concat([decipher.update(ct), decipher.final()]);
    } catch (cause) {
      // Buraya düşmek artık tek bir anlama geliyor: anahtar doğru,
      // biçim doğru, ama doğrulama etiketi tutmadı.
      const err = new Error(
        `[vault] sır açılamadı${where}: kimlik doğrulama etiketi tutmadı. `
        + (legacy
          ? 'Kayıt eski (imzasız) biçimde; kasa sırrı bu kayıt yazıldıktan sonra değişmiş olabilir. '
          : '')
        + 'Kasa sırrı (FITFAK_MAIL_VAULT_SECRET) doğruysa kayıt bozulmuştur ve yeniden üretilmelidir.',
      );
      err.code = 'VAULT_DECRYPT_FAILED';
      err.cause = cause;
      throw err;
    }
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
  async put({
    kind, name, value, activate = true, notAfter = 0,
    contentType = 'application/octet-stream', meta = null, createdBySub = '',
    verify = true,
  }) {
    if (!kind || !name) throw new Error('[vault] kind ve name zorunlu');
    const plaintext = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
    if (!plaintext.length) throw new Error(`[vault] boş sır yazılamaz: ${kind}`);

    const version = (await this._highestVersion(kind, name)) + 1;
    const secretKey = KeyVault.keyFor(kind, name, version);

    // Aynı ad için eşzamanlı iki `put`, aynı sürüm numarasını hesaplayıp iki
    // kayıt yazabilir. Sürüm sayacı bir kilit değil; bu yüzden yazmadan önce
    // anahtarın boş olduğu doğrulanıyor ve doluysa sürüm ilerletiliyor.
    if (await this.collection.findOne('secretKey', secretKey)) {
      return this.put({
        kind, name, value, activate, notAfter, contentType, meta, createdBySub, verify,
      });
    }

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

    // GİDİŞ-DÖNÜŞ DENETİMİ. Yazdığımız zarfı veritabanından GERİ OKUYUP
    // açıyoruz. Sürücü ikili alanı başka bir şekle çevirdiyse (dizge, base64,
    // {type:'Buffer'}) burada anlaşılır; denetim olmadan bu, aylar sonra
    // "eposta gönderilemiyor" olarak ve tamamen başka bir yerde patlıyordu.
    if (verify) {
      const stored = await this.collection.findOne('secretKey', secretKey);
      if (!stored) {
        throw new Error(`[vault] sır yazıldı ama geri okunamadı: ${kind} v${version}`);
      }
      const roundTrip = this._unwrap(
        stored.ciphertext,
        KeyVault.aadFor(kind, name, version),
        stored.wrapKeyId,
        { label: `${kind} v${version}` },
      );
      if (!roundTrip.equals(plaintext)) {
        throw new Error(
          `[vault] gidiş-dönüş denetimi başarısız: ${kind} v${version}. `
          + 'Veritabanı sürücüsü ikili alanı olduğu gibi geri döndürmüyor.',
        );
      }
    }

    if (activate) await this._retireOthers(kind, name, version);
    if (this.logger) {
      this.logger.info({
        kind, version, status: record.status, bytes: plaintext.length,
        sha256: record.sha256Hex.slice(0, 12), msg: 'kasaya sır yazıldı',
      });
    }
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
    const value = this._unwrap(
      row.ciphertext,
      KeyVault.aadFor(row.kind, row.name, Number(row.version)),
      row.wrapKeyId,
      { label: `${row.kind} v${row.version}` },
    );
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
          value: this._unwrap(
            row.ciphertext,
            KeyVault.aadFor(row.kind, row.name, Number(row.version)),
            row.wrapKeyId,
            { label: `${row.kind} v${row.version}` },
          ),
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

  /**
   * Kasanın sağlık durumu: her kayıt AÇILABİLİYOR MU?
   *
   * "Yazma çalışıyor ama okuma çalışıyor mu emin değilim" sorusunun tek
   * dürüst cevabı, kayıtları gerçekten açmayı denemektir. Değerler DÖNMEZ,
   * yalnızca açılıp açılamadığı ve açılamıyorsa NEDENİ.
   */
  async diagnose({ kinds = null } = {}) {
    // `mismatched` ile `failed` AYRI sayılır ve ayrım önemli:
    //
    //   mismatched — kayıt başka bir kasa anahtarıyla sarılmış. Veri
    //                sağlamdır; ya sır döndürülmüş ve `rewrapAll`
    //                tamamlanmamıştır, ya da eski bir sırla yazılmıştır.
    //   failed     — anahtar doğru ama içerik açılamıyor. Bu gerçek bir
    //                bozulmadır ve yedekten dönmeyi gerektirir.
    //
    // İkisini tek sayıda toplamak, "3 kayıt bozuk" diye alarm verip
    // operatörü yedeğe göndermek olurdu; oysa yapılması gereken şey
    // rotasyonu tamamlamak olabilir.
    const out = { total: 0, ok: 0, failed: 0, mismatched: 0, byKind: {}, problems: [] };
    for await (const row of this.collection.scan()) {
      if (kinds && !kinds.includes(row.kind)) continue;
      out.total++;
      const kind = row.kind || 'bilinmiyor';
      out.byKind[kind] = out.byKind[kind] || { ok: 0, failed: 0, mismatched: 0 };
      try {
        const value = this._unwrap(
          row.ciphertext,
          KeyVault.aadFor(row.kind, row.name, Number(row.version)),
          row.wrapKeyId,
          { label: `${row.kind} v${row.version}` },
        );
        const digest = crypto.createHash('sha256').update(value).digest('hex');
        if (row.sha256Hex && digest !== row.sha256Hex) {
          throw Object.assign(new Error('[vault] açılan değerin özeti kayıttakiyle uyuşmuyor'), {
            code: 'VAULT_DIGEST_MISMATCH',
          });
        }
        out.ok++;
        out.byKind[kind].ok++;
      } catch (err) {
        const mismatch = err.code === 'VAULT_KEY_MISMATCH';
        if (mismatch) { out.mismatched++; out.byKind[kind].mismatched++; }
        else { out.failed++; out.byKind[kind].failed++; }
        out.problems.push({
          kind: row.kind,
          version: Number(row.version || 0),
          status: row.status,
          code: err.code || 'UNKNOWN',
          wrapKeyId: row.wrapKeyId || '',
          error: err.message,
        });
      }
    }
    return out;
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
      const plaintext = this._unwrap(row.ciphertext, aad, row.wrapKeyId, { label: `${row.kind} v${row.version}` });
      const iv = crypto.randomBytes(IV_BYTES);
      const cipher = crypto.createCipheriv('aes-256-gcm', nextKey, iv);
      cipher.setAAD(Buffer.from(aad, 'utf8'));
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      await this.collection.update(String(row._id), {
        ciphertext: Buffer.concat([ENVELOPE_MAGIC, iv, cipher.getAuthTag(), ct]),
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
