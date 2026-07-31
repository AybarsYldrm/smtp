'use strict';

const crypto = require('node:crypto');
const zlib = require('node:zlib');

const { toBuffer, tryDecodeBase64 } = require('../util/bytes');

const COMPRESS_MIN_BYTES = 4096;
const INCOMPRESSIBLE = /^(image\/(?!svg)|video\/|audio\/|application\/(zip|gzip|x-7z|x-rar|pdf))/i;

/**
 * İkili veri deposu: üstbilgi (`blobs`) + parçalar (`blob_chunks`).
 *
 * ── BİLDİRİLEN HATA: "ekler base64 ve eksik geliyordu" ────────────────────
 *
 * Parçalar veritabanına base64 DİZGE olarak yazılıyordu (bir sürücü
 * uyumsuzluğunu aşmak için). Okuma tarafı `Buffer.from(row.bytes, 'base64')`
 * diyordu ve bu, `row.bytes` bir DİZGE olduğu sürece doğru çalışıyor. Ama
 * gRPC sürücüsü `bytes` alanına yazılan dizgeyi baytlara çeviriyor ve geri
 * okurken Buffer döndürüyor — `Buffer.from(buffer, 'base64')` ise kodlama
 * argümanını YOK SAYIP baytları olduğu gibi kopyalar.
 *
 * Sonuç tam olarak bildirilen davranıştı:
 *   - içerik base64 METNİ olarak iniyordu (çözülmemiş),
 *   - ve `content-length` ham boyuta göre yazıldığı için (base64 ~%33 daha
 *     uzun) tarayıcı gövdeyi ham boyutta KESİYORDU.
 *
 * Çözüm iki katmanlı:
 *
 *   1. KENDİNİ TANITAN PARÇA. Yeni parçalar `b64:` ön ekiyle yazılır. Ön ek
 *      dizge olarak da bayt olarak da aynı görünür; hangi sürücüden
 *      geçtiğinden bağımsız olarak "bu değer base64 metnidir" bilgisi
 *      verinin İÇİNDE taşınır. Tahmin gerekmez.
 *
 *   2. ESKİ VERİ İÇİN BELİRLENİMCİ ÇÖZÜM. Ön eksiz parçalar için yorum
 *      tahminle değil ARİTMETİKLE seçilir: sıkıştırılmamış bir blob'ta
 *      parçaların toplam uzunluğu `totalBytes` ile eşleşmek ZORUNDA. İki
 *      yorumdan (ham / base64) hangisi eşleşiyorsa doğru olan odur;
 *      sıkıştırılmış blob'ta ise sha256 karar verir.
 *
 * Böylece yazılmış veriler taşınmadan okunabilir kalır ve yeni veriler bu
 * belirsizliğe hiç girmez.
 */

const CHUNK_PREFIX = 'b64:';
const CHUNK_PREFIX_BYTES = Buffer.from(CHUNK_PREFIX, 'latin1');

function hasChunkPrefix(buf) {
  return buf.length >= CHUNK_PREFIX_BYTES.length
    && buf.subarray(0, CHUNK_PREFIX_BYTES.length).equals(CHUNK_PREFIX_BYTES);
}

function encodeChunk(slice) {
  return CHUNK_PREFIX + slice.toString('base64');
}

class BlobStore {
  constructor(db, { chunkBytes = 256 * 1024, logger = null } = {}) {
    this.db = db;
    this.chunkBytes = chunkBytes;
    this.logger = logger;
  }

  get blobs() { return this.db.collection('blobs'); }
  get chunks() { return this.db.collection('blob_chunks'); }

  _shouldCompress(buf, contentType) {
    if (buf.length < COMPRESS_MIN_BYTES) return false;
    return !INCOMPRESSIBLE.test(String(contentType || ''));
  }

  async write(buffer, { kind = 'generic', ownerRef = '', contentType = 'application/octet-stream', expiresAt = 0, dedupe = true } = {}) {
    const raw = Buffer.isBuffer(buffer) ? buffer : Buffer.from(String(buffer), 'utf8');
    const sha256Hex = crypto.createHash('sha256').update(raw).digest('hex');

    if (dedupe) {
      const existing = (await this.blobs.find('sha256Hex', sha256Hex)).find((b) => b.kind === kind);
      if (existing) {
        await this.blobs.update(String(existing._id), { refCount: Number(existing.refCount || 1) + 1 });
        return { blobId: existing.blobId, deduped: true, totalBytes: Number(existing.totalBytes), sha256Hex };
      }
    }

    const compress = this._shouldCompress(raw, contentType);
    const payload = compress ? zlib.gzipSync(raw, { level: 6 }) : raw;
    const blobId = crypto.randomBytes(16).toString('hex');
    const now = Date.now();

    const chunkCount = Math.max(1, Math.ceil(payload.length / this.chunkBytes));
    for (let i = 0; i < chunkCount; i++) {
      const slice = payload.subarray(i * this.chunkBytes, Math.min(payload.length, (i + 1) * this.chunkBytes));
      // Parça kendini tanıtır: `b64:` ön eki, değer sürücüde dizge olarak da
      // bayt olarak da saklansa okunabilir kalır.
      await this.chunks.insert({ blobId, seq: i, bytes: encodeChunk(slice), createdAt: now });
    }

    await this.blobs.insert({
      blobId,
      kind,
      ownerRef: String(ownerRef || ''),
      totalBytes: raw.length,
      chunkCount,
      sha256Hex,
      contentType,
      createdAt: now,
      expiresAt: Number(expiresAt) || 0,
      refCount: 1,
      compression: compress ? 'gzip' : '',
    });

    return { blobId, deduped: false, totalBytes: raw.length, sha256Hex };
  }

  async head(blobId) {
    const row = await this.blobs.findOne('blobId', String(blobId));
    if (!row) return null;
    return {
      blobId: row.blobId,
      kind: row.kind,
      ownerRef: row.ownerRef,
      totalBytes: Number(row.totalBytes),
      chunkCount: Number(row.chunkCount),
      sha256Hex: row.sha256Hex,
      contentType: row.contentType,
      createdAt: Number(row.createdAt || 0),
      expiresAt: Number(row.expiresAt || 0),
      refCount: Number(row.refCount || 1),
      compression: row.compression || '',
    };
  }

  /**
   * Parçaları sıralı ve ÇÖZÜLMÜŞ olarak getirir.
   *
   * Ön ekli parçalarda yorum kesindir. Ön eksiz (eski) parçalarda iki aday
   * vardır ve seçim `meta` ile doğrulanır — böylece "base64 mü ham mı"
   * sorusu tahminle değil, blob'un kendi kaydettiği uzunlukla cevaplanır.
   */
  async _loadChunks(blobId, meta) {
    const rows = await this.chunks.find('blobId', String(blobId));
    if (rows.length !== meta.chunkCount) {
      throw new Error(`[blob] eksik parça: ${blobId} (${rows.length}/${meta.chunkCount})`);
    }
    rows.sort((a, b) => Number(a.seq) - Number(b.seq));

    const rawValues = rows.map((r) => toBuffer(r.bytes));

    // 1. Kendini tanıtan parçalar: doğrudan çöz.
    if (rawValues.every(hasChunkPrefix)) {
      return rawValues.map((buf) => Buffer.from(buf.subarray(CHUNK_PREFIX_BYTES.length).toString('latin1'), 'base64'));
    }

    // 2. Eski veri. İki aday üret ve blob üstbilgisiyle doğrula.
    const decodedValues = rawValues.map(tryDecodeBase64);
    const base64Possible = decodedValues.every((d) => d != null);

    if (!meta.compression) {
      const rawTotal = rawValues.reduce((n, b) => n + b.length, 0);
      if (rawTotal === meta.totalBytes) return rawValues;
      if (base64Possible) {
        const decodedTotal = decodedValues.reduce((n, b) => n + b.length, 0);
        if (decodedTotal === meta.totalBytes) {
          this._warnLegacy(blobId);
          return decodedValues;
        }
      }
      throw new Error(
        `[blob] parça uzunlukları üstbilgiyle uyuşmuyor: ${blobId} `
        + `(beklenen ${meta.totalBytes} bayt)`,
      );
    }

    // Sıkıştırılmış: uzunluk bilgisi yok, gzip başlığı karar verir.
    const isGzip = (b) => b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b;
    if (isGzip(rawValues[0])) return rawValues;
    if (base64Possible && isGzip(decodedValues[0])) {
      this._warnLegacy(blobId);
      return decodedValues;
    }
    return rawValues;
  }

  _warnLegacy(blobId) {
    if (this._legacyWarned) return;
    this._legacyWarned = true;
    if (this.logger) {
      this.logger.warn({
        blobId,
        msg: 'eski biçimde (ön eksiz base64) yazılmış blob parçaları okundu — '
          + 'yeni yazımlar kendini tanıtan biçimde yapılıyor, bu kayıtlar olduğu gibi okunabilir kalır',
      });
    }
  }

  async read(blobId) {
    const meta = await this.head(blobId);
    if (!meta) return null;
    const parts = await this._loadChunks(blobId, meta);
    const payload = Buffer.concat(parts);

    const out = meta.compression === 'gzip' ? zlib.gunzipSync(payload) : payload;
    const digest = crypto.createHash('sha256').update(out).digest('hex');
    if (digest !== meta.sha256Hex) throw new Error(`[blob] özet uyuşmuyor: ${blobId}`);
    return out;
  }

  async *readStream(blobId, { start = 0, end = null } = {}) {
    const meta = await this.head(blobId);
    if (!meta) return;
    if (meta.compression === 'gzip') {
      const full = await this.read(blobId);
      yield full.subarray(start, end == null ? undefined : end + 1);
      return;
    }
    const parts = await this._loadChunks(blobId, meta);
    const last = end == null ? meta.totalBytes - 1 : Math.min(end, meta.totalBytes - 1);
    let offset = 0;
    for (const buf of parts) {
      const chunkStart = offset;
      const chunkEnd = offset + buf.length - 1;
      offset += buf.length;
      if (chunkEnd < start) continue;
      if (chunkStart > last) break;
      const from = Math.max(0, start - chunkStart);
      const to = Math.min(buf.length - 1, last - chunkStart);
      yield buf.subarray(from, to + 1);
    }
  }

  async release(blobId) {
    const row = await this.blobs.findOne('blobId', String(blobId));
    if (!row) return false;
    const next = Number(row.refCount || 1) - 1;
    if (next > 0) {
      await this.blobs.update(String(row._id), { refCount: next });
      return false;
    }
    const chunkRows = await this.chunks.find('blobId', String(blobId));
    for (const c of chunkRows) await this.chunks.delete(String(c._id));
    await this.blobs.delete(String(row._id));
    return true;
  }

  async retain(blobId) {
    const row = await this.blobs.findOne('blobId', String(blobId));
    if (!row) return false;
    await this.blobs.update(String(row._id), { refCount: Number(row.refCount || 1) + 1 });
    return true;
  }

  async sweepExpired({ now = Date.now(), limit = 500 } = {}) {
    const rows = await this.blobs.findRange('expiresAt', 1, now, { limit });
    let removed = 0;
    for (const row of rows) {
      const chunkRows = await this.chunks.find('blobId', row.blobId);
      for (const c of chunkRows) await this.chunks.delete(String(c._id));
      await this.blobs.delete(String(row._id));
      removed++;
    }
    return removed;
  }

  async sweepOrphans({ olderThanMs = 3600_000, limit = 2000 } = {}) {
    const cutoff = Date.now() - olderThanMs;
    const seen = new Map();
    let scanned = 0;
    for await (const c of this.chunks.scan()) {
      if (++scanned > limit) break;
      if (Number(c.createdAt || 0) > cutoff) continue;
      if (!seen.has(c.blobId)) seen.set(c.blobId, []);
      seen.get(c.blobId).push(String(c._id));
    }
    let removed = 0;
    for (const [blobId, ids] of seen) {
      const head = await this.blobs.findOne('blobId', blobId);
      if (head) continue;
      for (const id of ids) { await this.chunks.delete(id); removed++; }
    }
    return removed;
  }
}

module.exports = { BlobStore, CHUNK_PREFIX };
