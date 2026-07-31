'use strict';

const crypto = require('node:crypto');
const zlib = require('node:zlib');

const COMPRESS_MIN_BYTES = 4096;
const INCOMPRESSIBLE = /^(image\/(?!svg)|video\/|audio\/|application\/(zip|gzip|x-7z|x-rar|pdf))/i;

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
      
      // ÇÖZÜM: @fitfak/database paketinin Buffer hatasını aşmak için 
      // parçayı veritabanına saf Buffer yerine Base64 string olarak yazıyoruz.
      await this.chunks.insert({ blobId, seq: i, bytes: slice.toString('base64'), createdAt: now });
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

  async read(blobId) {
    const meta = await this.head(blobId);
    if (!meta) return null;
    const rows = await this.chunks.find('blobId', String(blobId));
    if (rows.length !== meta.chunkCount) {
      throw new Error(`[blob] eksik parça: ${blobId} (${rows.length}/${meta.chunkCount})`);
    }
    rows.sort((a, b) => Number(a.seq) - Number(b.seq));
    
    // ÇÖZÜM: Veritabanından string olarak gelen Base64 verisini Buffer'a geri çeviriyoruz.
    const payload = Buffer.concat(rows.map((r) => Buffer.from(r.bytes, 'base64')));
    
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
    const rows = await this.chunks.find('blobId', String(blobId));
    rows.sort((a, b) => Number(a.seq) - Number(b.seq));
    const last = end == null ? meta.totalBytes - 1 : Math.min(end, meta.totalBytes - 1);
    let offset = 0;
    for (const row of rows) {
      
      // ÇÖZÜM: Akışlı okumada da Base64 string'i güvenle Buffer'a çeviriyoruz.
      const buf = Buffer.from(row.bytes, 'base64');
      
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

module.exports = { BlobStore };