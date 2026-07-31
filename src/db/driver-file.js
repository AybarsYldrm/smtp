'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

const { KeyedQueue } = require('../util/async');

/**
 * Şifreli, ekleme-yalnızca dosya sürücüsü.
 *
 * Bu, @fitfak/database'in YERİNE geçmek için değil, iki somut ihtiyaç için
 * var:
 *
 *   1. Test edilebilirlik. Depo (repository) katmanının doğruluğu, ağdaki bir
 *      gRPC sunucusuna ve yayımlanmamış bir pakete bağlı olmamalı. Testler bu
 *      sürücüyle çalışır ve `_id`'nin BigInt dönmesi gibi motorun gerçek
 *      tuhaflıklarını bilerek taklit eder — böylece `bigint === string`
 *      karşılaştırması testte patlar, üretimde değil.
 *   2. Tek makinede çalışan bir kurulum. Kimlik kaydı (enrolment) yapmadan,
 *      gRPC olmadan ayağa kalkması gereken bir posta sunucusu makul bir
 *      istek; verinin diskte düz metin olması değil.
 *
 * Çerçeve biçimi @fitfak/database'in belgelenmiş biçimiyle aynı hizada:
 *
 *   [op:1][flags:1][id:8 BE][version:4 BE][payloadLen:4 BE][payload]
 *   payload = iv(12) || tag(16) || AES-256-GCM(kayıt)
 *   AAD     = id || op || flags || version
 *
 * `version`'ın AAD'ye bağlanması, sürüm sayacını kurcalamaya karşı kanıt
 * üretir: eski ama gerçek bir çerçeveyi yeni sürüm numarasıyla sunmak
 * doğrulamayı bozar.
 *
 * SINIRLARI açıkça: tek süreç. İki süreç aynı dizini açarsa ikisi de kendi
 * bellek içi dizinini tutar ve birbirinin yazdığını görmez. Çok süreçli
 * kurulum için gerçek sürücü (gRPC) gerekir.
 */

const OP_INSERT = 1;
const OP_UPDATE = 2;
const OP_DELETE = 3;

const FLAG_DEFLATE = 0x01;

const HEADER_BYTES = 1 + 1 + 8 + 4 + 4;
const DEFLATE_THRESHOLD = 1024;

function hkdf(secret, info, length = 32, salt = Buffer.alloc(32)) {
  return Buffer.from(crypto.hkdfSync('sha256', secret, salt, Buffer.from(info, 'utf8'), length));
}

/** Tekdüze artan 64-bit kimlik: (ms << 20) | sayaç. */
function createIdGenerator(workerId = 0) {
  let lastMs = 0n;
  let counter = 0n;
  const worker = BigInt(workerId & 0x3ff);
  return function next() {
    let ms = BigInt(Date.now());
    if (ms === lastMs) {
      counter += 1n;
      if (counter > 0x3ffn) { // aynı milisaniyede taşma: sonraki ms'yi bekle
        while (BigInt(Date.now()) <= lastMs) { /* spin */ }
        ms = BigInt(Date.now());
        counter = 0n;
      }
    } else {
      counter = 0n;
    }
    lastMs = ms;
    return (ms << 20n) | (worker << 10n) | counter;
  };
}

function normalizeIndexValue(value) {
  if (value == null) return null;
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') return String(value);
  if (Buffer.isBuffer(value)) return value.toString('base64');
  return String(value);
}

function toNumeric(value) {
  if (value == null) return null;
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

class VersionConflictError extends Error {
  constructor(id, expected, actual) {
    super(`ABORTED: kayıt sürümü değişti (id=${id}, beklenen=${expected}, gerçek=${actual})`);
    this.code = 'ABORTED';
    this.expectedVersion = expected;
    this.actualVersion = actual;
  }
}

class FileCollection {
  constructor(db, name, schema) {
    this.db = db;
    this.name = name;
    this.file = path.join(db.dir, `${name}.seg`);
    this.key = hkdf(db.ddk, `fitmail-collection:${name}`);
    this.schema = null;
    this.fields = new Map();
    this.indexes = new Map();      // field -> Map(normValue -> Set(idStr))
    this.blindIndexes = new Map(); // field -> Map(hmacHex -> Set(idStr))
    this.blindKeys = new Map();    // field -> Buffer
    this.rangeFields = new Set();
    this.records = new Map();      // idStr -> { record, version, offset }
    this.seq = 0;
    this.fd = null;
    this.bytesWritten = 0;
    this.pendingSync = false;
    this.applySchema(schema);
  }

  applySchema(schema) {
    const fields = (schema && schema.fields) || [];
    const previous = this.schema;
    // Tür değişikliği ve alan silme motorda reddediliyor; burada da
    // reddediyoruz, yoksa iki sürücü aynı şemayı farklı kabul eder ve hata
    // yalnızca üretimde görünür.
    if (previous) {
      const oldByNo = new Map(previous.fields.map((f) => [f.no, f]));
      for (const f of fields) {
        const old = oldByNo.get(f.no);
        if (old && old.type !== f.type) {
          throw new Error(`[db] ${this.name}.${f.name}: alan türü değiştirilemez (${old.type} -> ${f.type})`);
        }
        oldByNo.delete(f.no);
      }
      for (const dropped of oldByNo.values()) {
        throw new Error(`[db] ${this.name}: alan silinemez (no=${dropped.no}, ad=${dropped.name})`);
      }
    }

    this.schema = { fields: fields.map((f) => ({ ...f })) };
    this.fields = new Map(fields.map((f) => [f.name, f]));
    for (const f of fields) {
      if (f.index && !this.indexes.has(f.name)) this.indexes.set(f.name, new Map());
      if (f.blindIndex) {
        if (!this.blindIndexes.has(f.name)) this.blindIndexes.set(f.name, new Map());
        if (!this.blindKeys.has(f.name)) this.blindKeys.set(f.name, hkdf(this.db.ddk, `fitmail-blind:${this.name}:${f.name}`));
      }
      if (f.rangeBucket) this.rangeFields.add(f.name);
    }
    return { migrated: !!previous, schemaVersion: 1 };
  }

  blindToken(field, value) {
    const key = this.blindKeys.get(field);
    if (!key) return null;
    const norm = normalizeIndexValue(value);
    if (norm == null) return null;
    return crypto.createHmac('sha256', key).update(norm, 'utf8').digest('hex');
  }

  /* ── dizin bakımı ─────────────────────────────────────────── */

  _indexAdd(idStr, record) {
    for (const [field, map] of this.indexes) {
      const v = normalizeIndexValue(record[field]);
      if (v == null) continue;
      let set = map.get(v);
      if (!set) { set = new Set(); map.set(v, set); }
      set.add(idStr);
    }
    for (const [field, map] of this.blindIndexes) {
      const token = this.blindToken(field, record[field]);
      if (!token) continue;
      let set = map.get(token);
      if (!set) { set = new Set(); map.set(token, set); }
      set.add(idStr);
    }
  }

  _indexRemove(idStr, record) {
    for (const [field, map] of this.indexes) {
      const v = normalizeIndexValue(record[field]);
      if (v == null) continue;
      const set = map.get(v);
      if (set) { set.delete(idStr); if (!set.size) map.delete(v); }
    }
    for (const [field, map] of this.blindIndexes) {
      const token = this.blindToken(field, record[field]);
      if (!token) continue;
      const set = map.get(token);
      if (set) { set.delete(idStr); if (!set.size) map.delete(token); }
    }
  }

  /* ── çerçeve kodlama ──────────────────────────────────────── */

  _encodeFrame(op, id, version, record) {
    const idBuf = Buffer.alloc(8);
    idBuf.writeBigUInt64BE(id);

    let body = Buffer.from(JSON.stringify(record, (k, v) => (typeof v === 'bigint' ? { $bigint: v.toString() } : v)), 'utf8');
    let flags = 0;
    if (body.length >= DEFLATE_THRESHOLD) {
      const deflated = require('node:zlib').deflateRawSync(body);
      if (deflated.length < body.length) { body = deflated; flags |= FLAG_DEFLATE; }
    }

    const versionBuf = Buffer.alloc(4);
    versionBuf.writeUInt32BE(version);
    const aad = Buffer.concat([idBuf, Buffer.from([op, flags]), versionBuf]);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(aad);
    const ct = Buffer.concat([cipher.update(body), cipher.final()]);
    const payload = Buffer.concat([iv, cipher.getAuthTag(), ct]);

    const head = Buffer.alloc(HEADER_BYTES);
    head[0] = op;
    head[1] = flags;
    idBuf.copy(head, 2);
    head.writeUInt32BE(version, 10);
    head.writeUInt32BE(payload.length, 14);
    return Buffer.concat([head, payload]);
  }

  _decodeFrame(buf, offset) {
    if (offset + HEADER_BYTES > buf.length) return null;
    const op = buf[offset];
    const flags = buf[offset + 1];
    const id = buf.readBigUInt64BE(offset + 2);
    const version = buf.readUInt32BE(offset + 10);
    const payloadLen = buf.readUInt32BE(offset + 14);
    const start = offset + HEADER_BYTES;
    if (start + payloadLen > buf.length) return null; // yarım çerçeve: kuyruk kesilmiş
    if (op !== OP_INSERT && op !== OP_UPDATE && op !== OP_DELETE) return null;

    const payload = buf.subarray(start, start + payloadLen);
    const iv = payload.subarray(0, 12);
    const tag = payload.subarray(12, 28);
    const ct = payload.subarray(28);

    const idBuf = Buffer.alloc(8);
    idBuf.writeBigUInt64BE(id);
    const versionBuf = Buffer.alloc(4);
    versionBuf.writeUInt32BE(version);
    const aad = Buffer.concat([idBuf, Buffer.from([op, flags]), versionBuf]);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    let body;
    try { body = Buffer.concat([decipher.update(ct), decipher.final()]); }
    catch (err) { throw new Error(`[db] ${this.name}: çerçeve doğrulanamadı (offset=${offset}): ${err.message}`); }
    if (flags & FLAG_DEFLATE) body = require('node:zlib').inflateRawSync(body);

    const record = JSON.parse(body.toString('utf8'), (k, v) => (
      v && typeof v === 'object' && typeof v.$bigint === 'string' ? BigInt(v.$bigint) : v
    ));
    return { op, id, version, record, next: start + payloadLen };
  }

  /** Açılışta segmenti baştan sona oynatır; bellek içi durum buradan doğar. */
  async load() {
    await fsp.mkdir(this.db.dir, { recursive: true, mode: 0o700 });
    let buf;
    try { buf = await fsp.readFile(this.file); }
    catch (err) {
      if (err.code !== 'ENOENT') throw err;
      buf = Buffer.alloc(0);
    }

    let offset = 0;
    let lastGood = 0;
    while (offset < buf.length) {
      let frame;
      try { frame = this._decodeFrame(buf, offset); }
      catch (err) {
        // Bozuk çerçeve: kuyruğu kes. Temiz kapanmayan bir süreç yarım
        // çerçeve bırakabilir; buna kadar okunanlar geçerlidir.
        this.db.logger.warn({ collection: this.name, offset, error: err.message, msg: 'bozuk çerçeve, kuyruk kesiliyor' });
        break;
      }
      if (!frame) break;
      const idStr = frame.id.toString();
      if (frame.op === OP_DELETE) {
        const existing = this.records.get(idStr);
        if (existing) { this._indexRemove(idStr, existing.record); this.records.delete(idStr); }
      } else {
        const existing = this.records.get(idStr);
        if (existing) this._indexRemove(idStr, existing.record);
        this.records.set(idStr, { record: frame.record, version: frame.version });
        this._indexAdd(idStr, frame.record);
      }
      offset = frame.next;
      lastGood = offset;
    }

    if (lastGood !== buf.length) {
      await fsp.truncate(this.file, lastGood).catch(() => {});
    }
    this.bytesWritten = lastGood;
    this.fd = await fsp.open(this.file, 'a');
    return this;
  }

  async _append(frame) {
    await this.fd.write(frame);
    this.bytesWritten += frame.length;
    this.db._scheduleSync(this);
  }

  async close() {
    if (this.fd) { try { await this.fd.sync(); } catch { /* yok sayılır */ } await this.fd.close(); this.fd = null; }
  }

  /* ── genel API ────────────────────────────────────────────── */

  _validate(record) {
    for (const f of this.schema.fields) {
      if (f.required && (record[f.name] == null || record[f.name] === '')) {
        throw new Error(`[db] ${this.name}.${f.name} zorunlu`);
      }
    }
    for (const key of Object.keys(record)) {
      if (key === '_id') continue;
      if (!this.fields.has(key)) throw new Error(`[db] ${this.name}: şemada olmayan alan "${key}"`);
    }
  }

  async insert(record) {
    this._validate(record);
    return this.db.writes.run(this.name, async () => {
      const id = this.db.nextId();
      const idStr = id.toString();
      const stored = { ...record };
      const frame = this._encodeFrame(OP_INSERT, id, 1, stored);
      await this._append(frame);
      this.records.set(idStr, { record: stored, version: 1 });
      this._indexAdd(idStr, stored);
      this.db._emitChange(this.name, { type: 'insert', id: idStr, record: this._decorate(idStr, stored) });
      // Motor `insert()` için STRING döner (kayıt içindeki `_id` ise BigInt).
      return idStr;
    });
  }

  async update(id, patch, { expectedVersion = null } = {}) {
    const idStr = String(id);
    return this.db.writes.run(this.name, async () => {
      const cur = this.records.get(idStr);
      if (!cur) throw new Error(`[db] ${this.name}: kayıt yok (id=${idStr})`);
      if (expectedVersion != null && Number(expectedVersion) !== cur.version) {
        throw new VersionConflictError(idStr, Number(expectedVersion), cur.version);
      }
      const next = { ...cur.record };
      for (const [k, v] of Object.entries(patch)) {
        if (k === '_id') continue;
        if (!this.fields.has(k)) throw new Error(`[db] ${this.name}: şemada olmayan alan "${k}"`);
        if (v === undefined) continue;
        next[k] = v;
      }
      const version = cur.version + 1;
      const frame = this._encodeFrame(OP_UPDATE, BigInt(idStr), version, next);
      await this._append(frame);
      this._indexRemove(idStr, cur.record);
      this.records.set(idStr, { record: next, version });
      this._indexAdd(idStr, next);
      this.db._emitChange(this.name, { type: 'update', id: idStr, record: this._decorate(idStr, next) });
      return { version };
    });
  }

  async delete(id) {
    const idStr = String(id);
    return this.db.writes.run(this.name, async () => {
      const cur = this.records.get(idStr);
      if (!cur) return false;
      const frame = this._encodeFrame(OP_DELETE, BigInt(idStr), cur.version + 1, {});
      await this._append(frame);
      this._indexRemove(idStr, cur.record);
      this.records.delete(idStr);
      this.db._emitChange(this.name, { type: 'delete', id: idStr });
      return true;
    });
  }

  _decorate(idStr, record) {
    // `_id` BigInt olarak döner — motorun davranışı bu. Depo katmanı her
    // yerde String(rec._id) kullanmak zorunda ve testler bunu yakalar.
    return { ...record, _id: BigInt(idStr) };
  }

  async get(id) {
    const cur = this.records.get(String(id));
    return cur ? this._decorate(String(id), cur.record) : null;
  }

  async getWithVersion(id) {
    const cur = this.records.get(String(id));
    return cur ? { record: this._decorate(String(id), cur.record), version: cur.version } : null;
  }

  _idsFor(field, value) {
    if (field === '_id') {
      return this.records.has(String(value)) ? [String(value)] : [];
    }
    if (this.blindIndexes.has(field)) {
      const token = this.blindToken(field, value);
      const set = token ? this.blindIndexes.get(field).get(token) : null;
      return set ? [...set] : [];
    }
    if (this.indexes.has(field)) {
      const set = this.indexes.get(field).get(normalizeIndexValue(value));
      return set ? [...set] : [];
    }
    if (!this.fields.has(field)) throw new Error(`[db] ${this.name}: böyle bir alan yok "${field}"`);
    throw new Error(`[db] ${this.name}.${field} dizinli değil — find() kullanılamaz`);
  }

  async find(field, value, { limit = 0 } = {}) {
    const ids = this._idsFor(field, value);
    ids.sort(compareIdStr);
    const out = [];
    for (const idStr of ids) {
      const cur = this.records.get(idStr);
      if (!cur) continue;
      out.push(this._decorate(idStr, cur.record));
      if (limit && out.length >= limit) break;
    }
    return out;
  }

  async findOne(field, value) {
    const list = await this.find(field, value, { limit: 1 });
    return list[0] || null;
  }

  async count(field, value) {
    return this._idsFor(field, value).length;
  }

  async findRange(field, min, max, { limit = 0 } = {}) {
    if (!this.rangeFields.has(field) && !this.indexes.has(field)) {
      throw new Error(`[db] ${this.name}.${field} aralık sorgusuna açık değil (rangeBucket gerekir)`);
    }
    const lo = min == null ? -Infinity : toNumeric(min);
    const hi = max == null ? Infinity : toNumeric(max);
    const out = [];
    for (const [idStr, cur] of this.records) {
      const v = toNumeric(cur.record[field]);
      if (v == null || v < lo || v > hi) continue;
      out.push(this._decorate(idStr, cur.record));
    }
    out.sort((a, b) => (toNumeric(a[field]) - toNumeric(b[field])) || compareIdStr(String(a._id), String(b._id)));
    return limit ? out.slice(0, limit) : out;
  }

  async *scan({ limit = 0, after = null } = {}) {
    const ids = [...this.records.keys()].sort(compareIdStr);
    let yielded = 0;
    for (const idStr of ids) {
      if (after && compareIdStr(idStr, String(after)) <= 0) continue;
      const cur = this.records.get(idStr);
      if (!cur) continue;
      yield this._decorate(idStr, cur.record);
      if (limit && ++yielded >= limit) return;
    }
  }

  async all() {
    const out = [];
    for await (const rec of this.scan()) out.push(rec);
    return out;
  }

  /** Değişiklik akışı üzerine kurulu, ağ gerektirmeyen canlı görünüm. */
  watch() {
    const view = new EventEmitter();
    const map = new Map();
    for (const [idStr, cur] of this.records) map.set(idStr, this._decorate(idStr, cur.record));

    const onChange = (evt) => {
      if (evt.type === 'delete') map.delete(evt.id);
      else map.set(evt.id, evt.record);
      view.emit('change', evt);
    };
    this.db.changes.on(`change:${this.name}`, onChange);

    view.fresh = true;
    view.ready = async () => view;
    view.get = (id) => map.get(String(id)) || null;
    view.all = () => [...map.values()];
    view.size = () => map.size;
    view.close = () => { this.db.changes.off(`change:${this.name}`, onChange); };
    return view;
  }
}

function compareIdStr(a, b) {
  if (a.length !== b.length) return a.length - b.length;
  return a < b ? -1 : a > b ? 1 : 0;
}

class FileDatabase {
  constructor({ dir, rootSecret, logger, workerId = 0, syncIntervalMs = 250 }) {
    this.dir = dir;
    this.logger = logger;
    this.mode = 'file';
    const kek = hkdf(rootSecret, 'fitmail-file-kek');
    this.ddk = hkdf(kek, 'fitmail-file-ddk');
    this.collections = new Map();
    this.writes = new KeyedQueue();
    this.changes = new EventEmitter();
    this.changes.setMaxListeners(0);
    this.globalSeq = 0;
    this.collectionSeq = new Map();
    this.nextId = createIdGenerator(workerId);
    // Grup taahhüdü: her yazmada fsync, toplu gönderimde teslimatı bir
    // düzine kat yavaşlatır. Bunun yerine kısa bir pencerede biriktirip tek
    // fsync atıyoruz — çökme durumunda kaybedilebilecek pencere bu kadar ve
    // bu bilinçli bir takas.
    this.syncIntervalMs = syncIntervalMs;
    this._syncTimer = null;
    this._dirty = new Set();
  }

  _scheduleSync(collection) {
    this._dirty.add(collection);
    if (this._syncTimer) return;
    this._syncTimer = setTimeout(() => {
      this._syncTimer = null;
      const dirty = [...this._dirty];
      this._dirty.clear();
      for (const col of dirty) {
        if (col.fd) col.fd.sync().catch(() => {});
      }
    }, this.syncIntervalMs);
    if (this._syncTimer.unref) this._syncTimer.unref();
  }

  _emitChange(collectionName, event) {
    this.globalSeq++;
    const colSeq = (this.collectionSeq.get(collectionName) || 0) + 1;
    this.collectionSeq.set(collectionName, colSeq);
    const enriched = { ...event, collection: collectionName, seq: this.globalSeq, collectionSeq: colSeq };
    this.changes.emit(`change:${collectionName}`, enriched);
    this.changes.emit('change', enriched);
  }

  async defineCollection(name, schema) {
    let col = this.collections.get(name);
    if (col) return col.applySchema(schema);
    col = new FileCollection(this, name, schema);
    await col.load();
    this.collections.set(name, col);
    return { migrated: false, schemaVersion: 1 };
  }

  async applySchemaRegistry(registry) {
    // Hepsi ya da hiçbiri: önce tümü doğrulanır, sonra uygulanır. Yarım
    // uygulanmış bir şema, uygulamayı yarısı eski yarısı yeni bir yapıyla
    // baş başa bırakır.
    const results = {};
    for (const [name, schema] of Object.entries(registry)) {
      const existing = this.collections.get(name);
      if (existing) {
        const clone = new FileCollection(this, `${name}__dryrun`, existing.schema);
        clone.applySchema(schema); // uyumsuzluk burada patlar, yazma olmadan
      }
    }
    for (const [name, schema] of Object.entries(registry)) {
      results[name] = await this.defineCollection(name, schema);
    }
    return results;
  }

  collection(name) {
    const col = this.collections.get(name);
    if (!col) throw new Error(`[db] tanımsız koleksiyon: ${name}`);
    return col;
  }

  async snapshot() {
    // Sayaçlar taramadan ÖNCE okunur: sonra okumak, tarama sırasında düşen
    // bir yazmanın hem taramada görünmemesine hem de "uygulanmış" sayılmasına
    // yol açar ve izleyici o kaydı bir daha hiç görmez.
    const seq = this.globalSeq;
    const data = {};
    for (const [name, col] of this.collections) data[name] = await col.all();
    return { seq, data };
  }

  async close() {
    if (this._syncTimer) { clearTimeout(this._syncTimer); this._syncTimer = null; }
    for (const col of this.collections.values()) await col.close();
  }

  stats() {
    const out = { mode: 'file', dir: this.dir, globalSeq: this.globalSeq, collections: {} };
    for (const [name, col] of this.collections) {
      out.collections[name] = { records: col.records.size, bytes: col.bytesWritten };
    }
    return out;
  }
}

async function openFileDatabase({ dir, rootSecret, logger, workerId = 0 }) {
  if (!rootSecret || rootSecret.length < 32) {
    throw new Error('[db] dosya sürücüsü için en az 32 baytlık bir kök sır gerekir');
  }
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const db = new FileDatabase({ dir, rootSecret, logger, workerId });
  return db;
}

module.exports = { openFileDatabase, FileDatabase, FileCollection, VersionConflictError, createIdGenerator };
