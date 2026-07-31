'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');

// @fitfak/database sürücüsü: gömülü motor ya da mTLS üzerinden uzak sunucu.
//
// Uzak durumda yumurta-tavuk sorunu vardır ve çözümü paketin kendi
// belgelediği sıradır: bootstrap TLS -> güven çıpaları -> enrolment -> mTLS.
// Buradaki tek katkı, o sırayı posta sunucusunun yaşam döngüsüne bağlamak ve
// iki dosyayı (kimlik + veritabanı tutamağı) 0600 ile, temp+rename ile
// saklamak.
//
// Veritabanı tutamağındaki `clientSecret` sunucuda SAKLANMAZ; oluşturma
// anında bir kez döner. O dosya kaybolursa veri de kaybolur — bu yüzden sır
// önce yazılır, sonra kullanılır: aradaki bir çökme, açılamayan bir
// veritabanı bırakırdı.

const IDENTITY_FILE = 'identity.json';
const DB_HANDLE_FILE = 'database.json';

function loadPackage() {
  try { return require('@fitfak/database'); }
  catch (err) {
    const e = new Error(
      '[db] @fitfak/database yüklü değil. Ya paketi kurun (npm run link:database) '
      + 'ya da FITFAK_MAIL_DB_DRIVER=file ile dosya sürücüsünü kullanın.',
    );
    e.cause = err;
    throw e;
  }
}

async function writeSecretFile(dir, name, payload) {
  await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = path.join(dir, name);
  const tmp = `${file}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(payload, null, 2), { mode: 0o600 });
  await fsp.rename(tmp, file);
}

async function readJsonFile(dir, name) {
  try { return JSON.parse(await fsp.readFile(path.join(dir, name), 'utf8')); }
  catch { return null; }
}

async function loadStoredIdentity(dir) {
  const stored = await readJsonFile(dir, IDENTITY_FILE);
  if (!stored || !stored.certPem || !stored.privateKeyPem) return null;
  try {
    // Süresi dolmuş sertifikayla bağlanmayı denemek, anlaşılması zor bir TLS
    // hatası verir. Burada erken fark edip yeniden enrolment yolu daha okunur.
    const cert = new crypto.X509Certificate(stored.certPem);
    const notAfter = new Date(cert.validTo).getTime();
    if (Number.isFinite(notAfter) && notAfter < Date.now() + 60_000) return null;
  } catch { return null; }
  return stored;
}

/**
 * @fitfak/database koleksiyonunu, dosya sürücüsüyle aynı yüzeye getirir.
 * Üst katmanlar hangi sürücüde olduklarını bilmez; bu yüzden eksik olan
 * birkaç yardımcı (count, all) burada tamamlanır.
 */
class FitfakCollection {
  constructor(inner, name, schema, hub) {
    this.inner = inner;
    this.name = name;
    this.schema = schema;
    this.hub = hub;
    this.fields = new Map((schema.fields || []).map((f) => [f.name, f]));
  }

  async insert(record) {
    const id = await this.inner.insert(record);
    const idStr = String(id);
    this.hub.emitLocal(this.name, { type: 'insert', id: idStr, record: { ...record, _id: BigInt(idStr) } });
    return idStr;
  }

  async update(id, patch, opts = {}) {
    const res = await this.inner.update(String(id), patch, opts);
    this.hub.emitLocal(this.name, { type: 'update', id: String(id), record: null });
    return res || { version: null };
  }

  async delete(id) {
    if (typeof this.inner.delete === 'function') await this.inner.delete(String(id));
    else if (typeof this.inner.remove === 'function') await this.inner.remove(String(id));
    else throw new Error(`[db] ${this.name}: silme desteklenmiyor`);
    this.hub.emitLocal(this.name, { type: 'delete', id: String(id) });
    return true;
  }

  async get(id) {
    if (typeof this.inner.get === 'function') return this.inner.get(String(id));
    return this.inner.findOne('_id', String(id));
  }

  async getWithVersion(id) {
    const record = await this.get(id);
    if (!record) return null;
    // Motor sürümü kayıt üstünde taşımıyorsa iyimser kilit kullanılamaz;
    // bunu gizlemek yerine null döndürüyoruz, çağıran karar verir.
    return { record, version: record._version != null ? Number(record._version) : null };
  }

  async find(field, value, { limit = 0 } = {}) {
    const out = await this.inner.find(field, value);
    const list = Array.isArray(out) ? out : [];
    return limit ? list.slice(0, limit) : list;
  }

  async findOne(field, value) {
    if (typeof this.inner.findOne === 'function') return this.inner.findOne(field, value);
    const list = await this.find(field, value, { limit: 1 });
    return list[0] || null;
  }

  async count(field, value) {
    const list = await this.find(field, value);
    return list.length;
  }

  async findRange(field, min, max, { limit = 0 } = {}) {
    const out = await this.inner.findRange(field, min, max);
    const list = Array.isArray(out) ? out : [];
    return limit ? list.slice(0, limit) : list;
  }

  async *scan(opts = {}) {
    let count = 0;
    for await (const rec of this.inner.scan(opts)) {
      yield rec;
      if (opts.limit && ++count >= opts.limit) return;
    }
  }

  async all() {
    const out = [];
    for await (const rec of this.scan()) out.push(rec);
    return out;
  }

  watch() {
    if (typeof this.inner.watch !== 'function') {
      throw new Error(`[db] ${this.name}: bu sürücüde watch() yok`);
    }
    return this.inner.watch();
  }
}

class FitfakDatabase {
  constructor({ db, handle, identity, manager, mode, logger }) {
    this.inner = db;
    this.handle = handle;
    this.identity = identity;
    this.manager = manager;
    this.mode = mode; // 'embedded' | 'mtls'
    this.logger = logger;
    this.collections = new Map();
    this.changes = new EventEmitter();
    this.changes.setMaxListeners(0);
    this.globalSeq = 0;
    this.collectionSeq = new Map();
  }

  emitLocal(collectionName, event) {
    this.globalSeq++;
    const colSeq = (this.collectionSeq.get(collectionName) || 0) + 1;
    this.collectionSeq.set(collectionName, colSeq);
    const enriched = { ...event, collection: collectionName, seq: this.globalSeq, collectionSeq: colSeq };
    this.changes.emit(`change:${collectionName}`, enriched);
    this.changes.emit('change', enriched);
  }

  async defineCollection(name, schema) {
    const res = await this.inner.defineCollection(name, schema);
    this.collections.set(name, new FitfakCollection(this.inner.collection(name), name, schema, this));
    return res;
  }

  async applySchemaRegistry(registry) {
    // Motorun kendi hepsi-ya-hiçbiri uygulamasını kullanıyoruz: her koleksiyon
    // önce denetlenir, bir ret bütün kümeyi engeller.
    let res = null;
    if (typeof this.inner.applySchemaRegistry === 'function') {
      res = await this.inner.applySchemaRegistry(registry);
      for (const [name, schema] of Object.entries(registry)) {
        this.collections.set(name, new FitfakCollection(this.inner.collection(name), name, schema, this));
      }
    } else {
      res = {};
      for (const [name, schema] of Object.entries(registry)) res[name] = await this.defineCollection(name, schema);
    }
    return res;
  }

  collection(name) {
    const col = this.collections.get(name);
    if (!col) throw new Error(`[db] tanımsız koleksiyon: ${name}`);
    return col;
  }

  async snapshot() {
    if (typeof this.inner.snapshot === 'function') return this.inner.snapshot();
    const seq = this.globalSeq;
    const data = {};
    for (const [name, col] of this.collections) data[name] = await col.all();
    return { seq, data };
  }

  async close() {
    try { if (this.identity && typeof this.identity.stopAutoRenewal === 'function') this.identity.stopAutoRenewal(); } catch { /* yok say */ }
    try { if (this.handle && typeof this.handle.close === 'function') await this.handle.close(); } catch { /* yok say */ }
    try { if (this.manager && typeof this.manager.close === 'function') await this.manager.close(); } catch { /* yok say */ }
  }

  stats() {
    return { mode: this.mode, globalSeq: this.globalSeq, principal: this.identity ? this.identity.principal : null };
  }
}

/* ── gömülü motor ─────────────────────────────────────────── */

async function openEmbedded({ config, logger }) {
  const pkg = loadPackage();
  const { DatabaseManager, ClientSecretKeyProvider, SnowflakeGenerator } = pkg;
  const dbCfg = config.db;
  const rootSecret = dbCfg.rootSecret;
  if (!rootSecret) throw new Error('[db] gömülü motor için FITFAK_MAIL_DB_ROOT_SECRET gerekir');

  const snowflake = new SnowflakeGenerator({ workerId: dbCfg.snowflakeWorkerId });
  const manager = new DatabaseManager({ baseDir: dbCfg.dataDir, snowflake });
  const keyProvider = new ClientSecretKeyProvider(rootSecret);

  await fsp.mkdir(dbCfg.dataDir, { recursive: true, mode: 0o700 });
  const dbIdFile = path.join(dbCfg.dataDir, 'mail_db_id.txt');
  const dbId = dbCfg.dbId || (fs.existsSync(dbIdFile) ? fs.readFileSync(dbIdFile, 'utf8').trim() : null);

  if (dbId) {
    const db = await manager.openDatabase({
      ownerId: dbCfg.ownerId, dbId, requesterId: dbCfg.ownerId, keyProvider,
    });
    logger.info({ mode: 'embedded', dbId, msg: 'veritabanı açıldı' });
    return new FitfakDatabase({ db, manager, mode: 'embedded', logger });
  }

  const created = await manager.createDatabase({ ownerId: dbCfg.ownerId, name: 'mail', keyProvider });
  await fsp.writeFile(dbIdFile, created.dbId, { mode: 0o600 });
  logger.warn({ mode: 'embedded', dbId: created.dbId, msg: 'yeni veritabanı oluşturuldu' });
  return new FitfakDatabase({ db: created.db, manager, mode: 'embedded', logger });
}

/* ── uzak sunucu: TLS -> enrolment -> mTLS ────────────────── */

async function openRemote({ config, logger }) {
  const pkg = loadPackage();
  const { enroll, resume, connectDatabase, createFitfakSslCsrProvider } = pkg;
  const dbCfg = config.db;

  let csrProvider;
  try {
    // @fitfak/ssl varsa onun CSR sağlayıcısı; yoksa kendi PKCS#10
    // üreticimiz. İkincisi, tek bir paketin eksikliğinin sistemi
    // başlatılamaz hâle getirmemesi için var.
    const ssl = require('@fitfak/ssl');
    csrProvider = createFitfakSslCsrProvider({ ssl });
  } catch {
    csrProvider = require('../certs/csr').createLocalCsrProvider();
    logger.warn({ msg: '@fitfak/ssl yok; yerel CSR üreticisi kullanılıyor' });
  }

  const trust = {};
  if (dbCfg.caPath) trust.caPem = await fsp.readFile(dbCfg.caPath, 'utf8');
  else if (dbCfg.caFingerprint) trust.pinnedFingerprints = [dbCfg.caFingerprint];
  else {
    // Buraya düşmek, sunucuyu doğrulamadan enrolment yapmak demektir: o
    // kanala verilecek tek kullanımlık sır, araya giren birine verilir.
    throw new Error(
      '[db] Veritabanı sunucusunu doğrulayacak güven çıpası yok '
      + '(FITFAK_MAIL_DB_CA_PATH ya da FITFAK_MAIL_DB_CA_FINGERPRINT gerekli).',
    );
  }

  const stored = await loadStoredIdentity(dbCfg.identityDir);
  let identity;
  if (stored) {
    logger.info({ msg: 'kayıtlı mTLS kimliği bulundu, enrolment atlanıyor' });
    identity = await resume({
      target: dbCfg.remoteTarget,
      certPem: stored.certPem,
      privateKeyPem: stored.privateKeyPem,
      chainPem: stored.chainPem,
      principal: stored.principal,
      roles: stored.roles,
      notAfter: stored.notAfter,
      renewAfter: stored.renewAfter,
      csrProvider,
      logger: { info: (m) => logger.info({ msg: m }) },
    });
  } else {
    if (!dbCfg.enrolmentSecret) {
      throw new Error(
        '[db] mTLS kimliği yok ve FITFAK_MAIL_DB_ENROLMENT_SECRET verilmemiş.\n'
        + '  İlk çalıştırmada posta sunucusu kendini veritabanına tanıtacak tek kullanımlık bir sırra ihtiyaç duyar.',
      );
    }
    logger.info({ msg: 'mTLS kimliği yok — enrolment yapılıyor (TLS -> enrol -> mTLS)' });
    identity = await enroll({
      target: dbCfg.remoteTarget,
      serviceName: dbCfg.serviceName,
      csrProvider,
      trust,
      bootstrap: { secret: Buffer.from(dbCfg.enrolmentSecret, 'base64') },
      altNames: [dbCfg.serviceName, config.hostname],
      logger: { info: (m) => logger.info({ msg: m }), warn: (m) => logger.warn({ msg: m }) },
    });
    await writeSecretFile(dbCfg.identityDir, IDENTITY_FILE, {
      certPem: identity.certPem, privateKeyPem: identity.privateKeyPem, chainPem: identity.chainPem,
      principal: identity.principal, roles: identity.roles,
      notAfter: identity.notAfter, renewAfter: identity.renewAfter,
    });
    logger.warn({ msg: 'enrolment tamamlandı; paylaşılan sır TÜKENDİ, ortamdan kaldırılabilir', principal: identity.principal });
  }

  identity.startAutoRenewal();
  identity.on('renewed', async (e) => {
    await writeSecretFile(dbCfg.identityDir, IDENTITY_FILE, {
      certPem: identity.certPem, privateKeyPem: identity.privateKeyPem, chainPem: identity.chainPem,
      principal: identity.principal, roles: identity.roles,
      notAfter: e.notAfter, renewAfter: e.renewAfter,
    });
    logger.info({ msg: 'sertifika yenilendi', notAfter: new Date(e.notAfter).toISOString() });
  });

  const handle = await connectDatabase({ target: dbCfg.remoteTarget, identity });

  const storedHandle = await readJsonFile(dbCfg.identityDir, DB_HANDLE_FILE);
  let db;
  if (storedHandle && storedHandle.dbId && storedHandle.clientSecret) {
    db = await handle.openDatabase({ dbId: storedHandle.dbId, clientSecret: storedHandle.clientSecret });
    logger.info({ msg: 'veritabanı açıldı', dbId: storedHandle.dbId });
  } else if (dbCfg.dbId && dbCfg.rootSecret) {
    const clientSecret = dbCfg.rootSecret.toString('base64');
    db = await handle.openDatabase({ dbId: dbCfg.dbId, clientSecret });
    await writeSecretFile(dbCfg.identityDir, DB_HANDLE_FILE, { dbId: dbCfg.dbId, clientSecret });
  } else {
    const created = await handle.createDatabase('posta');
    // Sır ÖNCE saklanır, sonra kullanılır.
    await writeSecretFile(dbCfg.identityDir, DB_HANDLE_FILE, {
      dbId: created.dbId, clientSecret: created.clientSecret,
    });
    logger.warn({
      dbId: created.dbId,
      file: path.join(dbCfg.identityDir, DB_HANDLE_FILE),
      msg: 'yeni veritabanı oluşturuldu — erişim sırrı bu dosyada (0600); kaybolursa veritabanı AÇILAMAZ, yedekleyin',
    });
    db = await handle.openDatabase({ dbId: created.dbId, clientSecret: created.clientSecret });
  }

  return new FitfakDatabase({ db, handle, identity, mode: 'mtls', logger });
}

async function openFitfakDatabase({ config, logger }) {
  return config.db.remoteTarget ? openRemote({ config, logger }) : openEmbedded({ config, logger });
}

function isAvailable() {
  try { require.resolve('@fitfak/database'); return true; }
  catch { return false; }
}

module.exports = { openFitfakDatabase, isAvailable, FitfakDatabase, FitfakCollection };
