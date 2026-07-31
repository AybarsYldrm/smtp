'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const fsp = require('node:fs/promises');

const schemaRegistry = require('./schema');
const log = require('../util/log');

/**
 * Veritabanı bağlantısının tek giriş noktası.
 *
 * Sürücü seçimi:
 *   fitfak  — @fitfak/database (gömülü ya da mTLS/gRPC ile uzak)
 *   file    — şifreli yerel dosya sürücüsü
 *   auto    — @fitfak/database varsa o, yoksa file
 *
 * Üst katmanların tamamı yalnızca döndürülen yüzeye bakar. Bu, "veritabanına
 * nasıl bağlanılıyor" sorusunun cevabını tek dosyada tutar; bir depo
 * (repository) dosyasında gRPC ayrıntısı görmek, o dosyanın iki sürücüden
 * birinde sessizce çalışmayacağı anlamına gelirdi.
 */

const DEV_SECRET_FILE = 'dev-root-secret';

async function resolveRootSecret(config, logger) {
  if (config.db.rootSecret) return config.db.rootSecret;
  if (config.isProd) {
    throw new Error('[db] Üretimde FITFAK_MAIL_DB_ROOT_SECRET zorunludur.');
  }
  // Geliştirmede sır üretilip diske yazılır. Her açılışta rastgele üretmek,
  // önceki çalıştırmanın verisini okunamaz yapar ve bunu "veri kaybı" olarak
  // değil "boş veritabanı" olarak gösterir — bulunması en zor hata türü.
  const file = path.join(config.dataDir, DEV_SECRET_FILE);
  try {
    const existing = await fsp.readFile(file);
    if (existing.length >= 32) return existing;
  } catch { /* yok, üretilecek */ }
  const generated = crypto.randomBytes(48);
  await fsp.mkdir(config.dataDir, { recursive: true, mode: 0o700 });
  await fsp.writeFile(file, generated, { mode: 0o600 });
  logger.warn({ file, msg: 'geliştirme kök sırrı üretildi — üretimde FITFAK_MAIL_DB_ROOT_SECRET verin' });
  return generated;
}

/**
 * @param {object} config
 * @param {object} [opts]
 * @param {boolean} [opts.applySchema=true]
 * @returns {Promise<object>} sürücü bağımsız veritabanı yüzeyi
 */
async function connect(config, { applySchema = true, logger = log.child('db') } = {}) {
  const requested = config.db.driver || 'auto';
  const fitfakDriver = require('./driver-fitfak');

  let driver = requested;
  if (requested === 'auto') {
    driver = fitfakDriver.isAvailable() ? 'fitfak' : 'file';
    if (driver === 'file') {
      logger.warn({ msg: '@fitfak/database bulunamadı; şifreli dosya sürücüsü kullanılıyor (tek süreç)' });
    }
  }

  let db;
  if (driver === 'fitfak') {
    db = await fitfakDriver.openFitfakDatabase({ config, logger });
  } else if (driver === 'file') {
    const { openFileDatabase } = require('./driver-file');
    const rootSecret = await resolveRootSecret(config, logger);
    db = await openFileDatabase({
      dir: config.db.dataDir,
      rootSecret,
      logger,
      workerId: config.db.snowflakeWorkerId,
    });
    logger.info({ mode: 'file', dir: config.db.dataDir, msg: 'veritabanı açıldı' });
  } else {
    throw new Error(`[db] bilinmeyen sürücü: ${driver}`);
  }

  if (applySchema) {
    const result = await db.applySchemaRegistry(schemaRegistry);
    const migrated = Object.entries(result || {})
      .filter(([, r]) => r && (r.migrated || r.indexesRebuilt))
      .map(([name]) => name);
    if (migrated.length) logger.warn({ collections: migrated.join(','), msg: 'şema göçü uygulandı' });
  }

  db.schemaRegistry = schemaRegistry;
  return db;
}

module.exports = { connect, schemaRegistry };
