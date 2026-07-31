'use strict';

const crypto = require('node:crypto');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  createContext, cleanupAll, TestRunner,
  assert, assertEqual, assertThrows,
} = require('./helpers');

const runner = new TestRunner('Sürücü şekilleri, kasa zarfı, PKCS#12');

/**
 * ── BU DOSYA NEYİ KORUYOR ────────────────────────────────────────────────
 *
 * Üretimde görülen iki hatanın da tek bir ortak kökü vardı: bir `bytes`
 * alanına yazılan değerin GERİ OKUNDUĞUNDA hangi JavaScript türüyle
 * geleceğinin sürücüye bağlı olması.
 *
 *   - Ekler base64 METNİ ve KESİK iniyordu (blob parçaları).
 *   - Giden posta "Unsupported state or unable to authenticate data" ile
 *     düşüyordu (kasadaki DKIM anahtarı).
 *
 * Dosya sürücüsü JSON üzerinden gittiği için bu şekil değişimini YAŞAMIYOR
 * ve testler bu yüzden yeşil kalıyordu; hata yalnızca gRPC sürücüsüyle,
 * yani yalnızca üretimde görünüyordu.
 *
 * Aşağıdaki `wrapCollection`, o sürücünün davranışını taklit ediyor:
 * `bytes` alanına yazılan bir DİZGE bayta çevriliyor, yazılan bir BUFFER ise
 * base64 dizgeye. İki dönüşüm de gerçek sürücülerde görülmüş şekiller ve
 * ikisinde de kod artık doğru okumak zorunda.
 */
const BYTES_FIELDS = { blob_chunks: ['bytes'], secrets: ['ciphertext'] };

function mangle(record, fields, mode) {
  const out = { ...record };
  for (const field of fields) {
    const value = out[field];
    if (value == null) continue;
    if (mode === 'string-to-bytes') {
      // gRPC sürücüsü: `bytes` alanına yazılan dizgeyi kodlar.
      out[field] = typeof value === 'string' ? Buffer.from(value, 'utf8') : value;
    } else if (mode === 'bytes-to-base64') {
      // JSON köprüsü: Buffer'ı base64 dizge olarak taşır.
      out[field] = Buffer.isBuffer(value) ? value.toString('base64') : value;
    }
  }
  return out;
}

function wrapCollection(collection, fields, mode) {
  const transform = (row) => (row ? mangle(row, fields, mode) : row);
  return {
    insert: (record) => collection.insert(record),
    update: (id, patch, opts) => collection.update(id, patch, opts),
    delete: (id) => collection.delete(id),
    get: async (id) => transform(await collection.get(id)),
    findOne: async (f, v) => transform(await collection.findOne(f, v)),
    find: async (f, v, o) => (await collection.find(f, v, o)).map(transform),
    findRange: async (f, min, max, o) => (await collection.findRange(f, min, max, o)).map(transform),
    count: (f, v) => collection.count(f, v),
    async* scan(o) { for await (const row of collection.scan(o)) yield transform(row); },
  };
}

function wrapDb(db, mode) {
  return {
    collection(name) {
      const inner = db.collection(name);
      const fields = BYTES_FIELDS[name];
      return fields ? wrapCollection(inner, fields, mode) : inner;
    },
  };
}

let ctx;
async function setup() { ctx = await createContext(); }

/* ── blob deposu: ek baytları ──────────────────────────────── */

for (const mode of ['string-to-bytes', 'bytes-to-base64', 'passthrough']) {
  runner.test(`blob: ${mode} sürücüsünde ek baytları bozulmadan döner`, async () => {
    const { BlobStore } = require('../src/db/blob-store');
    const store = new BlobStore(wrapDb(ctx.db, mode), { chunkBytes: 1024, logger: ctx.logger });

    // Sıkıştırılamayan veri seçildi ki parçalar ham yazılsın ve akış yolu
    // (readStream) da denensin — sıkıştırılmış blob'lar read() üzerinden
    // gidiyor ve farklı bir kod yolu.
    const payload = crypto.randomBytes(5000);
    const { blobId, totalBytes } = await store.write(payload, {
      kind: 'attachment', contentType: 'image/png',
    });
    assertEqual(totalBytes, payload.length, 'bildirilen boyut');

    const read = await store.read(blobId);
    assert(read.equals(payload), 'read() baytları aynı olmalı');

    const chunks = [];
    for await (const chunk of store.readStream(blobId)) {
      assert(Buffer.isBuffer(chunk), 'akış Buffer üretmeli (dizge yazmak gövdeyi keser)');
      chunks.push(chunk);
    }
    const streamed = Buffer.concat(chunks);
    // Bildirilen hata tam olarak buydu: akıtılan gövde base64 metniydi ve
    // `content-length` ham boyuta göre yazıldığı için tarayıcı kesiyordu.
    assertEqual(streamed.length, payload.length, 'akıtılan uzunluk content-length ile eşleşmeli');
    assert(streamed.equals(payload), 'akıtılan baytlar aynı olmalı');

    // Aralık isteği (video/pdf önizlemesi bunu kullanır).
    const rangeChunks = [];
    for await (const chunk of store.readStream(blobId, { start: 100, end: 199 })) rangeChunks.push(chunk);
    const ranged = Buffer.concat(rangeChunks);
    assertEqual(ranged.length, 100, 'aralık uzunluğu');
    assert(ranged.equals(payload.subarray(100, 200)), 'aralık içeriği');
  });
}

runner.test('blob: sıkıştırılan gövde de her sürücüde açılır', async () => {
  const { BlobStore } = require('../src/db/blob-store');
  for (const mode of ['string-to-bytes', 'bytes-to-base64', 'passthrough']) {
    const store = new BlobStore(wrapDb(ctx.db, mode), { chunkBytes: 1024, logger: ctx.logger });
    const text = Buffer.from('merhaba dünya '.repeat(2000), 'utf8'); // sıkıştırılabilir
    const { blobId } = await store.write(text, { kind: 'body', contentType: 'text/plain' });
    const back = await store.read(blobId);
    assert(back.equals(text), `${mode}: sıkıştırılmış gövde`);
  }
});

runner.test('blob: eski (ön eksiz base64) parçalar okunabilir kalır', async () => {
  // Üretimde hâlihazırda bu biçimde yazılmış veri var; onu taşımadan
  // okuyabilmek şart, aksi hâlde düzeltme mevcut ekleri erişilemez yapardı.
  const { BlobStore } = require('../src/db/blob-store');
  const store = new BlobStore(ctx.db, { chunkBytes: 1024, logger: ctx.logger });
  const payload = crypto.randomBytes(3000);

  const blobId = crypto.randomBytes(16).toString('hex');
  const now = Date.now();
  const chunkCount = Math.ceil(payload.length / 1024);
  for (let i = 0; i < chunkCount; i++) {
    const slice = payload.subarray(i * 1024, Math.min(payload.length, (i + 1) * 1024));
    // Eski biçim: ÖN EKSİZ base64 dizge.
    await ctx.db.collection('blob_chunks').insert({
      blobId, seq: i, bytes: slice.toString('base64'), createdAt: now,
    });
  }
  await ctx.db.collection('blobs').insert({
    blobId, kind: 'attachment', ownerRef: '', totalBytes: payload.length,
    chunkCount, sha256Hex: crypto.createHash('sha256').update(payload).digest('hex'),
    contentType: 'application/pdf', createdAt: now, expiresAt: 0, refCount: 1, compression: '',
  });

  const back = await store.read(blobId);
  assert(back.equals(payload), 'eski biçimdeki parçalar doğru çözülmeli');
});

/* ── kasa: sarma zarfı ─────────────────────────────────────── */

for (const mode of ['string-to-bytes', 'bytes-to-base64', 'passthrough']) {
  runner.test(`kasa: ${mode} sürücüsünde sır geri açılır`, async () => {
    const { KeyVault } = require('../src/db/vault');
    const secret = crypto.randomBytes(32);
    const vault = new KeyVault(wrapDb(ctx.db, mode), secret, { logger: ctx.logger });

    const pem = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
      .privateKey.export({ type: 'pkcs8', format: 'pem' });

    // `put` gidiş-dönüş denetimi yapıyor: sürücü baytları bozsaydı burası
    // patlardı ve hata aylar sonra gönderim yolunda değil BURADA görünürdü.
    const written = await vault.put({
      kind: 'dkim-key', name: `dkim/test-${mode}/mail`, value: pem,
      contentType: 'application/x-pem-file',
    });
    assertEqual(written.version, 1, 'ilk sürüm');

    const read = await vault.get('dkim-key', `dkim/test-${mode}/mail`);
    assert(read, 'sır geri okunmalı');
    assertEqual(read.value.toString('utf8'), pem, 'anahtar aynı dönmeli');

    const health = await vault.diagnose({ kinds: ['dkim-key'] });
    assertEqual(health.failed, 0, `açılamayan kayıt olmamalı: ${JSON.stringify(health.problems)}`);
  });
}

runner.test('kasa: yanlış kasa sırrı ANLAŞILIR bir hata verir', async () => {
  const { KeyVault } = require('../src/db/vault');
  const vault = new KeyVault(ctx.db, crypto.randomBytes(32), { logger: ctx.logger });
  await vault.put({ kind: 'token', name: 'rotasyon-testi', value: 'gizli-değer' });

  // Sırrı değiştirmek, "Unsupported state or unable to authenticate data"
  // yerine ne yapılması gerektiğini söyleyen bir hata üretmeli.
  const other = new KeyVault(ctx.db, crypto.randomBytes(32), { logger: ctx.logger });
  const err = await assertThrows(() => other.get('token', 'rotasyon-testi'));
  assertEqual(err.code, 'VAULT_KEY_MISMATCH', 'hata kodu ayırt edici olmalı');
  assert(/FITFAK_MAIL_VAULT_SECRET/.test(err.message), 'hata hangi ayarı işaret ettiğini söylemeli');
});

runner.test('imzalayıcı: açılamayan DKIM anahtarı gönderimi durdurmaz', async () => {
  // Kasadaki anahtar açılamıyorsa eskiden `signDkim` istisna atıyor ve
  // POST /send 500 dönüyordu — yani tek bir okunamayan kayıt yüzünden HİÇ
  // posta gitmiyordu.
  const domain = ctx.config.domains[0].name;
  const key = await ctx.signer.getDkimKey(domain);
  assert(key && key.privateKeyPem, 'anahtar hazırlanmalı');

  const name = `dkim/${domain}/${key.selector}`;
  const row = await ctx.stores.vault.collection.findOne('secretKey', `dkim-key|${name}|v${key.version}`);
  assert(row, 'kasa satırı bulunmalı');
  // Şifreli gövdeyi bozuyoruz: anahtar doğru, veri okunamaz.
  const broken = Buffer.from(require('../src/util/bytes').toBuffer(row.ciphertext));
  broken[broken.length - 1] ^= 0xff;
  await ctx.stores.vault.collection.update(String(row._id), { ciphertext: broken });
  ctx.signer.invalidate(null, domain);

  const raw = Buffer.from(
    `From: network@${domain}\r\nTo: a@example.com\r\nSubject: t\r\n\r\ngövde\r\n`, 'utf8',
  );
  const result = await ctx.signer.signDkim(raw, { fromAddress: `network@${domain}` });
  assert(result.rawMessage, 'ileti geri dönmeli (gönderim durmamalı)');
  // Bozuk sürüm işaretlenip yerine yenisi üretildiği için imza yeniden atılır.
  assert(result.signed || /alınamadı/.test(result.reason || ''), 'imza atılmalı ya da nedeni bildirilmeli');
});

/* ── SPF: DMARC hizalaması için alan adı ───────────────────── */

runner.test('SPF: redirect sonrası bile ZARF alanı döner (DMARC hizalaması)', async () => {
  const spf = require('../src/mail/spf');
  const dmarc = require('../src/mail/dmarc');

  // gmail.com'un gerçek yapısı: kayıt `redirect=_spf.google.com` diyor.
  const resolver = {
    resolveTxt: async (name) => {
      if (name === 'gmail.com') return [['v=spf1 redirect=_spf.google.com']];
      if (name === '_spf.google.com') return [['v=spf1 ip4:74.125.224.0/19 -all']];
      return [];
    },
    resolve4: async () => [],
    resolve6: async () => [],
    resolveMx: async () => [],
    reverse: async () => [],
  };

  const result = await spf.check({
    ip: '74.125.224.54', sender: 'aybarsyildirim.mail@gmail.com', heloDomain: 'mail-yx1-f54.google.com', resolver,
  });
  assertEqual(result.result, 'pass', 'SPF geçmeli');
  // Bildirilen hata: burası `_spf.google.com` dönüyordu ve DMARC hizalaması
  // hiçbir zaman tutmuyordu.
  assertEqual(result.domain, 'gmail.com', 'hizalama için ZARF alanı dönmeli');
  assertEqual(result.matchedDomain, '_spf.google.com', 'eşleşme yeri ayrıca taşınmalı');

  assert(dmarc.isAligned('gmail.com', result.domain, 'r'), 'DMARC hizalaması tutmalı');

  const header = dmarc.authenticationResultsHeader({
    hostname: 'mail.fitfak.net', spf: result,
  });
  assert(header.includes('smtp.mailfrom=gmail.com'), `başlık zarf alanını yazmalı: ${header}`);
});

runner.test('SPF: zarf boşken HELO kimliği bildirilir', async () => {
  const spf = require('../src/mail/spf');
  const resolver = {
    resolveTxt: async (name) => (name === 'bounce.example.com' ? [['v=spf1 ip4:198.51.100.7 -all']] : []),
    resolve4: async () => [], resolve6: async () => [], resolveMx: async () => [], reverse: async () => [],
  };
  const result = await spf.check({ ip: '198.51.100.7', sender: '', heloDomain: 'bounce.example.com', resolver });
  assertEqual(result.result, 'pass', 'HELO üzerinden geçmeli');
  assertEqual(result.identity, 'helo', 'kimlik HELO olmalı');
});

/* ── PKCS#12 ───────────────────────────────────────────────── */

function opensslAvailable() {
  try { return cp.spawnSync('openssl', ['version']).status === 0; }
  catch { return false; }
}

const OPENSSL = opensslAvailable();

runner.test('PKCS#12: üretilen .pfx kendi ayrıştırıcımızla açılır', async () => {
  if (!OPENSSL) return;
  const { PKCS12 } = require('../src/certs/pkcs12');
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const certPem = selfSignedCert(keyPem);

  const p12 = new PKCS12('parola-123');
  const der = p12.build(certPem, keyPem, { friendlyName: 'Test' });

  const parsed = new PKCS12('parola-123').parse(der);
  assertEqual(parsed.macVerified, true, 'MacData doğrulanmalı (Windows/macOS bunu şart koşuyor)');
  assertEqual(parsed.certificates.length, 1, 'sertifika sayısı');
  assertEqual(parsed.privateKeys.length, 1, 'anahtar sayısı');
  assertEqual(
    parsed.certificates[0].replace(/\s+/g, ''),
    certPem.replace(/\s+/g, ''),
    'sertifika aynı dönmeli',
  );
  assertEqual(
    crypto.createPrivateKey(parsed.privateKeys[0]).export({ type: 'pkcs8', format: 'der' }).toString('hex'),
    crypto.createPrivateKey(keyPem).export({ type: 'pkcs8', format: 'der' }).toString('hex'),
    'anahtar aynı dönmeli',
  );

  // Yanlış parola: bütünlük katmanı bunu içerik çözülmeden yakalamalı.
  const err = await assertThrows(() => new PKCS12('yanlis').parse(der));
  assert(/bütünlük/.test(err.message), `anlaşılır hata bekleniyordu: ${err.message}`);
});

runner.test('PKCS#12: OpenSSL üretilen dosyayı açabilmeli', async () => {
  if (!OPENSSL) return;
  const { PKCS12 } = require('../src/certs/pkcs12');
  const { privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const certPem = selfSignedCert(keyPem);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitmail-pfx-'));
  const file = path.join(dir, 'test.pfx');
  fs.writeFileSync(file, new PKCS12('parola-123').build(certPem, keyPem));

  const out = cp.spawnSync('openssl', ['pkcs12', '-in', file, '-passin', 'pass:parola-123', '-nodes', '-info'], {
    encoding: 'utf8',
  });
  fs.rmSync(dir, { recursive: true, force: true });

  // Bu, kullanıcının pfx.js'inde eksik olan iki şeyin (IMPLICIT [0] ve
  // MacData) gerçekten düzeldiğinin dışarıdan kanıtı.
  assertEqual(out.status, 0, `openssl dosyayı açamadı: ${out.stderr}`);
  assert(/BEGIN CERTIFICATE/.test(out.stdout), 'sertifika çıkmalı');
  assert(/BEGIN PRIVATE KEY/.test(out.stdout), 'anahtar çıkmalı');
  assert(/MAC/.test(out.stderr + out.stdout), 'MacData bulunmalı');
});

runner.test('PKCS#12: OpenSSL üretimi bizim ayrıştırıcımızla okunur', async () => {
  if (!OPENSSL) return;
  const { PKCS12 } = require('../src/certs/pkcs12');
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const certPem = selfSignedCert(keyPem);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitmail-pfx-'));
  const keyFile = path.join(dir, 'k.pem');
  const certFile = path.join(dir, 'c.pem');
  const pfxFile = path.join(dir, 'o.pfx');
  fs.writeFileSync(keyFile, keyPem);
  fs.writeFileSync(certFile, certPem);

  const made = cp.spawnSync('openssl', [
    'pkcs12', '-export', '-in', certFile, '-inkey', keyFile, '-out', pfxFile,
    '-passout', 'pass:parola-123', '-keypbe', 'AES-256-CBC', '-certpbe', 'AES-256-CBC',
  ], { encoding: 'utf8' });
  if (made.status !== 0) { fs.rmSync(dir, { recursive: true, force: true }); return; }

  const parsed = new PKCS12('parola-123').parse(fs.readFileSync(pfxFile));
  fs.rmSync(dir, { recursive: true, force: true });
  assertEqual(parsed.macVerified, true, 'OpenSSL MacData doğrulanmalı');
  assertEqual(parsed.certificates.length, 1, 'sertifika');
  assertEqual(parsed.privateKeys.length, 1, 'anahtar');
});

runner.test('PKCS#12: içe alım sertifikayı kutuya ve anahtara bağlar', async () => {
  if (!OPENSSL) return;
  const { matchCertificateToMailbox } = require('../src/http/api/webmail');
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const certPem = selfSignedCert(keyPem, 'network@fitfak.net');

  const ok = matchCertificateToMailbox(
    { certificates: [certPem], privateKeys: [keyPem] }, 'network@fitfak.net',
  );
  assert(ok.ok, `eşleşmeliydi: ${ok.reason}`);

  // Başka bir adres: kabul edilirse o kutunun adına imza atılabilir.
  const wrongBox = matchCertificateToMailbox(
    { certificates: [certPem], privateKeys: [keyPem] }, 'baskasi@fitfak.net',
  );
  assert(!wrongBox.ok, 'yabancı adres reddedilmeli');
  assertEqual(wrongBox.code, 'PFX_ADDRESS_MISMATCH', 'hata kodu');

  // Sertifikaya ait olmayan bir anahtar: uyuşmazlık ilk imzalamada değil
  // ŞİMDİ yakalanmalı.
  const otherKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'pem' });
  const wrongKey = matchCertificateToMailbox(
    { certificates: [certPem], privateKeys: [otherKey] }, 'network@fitfak.net',
  );
  assert(!wrongKey.ok, 'yabancı anahtar reddedilmeli');
  assertEqual(wrongKey.code, 'PFX_KEY_MISMATCH', 'hata kodu');
});

/** Testler için kendinden imzalı sertifika (openssl varsa ondan). */
function selfSignedCert(keyPem, email = 'test@fitfak.net') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fitmail-cert-'));
  const keyFile = path.join(dir, 'k.pem');
  const certFile = path.join(dir, 'c.pem');
  fs.writeFileSync(keyFile, keyPem);
  const res = cp.spawnSync('openssl', [
    'req', '-x509', '-new', '-key', keyFile, '-out', certFile, '-days', '30',
    '-subj', `/CN=Test/emailAddress=${email}`,
    '-addext', `subjectAltName=email:${email}`,
  ], { encoding: 'utf8' });
  const pem = res.status === 0 ? fs.readFileSync(certFile, 'utf8') : null;
  fs.rmSync(dir, { recursive: true, force: true });
  if (!pem) throw new Error(`test sertifikası üretilemedi: ${res.stderr}`);
  return pem;
}

(async () => {
  try {
    await setup();
    if (!OPENSSL) {
      process.stdout.write('  (openssl yok — sertifika gerektiren denetimler atlandı)\n');
    }
    const ok = await runner.run();
    await ctx.close();
    await cleanupAll();
    process.exit(ok ? 0 : 1);
  } catch (err) {
    process.stderr.write(`kurulum hatası: ${err.stack}\n`);
    if (ctx) await ctx.close().catch(() => {});
    await cleanupAll();
    process.exit(1);
  }
})();
