#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const readline = require('node:readline');

/**
 * fitfak-mail-cert — cihaz kodu akışıyla S/MIME sertifikası alır.
 *
 * Bu, kullanıcı tarafındaki yol: özel anahtar BU MAKİNEDE üretilir ve burada
 * kalır. Sunucuya yalnızca CSR (açık anahtar + istek) gider, geri sertifika
 * (yine açık veri) gelir. Sunucu bu anahtarla imzalayamaz — imzalamayı
 * kullanıcının posta istemcisi yapar.
 *
 * Kullanım:
 *   fitfak-mail-cert issue --address network@fitfak.net [--out ./certs]
 *   fitfak-mail-cert bootstrap        # servis için yenileme jetonu kaydeder
 *   fitfak-mail-cert register --address a@b --cert ./sign.crt
 */

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith('--')) {
      const eq = token.indexOf('=');
      if (eq > 0) out[token.slice(2, eq)] = token.slice(eq + 1);
      else if (argv[i + 1] && !argv[i + 1].startsWith('--')) out[token.slice(2)] = argv[++i];
      else out[token.slice(2)] = true;
    } else out._.push(token);
  }
  return out;
}

function print(msg) { process.stdout.write(`${msg}\n`); }
function fail(msg, code = 1) { process.stderr.write(`hata: ${msg}\n`); process.exit(code); }

async function confirm(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question(`${question} [e/H] `, resolve));
  rl.close();
  return /^(e|evet|y|yes)$/i.test(answer.trim());
}

/** Cihaz kodu akışını yürütür ve jetonları döndürür. */
async function deviceLogin({ idp, scopes, clientId }) {
  const start = await idp.startDeviceAuthorization({ scopes, clientId });

  print('');
  print('══════════════════════════════════════════════════════════');
  print(' Tarayıcıda şu adresi açın:');
  print(`   ${start.verificationUriComplete || start.verificationUri}`);
  if (!start.verificationUriComplete) {
    print('');
    print(` Eşleştirme kodu: ${start.userCode}`);
  }
  print('══════════════════════════════════════════════════════════');
  print('');
  process.stdout.write(' Onay bekleniyor');

  const keepAlive = setInterval(() => {}, 1000);

  let tokens;
  try {
    tokens = await idp.pollDeviceToken({
      deviceCode: start.deviceCode,
      interval: start.interval,
      expiresIn: start.expiresIn,
      clientId,
      onPending: () => process.stdout.write('.'),
    });
  } finally {
    // İşlem bitince (veya hata verince) zamanlayıcıyı temizliyoruz
    clearInterval(keepAlive);
  }
  print(' onaylandı.');
  return tokens;
}

function loadConfig() {
  // CLI, sunucu yapılandırmasını okur ama sunucu sırlarına ihtiyaç duymaz:
  // üretim doğrulaması burada çalıştırılmıyor.
  process.env.FITFAK_MAIL_VAULT_SECRET = process.env.FITFAK_MAIL_VAULT_SECRET
    || require('node:crypto').randomBytes(32).toString('base64');
  return require('../src/config');
}

async function commandIssue(args) {
  const config = loadConfig();
  const address = String(args.address || '').trim().toLowerCase();
  if (!address.includes('@')) fail('--address bir posta adresi olmalı');

  const { IdpClient } = require('../src/auth/idp-client');
  const { createSmimeRequest, isAvailable } = require('../src/certs/csr');
  if (!isAvailable()) fail('@fitfak/ssl bulunamadı — npm run link:deps');

  const clientId = args['client-id'] || config.idp.deviceClientId || config.idp.clientId;
  if (!clientId) fail('istemci kimliği yok (--client-id ya da FITFAK_MAIL_DEVICE_CLIENT_ID)');

  const idp = new IdpClient({
    baseUrl: args.idp || config.idp.baseUrl,
    clientId,
    clientSecret: '', // cihaz akışında genel istemci: sır yok
    scopes: ['openid', 'profile', 'email', 'cert:issue'],
    config,
  });

  print(`Anahtar üretiliyor (${args.algorithm || 'ec P-256'})…`);
  const request = createSmimeRequest({
    address,
    displayName: args.name || address,
    algorithm: args.algorithm === 'rsa' ? 'rsa' : 'ec',
  });

  const tokens = await deviceLogin({
    idp,
    scopes: ['openid', 'profile', 'email', 'cert:issue'],
    clientId,
  });

  // Jetonun sahibi ile istenen adres uyuşmuyorsa uyarılır: sertifika
  // sunucusu zaten reddedecek, ama sebebi burada söylemek daha anlaşılır.
  try {
    const profile = IdpClient.normalizeProfile(await idp.userinfo(tokens.accessToken));
    if (profile.email && profile.email !== address) {
      print(`uyarı: giriş yapan kimlik ${profile.email}, istenen adres ${address}`);
      print('       sertifika sunucusu bu isteği reddedebilir (yetkiniz yoksa).');
    }
  } catch { /* userinfo yoksa devam */ }

  print('Sertifika isteği gönderiliyor…');
  const { CertificateManager } = require('../src/certs/manager');
  const manager = new CertificateManager({
    config,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    stores: null,
  });
  const issued = await manager.requestCertificate({
    csrPem: request.csrPem,
    profile: args.profile || config.trust.smimeProfile,
    accessToken: tokens.accessToken,
    path: config.trust.devicePath,
    extra: { subjectAddress: address },
  }).catch((err) => fail(err.message));

  const outDir = path.resolve(args.out || path.join(process.cwd(), 'certs', address.replace(/[^a-z0-9]+/gi, '_')));
  await fsp.mkdir(outDir, { recursive: true, mode: 0o700 });
  // Özel anahtar 0600: aynı makinedeki başka bir kullanıcının okuyabilmesi,
  // anahtarı üretmenin bütün amacını ortadan kaldırır.
  await fsp.writeFile(path.join(outDir, 'smime.key'), request.privateKeyPem, { mode: 0o600 });
  await fsp.writeFile(path.join(outDir, 'smime.crt'), issued.certPem, { mode: 0o644 });
  if (issued.chainPem) await fsp.writeFile(path.join(outDir, 'chain.pem'), issued.chainPem, { mode: 0o644 });
  await fsp.writeFile(path.join(outDir, 'request.csr'), request.csrPem, { mode: 0o644 });

  const crypto = require('node:crypto');
  const x509 = new crypto.X509Certificate(issued.certPem);
  print('');
  print('Sertifika alındı:');
  print(`  konu       : ${String(x509.subject).replace(/\n/g, ', ')}`);
  print(`  veren      : ${String(x509.issuer).replace(/\n/g, ', ')}`);
  print(`  geçerlilik : ${x509.validFrom} — ${x509.validTo}`);
  print(`  SAN        : ${x509.subjectAltName || '(yok)'}`);
  print(`  parmak izi : ${x509.fingerprint256}`);
  print('');
  print(`Dosyalar: ${outDir}`);
  print('  smime.key  (özel anahtar — 0600, paylaşmayın)');
  print('  smime.crt  (sertifika)');
  print('');
  print('Posta istemcinize eklemek için PKCS#12 üretmek isterseniz:');
  print(`  openssl pkcs12 -export -inkey ${path.join(outDir, 'smime.key')} \\`);
  print(`    -in ${path.join(outDir, 'smime.crt')} -out ${path.join(outDir, 'smime.p12')}`);
}

async function commandBootstrap(args) {
  const config = loadConfig();
  const { IdpClient } = require('../src/auth/idp-client');
  const clientId = args['client-id'] || config.idp.deviceClientId || config.idp.clientId;
  if (!clientId) fail('istemci kimliği yok');

  const idp = new IdpClient({
    baseUrl: args.idp || config.idp.baseUrl,
    clientId,
    clientSecret: config.idp.clientSecret || '',
    scopes: ['openid', 'cert:issue', 'offline_access'],
    config,
  });

  print('Sunucunun sertifika verme yetkisi için bir yenileme jetonu alınacak.');
  print('Bu jeton kasaya yazılır ve sunucu, posta kutuları adına sertifika');
  print('isterken onu kullanır.');
  if (!args.yes && !(await confirm('Devam edilsin mi?'))) { print('iptal edildi.'); return; }

  const tokens = await deviceLogin({ idp, scopes: ['openid', 'cert:issue', 'offline_access'], clientId });
  if (!tokens.refreshToken) {
    fail('IdP yenileme jetonu döndürmedi — "offline_access" kapsamı isteniyor mu?');
  }

  const { connect } = require('../src/db');
  const { createStores } = require('../src/db/repos');
  const log = require('../src/util/log');
  const logger = log.child('cert-cli');
  if (!process.env.FITFAK_MAIL_VAULT_SECRET) {
    fail('FITFAK_MAIL_VAULT_SECRET verilmeli: jeton sunucunun kasasına yazılacak');
  }
  const db = await connect(config, { logger });
  const stores = createStores(db, { config, logger });
  const { ServiceTokenProvider } = require('../src/auth/service-token');
  const provider = new ServiceTokenProvider({ idp, vault: stores.vault, logger });
  await provider.storeRefreshToken(tokens.refreshToken);
  await db.close();

  print('');
  print('Yenileme jetonu kasaya yazıldı. Sunucu bundan sonra kendi başına');
  print('sertifika isteyebilir.');
}

async function commandRegister(args) {
  const config = loadConfig();
  const address = String(args.address || '').trim().toLowerCase();
  const certPath = args.cert;
  if (!address.includes('@')) fail('--address gerekli');
  if (!certPath || !fs.existsSync(certPath)) fail('--cert bir sertifika dosyası olmalı');
  if (!process.env.FITFAK_MAIL_VAULT_SECRET) fail('FITFAK_MAIL_VAULT_SECRET gerekli');

  const { connect } = require('../src/db');
  const { createStores } = require('../src/db/repos');
  const log = require('../src/util/log');
  const logger = log.child('cert-cli');
  const db = await connect(config, { logger });
  const stores = createStores(db, { config, logger });
  const { CertificateManager } = require('../src/certs/manager');
  const manager = new CertificateManager({ config, logger, stores });

  const result = await manager.registerUserCertificate({
    address,
    certPem: await fsp.readFile(certPath, 'utf8'),
    chainPem: args.chain && fs.existsSync(args.chain) ? await fsp.readFile(args.chain, 'utf8') : '',
    requestedBySub: args.actor || 'cli',
  }).catch((err) => fail(err.message));

  await db.close();
  print(`kaydedildi: sürüm ${result.version}, geçerlilik sonu ${new Date(result.notAfter).toISOString()}`);
  print('not: özel anahtar sunucuya alınmadı; imzalama istemcinizde yapılır.');
}

async function commandStatus() {
  const config = loadConfig();
  if (!process.env.FITFAK_MAIL_VAULT_SECRET) fail('FITFAK_MAIL_VAULT_SECRET gerekli');
  const { connect } = require('../src/db');
  const { createStores } = require('../src/db/repos');
  const log = require('../src/util/log');
  const logger = log.child('cert-cli');
  const db = await connect(config, { logger });
  const stores = createStores(db, { config, logger });
  const { CertificateManager } = require('../src/certs/manager');
  const manager = new CertificateManager({ config, logger, stores });
  const status = await manager.status();
  await db.close();
  print(JSON.stringify(status, null, 2));
}

function usage() {
  print('fitfak-mail-cert <komut> [seçenekler]');
  print('');
  print('Komutlar:');
  print('  issue      --address <eposta> [--out <dizin>] [--algorithm ec|rsa]');
  print('             Cihaz kodu ile giriş yapar ve S/MIME sertifikası alır.');
  print('             Özel anahtar bu makinede üretilir ve burada kalır.');
  print('');
  print('  bootstrap  [--client-id <id>]');
  print('             Sunucunun kutular adına sertifika isteyebilmesi için');
  print('             cihaz akışından bir yenileme jetonu alır ve kasaya yazar.');
  print('');
  print('  register   --address <eposta> --cert <dosya> [--chain <dosya>]');
  print('             Kullanıcının kendi sertifikasını doğrulama için kaydeder.');
  print('');
  print('  status     Sertifika kapsamını ve yenileme durumunu gösterir.');
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const command = args._[0];
  try {
    switch (command) {
      case 'issue': await commandIssue(args); break;
      case 'bootstrap': await commandBootstrap(args); break;
      case 'register': await commandRegister(args); break;
      case 'status': await commandStatus(args); break;
      default: usage(); process.exit(command ? 1 : 0);
    }
  } catch (err) {
    fail(err.stack || err.message);
  }
})();
