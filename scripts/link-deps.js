'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Yan yana duran @fitfak paketlerini bu projenin node_modules'una bağlar.
//
// @fitfak/ssl (PKI: ASN.1, OID, CSR, sertifika profilleri) ve
// @fitfak/database (şifreli depolama + mTLS gRPC) henüz kayıt defterinde
// yayımlı değil. `npm link` küresel durum bırakıyor ve bayatladığında hata
// "bozuk bağımlılık" gibi görünüyor; projenin kendi node_modules'una konan
// bir sembolik bağ ise projeyle birlikte yok oluyor.
//
//   node scripts/link-deps.js                 # ../ssl, ../database, ../grpc
//   node scripts/link-deps.js /yol/ssl        # tek paket, açık yol
//
// @fitfak/database kendi taşıma katmanı için @fitfak/grpc'ye ihtiyaç duyuyor,
// o yüzden üçü birlikte bağlanır.

const PACKAGES = [
  { name: '@fitfak/ssl', dirs: ['ssl', 'fitfak-ssl'], env: 'FITFAK_SSL_PATH' },
  { name: '@fitfak/database', dirs: ['database', 'fitfak-database'], env: 'FITFAK_DATABASE_PATH' },
  { name: '@fitfak/grpc', dirs: ['grpc', 'fitfak-grpc'], env: 'FITFAK_GRPC_PATH' },
];

const explicit = process.argv.slice(2).filter(Boolean);

function packageNameAt(dir) {
  try { return require(path.join(dir, 'package.json')).name; }
  catch { return null; }
}

function findSource(pkg) {
  const candidates = [
    ...explicit,
    process.env[pkg.env],
    ...pkg.dirs.map((d) => path.resolve(__dirname, '..', '..', d)),
  ].filter(Boolean);
  return candidates.find((c) => packageNameAt(c) === pkg.name) || null;
}

let linked = 0;
let missing = [];

for (const pkg of PACKAGES) {
  const source = findSource(pkg);
  if (!source) { missing.push(pkg); continue; }
  const target = path.resolve(__dirname, '..', 'node_modules', ...pkg.name.split('/'));
  fs.mkdirSync(path.dirname(target), { recursive: true });
  // Ne varsa değiştirilir: taşınmış bir kopyaya işaret eden bayat bağ,
  // paketin hiç kurulu olmamasından daha kafa karıştırıcı bir hata verir.
  try { fs.rmSync(target, { recursive: true, force: true }); } catch { /* yok say */ }
  fs.symlinkSync(source, target, 'junction');
  console.log(`bağlandı ${pkg.name} -> ${source}`);
  linked++;
}

for (const pkg of missing) {
  console.warn(`bulunamadı ${pkg.name} (aradığım yerler: ${pkg.dirs.map((d) => `../${d}`).join(', ')}, $${pkg.env})`);
}

if (!linked) {
  console.error('\nHiçbir paket bağlanamadı. Yolu açıkça verin: node scripts/link-deps.js /yol/ssl');
  process.exit(1);
}

// @fitfak/ssl olmadan da çalışılabilir (S/MIME ve sertifika üretimi devre
// dışı kalır, posta akışı çalışır); @fitfak/database olmadan dosya sürücüsü
// devreye girer. İkisi de eksikse bu bir kurulum hatası değil, bilinçli bir
// geliştirme kipidir — bu yüzden uyarı, hata değil.
if (missing.length) {
  console.warn('\nEksik paketler olmadan sistem çalışır ama ilgili yetenekler kapalı olur.');
}
