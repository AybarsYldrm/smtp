'use strict';

const cp = require('node:child_process');
const path = require('node:path');

/**
 * Bütün denetimleri sırayla çalıştırır.
 *
 * Her dosya AYRI bir süreçte: testler ortam değişkenlerini ve modül
 * önbelleğini değiştiriyor (yapılandırma açılışta okunuyor), aynı süreçte
 * çalıştırmak birinin ayarını diğerine sızdırır ve hata ilgisiz bir dosyada
 * görünür.
 */
const SUITES = [
  ['crypto', 'DKIM, SPF, DMARC, S/MIME'],
  ['mime', 'MIME oluşturma/ayrıştırma ve ek politikası'],
  ['storage', 'veritabanı sürücüsü, depolar, kasa, kuyruk'],
  ['smtp-e2e', 'SMTP uçtan uca'],
  ['client', 'SMTP istemcisi ve kütüphane yüzeyi'],
  ['auth-identity', 'IdP kimlik doğrulama ve kimlik bağları'],
  ['http-api', 'HTTP API, gerçek zamanlı, kişisel site'],
];

const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const results = [];
let failed = 0;

for (const [name, description] of SUITES) {
  if (only.length && !only.includes(name)) continue;
  const file = path.join(__dirname, `${name}.test.js`);
  process.stdout.write(`\n\x1b[1m── ${name}\x1b[0m — ${description}\n`);

  const started = Date.now();
  const result = cp.spawnSync(process.execPath, [file], {
    stdio: 'inherit',
    env: { ...process.env, TEST_LOG_LEVEL: process.env.TEST_LOG_LEVEL || 'silent' },
    timeout: 180_000,
  });
  const durationMs = Date.now() - started;

  const ok = result.status === 0;
  if (!ok) failed++;
  results.push({ name, ok, durationMs, status: result.status, signal: result.signal });
}

process.stdout.write('\n\x1b[1m── özet\x1b[0m\n');
for (const r of results) {
  const mark = r.ok ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
  const detail = r.ok ? '' : ` (çıkış ${r.status}${r.signal ? `, sinyal ${r.signal}` : ''})`;
  process.stdout.write(`  ${mark} ${r.name.padEnd(16)} ${String(r.durationMs).padStart(6)} ms${detail}\n`);
}

const total = results.length;
process.stdout.write(
  failed
    ? `\n\x1b[31m${failed}/${total} paket başarısız\x1b[0m\n\n`
    : `\n\x1b[32m${total}/${total} paket geçti\x1b[0m\n\n`,
);
process.exit(failed ? 1 : 0);
