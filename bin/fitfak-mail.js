#!/usr/bin/env node
'use strict';

/**
 * Fitfak posta sunucusu — giriş noktası.
 *
 *   fitfak-mail                 hepsini başlat
 *   fitfak-mail --no-smtp       yalnızca HTTP (arayüz geliştirme)
 *   fitfak-mail --no-http       yalnızca posta akışı
 *   fitfak-mail --check         yapılandırmayı doğrula ve çık
 */

const config = require('../src/config');
const { MailApplication } = require('../src/app');

const args = new Set(process.argv.slice(2));

if (args.has('--help') || args.has('-h')) {
  process.stdout.write([
    'fitfak-mail [seçenekler]',
    '',
    '  --no-smtp    SMTP dinleyicilerini başlatma',
    '  --no-http    HTTP sunucularını başlatma',
    '  --no-queue   giden kuyruk işçisini başlatma',
    '  --no-certs   sertifika yöneticisini başlatma',
    '  --no-dns     DNS denetimini başlatma',
    '  --check      yapılandırmayı doğrula ve çık',
    '',
    'Yapılandırma ortam değişkenlerinden okunur; ayrıntı için README.',
    '',
  ].join('\n'));
  process.exit(0);
}

if (args.has('--check')) {
  try {
    config.validate();
    process.stdout.write([
      'Yapılandırma geçerli.',
      `  ortam        : ${config.env}`,
      `  sunucu adı   : ${config.hostname}`,
      `  alan adları  : ${config.domains.map((d) => `${d.name}${d.receive ? '' : ' (yalnızca gönderim)'}`).join(', ')}`,
      `  vhost'lar    : ${config.vhosts.map((v) => `${v.host} -> ${v.bind}:${v.port}`).join(', ')}`,
      `  SMTP portlar : ${Object.entries(config.smtp.ports).map(([k, v]) => `${k}=${v}`).join(' ')}`,
      `  veritabanı   : ${config.db.driver}${config.db.remoteTarget ? ` (${config.db.remoteTarget})` : ''}`,
      `  IdP          : ${config.idp.baseUrl}`,
      `  sertifika CA : ${config.trust.baseUrl}`,
      '',
    ].join('\n'));
    process.exit(0);
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(1);
  }
}

const app = new MailApplication(config);
app.installSignalHandlers();

app.start({
  withSmtp: !args.has('--no-smtp'),
  withHttp: !args.has('--no-http'),
  withQueue: !args.has('--no-queue'),
  withCerts: !args.has('--no-certs'),
  withDns: !args.has('--no-dns'),
}).catch((err) => {
  process.stderr.write(`\nBaşlatılamadı: ${err.message}\n`);
  if (err.stack && process.env.LOG_LEVEL === 'debug') process.stderr.write(`${err.stack}\n`);
  process.exit(1);
});
