'use strict';

/**
 * @fitfak/smtp — açık yüzey.
 *
 * Paket üç ayrı biçimde kullanılabiliyor ve üçü de burada:
 *
 *   1. TAM SUNUCU. Kendi posta sunucunuzu ayağa kaldırırsınız: SMTP
 *      (25/465/587), webmail, kuyruk, DKIM, S/MIME, gerçek zamanlı bildirim.
 *
 *        const { defineConfig, createServer } = require('@fitfak/smtp');
 *        const config = defineConfig({ … });
 *        await createServer(config).start();
 *
 *   2. YALNIZCA İSTEMCİ. Posta göndermek istiyorsunuz, sunucu işletmek
 *      istemiyorsunuz. Veritabanı ya da yapılandırma gerekmez.
 *
 *        const { SmtpClient } = require('@fitfak/smtp');
 *        await new SmtpClient({ host: 'mail.ornek.com', port: 587, auth }).sendMail({ … });
 *
 *   3. PARÇALAR. DKIM imzalama/doğrulama, SPF, DMARC, MIME ayrıştırma ve
 *      kurma bağımsız modüller. Kendi hattınızı kuruyorsanız bunları tek
 *      tek alabilirsiniz — hiçbiri diğerini ya da yapılandırmayı istemiyor.
 *
 *        const { dkim, spf, dmarc, parseMessage } = require('@fitfak/smtp');
 *
 * `defineConfig` çağrılmazsa yapılandırma ortam değişkenlerinden okunur;
 * `bin/fitfak-mail.js` bu yolu kullanıyor.
 */

const { defineConfig } = require('./src/define-config');
const { MailApplication } = require('./src/app');
const { SmtpClient } = require('./src/smtp/client');
const log = require('./src/util/log');

/**
 * Sunucu örneği kurar (henüz başlatmaz).
 *
 * @param {object} [config] `defineConfig()` çıktısı; verilmezse ortamdan okunur.
 * @returns {MailApplication}
 */
function createServer(config = null) {
  return new MailApplication(config || require('./src/config'));
}

/** Ayağa kaldırıp bekler. Kısayol: `createServer(config).start(options)`. */
async function startServer(config = null, options = {}) {
  const app = createServer(config);
  app.installSignalHandlers();
  await app.start(options);
  return app;
}

module.exports = {
  // kurulum
  defineConfig,
  createServer,
  startServer,
  MailApplication,

  // istemci
  SmtpClient,

  // posta parçaları — hepsi bağımsız kullanılabilir
  dkim: require('./src/mail/dkim'),
  spf: require('./src/mail/spf'),
  dmarc: require('./src/mail/dmarc'),
  mimeParser: require('./src/mail/mime-parser'),
  mimeBuilder: require('./src/mail/mime-builder'),
  parseMessage: require('./src/mail/mime-parser').parseMessage,
  buildMessage: require('./src/mail/mime-builder').buildMessage,

  // sunucu parçaları
  SmtpServer: require('./src/smtp/server').SmtpServer,
  MailPipeline: require('./src/mail/pipeline').MailPipeline,
  MailSigner: require('./src/mail/signer').MailSigner,
  OutboundQueue: require('./src/smtp/queue').OutboundQueue,
  CertificateManager: require('./src/certs/manager').CertificateManager,
  IdpClient: require('./src/auth/idp-client').IdpClient,
  SessionManager: require('./src/auth/session-manager').SessionManager,

  // kayıt
  log,
};
