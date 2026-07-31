'use strict';

const net = require('node:net');

const { TestRunner, assert, assertEqual, assertMatch } = require('./helpers');
const { SmtpClient } = require('../src/smtp/client');
const dkim = require('../src/mail/dkim');
const { defineConfig } = require('../src/define-config');

const runner = new TestRunner('SMTP istemcisi ve kütüphane yüzeyi');

const silentLogger = {
  trace() {}, debug() {}, info() {}, warn() {}, error() {}, http() {},
  timer() { return () => {}; },
  child() { return silentLogger; },
  hex() {},
  enabled() { return false; },
};

/**
 * Sahte bir submission sunucusu.
 *
 * Gerçek bir MX'e bağlanan test, ağ olmadan çalışmaz ve olduğunda da
 * karşı tarafın hız sınırına takılır. Buradaki sunucu yalnızca protokolü
 * konuşuyor ve GÖRDÜĞÜ satırları biriktiriyor — doğrulanan şey, istemcinin
 * tele ne yazdığı.
 */
function startFakeServer({ requireAuth = false, capabilities = ['8BITMIME', 'SIZE 1000000', 'AUTH PLAIN LOGIN'] } = {}) {
  const seen = { commands: [], body: [], authenticated: false };
  const server = net.createServer((socket) => {
    let inData = false;
    // Satırlar CHUNK SINIRINDAN bağımsız ayrıştırılmalı. Gelen paketi olduğu
    // gibi bölmek, paket tam bir satırın ortasında bittiğinde sahte bir boş
    // satır üretiyor — ve o boş satır, başlık bloğunu erken bitirip
    // yeniden kurulan iletiyi bozuyor.
    let pending = '';
    socket.write('220 sahte.local ESMTP\r\n');
    socket.on('error', () => {});
    socket.on('data', (chunk) => {
      pending += chunk.toString('utf8');
      const lines = pending.split('\r\n');
      pending = lines.pop();
      for (const line of lines) {
        if (line === '' && !inData) continue;
        if (inData) {
          if (line === '.') { inData = false; socket.write('250 2.0.0 Ok: queued as ABC123\r\n'); }
          else seen.body.push(line);
          continue;
        }
        seen.commands.push(line);
        if (/^EHLO/i.test(line)) {
          const lines = ['250-sahte.local', ...capabilities.map((c, i) => (i === capabilities.length - 1 ? `250 ${c}` : `250-${c}`))];
          socket.write(`${lines.join('\r\n')}\r\n`);
        } else if (/^AUTH PLAIN /i.test(line)) {
          seen.authenticated = true;
          socket.write('235 2.7.0 Authentication successful\r\n');
        } else if (/^MAIL FROM/i.test(line)) {
          if (requireAuth && !seen.authenticated) socket.write('530 5.7.0 Authentication required\r\n');
          else socket.write('250 2.1.0 Ok\r\n');
        } else if (/^RCPT TO/i.test(line)) {
          socket.write(/reddet@/.test(line) ? '550 5.1.1 No such user\r\n' : '250 2.1.5 Ok\r\n');
        } else if (/^DATA/i.test(line)) {
          inData = true;
          socket.write('354 End data with <CR><LF>.<CR><LF>\r\n');
        } else if (/^QUIT/i.test(line)) {
          socket.write('221 2.0.0 Bye\r\n');
          socket.end();
        } else {
          socket.write('250 2.0.0 Ok\r\n');
        }
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port, seen }));
  });
}

function clientFor(port, extra = {}) {
  return new SmtpClient({
    host: '127.0.0.1',
    port,
    requireTls: false,
    heloName: 'test.local',
    logger: silentLogger,
    ...extra,
  });
}

runner.test('aktarıcıya ileti gönderir ve zarfı doğru yazar', async () => {
  const { server, port, seen } = await startFakeServer();
  try {
    const result = await clientFor(port).sendMail({
      from: 'gonderen@ornek.com',
      to: ['alici@example.com'],
      subject: 'Merhaba dünya',
      text: 'Deneme gövdesi.',
    });
    assertEqual(result.accepted.length, 1, 'bir alıcı kabul edilmeli');
    assertEqual(result.rejected.length, 0, 'reddedilen olmamalı');
    assert(seen.commands.some((c) => c === 'MAIL FROM:<gonderen@ornek.com> BODY=8BITMIME SIZE=' + result.sizeBytes),
      `zarf göndereni yazılmalı: ${seen.commands.join(' | ')}`);
    assert(seen.commands.includes('RCPT TO:<alici@example.com>'), 'alıcı yazılmalı');
    assert(seen.body.some((l) => /^Subject:/.test(l)), 'konu başlığı gövdede olmalı');
  } finally { server.close(); }
});

runner.test('alıcı başına sonuç döner — biri reddedilse diğeri gider', async () => {
  const { server, port } = await startFakeServer();
  try {
    const result = await clientFor(port).sendMail({
      from: 'gonderen@ornek.com',
      to: ['iyi@example.com', 'reddet@example.com'],
      subject: 'Çoklu alıcı',
      text: 'gövde',
    });
    assertEqual(result.accepted.length, 1, 'bir alıcıya gitmeli');
    assertEqual(result.accepted[0], 'iyi@example.com', 'geçen alıcı');
    assertEqual(result.rejected.length, 1, 'bir alıcı reddedilmeli');
    assertEqual(result.rejected[0].recipient, 'reddet@example.com', 'reddedilen alıcı');
    assert(result.rejected[0].permanent, '550 kalıcı sayılmalı');
  } finally { server.close(); }
});

runner.test('DKIM anahtarı verilirse ileti imzalanır', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const { server, port, seen } = await startFakeServer();
  try {
    const result = await clientFor(port, {
      dkim: { domain: 'ornek.com', selector: 'mail', privateKeyPem: keys.privateKeyPem },
    }).sendMail({
      from: 'gonderen@ornek.com',
      to: ['alici@example.com'],
      subject: 'İmzalı',
      text: 'gövde',
    });
    assert(result.dkimSigned, 'imzalandı bayrağı');
    const signatureLine = seen.body.find((l) => /^DKIM-Signature:/.test(l));
    assert(signatureLine, 'DKIM-Signature başlığı tele yazılmalı');
    assertMatch(signatureLine, /d=ornek\.com/, 'imzalayan alan');

    // Asıl denetim: tele YAZILAN baytlar doğrulanabiliyor mu? İmzayı atıp
    // sonra başlıkları yeniden yazan bir katman olsaydı bu adım düşerdi.
    const wire = Buffer.from(`${seen.body.join('\r\n')}\r\n`, 'utf8');
    const verdict = await dkim.verifyMessage(wire, {
      keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
    });
    assertEqual(verdict.overall, 'pass', `tel üzerindeki imza doğrulanmalı: ${verdict.reason || ''}`);
  } finally { server.close(); }
});

runner.test('kimlik doğrulama şifresiz kanalda reddedilir', async () => {
  const { server, port } = await startFakeServer({ requireAuth: true });
  try {
    const result = await clientFor(port, {
      auth: { username: 'kullanici@ornek.com', password: 'parola' },
    }).sendMail({ from: 'kullanici@ornek.com', to: ['alici@example.com'], subject: 'x', text: 'y' });
    assertEqual(result.accepted.length, 0, 'gönderilmemeli');
    assertMatch(result.rejected[0].error, /şifreli değil/, 'sebep açık olmalı');
  } finally { server.close(); }
});

runner.test('kimlik doğrulama yalnızca aktarıcı kipinde kabul edilir', async () => {
  let threw = null;
  try {
    // eslint-disable-next-line no-new
    new SmtpClient({ auth: { username: 'a', password: 'b' } });
  } catch (err) { threw = err; }
  assert(threw, 'host olmadan auth verilmesi hata olmalı');
  assertMatch(threw.message, /aktarıcı kipinde/, 'hata mesajı yönlendirici olmalı');
});

runner.test('defineConfig kısa listeden tam yapılandırma üretir', async () => {
  const config = defineConfig({
    domain: 'ornek.com',
    publicIp: '203.0.113.10',
    vaultSecret: 'v'.repeat(48),
    database: { target: 'https://db.ornek.com:51572', caFingerprint: 'ab'.repeat(32), rootSecret: 'r'.repeat(48) },
    identity: { baseUrl: 'https://kimlik.ornek.com', clientId: 'cid', clientSecret: 'csec' },
    cloudflare: { apiToken: 'tok', zoneId: 'zone' },
  });
  config.validate();
  assertEqual(config.primaryDomain, 'ornek.com', 'birincil alan');
  assertEqual(config.hostname, 'mail.ornek.com', 'sunucu adı türetilmeli');
  assertEqual(config.webmailOrigin, 'https://posta.ornek.com', 'webmail kökeni türetilmeli');
  assertEqual(config.idp.baseUrl, 'https://kimlik.ornek.com', 'IdP adresi');
  assertEqual(config.db.remoteTarget, 'https://db.ornek.com:51572', 'veritabanı hedefi');
  assertEqual(config.dns.zoneId, 'zone', 'Cloudflare bölgesi');
  assertEqual(config.vaultSecret.length >= 32, true, 'kasa sırrı çözülmeli');
  // Kişisel site istenmedi: ikinci bir dinleyici açılmamalı.
  assertEqual(config.vhosts.length, 1, 'yalnızca webmail vhost açılmalı');
});

runner.test('defineConfig bilinmeyen ayarı sessizce yutmaz', async () => {
  let threw = null;
  try { defineConfig({ domain: 'ornek.com', dommain: 'yazim-hatasi' }); }
  catch (err) { threw = err; }
  assert(threw, 'yazım hatası hata vermeli');
  assertMatch(threw.message, /bilinmeyen ayar: dommain/, 'hangi anahtar olduğu söylenmeli');
});

runner.run().then((ok) => process.exit(ok ? 0 : 1));
