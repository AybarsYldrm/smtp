'use strict';

const {
  createContext, cleanupAll, TestSmtpClient, TestRunner,
  assert, assertEqual, assertMatch,
} = require('./helpers');

const dkim = require('../src/mail/dkim');
const { parseMessage } = require('../src/mail/mime-parser');

const runner = new TestRunner('SMTP uçtan uca');

let ctx;
let mailbox;

async function setup() {
  ctx = await createContext({ smtp: true });
  const ensured = await ctx.stores.mailboxes.ensure('network@fitfak.net', {
    displayName: 'Fitfak Ağ', ownerSub: 'sub-network',
  });
  mailbox = ensured.mailbox;
  await ctx.stores.mailboxes.ensure('dmarc@fitfak.net', { displayName: 'DMARC' });
  const cred = await ctx.stores.mailboxes.createSmtpCredential({
    mailboxRef: mailbox.ref, label: 'test istemcisi',
  });
  ctx.credentials = cred;
}

runner.test('MX portu yerel alıcıyı kabul eder ve iletiyi saklar', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.mx });
  const greeting = await client.connect();
  assertEqual(greeting.code, 220, 'karşılama');

  const ehlo = await client.send('EHLO test.example');
  assertEqual(ehlo.code, 250, 'EHLO');
  assert(ehlo.text.includes('SIZE'), 'SIZE duyurulmalı');
  assert(!/AUTH/.test(ehlo.text), '25 portunda AUTH duyurulmamalı');

  assertEqual((await client.send('MAIL FROM:<gonderen@example.com>')).code, 250, 'MAIL FROM');
  assertEqual((await client.send('RCPT TO:<network@fitfak.net>')).code, 250, 'RCPT TO');
  assertEqual((await client.send('DATA')).code, 354, 'DATA');

  const raw = [
    'From: "Gönderen Kişi" <gonderen@example.com>',
    'To: <network@fitfak.net>',
    'Subject: =?UTF-8?B?VGVzdCBpbGV0aXNp?=',
    'Message-ID: <e2e-1@example.com>',
    'Date: Wed, 30 Jul 2026 12:00:00 +0000',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Gövde metni.',
    '.tek nokta ile başlayan satır',
    '',
  ].join('\r\n');
  const accepted = await client.sendData(raw);
  assertEqual(accepted.code, 250, 'ileti kabulü');
  client.close();

  const list = await ctx.stores.messages.list({ mailboxRef: mailbox.ref, folder: 'inbox' });
  assertEqual(list.total, 1, 'bir ileti saklanmalı');
  const message = list.messages[0];
  assertEqual(message.subject, 'Test iletisi', 'konu çözülmeli');
  assertEqual(message.from.address, 'gonderen@example.com', 'gönderen');

  const full = await ctx.stores.messages.getFull(message.ref);
  assert(full.text.includes('Gövde metni.'), 'gövde saklanmalı');
  // Nokta açma: istemci ".." yazdı, saklanan tek nokta olmalı.
  assert(full.text.includes('\n.tek nokta ile başlayan satır'), `nokta açma başarısız: ${JSON.stringify(full.text)}`);
});

runner.test('MX portu bilinmeyen alıcıyı ve aktarmayı reddeder', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.mx });
  await client.connect();
  await client.send('EHLO test.example');
  await client.send('MAIL FROM:<gonderen@example.com>');

  const unknown = await client.send('RCPT TO:<boyle-biri-yok@fitfak.net>');
  assertEqual(unknown.code, 550, 'bilinmeyen alıcı reddedilmeli');

  const relay = await client.send('RCPT TO:<baskasi@example.org>');
  assertEqual(relay.code, 550, 'aktarma reddedilmeli');
  assertMatch(relay.text, /Aktarma yasak/, 'aktarma reddi gerekçesi');
  client.close();
});

runner.test('submission portu kimlik doğrulamasız gönderimi reddeder', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.submission });
  await client.connect();
  const ehlo = await client.send('EHLO istemci.example');
  assert(/AUTH/.test(ehlo.text), '587 portunda AUTH duyurulmalı');

  const mail = await client.send('MAIL FROM:<network@fitfak.net>');
  assertEqual(mail.code, 530, 'kimlik doğrulamasız MAIL FROM reddedilmeli');
  client.close();
});

runner.test('yanlış parola reddedilir ve sebep ayrıştırılmaz', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.submission });
  await client.connect();
  await client.send('EHLO istemci.example');
  const token = Buffer.from(`\0network@fitfak.net\0yanlisparola`).toString('base64');
  const auth = await client.send(`AUTH PLAIN ${token}`);
  assertEqual(auth.code, 535, 'yanlış parola');

  const client2 = new TestSmtpClient({ port: ctx.ports.submission });
  await client2.connect();
  await client2.send('EHLO istemci.example');
  const token2 = Buffer.from(`\0olmayan@fitfak.net\0herhangi`).toString('base64');
  const auth2 = await client2.send(`AUTH PLAIN ${token2}`);
  assertEqual(auth2.code, 535, 'olmayan kullanıcı');
  assertEqual(auth2.text.replace(/^\d+\s/, ''), auth.text.replace(/^\d+\s/, ''), 'iki hata aynı mesajı vermeli');
  client.close();
  client2.close();
});

runner.test('465/587 üzerinden gönderilen ileti DKIM ile imzalanır', async () => {
  // Bildirilen hatanın testi: istemciden gelen ham ileti imzalanmalı.
  const client = new TestSmtpClient({ port: ctx.ports.submission });
  await client.connect();
  await client.send('EHLO istemci.example');

  const token = Buffer.from(`\0${ctx.credentials.username}\0${ctx.credentials.password}`).toString('base64');
  assertEqual((await client.send(`AUTH PLAIN ${token}`)).code, 235, 'AUTH');
  assertEqual((await client.send('MAIL FROM:<network@fitfak.net>')).code, 250, 'MAIL FROM');
  assertEqual((await client.send('RCPT TO:<dmarc@fitfak.net>')).code, 250, 'yerel alıcı');
  assertEqual((await client.send('DATA')).code, 354, 'DATA');

  const raw = [
    'From: "Fitfak Ağ" <network@fitfak.net>',
    'To: <dmarc@fitfak.net>',
    'Subject: İmza testi',
    'Message-ID: <submission-1@fitfak.net>',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Bu ileti bir posta istemcisinden gönderildi.',
    '',
  ].join('\r\n');
  assertEqual((await client.sendData(raw)).code, 250, 'gönderim kabulü');
  client.close();

  // Yerel alıcının kutusunda DKIM-Signature bulunmalı.
  const target = await ctx.stores.mailboxes.getByAddress('dmarc@fitfak.net');
  const list = await ctx.stores.messages.list({ mailboxRef: target.ref, folder: 'inbox' });
  assertEqual(list.total, 1, 'yerel teslimat');
  const rawStored = await ctx.stores.messages.getRaw(list.messages[0].ref);
  assert(rawStored, 'ham ileti saklanmalı');
  assertMatch(rawStored.toString('utf8'), /DKIM-Signature:/, 'DKIM-Signature başlığı bulunmalı');

  // İmza gerçekten doğrulanabilir olmalı — varlığı yetmez.
  const key = await ctx.signer.getDkimKey('fitfak.net');
  const record = dkim.dnsRecordFromPrivateKey(key.privateKeyPem);
  // Saklanan ham iletide Received/Authentication-Results başlıkları eklendi;
  // DKIM bunlara duyarsız olmak zorunda (imzalanan başlıklar listesinde yok).
  const verdict = await dkim.verifyMessage(rawStored, { keyLookup: async () => [record] });
  assertEqual(verdict.overall, 'pass', `DKIM doğrulaması: ${JSON.stringify(verdict.results)}`);

  // Gönderilenler klasörüne kopya konmalı.
  const sent = await ctx.stores.messages.list({ mailboxRef: mailbox.ref, folder: 'sent' });
  assertEqual(sent.total, 1, 'gönderilenler kopyası');
});

runner.test('yetkisiz From adresiyle gönderim reddedilir', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.submission });
  await client.connect();
  await client.send('EHLO istemci.example');
  const token = Buffer.from(`\0${ctx.credentials.username}\0${ctx.credentials.password}`).toString('base64');
  await client.send(`AUTH PLAIN ${token}`);
  await client.send('MAIL FROM:<network@fitfak.net>');
  await client.send('RCPT TO:<baskasi@example.org>');
  await client.send('DATA');

  const raw = [
    'From: <patron@fitfak.net>',
    'To: <baskasi@example.org>',
    'Subject: Taklit',
    '',
    'Başka birinin adına.',
    '',
  ].join('\r\n');
  const result = await client.sendData(raw);
  assertEqual(result.code, 550, 'yetkisiz From reddedilmeli');
  // Yanıt metni tele ASCII olarak yazılır (RFC 5321 §4.2.1), bu yüzden
  // beklenen desen de ASCII: "gönderme" değil "gonderme".
  assertMatch(result.text, /gonderme yetkiniz yok/, 'gerekçe');
  assertMatch(result.text, /patron@fitfak\.net/, 'reddedilen adres bildirilmeli');
  client.close();
});

runner.test('uzak alıcı kuyruğa alınır, yerel alıcı doğrudan teslim edilir', async () => {
  const before = await ctx.stores.outbound.stats();
  const client = new TestSmtpClient({ port: ctx.ports.submission });
  await client.connect();
  await client.send('EHLO istemci.example');
  const token = Buffer.from(`\0${ctx.credentials.username}\0${ctx.credentials.password}`).toString('base64');
  await client.send(`AUTH PLAIN ${token}`);
  await client.send('MAIL FROM:<network@fitfak.net>');
  await client.send('RCPT TO:<uzak@example.org>');
  await client.send('RCPT TO:<uzak2@example.net>');
  await client.send('DATA');
  await client.sendData([
    'From: <network@fitfak.net>',
    'To: <uzak@example.org>, <uzak2@example.net>',
    'Subject: Kuyruk testi',
    '',
    'Uzak alıcılar.',
    '',
  ].join('\r\n'));
  client.close();

  const after = await ctx.stores.outbound.stats();
  assertEqual(after.queued - before.queued, 2, 'iki alıcı kuyruğa alınmalı');
});

runner.test('çok alıcılı ileti her alıcıya teslim edilir', async () => {
  // Önceki sürümdeki hata: RCPT TO her seferinde üzerine yazıyordu ve
  // yalnızca son alıcı teslim alıyordu.
  await ctx.stores.mailboxes.ensure('test1@fitfak.net', {});
  await ctx.stores.mailboxes.ensure('test2@fitfak.net', {});
  await ctx.stores.mailboxes.ensure('test3@fitfak.net', {});

  const client = new TestSmtpClient({ port: ctx.ports.mx });
  await client.connect();
  await client.send('EHLO test.example');
  await client.send('MAIL FROM:<gonderen@example.com>');
  for (const addr of ['test1@fitfak.net', 'test2@fitfak.net', 'test3@fitfak.net']) {
    assertEqual((await client.send(`RCPT TO:<${addr}>`)).code, 250, `RCPT ${addr}`);
  }
  await client.send('DATA');
  const result = await client.sendData([
    'From: <gonderen@example.com>',
    'To: <test1@fitfak.net>',
    'Subject: Çok alıcı',
    'Message-ID: <multi-1@example.com>',
    '',
    'Herkese.',
    '',
  ].join('\r\n'));
  assertEqual(result.code, 250, 'kabul');
  client.close();

  for (const addr of ['test1@fitfak.net', 'test2@fitfak.net', 'test3@fitfak.net']) {
    const box = await ctx.stores.mailboxes.getByAddress(addr);
    const list = await ctx.stores.messages.list({ mailboxRef: box.ref, folder: 'inbox' });
    assertEqual(list.total, 1, `${addr} iletiyi almalı`);
  }
});

runner.test('ileti boyutu sınırı uygulanır', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.mx });
  await client.connect();
  await client.send('EHLO test.example');
  const declared = await client.send(`MAIL FROM:<gonderen@example.com> SIZE=${ctx.config.smtp.maxMessageBytes + 1}`);
  assertEqual(declared.code, 552, 'bildirilen boyut reddedilmeli');
  client.close();
});

runner.test('8bit ekli ileti bozulmadan saklanır', async () => {
  // Önceki sürüm soketi utf8 olarak okuyordu; ikili veri bozuluyordu.
  const binary = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0x81]);
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), binary]);
  const b64 = png.toString('base64');

  const client = new TestSmtpClient({ port: ctx.ports.mx });
  await client.connect();
  await client.send('EHLO test.example');
  await client.send('MAIL FROM:<gonderen@example.com>');
  await client.send('RCPT TO:<network@fitfak.net>');
  await client.send('DATA');
  await client.sendData([
    'From: <gonderen@example.com>',
    'To: <network@fitfak.net>',
    'Subject: İkili ek',
    'Message-ID: <binary-1@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="sinir1"',
    '',
    '--sinir1',
    'Content-Type: text/plain; charset=utf-8',
    '',
    'Ekli.',
    '--sinir1',
    'Content-Type: image/png; name="g.png"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="g.png"',
    '',
    b64,
    '--sinir1--',
    '',
  ].join('\r\n'));
  client.close();

  const list = await ctx.stores.messages.list({ mailboxRef: mailbox.ref, folder: 'inbox' });
  const withAtt = list.messages.find((m) => m.subject === 'İkili ek');
  assert(withAtt, 'ileti bulunmalı');
  const full = await ctx.stores.messages.getFull(withAtt.ref);
  assertEqual(full.attachments.length, 1, 'bir ek');
  const stored = await ctx.stores.blobs.read(full.attachments[0].blobId);
  assertEqual(stored.length, png.length, 'ek boyutu korunmalı');
  assert(stored.equals(png), 'ek baytları birebir korunmalı');
});

runner.test('reddedilen ek üstverisi saklanır, baytları saklanmaz', async () => {
  const exe = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(500, 7)]);
  const client = new TestSmtpClient({ port: ctx.ports.mx });
  await client.connect();
  await client.send('EHLO test.example');
  await client.send('MAIL FROM:<gonderen@example.com>');
  await client.send('RCPT TO:<network@fitfak.net>');
  await client.send('DATA');
  await client.sendData([
    'From: <gonderen@example.com>',
    'To: <network@fitfak.net>',
    'Subject: Kotu ek',
    'Message-ID: <evil-1@example.com>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="s2"',
    '',
    '--s2',
    'Content-Type: text/plain',
    '',
    'Bak.',
    '--s2',
    'Content-Type: application/pdf; name="fatura.pdf.exe"',
    'Content-Transfer-Encoding: base64',
    'Content-Disposition: attachment; filename="fatura.pdf.exe"',
    '',
    exe.toString('base64'),
    '--s2--',
    '',
  ].join('\r\n'));
  client.close();

  const list = await ctx.stores.messages.list({ mailboxRef: mailbox.ref, folder: 'inbox' });
  const found = list.messages.find((m) => m.subject === 'Kotu ek');
  const full = await ctx.stores.messages.getFull(found.ref);
  assertEqual(full.attachments.length, 1, 'ek kaydı tutulmalı');
  assertEqual(full.attachments[0].scanStatus, 'rejected_extension', 'ret sebebi');
  assertEqual(full.attachments[0].blobId, '', 'baytlar saklanmamalı');
  assertEqual(full.hasAttachments, false, 'kabul edilen ek yok');
});

runner.test('PROXY başlığı güvenilmeyen kaynaktan reddedilir', async () => {
  const client = new TestSmtpClient({ port: ctx.ports.mx });
  await client.connect();
  // 127.0.0.1 güvenilen listede; testte güvenilmeyeni benzetmek için
  // yapılandırmayı geçici olarak değiştiriyoruz.
  const original = ctx.config.smtp.trustedProxies.slice();
  ctx.config.smtp.trustedProxies.length = 0;
  ctx.config.smtp.trustedProxies.push('10.99.99.99');
  const client2 = new TestSmtpClient({ port: ctx.ports.mx });
  await client2.connect();
  const reply = await client2.send('PROXY TCP4 1.2.3.4 5.6.7.8 1111 25');
  assertEqual(reply.code, 421, 'güvenilmeyen PROXY reddedilmeli');
  ctx.config.smtp.trustedProxies.length = 0;
  ctx.config.smtp.trustedProxies.push(...original);
  client.close();
  client2.close();
});

runner.test('kopya Message-ID ikinci kez saklanmaz', async () => {
  const send = async () => {
    const client = new TestSmtpClient({ port: ctx.ports.mx });
    await client.connect();
    await client.send('EHLO test.example');
    await client.send('MAIL FROM:<gonderen@example.com>');
    await client.send('RCPT TO:<network@fitfak.net>');
    await client.send('DATA');
    const r = await client.sendData([
      'From: <gonderen@example.com>',
      'To: <network@fitfak.net>',
      'Subject: Kopya denemesi',
      'Message-ID: <dedupe-1@example.com>',
      '',
      'Aynı ileti.',
      '',
    ].join('\r\n'));
    client.close();
    return r;
  };
  assertEqual((await send()).code, 250, 'ilk gönderim');
  assertEqual((await send()).code, 250, 'ikinci gönderim de kabul edilir');

  const list = await ctx.stores.messages.list({ mailboxRef: mailbox.ref, folder: 'inbox', limit: 100 });
  const matches = list.messages.filter((m) => m.messageId === '<dedupe-1@example.com>');
  assertEqual(matches.length, 1, 'yalnızca bir kopya saklanmalı');
});

(async () => {
  try {
    await setup();
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
