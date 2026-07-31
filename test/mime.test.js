'use strict';

const crypto = require('node:crypto');

const { TestRunner, assert, assertEqual, assertMatch } = require('./helpers');

const builder = require('../src/mail/mime-builder');
const parser = require('../src/mail/mime-parser');
const encoding = require('../src/util/encoding');

const runner = new TestRunner('MIME: oluşturma, ayrıştırma, ek politikası');

const LIMITS = {
  maxAttachmentsPerMessage: 25,
  maxAttachmentBytes: 2 * 1024 * 1024,
  maxTotalAttachmentBytes: 4 * 1024 * 1024,
  maxBodyBytes: 512 * 1024,
  maxMimeParts: 200,
  maxMimeDepth: 20,
  allowedAttachmentTypes: [
    'application/pdf', 'image/png', 'image/jpeg', 'text/plain',
    'message/rfc822', 'application/zip',
  ],
  blockedAttachmentExtensions: ['.exe', '.js', '.bat', '.scr'],
};

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(400, 7)]);
const PDF = Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(800, 3)]);
const EXE = Buffer.concat([Buffer.from([0x4d, 0x5a]), Buffer.alloc(300, 9)]);

/* ── kodlama yardımcıları ──────────────────────────────────── */

runner.test('kodlama: RFC 2047 başlıkları çözülür', () => {
  const encoded = `=?UTF-8?B?${Buffer.from('Merhaba dünya').toString('base64')}?=`;
  assertEqual(encoding.decodeMimeWords(encoded), 'Merhaba dünya', 'base64 sözcük');

  // Bölünmüş çok baytlı karakter: aradaki boşluk yok sayılmalı, yoksa
  // karakter bozulur.
  const part1 = Buffer.from('Türk', 'utf8').toString('base64');
  const part2 = Buffer.from('çe', 'utf8').toString('base64');
  assertEqual(encoding.decodeMimeWords(`=?UTF-8?B?${part1}?= =?UTF-8?B?${part2}?=`), 'Türkçe', 'bölünmüş sözcük');
});

runner.test('kodlama: quoted-printable çift yönlü çalışır', () => {
  const original = 'Merhaba dünya\r\nsatır sonunda boşluk ';
  const encoded = encoding.encodeQuotedPrintable(Buffer.from(original, 'utf8'));
  // Satır sonundaki boşluk kodlanmak zorunda; aktarımda kırpılırsa gövde
  // özeti (ve DKIM imzası) değişir.
  assertMatch(encoded, /=20$/m, 'sondaki boşluk kodlanmalı');
  assertEqual(encoding.decodeQuotedPrintable(encoded).toString('utf8'), original, 'geri dönüş');
});

runner.test('kodlama: dosya adı sanitizasyonu yön değiştirmeyi engeller', () => {
  // RTL override ile "resim<U+202E>gpj.exe" dosyası "resimexe.jpg" gibi
  // görünür; karakteri düşürmek bu numarayı bozar.
  const tricky = 'resim‮gpj.exe';
  const safe = encoding.safeFileName(tricky);
  assert(!safe.includes('‮'), 'yön değiştirme karakteri kalmamalı');
  assertEqual(encoding.safeFileName('../../etc/passwd'), 'passwd', 'yol atılmalı');
});

runner.test('kodlama: adres listesi alıntıları anlar', () => {
  const list = encoding.parseAddressList('"Yıldırım, Aybars" <a@b.com>, c@d.net');
  assertEqual(list.length, 2, 'iki adres');
  assertEqual(list[0].address, 'a@b.com', 'ilk adres');
  assertEqual(list[0].name, 'Yıldırım, Aybars', 'alıntı içindeki virgül bölmemeli');
});

/* ── oluşturma ve ayrıştırma ───────────────────────────────── */

runner.test('düz metin ileti kurulur ve geri okunur', () => {
  const built = builder.buildMessage({
    from: { address: 'network@fitfak.net', name: 'Fitfak Ağ' },
    to: [{ address: 'alici@example.com', name: 'Alıcı' }],
    subject: 'Türkçe konu — deneme',
    text: 'Merhaba,\nBu düz metin.',
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.subject, 'Türkçe konu — deneme', 'konu');
  assertEqual(parsed.from.address, 'network@fitfak.net', 'gönderen adresi');
  assertEqual(parsed.from.name, 'Fitfak Ağ', 'gönderen adı');
  assertEqual(parsed.to[0].address, 'alici@example.com', 'alıcı');
  assert(parsed.text.includes('Bu düz metin.'), 'gövde');
});

runner.test('Bcc zarfa girer ama başlığa yazılmaz', () => {
  const built = builder.buildMessage({
    from: { address: 'a@fitfak.net' },
    to: ['t@example.com'],
    bcc: ['gizli@example.com'],
    subject: 'gizli kopya',
    text: 'x',
  });
  assert(built.envelope.to.includes('gizli@example.com'), 'zarfta olmalı');
  const headerBlock = built.raw.toString('utf8').split('\r\n\r\n')[0];
  assert(!headerBlock.includes('gizli@example.com'), 'başlıkta OLMAMALI');
});

runner.test('metin + html multipart/alternative üretir, sıra doğrudur', () => {
  const built = builder.buildMessage({
    from: { address: 'a@fitfak.net' }, to: ['t@example.com'],
    subject: 'alternatif', text: 'Düz sürüm.', html: '<p>HTML sürüm.</p>',
  });
  const raw = built.raw.toString('utf8');
  assertMatch(raw, /multipart\/alternative/, 'alternative olmalı');
  // En az tercih edilen alternatif ÖNCE gelir (RFC 2046 §5.1.4).
  assert(raw.indexOf('text/plain') < raw.indexOf('text/html'), 'düz metin önce gelmeli');

  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assert(parsed.text.includes('Düz sürüm.'), 'düz metin');
  assert(parsed.html.includes('HTML sürüm.'), 'html');
});

runner.test('gömülü görsel multipart/related içine sarılır', () => {
  const built = builder.buildMessage({
    from: { address: 'a@fitfak.net' }, to: ['t@example.com'],
    subject: 'gömülü', html: '<p>Bak: <img src="cid:logo1"></p>',
    attachments: [{
      fileName: 'logo.png', contentType: 'image/png', content: PNG,
      contentId: 'logo1', inline: true,
    }],
  });
  assertMatch(built.raw.toString('utf8'), /multipart\/related/, 'related olmalı');
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.attachments.length, 1, 'bir ek');
  assertEqual(parsed.attachments[0].isInline, true, 'gömülü işaretlenmeli');
  assertEqual(parsed.attachments[0].contentId, 'logo1', 'Content-ID eşleşmeli');
});

runner.test('iç içe multipart doğru bölünür, ek baytları bozulmaz', () => {
  // Önceki sürümün hatası: bütün sınırları tek regex'e toplayıp iletiyi
  // hepsine göre bölmek, parçaları yanlış yerden kesiyordu.
  const built = builder.buildMessage({
    from: { address: 'a@fitfak.net' }, to: ['t@example.com'],
    subject: 'iç içe', text: 'Düz.', html: '<p>HTML</p>',
    attachments: [
      { fileName: 'belge.pdf', contentType: 'application/pdf', content: PDF },
      { fileName: 'resim.png', contentType: 'image/png', content: PNG, contentId: 'i1', inline: true },
    ],
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.attachments.length, 2, 'iki ek');
  const pdf = parsed.attachments.find((a) => a.fileName === 'belge.pdf');
  const png = parsed.attachments.find((a) => a.fileName === 'resim.png');
  assert(pdf.content.equals(PDF), 'PDF baytları birebir');
  assert(png.content.equals(PNG), 'PNG baytları birebir');
  assert(parsed.text.includes('Düz.'), 'metin gövde ek baytlarıyla karışmamalı');
});

runner.test('RFC 2231 kodlu dosya adı çözülür', () => {
  const raw = [
    'From: <a@b.com>',
    'To: <c@d.com>',
    'Subject: parametre',
    'MIME-Version: 1.0',
    'Content-Type: multipart/mixed; boundary="s1"',
    '',
    '--s1',
    'Content-Type: text/plain',
    '',
    'gövde',
    '--s1',
    "Content-Type: application/pdf; name*0*=utf-8''%C3%A7%C3%B6z%C3%BCm; name*1*=.pdf",
    'Content-Transfer-Encoding: base64',
    "Content-Disposition: attachment; filename*0*=utf-8''%C3%A7%C3%B6z%C3%BCm; filename*1*=.pdf",
    '',
    PDF.toString('base64'),
    '--s1--',
    '',
  ].join('\r\n');
  const parsed = parser.parseMessage(Buffer.from(raw, 'utf8'), { limits: LIMITS });
  assertEqual(parsed.attachments.length, 1, 'bir ek');
  assertEqual(parsed.attachments[0].fileName, 'çözüm.pdf', 'RFC 2231 adı çözülmeli');
});

runner.test('ham UTF-8 başlık (8BITMIME) doğru okunur', () => {
  const raw = Buffer.from([
    'From: "Aybars Yıldırım" <a@fitfak.net>',
    'To: <t@example.com>',
    'Subject: Türkçe konu kodlanmamış',
    '',
    'gövde',
    '',
  ].join('\r\n'), 'utf8');
  const parsed = parser.parseMessage(raw, { limits: LIMITS });
  assertEqual(parsed.subject, 'Türkçe konu kodlanmamış', 'ham UTF-8 konu');
  assertEqual(parsed.from.name, 'Aybars Yıldırım', 'ham UTF-8 ad');
});

/* ── ek politikası ─────────────────────────────────────────── */

runner.test('politika: yasaklı uzantı reddedilir ve baytları saklanmaz', () => {
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'kötü', text: 'x',
    attachments: [{ fileName: 'fatura.pdf.exe', contentType: 'application/pdf', content: EXE }],
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.attachments[0].scanStatus, 'rejected_extension', 'uzantı reddi');
  assertEqual(parsed.attachments[0].content, null, 'baytlar taşınmamalı');
  assertMatch(parsed.attachments[0].rejectedReason, /\.exe/, 'gerekçe bildirilmeli');
});

runner.test('politika: beyan edilen tür ile içerik çelişkisi yakalanır', () => {
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'sahte', text: 'x',
    attachments: [{ fileName: 'resim.png', contentType: 'image/png', content: EXE }],
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.attachments[0].scanStatus, 'rejected_type', 'tür çelişkisi');
  assertMatch(parsed.attachments[0].rejectedReason, /çelişiyor/, 'gerekçe');
});

runner.test('politika: tek ek boyut sınırı uygulanır', () => {
  const big = Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(3 * 1024 * 1024, 1)]);
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'büyük', text: 'x',
    attachments: [{ fileName: 'buyuk.pdf', contentType: 'application/pdf', content: big }],
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.attachments[0].scanStatus, 'rejected_size', 'boyut reddi');
});

runner.test('politika: toplam ek boyutu sınırı uygulanır', () => {
  const chunk = Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(1600 * 1024, 1)]);
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'toplam', text: 'x',
    attachments: [
      { fileName: 'a.pdf', contentType: 'application/pdf', content: chunk },
      { fileName: 'b.pdf', contentType: 'application/pdf', content: chunk },
      { fileName: 'c.pdf', contentType: 'application/pdf', content: chunk },
    ],
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  const accepted = parsed.attachments.filter((a) => a.scanStatus === 'accepted');
  const rejected = parsed.attachments.filter((a) => a.scanStatus === 'rejected_size');
  assertEqual(accepted.length, 2, 'ilk ikisi kabul');
  assertEqual(rejected.length, 1, 'üçüncü toplam sınırını aşmalı');
});

runner.test('politika: izin listesi dışındaki tür reddedilir', () => {
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'tür', text: 'x',
    attachments: [{
      fileName: 'kayit.iso', contentType: 'application/x-iso9660-image',
      content: Buffer.alloc(200, 5),
    }],
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.attachments[0].scanStatus, 'rejected_type', 'izin listesi dışı');
});

runner.test('politika: gövde boyutu sınırı kesme olarak bildirilir', () => {
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'uzun',
    text: 'A'.repeat(600 * 1024),
  });
  const parsed = parser.parseMessage(built.raw, { limits: LIMITS });
  assertEqual(parsed.bodyTruncated, true, 'kesme bildirilmeli');
  assert(parsed.text.length < 600 * 1024, 'gövde kesilmiş olmalı');
});

runner.test('politika: OOXML dosyası zip olarak koklandığı için reddedilmez', () => {
  const docx = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04]), Buffer.alloc(300, 2)]);
  const limits = {
    ...LIMITS,
    allowedAttachmentTypes: [...LIMITS.allowedAttachmentTypes,
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
  };
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'], subject: 'docx', text: 'x',
    attachments: [{
      fileName: 'rapor.docx',
      contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      content: docx,
    }],
  });
  const parsed = parser.parseMessage(built.raw, { limits });
  assertEqual(parsed.attachments[0].scanStatus, 'accepted', 'OOXML kabul edilmeli');
});

/* ── iletme ve DSN ─────────────────────────────────────────── */

runner.test('iletme: özgün ileti ek olarak taşınır', () => {
  const original = builder.buildMessage({
    from: { address: 'x@example.com' }, to: ['network@fitfak.net'],
    subject: 'Özgün ileti', text: 'Özgün gövde.',
  });
  const forwarded = builder.buildForward({
    from: { address: 'network@fitfak.net' },
    to: ['baskasi@example.org'],
    originalSubject: 'Özgün ileti',
    comment: 'Bilgine.',
    originalRaw: original.raw,
  });
  const parsed = parser.parseMessage(forwarded.raw, { limits: LIMITS });
  assertEqual(parsed.subject, 'Fwd: Özgün ileti', 'konu ön eki');
  assertEqual(parsed.attachments.length, 1, 'özgün ileti ek olmalı');
  assertEqual(parsed.attachments[0].contentType, 'message/rfc822', 'ek türü');

  // Ek, özgün iletinin HAM baytlarıdır — gövdesi quoted-printable kodlu.
  // Doğru denetim, eki bir ileti olarak yeniden ayrıştırmak: baytların
  // birebir korunduğunu ancak böyle söyleyebiliriz.
  const inner = parser.parseMessage(parsed.attachments[0].content, { limits: LIMITS });
  assertEqual(inner.subject, 'Özgün ileti', 'özgün konu korunmalı');
  assert(inner.text.includes('Özgün gövde.'), 'özgün gövde korunmalı');
  assertEqual(inner.from.address, 'x@example.com', 'özgün gönderen korunmalı');
});

runner.test('DSN: rapor biçiminde üretilir', () => {
  const dsn = builder.buildDsn({
    from: 'mailer-daemon@fitfak.net',
    to: 'network@fitfak.net',
    originalRecipient: 'yok@example.com',
    status: '5.1.1',
    diagnostic: '550 5.1.1 no such user',
    reportingMta: 'mail.fitfak.net',
    originalMessageId: '<abc@fitfak.net>',
  });
  const parsed = parser.parseMessage(dsn, { limits: LIMITS });
  assertEqual(parsed.subject, 'Teslim edilemedi: iletiniz alıcıya ulaşmadı', 'konu okunabilir olmalı');
  assertMatch(parsed.contentType, /multipart\/report/, 'rapor türü');
  const types = parsed.parts.map((p) => p.contentType);
  assert(types.includes('message/delivery-status'), 'makine okunur kısım olmalı');
  assertEqual(parsed.autoSubmitted, 'auto-replied', 'otomatik yanıt işareti');
});

/* ── sağlamlık ─────────────────────────────────────────────── */

runner.test('sağlamlık: sınırsız multipart derinliği sınırlanır', () => {
  let raw = 'Content-Type: text/plain\r\n\r\ntaban';
  for (let i = 0; i < 40; i++) {
    raw = [
      `Content-Type: multipart/mixed; boundary="b${i}"`,
      '',
      `--b${i}`,
      raw,
      `--b${i}--`,
      '',
    ].join('\r\n');
  }
  const message = `From: <a@b.com>\r\nTo: <c@d.com>\r\nSubject: derin\r\n${raw}`;
  const parsed = parser.parseMessage(Buffer.from(message, 'utf8'), { limits: LIMITS });
  assert(parsed.partCount <= LIMITS.maxMimeParts + 5, `parça sayısı sınırlanmalı (${parsed.partCount})`);
});

runner.test('sağlamlık: sınırsız multipart bozuk olsa da çökmez', () => {
  const broken = [
    'From: <a@b.com>',
    'To: <c@d.com>',
    'Subject: bozuk',
    'Content-Type: multipart/mixed; boundary="yok"',
    '',
    'sınır hiç görünmüyor',
    '',
  ].join('\r\n');
  const parsed = parser.parseMessage(Buffer.from(broken, 'utf8'), { limits: LIMITS });
  assertEqual(parsed.subject, 'bozuk', 'başlıklar okunmalı');
});

runner.test('sağlamlık: sınırı olmayan multipart düz metin gibi ele alınır', () => {
  const raw = [
    'From: <a@b.com>',
    'To: <c@d.com>',
    'Subject: sınırsız',
    'Content-Type: multipart/mixed',
    '',
    'gövde metni',
    '',
  ].join('\r\n');
  const parsed = parser.parseMessage(Buffer.from(raw, 'utf8'), { limits: LIMITS });
  assert(parsed.text.includes('gövde metni'), 'gövde kurtarılmalı');
});

runner.test('sağlamlık: başlık enjeksiyonu engellenir', () => {
  const built = builder.buildMessage({
    from: { address: 'a@b.com' }, to: ['c@d.com'],
    subject: 'normal\r\nBcc: gizli@kotu.example',
    text: 'x',
    extraHeaders: { 'X-Test': 'deger\r\nX-Injected: evet' },
  });
  const headerBlock = built.raw.toString('utf8').split('\r\n\r\n')[0];
  assert(!/^Bcc:/m.test(headerBlock), 'konu üzerinden başlık eklenememeli');
  assert(!/^X-Injected:/m.test(headerBlock), 'ek başlık üzerinden enjeksiyon olmamalı');
});

runner.run().then((ok) => process.exit(ok ? 0 : 1));
