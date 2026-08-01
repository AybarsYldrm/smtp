'use strict';

const crypto = require('node:crypto');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { TestRunner, assert, assertEqual, issueTestSmimeCert } = require('./helpers');

const dkim = require('../src/mail/dkim');
const spf = require('../src/mail/spf');
const dmarc = require('../src/mail/dmarc');
const smime = require('../src/certs/smime');
const csrModule = require('../src/certs/csr');

const runner = new TestRunner('Kriptografi: DKIM, SPF, DMARC, S/MIME');

const SAMPLE = [
  'From: "Fitfak Ağ" <network@fitfak.net>',
  'To: <alici@example.com>',
  'Subject: =?UTF-8?B?RGVuZW1lIGtvbnVzdQ==?=',
  'Date: Wed, 30 Jul 2026 12:00:00 +0000',
  'Message-ID: <ornek-1@fitfak.net>',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  '',
  'Merhaba,',
  'Bu bir deneme iletisidir.   ',
  '',
  '',
].join('\r\n');

/* ── DKIM ──────────────────────────────────────────────────── */

/**
 * Gerçek bir MIME iletisi: MIME-Version + Content-Type +
 * Content-Transfer-Encoding başlıkları `h=` listesini 78 sütunun üstüne
 * çıkarıyor ve imza başlığı KATLANMAK zorunda kalıyor.
 *
 * Bu ayrıntı bir kaza değil, testin sebebi: katlama uzun süre `h=`
 * listesini bir başlık adının ORTASINDAN bölüyordu ve imza doğrulanamaz
 * hâle geliyordu. Az başlıklı örnek iletiler bunu göstermiyordu — yani
 * denemeler geçerken gerçek postalar başarısız oluyordu.
 */
const MIME_SAMPLE = [
  'From: Fitfak <network@fitfak.net>',
  'To: Alıcı <alici@example.com>',
  'Cc: Bilgi <bilgi@example.com>',
  'Subject: =?UTF-8?B?QmlyIGtvbnUgc2F0xLFyxLE=?=',
  'Date: Mon, 01 Jan 2024 09:00:00 +0000',
  'Message-ID: <mime-ornek@fitfak.net>',
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  'Content-Transfer-Encoding: quoted-printable',
  '',
  'Merhaba.',
  '',
].join('\r\n');

for (const algorithm of ['rsa', 'ed25519']) {
  runner.test(`DKIM ${algorithm}: katlanan h= listesi imzayı bozmaz`, async () => {
    const keys = dkim.generateKeyPair({ algorithm });
    const signed = dkim.signMessage({
      rawMessage: MIME_SAMPLE, domain: 'fitfak.net', selector: 'mail',
      privateKeyPem: keys.privateKeyPem, algorithm: keys.algorithm,
    });

    // Katlama gerçekten oldu mu? Olmadıysa test hiçbir şey kanıtlamıyor.
    const lines = signed.signatureHeader.split('\r\n');
    assert(lines.length > 1, 'imza başlığı katlanmalı (yoksa bu test anlamsız)');
    assert(lines.every((l) => l.length <= 78), `satırlar 78 sütunu aşmamalı: ${lines.map((l) => l.length).join(',')}`);

    // Hiçbir başlık adı ikiye bölünmemiş olmalı.
    const hTag = signed.signatureHeader.match(/h=([\s\S]*?);/)[1].replace(/\s+/g, '');
    assert(hTag.split(':').includes('content-transfer-encoding'),
      `başlık adı bölünmüş: ${JSON.stringify(hTag)}`);

    const verdict = await dkim.verifyMessage(signed.rawMessage, {
      keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
    });
    assertEqual(verdict.overall, 'pass', `doğrulama: ${verdict.reason || ''}`);
  });
}

/**
 * h= listesinde OLMAYAN ya da TEKRARLANAN bir başlık HİÇBİR ŞEY katmaz.
 *
 * ── BİLDİRİLEN ÇELİŞKİ ───────────────────────────────────────────────────
 * Kendi doğrulayıcımız giden iletiye `pass` diyordu, Gmail aynı iletiye
 * `dkim=fail`. Sebep DNS önbelleği değildi: imzalanan GİRDİ yanlıştı.
 *
 * RFC 6376 §3.5, h= listesinde olup iletide bulunmayan bir başlık için
 * "treated as the null input, **including the header field name, the
 * separating colon**, the header field value, and any CRLF terminator"
 * diyor — yani hiçbir şey eklenmez. Bizim kod oraya `from:` yazıyordu ve
 * imzalanan girdiye GERÇEK bir satır ekliyordu (567 bayt; doğrusu 560).
 *
 * Aynı hata iki tarafta da olduğu için imzalayıcımız ile doğrulayıcımız
 * birbiriyle tutarlıydı ve hata yalnızca dışarıya karşı görünüyordu — hem
 * giden postada (Gmail fail) hem gelen postada (Gmail ve MxToolbox
 * imzalarını reddediyorduk).
 */
runner.test('DKIM: oversign edilmiş h= imzayı bozmaz (Gmail uyumu)', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: MIME_SAMPLE, domain: 'fitfak.net', selector: 'mail',
    privateKeyPem: keys.privateKeyPem, algorithm: keys.algorithm,
  });

  const hTag = signed.signatureHeader.match(/h=([\s\S]*?);/)[1].replace(/\s+/g, '');
  const names = hTag.split(':');
  assertEqual(names.filter((n) => n === 'from').length, 2, 'from oversign edilmeli');

  // İmzalanan girdiyi ELLE, RFC'ye göre kur: ikinci `from` için hiçbir şey
  // eklenmez. Bu satırlar bilerek kodumuzu çağırmadan yazıldı — uygulama
  // standarttan saparsa bu test düşer.
  const { headers } = dkim.splitMessage(signed.rawMessage);
  const sig = headers.find((h) => h.name === 'dkim-signature');
  const selfNoB = sig.raw.replace(/([;\s]b=)[^;]*/i, '$1');

  const parts = [];
  for (const name of names) {
    const found = headers.find((h) => h.name === name);
    // Tekrar eden ad ikinci kez geçildiğinde ve iletide karşılığı
    // kalmadığında: hiçbir şey.
    if (!found || parts.some((p) => p.startsWith(`${name}:`))) continue;
    parts.push(dkim.canonicalizeHeaderRelaxed(found.raw));
  }
  parts.push(dkim.canonicalizeHeaderRelaxed(selfNoB));
  const expected = Buffer.from(parts.join('\r\n'), 'binary');

  const tags = dkim.parseTagList(sig.raw.slice(sig.raw.indexOf(':') + 1));
  const signature = Buffer.from(String(tags.b).replace(/\s+/g, ''), 'base64');
  const publicKeyPem = crypto.createPublicKey(keys.privateKeyPem)
    .export({ type: 'spki', format: 'pem' });

  assert(
    crypto.verify('rsa-sha256', expected, publicKeyPem, signature),
    'imza, RFC 6376 §3.5\'e göre kurulmuş girdiyle DOĞRULANMALI — '
    + 'aksi hâlde Gmail dkim=fail der',
  );

  // Eski (hatalı) girdi artık tutmamalı.
  const buggy = Buffer.from([...parts.slice(0, -1), 'from:', parts[parts.length - 1]].join('\r\n'), 'binary');
  assert(
    !crypto.verify('rsa-sha256', buggy, publicKeyPem, signature),
    'yok olan başlık için `from:` satırı ekleyen eski girdi ARTIK tutmamalı',
  );
});

/**
 * BAĞIMSIZ (yabancı) imzalayıcı.
 *
 * Kendi `signMessage`'ımızı kullanmak, gelen posta uyumunu test etmez: iki
 * taraf da aynı koddan geçtiği için aynı hatayı yapar ve test yeşil kalır —
 * bildirilen arıza tam olarak buydu. Bu yardımcı, DKIM-Signature başlığının
 * METNİNİ çağıranın verdiği gibi kurar (h= listesini olduğu gibi yazar) ve
 * imzalanan girdiyi RFC 6376'ya göre elle hesaplar. Böylece Gmail ve
 * MxToolbox'ın gerçekte ürettiği biçimler taklit edilebiliyor.
 */
function foreignSign(rawMessage, { hTagText, privateKeyPem, domain = 'example.com', selector = 'sel' }) {
  const { headers, body } = dkim.splitMessage(Buffer.from(rawMessage, 'binary'));
  const bh = dkim.bodyHash(body, { canon: 'relaxed', hash: 'sha256' });

  const sigText = `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${domain}; s=${selector};`
    + ` t=${Math.floor(Date.now() / 1000)}; h=${hTagText}; bh=${bh}; b=`;

  // RFC 6376 §5.4.2 + §3.5: adlar alttan tüketilir; karşılığı kalmayan ad
  // HİÇBİR ŞEY katmaz.
  const remaining = new Map();
  for (const h of headers) {
    if (!remaining.has(h.name)) remaining.set(h.name, []);
    remaining.get(h.name).push(h);
  }
  for (const list of remaining.values()) list.reverse();

  const parts = [];
  for (const name of hTagText.split(':').map((s) => s.trim().toLowerCase()).filter(Boolean)) {
    const list = remaining.get(name);
    if (!list || !list.length) continue;
    parts.push(dkim.canonicalizeHeaderRelaxed(list.shift().raw));
  }
  parts.push(dkim.canonicalizeHeaderRelaxed(sigText));

  const signature = crypto.sign('sha256', Buffer.from(parts.join('\r\n'), 'binary'), privateKeyPem);
  return `${sigText}${signature.toString('base64')}\r\n${rawMessage}`;
}

runner.test('DKIM: Gmail biçimli h= (tekrarlı + iletide olmayan adlar) doğrulanır', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  // Gmail'in gerçekten yayımladığı biçim: content-type/to/subject/date/
  // message-id/from tekrar ediyor, cc ve reply-to ise bu iletide YOK.
  const hTag = 'content-type:to:subject:message-id:date:from:mime-version:from:to'
    + ':cc:subject:date:message-id:reply-to:content-type';

  const message = foreignSign(MIME_SAMPLE, {
    hTagText: hTag, privateKeyPem: keys.privateKeyPem, domain: 'gmail.com', selector: '20251104',
  });

  const verdict = await dkim.verifyMessage(Buffer.from(message, 'binary'), {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'pass',
    `Gmail biçimli imza kabul edilmeli: ${verdict.reason || ''}`);
});

runner.test('DKIM: MxToolbox biçimli h= (iki nokta sonrası boşluklu) doğrulanır', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  // MxToolbox/Mailgun biçimi: ayırıcıdan sonra boşluk ve tekrarlanan adlar.
  const hTag = 'Message-Id: To: To: From: From: Subject: Subject: Content-Type: Mime-Version: Date: Sender: Sender';

  const message = foreignSign(MIME_SAMPLE, {
    hTagText: hTag, privateKeyPem: keys.privateKeyPem, domain: 'mxtoolbox.com', selector: 'mailo',
  });

  const verdict = await dkim.verifyMessage(Buffer.from(message, 'binary'), {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'pass',
    `MxToolbox biçimli imza kabul edilmeli: ${verdict.reason || ''}`);
});

runner.test('DKIM: h= listesi bir adın ortasından katlanmış imza yine okunur', async () => {
  // Başka bir imzalayıcı aynı hatayı yapmış olabilir. Boşlukları atarak
  // okumak, o imzaları kurtarıyor; başlık adları boşluk içeremediği için
  // bu hoşgörünün bir maliyeti yok.
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: MIME_SAMPLE, domain: 'fitfak.net', selector: 'mail',
    privateKeyPem: keys.privateKeyPem,
  });
  const parsed = dkim.parseTagList(signed.signatureHeader.slice('DKIM-Signature:'.length));
  assert(!/\s/.test(parsed.h), `h= etiketi boşluk içermemeli: ${JSON.stringify(parsed.h)}`);
});

for (const algorithm of ['rsa', 'ed25519']) {
  runner.test(`DKIM ${algorithm}: imza üretilir ve doğrulanır`, async () => {
    const keys = dkim.generateKeyPair({ algorithm });
    const signed = dkim.signMessage({
      rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail',
      privateKeyPem: keys.privateKeyPem, algorithm: keys.algorithm,
    });
    assert(/^DKIM-Signature:/.test(signed.signatureHeader), 'başlık üretilmeli');

    const record = dkim.dnsRecordFromPrivateKey(keys.privateKeyPem);
    const verdict = await dkim.verifyMessage(signed.rawMessage, { keyLookup: async () => [record] });
    assertEqual(verdict.overall, 'pass', `doğrulama: ${JSON.stringify(verdict.results)}`);
    assertEqual(verdict.results[0].domain, 'fitfak.net', 'alan adı');
    assertEqual(verdict.results[0].bodyHashMatch, true, 'gövde özeti');
  });

  runner.test(`DKIM ${algorithm}: gövde değişirse reddedilir`, async () => {
    const keys = dkim.generateKeyPair({ algorithm });
    const signed = dkim.signMessage({
      rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail',
      privateKeyPem: keys.privateKeyPem, algorithm: keys.algorithm,
    });
    const tampered = signed.rawMessage.toString('binary').replace('deneme iletisidir', 'DEGISTIRILMIS');
    const verdict = await dkim.verifyMessage(Buffer.from(tampered, 'binary'), {
      keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
    });
    assertEqual(verdict.overall, 'fail', 'gövde değişikliği yakalanmalı');
  });
}

runner.test('DKIM: konu değişirse reddedilir', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail', privateKeyPem: keys.privateKeyPem,
  });
  const tampered = signed.rawMessage.toString('binary')
    .replace('Subject: =?UTF-8?B?RGVuZW1lIGtvbnVzdQ==?=', 'Subject: Baska bir konu');
  const verdict = await dkim.verifyMessage(Buffer.from(tampered, 'binary'), {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'fail', 'konu değişikliği yakalanmalı');
});

runner.test('DKIM: sonradan eklenen From başlığı reddedilir', async () => {
  // From aşırı-imzalandığı (oversign) için ikinci bir From eklenmesi
  // doğrulamayı bozmalı; bozmasaydı gönderen taklit edilebilirdi.
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail', privateKeyPem: keys.privateKeyPem,
  });
  const injected = `From: <sahte@kotu.example>\r\n${signed.rawMessage.toString('binary')}`;
  const verdict = await dkim.verifyMessage(Buffer.from(injected, 'binary'), {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'fail', 'From enjeksiyonu yakalanmalı');
});

runner.test('DKIM: relaxed kanoniklik boşluk değişimini tolere eder', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail', privateKeyPem: keys.privateKeyPem,
  });
  const respaced = signed.rawMessage.toString('binary').replace('Bu bir deneme', 'Bu  bir   deneme');
  const verdict = await dkim.verifyMessage(Buffer.from(respaced, 'binary'), {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'pass', 'boşluk değişimi imzayı bozmamalı');
});

runner.test('DKIM: eklenen Received başlığı imzayı bozmaz', async () => {
  // Aradaki her MTA Received ekler; imzalanan başlık listesinde olmadığı
  // için bu doğrulamayı etkilememeli.
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail', privateKeyPem: keys.privateKeyPem,
  });
  const relayed = `Received: from x by y; ${new Date().toUTCString()}\r\n${signed.rawMessage.toString('binary')}`;
  const verdict = await dkim.verifyMessage(Buffer.from(relayed, 'binary'), {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'pass', 'Received eklenmesi imzayı bozmamalı');
});

runner.test('DKIM: süresi dolmuş imza (x=) reddedilir', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail',
    privateKeyPem: keys.privateKeyPem, expiresInMs: -1000,
  });
  const verdict = await dkim.verifyMessage(signed.rawMessage, {
    keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
  });
  assertEqual(verdict.overall, 'permerror', 'süresi dolmuş imza');
});

runner.test('DKIM: iptal edilmiş anahtar (boş p=) reddedilir', async () => {
  const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
  const signed = dkim.signMessage({
    rawMessage: SAMPLE, domain: 'fitfak.net', selector: 'mail', privateKeyPem: keys.privateKeyPem,
  });
  const verdict = await dkim.verifyMessage(signed.rawMessage, {
    keyLookup: async () => ['v=DKIM1; k=rsa; p='],
  });
  assertEqual(verdict.overall, 'permerror', 'iptal edilmiş anahtar');
});

/* ── SPF ───────────────────────────────────────────────────── */

const spfZone = {
  txt: {
    'fitfak.net': [['v=spf1 ip4:203.0.113.10 include:_spf.ortak.example mx -all']],
    '_spf.ortak.example': [['v=spf1 ip4:198.51.100.0/24 ~all']],
    'dongu.example': [['v=spf1 include:dongu.example -all']],
    'ikili.example': [['v=spf1 -all'], ['v=spf1 +all']],
    'yonlendir.example': [['v=spf1 redirect=fitfak.net']],
  },
  a: { 'mail.fitfak.net': ['203.0.113.11'] },
  mx: { 'fitfak.net': [{ exchange: 'mail.fitfak.net', priority: 10 }] },
};
const notFound = () => { const e = new Error('ENOTFOUND'); e.code = 'ENOTFOUND'; throw e; };
const spfResolver = {
  resolveTxt: async (n) => spfZone.txt[n] || notFound(),
  resolve4: async (n) => spfZone.a[n] || notFound(),
  resolve6: async () => notFound(),
  resolveMx: async (n) => spfZone.mx[n] || notFound(),
  reverse: async () => notFound(),
};

const spfCases = [
  ['doğrudan ip4 eşleşmesi', { ip: '203.0.113.10', sender: 'a@fitfak.net' }, 'pass'],
  ['mx üzerinden eşleşme', { ip: '203.0.113.11', sender: 'a@fitfak.net' }, 'pass'],
  ['include üzerinden eşleşme', { ip: '198.51.100.7', sender: 'a@fitfak.net' }, 'pass'],
  ['eşleşmeyen kaynak -all', { ip: '192.0.2.1', sender: 'a@fitfak.net' }, 'fail'],
  ['kayıt yok', { ip: '192.0.2.1', sender: 'a@yok.example' }, 'none'],
  ['include döngüsü sınırı', { ip: '192.0.2.1', sender: 'a@dongu.example' }, 'permerror'],
  ['iki SPF kaydı belirsiz', { ip: '192.0.2.1', sender: 'a@ikili.example' }, 'permerror'],
  ['redirect izlenir', { ip: '203.0.113.10', sender: 'a@yonlendir.example' }, 'pass'],
  ['boş zarf gönderen HELO ile', { ip: '203.0.113.10', sender: '', heloDomain: 'fitfak.net' }, 'pass'],
];

for (const [name, args, expected] of spfCases) {
  runner.test(`SPF: ${name}`, async () => {
    const result = await spf.check({ ...args, resolver: spfResolver });
    assertEqual(result.result, expected, `${name} (${result.explanation || ''})`);
  });
}

runner.test('SPF: DNS sorgu sınırı aşılırsa permerror', async () => {
  const chain = {};
  for (let i = 0; i < 15; i++) {
    chain[`z${i}.example`] = [[`v=spf1 include:z${i + 1}.example -all`]];
  }
  const resolver = {
    ...spfResolver,
    resolveTxt: async (n) => chain[n] || notFound(),
  };
  const result = await spf.check({ ip: '192.0.2.1', sender: 'a@z0.example', resolver });
  assertEqual(result.result, 'permerror', 'sorgu sınırı');
  assert(result.lookups <= 11, `sorgu sayısı sınırlanmalı (${result.lookups})`);
});

/* ── DMARC ─────────────────────────────────────────────────── */

const dmarcResolver = {
  resolveTxt: async (n) => ({
    '_dmarc.fitfak.net': [['v=DMARC1; p=quarantine; adkim=s; aspf=s; pct=100']],
    '_dmarc.aybars.net.tr': [['v=DMARC1; p=reject; sp=quarantine; pct=50']],
    '_dmarc.gevsek.example': [['v=DMARC1; p=reject']],
  }[n] || notFound()),
};

runner.test('DMARC: kurumsal alan adı çok etiketli sonekleri tanır', () => {
  assertEqual(dmarc.organizationalDomain('aybars.net.tr'), 'aybars.net.tr', 'net.tr soneki');
  assertEqual(dmarc.organizationalDomain('mail.aybars.net.tr'), 'aybars.net.tr', 'alt alan');
  assertEqual(dmarc.organizationalDomain('a.b.fitfak.net'), 'fitfak.net', 'iki etiket');
  assertEqual(dmarc.organizationalDomain('sub.x.co.uk'), 'x.co.uk', 'co.uk soneki');
});

runner.test('DMARC: hizalı DKIM geçer', async () => {
  const result = await dmarc.evaluate({
    fromDomain: 'fitfak.net',
    spf: { result: 'fail', domain: 'baska.example' },
    dkim: { results: [{ domain: 'fitfak.net', result: 'pass' }], overall: 'pass' },
    resolver: dmarcResolver,
  });
  assertEqual(result.result, 'pass', 'hizalı DKIM yeterli');
});

runner.test('DMARC: hizasız geçiş reddedilir', async () => {
  const result = await dmarc.evaluate({
    fromDomain: 'fitfak.net',
    spf: { result: 'pass', domain: 'kotu.example' },
    dkim: { results: [{ domain: 'kotu.example', result: 'pass' }], overall: 'pass' },
    resolver: dmarcResolver,
  });
  assertEqual(result.result, 'fail', 'başka alanın geçmesi yetmez');
  assertEqual(result.disposition, 'quarantine', 'politika uygulanmalı');
});

runner.test('DMARC: sıkı hizalama alt alanı kabul etmez', async () => {
  const result = await dmarc.evaluate({
    fromDomain: 'mail.fitfak.net',
    spf: { result: 'pass', domain: 'fitfak.net' },
    dkim: { results: [] },
    resolver: dmarcResolver,
  });
  assertEqual(result.result, 'fail', 'aspf=s alt alanı hizalı saymamalı');
});

runner.test('DMARC: gevşek hizalama alt alanı kabul eder', async () => {
  const result = await dmarc.evaluate({
    fromDomain: 'mail.gevsek.example',
    spf: { result: 'pass', domain: 'gevsek.example' },
    dkim: { results: [] },
    resolver: dmarcResolver,
  });
  assertEqual(result.result, 'pass', 'öntanımlı gevşek hizalama');
});

runner.test('DMARC: sp= alt alan politikası uygulanır', async () => {
  const result = await dmarc.evaluate({
    fromDomain: 'blog.aybars.net.tr',
    spf: { result: 'fail', domain: 'blog.aybars.net.tr' },
    dkim: { results: [] },
    resolver: dmarcResolver,
    sampleRoll: 10,
  });
  assertEqual(result.disposition, 'quarantine', 'sp=quarantine');
});

runner.test('DMARC: pct dışında kalan bir kademe düşürülür', async () => {
  const result = await dmarc.evaluate({
    fromDomain: 'aybars.net.tr',
    spf: { result: 'fail', domain: 'aybars.net.tr' },
    dkim: { results: [] },
    resolver: dmarcResolver,
    sampleRoll: 90,
  });
  assertEqual(result.disposition, 'quarantine', 'reject -> quarantine');
});

/* ── S/MIME ────────────────────────────────────────────────── */

/**
 * DOĞRULAMA, @fitfak/ssl OLMADAN da çalışmak zorunda.
 *
 * İmza ÜRETMEK sertifika profilleri ve OID kayıt defteri istiyor; imza
 * DOĞRULAMAK yalnızca DER okumak ve `crypto.verify` çağırmak — ikisi de
 * pakette zaten var. Buna rağmen doğrulama da aynı `require` üzerinden
 * gidiyordu, yani @fitfak/ssl kurulu değilken GELEN bir S/MIME imzası hiç
 * denetlenemiyordu. Gelen posta doğrulamasının, ancak sertifika ÜRETEBİLEN
 * bir kurulumda çalışması için hiçbir sebep yok.
 *
 * Bu paket bilerek OpenSSL ile üretilmiş bir CMS kullanıyor: hem @fitfak/ssl'e
 * dokunmuyor, hem de kendi ürettiğimizi kendimizin okuduğu döngüsel testten
 * kaçınıp gerçek bir üreticiyle uyumu ölçüyor.
 */
{
  const cp = require('node:child_process');
  const fsMod = require('node:fs');
  const osMod = require('node:os');
  const pathMod = require('node:path');
  const hasOpenssl = cp.spawnSync('openssl', ['version'], { encoding: 'utf8' }).status === 0;

  runner.test('S/MIME: OpenSSL üretimi imza @fitfak/ssl OLMADAN doğrulanır', () => {
    if (!hasOpenssl) return;
    const dir = fsMod.mkdtempSync(pathMod.join(osMod.tmpdir(), 'fitmail-cms-'));
    try {
      const keyFile = pathMod.join(dir, 'k.pem');
      const certFile = pathMod.join(dir, 'c.pem');
      const contentFile = pathMod.join(dir, 'content.txt');
      const sigFile = pathMod.join(dir, 'sig.der');

      const gen = cp.spawnSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', keyFile, '-out', certFile, '-days', '30',
        '-subj', '/CN=Imzalayan/emailAddress=imza@fitfak.net',
        '-addext', 'subjectAltName=email:imza@fitfak.net',
      ], { encoding: 'utf8' });
      assertEqual(gen.status, 0, `sertifika üretilemedi: ${gen.stderr}`);

      // İmzalanan baytlar, MIME parçasının başlıkları DÂHİL tam hâli ve CRLF.
      const contentPartLocal = [
        'Content-Type: text/plain; charset=utf-8',
        '',
        'OpenSSL tarafindan imzalanmis icerik.',
      ].join('\r\n');
      fsMod.writeFileSync(contentFile, Buffer.from(contentPartLocal, 'binary'));

      const sign = cp.spawnSync('openssl', [
        'cms', '-sign', '-binary', '-in', contentFile, '-signer', certFile,
        '-inkey', keyFile, '-outform', 'DER', '-out', sigFile, '-md', 'sha256',
      ], { encoding: 'utf8' });
      assertEqual(sign.status, 0, `CMS imzalanamadı: ${sign.stderr}`);

      const verdict = smime.verifyDetached({
        content: Buffer.from(contentPartLocal, 'binary'),
        signatureDer: fsMod.readFileSync(sigFile),
        expectedAddress: 'imza@fitfak.net',
      });

      assertEqual(verdict.valid, true, `OpenSSL imzası doğrulanmalı: ${verdict.reason || ''}`);
      assertEqual(verdict.digestMatch, true, 'içerik özeti uyuşmalı');
      assertEqual(verdict.addressMatch, true, 'SAN adresi eşleşmeli');
      assertEqual(verdict.timeValid, true, 'sertifika süresi içinde olmalı');
      assert(verdict.signer && verdict.signer.subject.includes('Imzalayan'), 'imzalayan bildirilmeli');

      // İçerik değişirse reddedilmeli — imzanın bu iletiye ait olduğunu
      // gösteren tek şey bu.
      const tampered = smime.verifyDetached({
        content: Buffer.from(contentPartLocal.replace('imzalanmis', 'degistirilmis'), 'binary'),
        signatureDer: fsMod.readFileSync(sigFile),
      });
      assertEqual(tampered.valid, false, 'kurcalanmış içerik reddedilmeli');
    } finally {
      fsMod.rmSync(dir, { recursive: true, force: true });
    }
  });
}

const smimeAvailable = csrModule.isAvailable();

if (!smimeAvailable) {
  runner.test('S/MIME imzalama testleri atlandı (@fitfak/ssl yok — doğrulama yine denetlendi)', () => {
    assert(true, 'npm run link:deps ile etkinleşir');
  });
} else {
  const fixture = issueTestSmimeCert('network@fitfak.net', 'Fitfak Network');
  const contentPart = [
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: quoted-printable',
    '',
    'S/MIME ile imzalanmis bir icerik.',
  ].join('\r\n');

  runner.test('S/MIME: CSR üretilir ve öz-imzası geçerlidir', () => {
    const request = csrModule.createSmimeRequest({ address: 'test@fitfak.net', displayName: 'Test' });
    const inspected = csrModule.inspectRequest(request.csrPem);
    assertEqual(inspected.signatureValid, true, 'öz-imza');
    assert(inspected.emails.includes('test@fitfak.net'), 'SAN adresi bulunmalı');
  });

  runner.test('S/MIME: ayrık imza üretilir ve doğrulanır', () => {
    const signature = smime.signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: fixture.certPem,
      privateKeyPem: fixture.privateKeyPem,
    });
    const verdict = smime.verifyDetached({
      content: Buffer.from(contentPart, 'utf8'),
      signatureDer: signature,
      trustedCaPems: [fixture.rootPem],
      expectedAddress: 'network@fitfak.net',
    });
    assertEqual(verdict.valid, true, `imza geçerli olmalı: ${verdict.reason}`);
    assertEqual(verdict.digestMatch, true, 'özet eşleşmeli');
    assertEqual(verdict.chainTrusted, true, 'zincir güvenilir olmalı');
    assertEqual(verdict.addressMatch, true, 'adres eşleşmeli');
    assertEqual(verdict.timeValid, true, 'süre geçerli olmalı');
  });

  runner.test('S/MIME: içerik kurcalanırsa reddedilir', () => {
    const signature = smime.signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: fixture.certPem,
      privateKeyPem: fixture.privateKeyPem,
    });
    const verdict = smime.verifyDetached({
      content: Buffer.from(contentPart.replace('imzalanmis', 'degistirilmis'), 'utf8'),
      signatureDer: signature,
    });
    assertEqual(verdict.valid, false, 'kurcalanmış içerik');
  });

  runner.test('S/MIME: güvenilmeyen zincir ayrı bildirilir', () => {
    // "İmza kriptografik olarak doğru" ile "imzalayan güvenilir" ayrı
    // sorular; ikisini birleştirmek kullanıcıya yanlış güvence verir.
    const other = issueTestSmimeCert('baska@fitfak.net');
    const signature = smime.signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: fixture.certPem,
      privateKeyPem: fixture.privateKeyPem,
    });
    const verdict = smime.verifyDetached({
      content: Buffer.from(contentPart, 'utf8'),
      signatureDer: signature,
      trustedCaPems: [other.rootPem],
    });
    assertEqual(verdict.valid, true, 'imza yine de geçerli');
    assertEqual(verdict.chainTrusted, false, 'zincir güvenilmemeli');
  });

  runner.test('S/MIME: adres uyuşmazlığı bildirilir', () => {
    const signature = smime.signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: fixture.certPem,
      privateKeyPem: fixture.privateKeyPem,
    });
    const verdict = smime.verifyDetached({
      content: Buffer.from(contentPart, 'utf8'),
      signatureDer: signature,
      trustedCaPems: [fixture.rootPem],
      expectedAddress: 'baskasi@fitfak.net',
    });
    assertEqual(verdict.addressMatch, false, 'adres uyuşmazlığı yakalanmalı');
  });

  runner.test('S/MIME: RSA anahtarla da imzalanır', () => {
    const ssl = require('@fitfak/ssl');
    const root = ssl.generateEcRootCA({ curveName: 'P-256' });
    const request = csrModule.createSmimeRequest({ address: 'rsa@fitfak.net', algorithm: 'rsa' });
    const issued = ssl.issueCertificateFromCSR(request.csrPem, root, { profile: 'email' });
    const signature = smime.signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: issued.pem || issued.certPem,
      privateKeyPem: request.privateKeyPem,
    });
    const verdict = smime.verifyDetached({
      content: Buffer.from(contentPart, 'utf8'),
      signatureDer: signature,
      trustedCaPems: [root.certPem],
      expectedAddress: 'rsa@fitfak.net',
    });
    assertEqual(verdict.valid, true, 'RSA imza');
    assertEqual(verdict.chainTrusted, true, 'RSA zinciri');
  });

  runner.test('S/MIME: openssl bağımsız olarak doğrular', () => {
    // Kendi doğrulayıcımızın kendi imzamızı kabul etmesi yeterli kanıt
    // değil: iki tarafta da aynı yanlış varsayım olabilir.
    let hasOpenssl = true;
    try { cp.execSync('openssl version', { stdio: 'ignore' }); }
    catch { hasOpenssl = false; }
    if (!hasOpenssl) { assert(true, 'openssl yok, atlandı'); return; }

    const signature = smime.signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: fixture.certPem,
      privateKeyPem: fixture.privateKeyPem,
    });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'smime-'));
    fs.writeFileSync(path.join(dir, 'content.txt'), contentPart);
    fs.writeFileSync(path.join(dir, 'sig.der'), signature);
    fs.writeFileSync(path.join(dir, 'ca.pem'), fixture.rootPem);
    const output = cp.execSync(
      `openssl cms -verify -content ${dir}/content.txt -in ${dir}/sig.der -inform DER `
      + `-CAfile ${dir}/ca.pem -out /dev/null 2>&1 || true`,
    ).toString().trim();
    fs.rmSync(dir, { recursive: true, force: true });
    assert(/Verification successful/i.test(output), `openssl doğrulaması: ${output}`);
  });

  runner.test('S/MIME: multipart/signed kurulur ve geri okunur', () => {
    const { buildMessage } = require('../src/mail/mime-builder');
    const { parseMessage } = require('../src/mail/mime-parser');
    const built = buildMessage({
      from: { address: 'network@fitfak.net', name: 'Fitfak' },
      to: ['alici@example.com'],
      subject: 'İmzalı ileti',
      text: 'Düz metin gövde.',
      html: '<p>HTML gövde.</p>',
      attachments: [{
        fileName: 'ek.pdf', contentType: 'application/pdf',
        content: Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(300, 2)]),
      }],
      smime: {
        certPem: fixture.certPem,
        privateKeyPem: fixture.privateKeyPem,
        chainPem: fixture.rootPem,
      },
    });
    assertEqual(built.smimeSigned, true, 'imzalandı işareti');

    const parsed = parseMessage(built.raw, {});
    const verdict = smime.verifyMessageSignature(parsed, {
      trustedCaPems: [fixture.rootPem],
      expectedAddress: 'network@fitfak.net',
    });
    assertEqual(verdict.status, 'signed-valid', `durum: ${verdict.reason || ''}`);
    // İmzalı ileti yine de okunabilir olmalı: imzayı anlamayan istemci de
    // gövdeyi görebilmeli, multipart/signed'ın amacı bu.
    assert(parsed.text.includes('Düz metin gövde'), 'gövde okunabilmeli');
    assertEqual(parsed.attachments.length, 1, 'ek görünmeli');
    assertEqual(parsed.attachments[0].fileName, 'ek.pdf', 'ek adı');
  });

  runner.test('S/MIME: DKIM eklendikten sonra imza geçerli kalır', async () => {
    const { buildMessage } = require('../src/mail/mime-builder');
    const { parseMessage } = require('../src/mail/mime-parser');
    const built = buildMessage({
      from: { address: 'network@fitfak.net' },
      to: ['alici@example.com'],
      subject: 'İmzalı + DKIM',
      text: 'İki imza bir arada.',
      smime: { certPem: fixture.certPem, privateKeyPem: fixture.privateKeyPem },
    });
    const keys = dkim.generateKeyPair({ algorithm: 'rsa' });
    const signed = dkim.signMessage({
      rawMessage: built.raw, domain: 'fitfak.net', selector: 'mail',
      privateKeyPem: keys.privateKeyPem,
    });

    const dkimVerdict = await dkim.verifyMessage(signed.rawMessage, {
      keyLookup: async () => [dkim.dnsRecordFromPrivateKey(keys.privateKeyPem)],
    });
    assertEqual(dkimVerdict.overall, 'pass', 'DKIM geçerli');

    const parsed = parseMessage(signed.rawMessage, {});
    const smimeVerdict = smime.verifyMessageSignature(parsed, { trustedCaPems: [fixture.rootPem] });
    assertEqual(smimeVerdict.status, 'signed-valid', 'S/MIME hâlâ geçerli');
  });
}

runner.run().then((ok) => process.exit(ok ? 0 : 1));
