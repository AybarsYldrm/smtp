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

const smimeAvailable = csrModule.isAvailable();

if (!smimeAvailable) {
  runner.test('S/MIME testleri atlandı (@fitfak/ssl yok)', () => {
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
