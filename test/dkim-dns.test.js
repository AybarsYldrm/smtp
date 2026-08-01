'use strict';

const {
  createContext, cleanupAll, TestRunner, assert, assertEqual,
} = require('./helpers');

const { publicKeyTag } = require('../src/mail/signer');

/**
 * DKIM anahtarının kasadaki durumu ve DNS ile hizası; DNS denetiminin
 * KAPSAMI.
 *
 * İki ayrı arıza buradan çıkmıştı:
 *
 *   1. "Anahtar var mı?" sorusunu soran her yol (durum ekranı, DNS denetimi,
 *      açılış) `getDkimKey` çağırıyordu ve o çağrı, anahtar yoksa YENİSİNİ
 *      ÜRETİYORDU. Yani soruyu sormak cevabı değiştiriyordu — ve yayındaki
 *      TXT kaydı o anda geçersizleşiyordu.
 *   2. Site alan adı (posta almayan, yalnızca web) posta alan adı listesine
 *      kendiliğinden giriyor, onun için de SPF/DKIM/DMARC bekleniyordu.
 */

const runner = new TestRunner('DKIM kasa/DNS hizası ve DNS denetim kapsamı');

const DOMAINS = [
  { name: 'fitfak.net', dkimSelector: 'mail' },
  { name: 'sadece-web.example', manageDns: false },
];

runner.test('peekDkimKey ANAHTAR ÜRETMEZ', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    const before = await ctx.signer.peekDkimKey('fitfak.net');
    assertEqual(before.present, false, 'kasa başlangıçta boş olmalı');

    // Tekrar bakmak da üretmemeli.
    const again = await ctx.signer.peekDkimKey('fitfak.net');
    assertEqual(again.present, false, 'bakmak anahtar yaratmamalı');

    const rows = await ctx.stores.vault.collection.find('name', 'dkim/fitfak.net/mail');
    assertEqual(rows.length, 0, 'kasada hiçbir kayıt oluşmamalı');
  } finally { await ctx.close(); }
});

runner.test('dkimDnsRecord öntanımlı olarak üretmez, create ile üretir', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    const none = await ctx.signer.dkimDnsRecord('fitfak.net');
    assertEqual(none, null, 'anahtar yokken kayıt da yok');

    const peekAfter = await ctx.signer.peekDkimKey('fitfak.net');
    assertEqual(peekAfter.present, false, 'kayıt sorgusu anahtar üretmemeli');

    const made = await ctx.signer.dkimDnsRecord('fitfak.net', { create: true });
    assert(made && made.value.includes('p='), 'create:true ile kayıt üretilmeli');
    assertEqual(made.name, 'mail._domainkey.fitfak.net', 'kayıt adı seçiciyi taşımalı');

    const peekNow = await ctx.signer.peekDkimKey('fitfak.net');
    assertEqual(peekNow.present, true, 'artık kasada bir anahtar olmalı');
  } finally { await ctx.close(); }
});

runner.test('verifyDkimPublication: kasa boş, DNS dolu -> kayıt ESKİ', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    // Yayında, elimizde OLMAYAN bir anahtarı duyuran bir kayıt var.
    const resolver = async () => [['v=DKIM1; k=rsa; p=BAŞKA_BIR_ANAHTAR']];
    const result = await ctx.signer.verifyDkimPublication('fitfak.net', { resolver });

    assertEqual(result.vault, 'missing', 'kasa boş bildirilmeli');
    assertEqual(result.dns, 'present', 'DNS kaydı var bildirilmeli');
    assertEqual(result.match, false, 'eşleşme olmamalı');
  } finally { await ctx.close(); }
});

runner.test('verifyDkimPublication: kasadaki anahtar yayındakiyle aynıysa hizalı', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    const key = await ctx.signer.getDkimKey('fitfak.net');
    const record = await ctx.signer.dkimDnsRecord('fitfak.net');
    assert(record, 'anahtar üretildikten sonra kayıt hesaplanabilmeli');

    // Sağlayıcılar uzun TXT değerlerini parçalayıp boşlukla birleştirebiliyor
    // ve etiket sırasını değiştirebiliyor: karşılaştırma yalnızca `p=` üstünden.
    const scrambled = `k=rsa; v=DKIM1; p=${publicKeyTag(record.value)}`;
    const resolver = async () => [[scrambled]];

    const result = await ctx.signer.verifyDkimPublication('fitfak.net', { resolver });
    assertEqual(result.vault, 'present', 'kasa dolu bildirilmeli');
    assertEqual(result.match, true, 'etiket sırası değişse de eşleşmeli');
    assertEqual(result.selector, key.selector, 'seçici bildirilmeli');
  } finally { await ctx.close(); }
});

runner.test('verifyDkimPublication: DNS kaydı yoksa açıkça söylenir', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    await ctx.signer.getDkimKey('fitfak.net');
    const resolver = async () => { const e = new Error('yok'); e.code = 'ENOTFOUND'; throw e; };
    const result = await ctx.signer.verifyDkimPublication('fitfak.net', { resolver });

    assertEqual(result.vault, 'present');
    assertEqual(result.dns, 'absent', 'kayıt yok olarak bildirilmeli');
    assertEqual(result.match, false);
  } finally { await ctx.close(); }
});

runner.test('DNS denetimi manageDns:false alan adı için kayıt beklemez', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    const { DnsAuditor } = require('../src/dns/auditor');
    const auditor = new DnsAuditor({
      config: ctx.config, logger: ctx.logger, stores: ctx.stores, signer: ctx.signer,
    });

    const expected = await auditor.expectedRecords();
    const names = expected.map((r) => r.name);

    assert(
      names.every((n) => !n.includes('sadece-web.example')),
      `manageDns:false alan adı için kayıt üretilmemeli, üretilenler: ${names.join(', ')}`,
    );
    assert(names.includes('fitfak.net'), 'yönetilen alan adı için kayıtlar üretilmeli');
    assert(names.includes('_dmarc.fitfak.net'), 'DMARC kaydı yönetilen alan için beklenmeli');
  } finally { await ctx.close(); }
});

runner.test('DNS denetimi beklenen kayıtları kurarken DKIM anahtarı ÜRETMEZ', async () => {
  const ctx = await createContext({ domains: DOMAINS });
  try {
    const { DnsAuditor } = require('../src/dns/auditor');
    const auditor = new DnsAuditor({
      config: ctx.config, logger: ctx.logger, stores: ctx.stores, signer: ctx.signer,
    });

    await auditor.expectedRecords();

    const peek = await ctx.signer.peekDkimKey('fitfak.net');
    assertEqual(peek.present, false,
      'denetim salt okunur: beklenen kayıt listesini kurmak kasaya anahtar yazmamalı');
  } finally { await ctx.close(); }
});

runner.test('öntanımlı yapılandırma site alan adını posta alan adı saymaz', async () => {
  const ctx = await createContext();
  try {
    const names = ctx.config.domains.map((d) => d.name);
    assert(
      !names.includes('aybars.net.tr'),
      `site alan adı posta alan adı listesine girmemeli, liste: ${names.join(', ')}`,
    );
    // Web tarafı etkilenmemeli: site vhost'u hâlâ o adı sunuyor.
    assert(
      ctx.config.vhosts.some((v) => v.host === 'aybars.net.tr'),
      'site alan adı web vhost olarak durmaya devam etmeli',
    );
  } finally { await ctx.close(); }
});

if (require.main === module) {
  runner.run().then((ok) => cleanupAll().then(() => process.exit(ok ? 0 : 1)));
}

module.exports = { runner };
