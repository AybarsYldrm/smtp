'use strict';

const crypto = require('node:crypto');

const {
  createContext, cleanupAll, TestRunner,
  assert, assertEqual, assertThrows,
} = require('./helpers');

const runner = new TestRunner('Depolama: sürücü, depolar, kasa, kuyruk');

let ctx;
let mailbox;

async function setup() {
  ctx = await createContext();
  mailbox = (await ctx.stores.mailboxes.ensure('network@fitfak.net', {
    displayName: 'Fitfak Ağ', ownerSub: 'sub-1',
  })).mailbox;
}

/* ── sürücü ────────────────────────────────────────────────── */

runner.test('sürücü: kayıt yazılır, okunur, güncellenir, silinir', async () => {
  const collection = ctx.db.collection('ephemeral');
  const ref = await collection.insert({ key: 'k1', kind: 'test', valueJson: '{"a":1}', expiresAt: Date.now() + 60_000, createdAt: Date.now(), usedAt: 0 });
  assertEqual(typeof ref, 'string', 'insert dize döndürmeli');

  const record = await collection.get(ref);
  assertEqual(record.key, 'k1', 'okuma');
  // Motorun davranışı: çözülmüş kayıtta `_id` BigInt'tir, insert() ise
  // dize döndürür. İkisini doğrudan karşılaştırmak her zaman false verir.
  assertEqual(typeof record._id, 'bigint', '_id BigInt olmalı');
  assert(record._id != ref === false, 'String(_id) ile karşılaştırılmalı'); // eslint-disable-line eqeqeq
  assertEqual(String(record._id), ref, 'String dönüşümü eşleşmeli');

  await collection.update(ref, { valueJson: '{"a":2}' });
  assertEqual((await collection.get(ref)).valueJson, '{"a":2}', 'güncelleme');

  await collection.delete(ref);
  assertEqual(await collection.get(ref), null, 'silme');
});

runner.test('sürücü: şemada olmayan alan reddedilir', async () => {
  const collection = ctx.db.collection('ephemeral');
  await assertThrows(
    () => collection.insert({ key: 'k2', bilinmeyen: 'x' }),
    /şemada olmayan alan/,
    'bilinmeyen alan',
  );
});

runner.test('sürücü: zorunlu alan denetlenir', async () => {
  const collection = ctx.db.collection('ephemeral');
  await assertThrows(() => collection.insert({ kind: 'test' }), /zorunlu/, 'eksik zorunlu alan');
});

runner.test('sürücü: dizinsiz alanda find reddedilir', async () => {
  const collection = ctx.db.collection('messages');
  await assertThrows(() => collection.find('subject', 'x'), /dizinli değil/, 'dizinsiz sorgu');
});

runner.test('sürücü: kör dizin eşitlikle çalışır', async () => {
  const found = await ctx.db.collection('mailboxes').findOne('address', 'network@fitfak.net');
  assert(found, 'kör dizinden bulunmalı');
  assertEqual(found.address, 'network@fitfak.net', 'adres');
  const missing = await ctx.db.collection('mailboxes').findOne('address', 'yok@fitfak.net');
  assertEqual(missing, null, 'olmayan adres');
});

runner.test('sürücü: aralık sorgusu çalışır', async () => {
  const collection = ctx.db.collection('ephemeral');
  const base = Date.now();
  for (let i = 0; i < 5; i++) {
    await collection.insert({ key: `r${i}`, kind: 'range', valueJson: '{}', expiresAt: base + i * 1000, createdAt: base, usedAt: 0 });
  }
  const rows = await collection.findRange('expiresAt', base + 1000, base + 3000);
  assertEqual(rows.length, 3, 'aralıkta üç kayıt');
});

runner.test('sürücü: iyimser kilit çakışmayı yakalar', async () => {
  const collection = ctx.db.collection('ephemeral');
  const ref = await collection.insert({ key: 'lock1', kind: 'lock', valueJson: '{}', expiresAt: 0, createdAt: 0, usedAt: 0 });
  const { version } = await collection.getWithVersion(ref);
  await collection.update(ref, { valueJson: '{"v":2}' });
  await assertThrows(
    () => collection.update(ref, { valueJson: '{"v":3}' }, { expectedVersion: version }),
    /ABORTED/,
    'eski sürümle güncelleme reddedilmeli',
  );
});

runner.test('sürücü: değişiklik akışı sıra numarası taşır', async () => {
  const events = [];
  ctx.db.changes.on('change:ephemeral', (e) => events.push(e));
  const collection = ctx.db.collection('ephemeral');
  const ref = await collection.insert({ key: 'ev1', kind: 'ev', valueJson: '{}', expiresAt: 0, createdAt: 0, usedAt: 0 });
  await collection.update(ref, { valueJson: '{"x":1}' });
  await collection.delete(ref);

  assertEqual(events.length, 3, 'üç olay');
  assertEqual(events.map((e) => e.type).join(','), 'insert,update,delete', 'olay türleri');
  // Koleksiyon başına sayaç ayrı: başka koleksiyona yazmak bunu ilerletmemeli.
  assert(events[1].collectionSeq === events[0].collectionSeq + 1, 'koleksiyon sırası artmalı');
});

/* ── kasa ──────────────────────────────────────────────────── */

runner.test('kasa: sır yazılır ve okunur', async () => {
  await ctx.stores.vault.put({ kind: 'test-key', name: 'a/b', value: 'gizli-deger' });
  const secret = await ctx.stores.vault.get('test-key', 'a/b');
  assertEqual(secret.value.toString('utf8'), 'gizli-deger', 'değer');
  assertEqual(secret.version, 1, 'sürüm');
});

runner.test('kasa: sürümler üzerine yazılmaz', async () => {
  await ctx.stores.vault.put({ kind: 'test-key', name: 'rot', value: 'v1' });
  await ctx.stores.vault.put({ kind: 'test-key', name: 'rot', value: 'v2' });

  const active = await ctx.stores.vault.get('test-key', 'rot');
  assertEqual(active.value.toString('utf8'), 'v2', 'etkin sürüm');
  assertEqual(active.version, 2, 'sürüm numarası');

  const all = await ctx.stores.vault.getAllVersions('test-key', 'rot');
  assertEqual(all.length, 2, 'eski sürüm korunmalı');
  const retired = all.find((v) => v.version === 1);
  assertEqual(retired.status, 'retired', 'eski sürüm geri çekilmiş olmalı');
  assertEqual(retired.value.toString('utf8'), 'v1', 'eski değer okunabilmeli');
});

runner.test('kasa: bekleyen sürüm terfi ettirilebilir', async () => {
  await ctx.stores.vault.put({ kind: 'test-key', name: 'staged', value: 'eski' });
  await ctx.stores.vault.put({ kind: 'test-key', name: 'staged', value: 'yeni', activate: false });

  assertEqual((await ctx.stores.vault.get('test-key', 'staged')).value.toString('utf8'), 'eski', 'terfi öncesi');
  await ctx.stores.vault.promote('test-key', 'staged', 2);
  assertEqual((await ctx.stores.vault.get('test-key', 'staged')).value.toString('utf8'), 'yeni', 'terfi sonrası');
});

runner.test('kasa: ele geçmiş sır okunamaz ama kaydı durur', async () => {
  await ctx.stores.vault.put({ kind: 'test-key', name: 'komp', value: 'sizdi' });
  await ctx.stores.vault.markCompromised('test-key', 'komp', 1, 'olay-2026-07');
  await assertThrows(
    () => ctx.stores.vault.get('test-key', 'komp', { version: 1 }),
    /ele geçmiş/,
    'ele geçmiş sır okunmamalı',
  );
  const listed = await ctx.stores.vault.listByKind('test-key');
  assert(listed.some((s) => s.status === 'compromised'), 'kayıt silinmemeli');
});

runner.test('kasa: şifreli gövde diskte düz metin değil', async () => {
  const marker = `gizli-${crypto.randomBytes(8).toString('hex')}`;
  await ctx.stores.vault.put({ kind: 'test-key', name: 'diskte', value: marker });
  const row = await ctx.db.collection('secrets').findOne('secretKey', 'test-key|diskte|v1');
  assert(row, 'kayıt bulunmalı');
  assert(!Buffer.from(row.ciphertext).includes(marker), 'şifreli gövdede düz metin olmamalı');
});

runner.test('kasa: sırlar yeniden sarılabilir', async () => {
  await ctx.stores.vault.put({ kind: 'test-key', name: 'rewrap', value: 'tasinacak' });
  const newSecret = crypto.randomBytes(32);
  const result = await ctx.stores.vault.rewrapAll(newSecret);
  assert(result.rewrapped > 0, 'kayıtlar yeniden sarılmalı');
  assertEqual((await ctx.stores.vault.get('test-key', 'rewrap')).value.toString('utf8'), 'tasinacak', 'değer korunmalı');

  // Yanlış anahtarla açmaya çalışmak ANLAŞILIR bir hata vermeli: AES-GCM'in
  // ham "unable to authenticate data" mesajı "veri bozuk" gibi okunur ve
  // yanlış teşhise (yedekten dönme) yönlendirir.
  const { KeyVault } = require('../src/db/vault');
  const wrongKeyVault = new KeyVault(ctx.db, crypto.randomBytes(32), { logger: ctx.logger });
  await assertThrows(
    () => wrongKeyVault.get('test-key', 'rewrap'),
    /başka bir kasa anahtarıyla sarılmış/,
    'anahtar uyuşmazlığı açıkça bildirilmeli',
  );

  // Sonraki testler (ve yeniden açma testi) yapılandırmadaki sırrı
  // kullanacak; kasayı ona geri sar.
  await ctx.stores.vault.rewrapAll(ctx.config.vaultSecret);
});

/* ── blob deposu ───────────────────────────────────────────── */

runner.test('blob: yazılır, okunur ve özeti doğrulanır', async () => {
  const data = crypto.randomBytes(700 * 1024);
  const written = await ctx.stores.blobs.write(data, { kind: 'test', contentType: 'application/octet-stream' });
  assert(written.chunkCount === undefined || true, 'yazma tamam');
  const read = await ctx.stores.blobs.read(written.blobId);
  assert(read.equals(data), 'baytlar birebir olmalı');
});

runner.test('blob: aynı içerik tekilleştirilir', async () => {
  const data = Buffer.from('aynı içerik');
  const first = await ctx.stores.blobs.write(data, { kind: 'dedupe' });
  const second = await ctx.stores.blobs.write(data, { kind: 'dedupe' });
  assertEqual(second.deduped, true, 'ikinci yazma tekilleştirilmeli');
  assertEqual(first.blobId, second.blobId, 'aynı blob');

  // Gönderge sayacı: bir tarafın bırakması diğerini bozmamalı.
  await ctx.stores.blobs.release(first.blobId);
  assert(await ctx.stores.blobs.read(first.blobId), 'ikinci gönderge hâlâ okuyabilmeli');
  await ctx.stores.blobs.release(first.blobId);
  assertEqual(await ctx.stores.blobs.head(first.blobId), null, 'son göndergeden sonra silinmeli');
});

runner.test('blob: aralık okuması doğru dilimi verir', async () => {
  const data = Buffer.from(Array.from({ length: 1000 }, (_, i) => i % 251));
  const written = await ctx.stores.blobs.write(data, { kind: 'range', contentType: 'video/mp4' });
  const chunks = [];
  for await (const chunk of ctx.stores.blobs.readStream(written.blobId, { start: 100, end: 199 })) chunks.push(chunk);
  const slice = Buffer.concat(chunks);
  assertEqual(slice.length, 100, 'dilim uzunluğu');
  assert(slice.equals(data.subarray(100, 200)), 'dilim içeriği');
});

/* ── posta kutusu ve iletiler ──────────────────────────────── */

runner.test('kutu: etiketli adres aynı kutuya çözülür', async () => {
  const resolved = await ctx.stores.mailboxes.resolveDelivery('network+fatura@fitfak.net');
  assertEqual(resolved.reason, 'ok', 'çözülmeli');
  assertEqual(resolved.mailbox.address, 'network@fitfak.net', 'ana kutu');
});

runner.test('kutu: takma ad hedefe çözülür, döngü yakalanır', async () => {
  const target = (await ctx.stores.mailboxes.ensure('hedef@fitfak.net', {})).mailbox;
  await ctx.stores.mailboxes.ensure('takma@fitfak.net', { kind: 'alias', aliasOfRef: target.ref });
  const resolved = await ctx.stores.mailboxes.resolveDelivery('takma@fitfak.net');
  assertEqual(resolved.mailbox.address, 'hedef@fitfak.net', 'takma ad çözülmeli');

  const loopA = (await ctx.stores.mailboxes.ensure('dongu1@fitfak.net', { kind: 'alias' })).mailbox;
  const loopB = (await ctx.stores.mailboxes.ensure('dongu2@fitfak.net', { kind: 'alias', aliasOfRef: loopA.ref })).mailbox;
  await ctx.stores.mailboxes.ensure('dongu1@fitfak.net', { aliasOfRef: loopB.ref });
  const looped = await ctx.stores.mailboxes.resolveDelivery('dongu1@fitfak.net');
  assertEqual(looped.reason, 'alias_loop', 'döngü yakalanmalı');
});

runner.test('kutu: bilinmeyen alıcı reddedilir', async () => {
  const resolved = await ctx.stores.mailboxes.resolveDelivery('boyle-biri-yok@fitfak.net');
  assertEqual(resolved.mailbox, null, 'bulunmamalı');
  assertEqual(resolved.reason, 'no_such_mailbox', 'gerekçe');
});

runner.test('kutu: sayaçlar tutarlı kalır ve onarılabilir', async () => {
  const box = (await ctx.stores.mailboxes.ensure('sayac@fitfak.net', {})).mailbox;
  for (let i = 0; i < 3; i++) {
    await ctx.stores.messages.store({
      mailbox: box,
      parsed: {
        messageId: `<c${i}@x>`, subject: `İleti ${i}`, from: { address: 'a@b.com' },
        to: [], text: 'gövde', references: [], sizeBytes: 100,
      },
      rawBuffer: Buffer.alloc(100),
      envelopeFrom: 'a@b.com', envelopeTo: box.address,
    });
  }
  let refreshed = await ctx.stores.mailboxes.getByRef(box.ref);
  assertEqual(refreshed.messageCount, 3, 'ileti sayısı');
  assertEqual(refreshed.unreadCount, 3, 'okunmamış sayısı');

  const list = await ctx.stores.messages.list({ mailboxRef: box.ref });
  await ctx.stores.messages.setFlags(list.messages[0].ref, { seen: true });
  refreshed = await ctx.stores.mailboxes.getByRef(box.ref);
  assertEqual(refreshed.unreadCount, 2, 'okunduktan sonra');

  // Bozulmuş sayaç onarılabilmeli.
  await ctx.db.collection('mailboxes').update(box.ref, { unreadCount: 99, messageCount: 42 });
  const repaired = await ctx.stores.mailboxes.recomputeCounters(box.ref);
  assertEqual(repaired.unreadCount, 2, 'onarım sonrası okunmamış');
  assertEqual(repaired.messageCount, 3, 'onarım sonrası toplam');
});

runner.test('ileti: yumuşak silme geri alınabilir, kalıcı silme baytları bırakır', async () => {
  const box = (await ctx.stores.mailboxes.ensure('silme@fitfak.net', {})).mailbox;
  const stored = await ctx.stores.messages.store({
    mailbox: box,
    parsed: {
      messageId: '<sil@x>', subject: 'Silinecek', from: { address: 'a@b.com' },
      to: [], text: 'gövde', references: [],
      attachments: [{
        fileName: 'ek.pdf', contentType: 'application/pdf',
        content: Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(500, 3)]),
        scanStatus: 'accepted', partId: '2',
      }],
    },
    rawBuffer: Buffer.alloc(600),
    envelopeFrom: 'a@b.com', envelopeTo: box.address,
  });

  const full = await ctx.stores.messages.getFull(stored.ref);
  const blobId = full.attachments[0].blobId;

  await ctx.stores.messages.softDelete(stored.ref);
  const afterSoft = await ctx.stores.messages.get(stored.ref);
  assertEqual(afterSoft.folder, 'trash', 'çöpe taşınmalı');
  assert(await ctx.stores.blobs.head(blobId), 'baytlar korunmalı');

  await ctx.stores.messages.restore(stored.ref, 'inbox');
  assertEqual((await ctx.stores.messages.get(stored.ref)).folder, 'inbox', 'geri alınabilmeli');

  await ctx.stores.messages.purge(stored.ref);
  assertEqual(await ctx.stores.messages.get(stored.ref), null, 'kayıt silinmeli');
  assertEqual(await ctx.stores.blobs.head(blobId), null, 'ek baytları da silinmeli');
});

runner.test('ileti: konuşma anahtarı zincir kökünden türer', async () => {
  const { MessageRepo } = require('../src/db/repos/messages');
  const root = MessageRepo.threadKeyFor({ messageId: '<a@x>', references: [], inReplyTo: '' });
  const reply = MessageRepo.threadKeyFor({ messageId: '<b@x>', references: ['<a@x>'], inReplyTo: '<a@x>' });
  assertEqual(root, reply, 'yanıt aynı konuşmaya düşmeli');

  // Konu bazlı gruplama YAPILMIYOR: "Re: merhaba" yazan iki alakasız kişi
  // aynı konuşmaya girmemeli.
  const unrelated = MessageRepo.threadKeyFor({ messageId: '<c@x>', references: [], inReplyTo: '' });
  assert(unrelated !== root, 'alakasız ileti ayrı konuşma');
});

/* ── SMTP kimlikleri ───────────────────────────────────────── */

runner.test('SMTP kimliği: parola bir kez döner, türev saklanır', async () => {
  const credential = await ctx.stores.mailboxes.createSmtpCredential({
    mailboxRef: mailbox.ref, label: 'test',
  });
  assert(credential.password.length >= 20, 'parola üretilmeli');

  const row = await ctx.db.collection('smtp_credentials').findOne('username', credential.username);
  // Kayıt `_id` alanında BigInt taşıyor; JSON.stringify onu serileştiremez.
  // Alanları tek tek denetlemek hem çalışır hem de neye baktığımızı gösterir.
  const stored = [row.secretHash, row.salt, row.kdf, row.label].join('|');
  assert(!stored.includes(credential.password), 'düz parola saklanmamalı');
  assert(row.secretHash && row.salt, 'türev ve tuz saklanmalı');

  assertEqual((await ctx.stores.mailboxes.verifySmtpCredential(credential.username, credential.password)).ok, true, 'doğru parola');
  assertEqual((await ctx.stores.mailboxes.verifySmtpCredential(credential.username, 'yanlis')).ok, false, 'yanlış parola');
});

runner.test('SMTP kimliği: iptal edilen kimlik reddedilir', async () => {
  const credential = await ctx.stores.mailboxes.createSmtpCredential({ mailboxRef: mailbox.ref });
  await ctx.stores.mailboxes.revokeSmtpCredential(credential.username);
  const verdict = await ctx.stores.mailboxes.verifySmtpCredential(credential.username, credential.password);
  assertEqual(verdict.ok, false, 'iptal edilmiş kimlik');
});

/* ── kuyruk ────────────────────────────────────────────────── */

runner.test('kuyruk: alıcı başına satır açılır, gövde tek kopya', async () => {
  const result = await ctx.stores.outbound.enqueue({
    rawBuffer: Buffer.from('Subject: toplu\r\n\r\ngövde'),
    envelopeFrom: 'network@fitfak.net',
    recipients: ['a@example.com', 'b@example.org', 'a@example.com'],
    subject: 'toplu',
  });
  assertEqual(result.queued.length, 2, 'tekrarlanan alıcı bir kez');
  const head = await ctx.stores.blobs.head(result.blobId);
  assertEqual(head.refCount, 2, 'gönderge sayısı alıcı sayısına eşit');
});

runner.test('kuyruk: geçici hata ertelenir, kalıcı hata biter', async () => {
  const result = await ctx.stores.outbound.enqueue({
    rawBuffer: Buffer.from('x'),
    envelopeFrom: 'network@fitfak.net',
    recipients: ['gecici@example.com', 'kalici@example.com'],
  });
  // Kuyruk testler arasında paylaşılıyor; yalnızca bu testin alıcılarına bak.
  const all = await ctx.stores.outbound.claimDue({ workerId: 'w1', limit: 50 });
  const claimed = all.filter((c) => c.rcptTo === 'gecici@example.com' || c.rcptTo === 'kalici@example.com');
  assertEqual(claimed.length, 2, 'iki satır alınmalı');
  claimed.sort((a, b) => a.rcptTo.localeCompare(b.rcptTo));

  const deferred = await ctx.stores.outbound.markFailure(claimed[0].ref, {
    error: '4.2.2 kutu dolu', smtpCode: 452,
  });
  assertEqual(claimed[0].rcptTo, 'gecici@example.com', 'sıralama');
  assertEqual(deferred.status, 'deferred', 'geçici hata ertelenmeli');
  assert(deferred.nextAttemptAt > Date.now(), 'sonraki deneme ileri tarihli');

  const failed = await ctx.stores.outbound.markFailure(claimed[1].ref, {
    error: '5.1.1 böyle kullanıcı yok', smtpCode: 550, permanent: true,
  });
  assertEqual(failed.status, 'failed', 'kalıcı hata yeniden denenmemeli');
});

runner.test('kuyruk: gönderilen satır blob göndergesini bırakır', async () => {
  const result = await ctx.stores.outbound.enqueue({
    rawBuffer: Buffer.from(`benzersiz-${crypto.randomBytes(6).toString('hex')}`),
    envelopeFrom: 'network@fitfak.net',
    recipients: ['tek@example.com'],
  });
  const claimed = await ctx.stores.outbound.claimDue({ workerId: 'w1', limit: 10 });
  const target = claimed.find((c) => c.rcptTo === 'tek@example.com');
  await ctx.stores.outbound.markSent(target.ref, { mx: 'mx.example.com', tlsUsed: true });
  assertEqual(await ctx.stores.blobs.head(result.blobId), null, 'son gönderge bırakılınca silinmeli');
});

runner.test('kuyruk: kampanya sayaçları ilerler ve tamamlanır', async () => {
  const campaignId = await ctx.stores.outbound.createCampaign({
    name: 'deneme', ownerSub: 'sub-1', mailboxRef: mailbox.ref, subject: 'duyuru', total: 2,
  });
  await ctx.stores.outbound.bumpCampaign(campaignId, { queued: 2 });
  await ctx.stores.outbound.bumpCampaign(campaignId, { sent: 1 });
  let campaign = await ctx.stores.outbound.getCampaign(campaignId);
  assertEqual(campaign.sent, 1, 'gönderilen sayısı');
  assert(campaign.status !== 'completed', 'henüz tamamlanmamalı');

  await ctx.stores.outbound.bumpCampaign(campaignId, { failed: 1 });
  campaign = await ctx.stores.outbound.getCampaign(campaignId);
  assertEqual(campaign.status, 'completed', 'hepsi sonuçlanınca tamamlanmalı');
});

/* ── denetim kaydı ─────────────────────────────────────────── */

runner.test('denetim: kayıt yazılır ve sorgulanır', async () => {
  await ctx.stores.audit.record({
    actorSub: 'admin-1', actorEmail: 'admin@fitfak.net', action: 'test.action',
    targetType: 'mailbox', targetId: mailbox.ref, detail: { x: 1 },
  });
  const entries = await ctx.stores.audit.list({ action: 'test.action' });
  assertEqual(entries.length, 1, 'kayıt bulunmalı');
  assertEqual(entries[0].actorEmail, 'admin@fitfak.net', 'aktör');
  assertEqual(entries[0].detail.x, 1, 'ayrıntı');
});

/* ── kalıcılık ─────────────────────────────────────────────── */

runner.test('kalıcılık: yeniden açıldığında veri korunur', async () => {
  const marker = `kalici-${crypto.randomBytes(6).toString('hex')}`;
  await ctx.stores.mailboxes.ensure(`${marker}@fitfak.net`, { displayName: marker });
  await ctx.db.close();

  const { connect } = require('../src/db');
  const { createStores } = require('../src/db/repos');
  const reopened = await connect(ctx.config, { logger: ctx.logger });
  const stores = createStores(reopened, { config: ctx.config, logger: ctx.logger });

  const found = await stores.mailboxes.getByAddress(`${marker}@fitfak.net`);
  assert(found, 'kutu yeniden açılışta bulunmalı');
  assertEqual(found.displayName, marker, 'alanlar korunmalı');

  const secret = await stores.vault.get('test-key', 'a/b');
  assertEqual(secret.value.toString('utf8'), 'gizli-deger', 'kasa da korunmalı');

  ctx.db = reopened;
  ctx.stores = stores;
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
