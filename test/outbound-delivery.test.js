'use strict';

const net = require('node:net');

const {
  createContext, cleanupAll, freePort, TestRunner, assert, assertEqual,
} = require('./helpers');

/**
 * Uçtan uca giden teslimat — gerçek kuyruk, gerçek veritabanı, gerçek SMTP
 * konuşması.
 *
 * ── NEDEN BU TEST VAR ────────────────────────────────────────────────────
 * Bildirilen arıza şuydu: kayıtta "kuyruğa alındı recipients=1" satırı
 * görünüyor, sonrası gelmiyor; veritabanına bağlanan diğer istemciler de
 * yanıt alamıyor; sunucu yeniden başlatıldığında sorun sürüyor ve ancak
 * veritabanı SİLİNDİĞİNDE geçiyordu.
 *
 * Nedeni teslimat kodunda değil, kuyruğun iş alma sorgusundaydı:
 * `findRange('nextAttemptAt', 0, now)`, dakika genişliğinde kovalanmış bir
 * alanda epoch'tan bugüne kadar her kovayı tek tek tarıyordu — otuz milyona
 * yakın eşzamanlı HMAC, olay döngüsü kilitli hâlde iki dakikadan uzun. Boş
 * bir koleksiyonda hızlıydı (alanın kova haritası ilk satır yazılana kadar
 * yok), bu yüzden veritabanını silmek "çözüyor", ilk ileti kuyruğa girince
 * geri geliyordu.
 *
 * Var olan testlerin hiçbiri bunu yakalayamazdı: hepsi `queue.tick`'i devre
 * dışı bırakıyor. Bu test gerçek turu çalıştırıyor ve sonucu ZAMAN SINIRIYLA
 * birlikte doğruluyor — çünkü arıza "yanlış sonuç" değil, "hiç sonuç yok"
 * biçiminde ortaya çıkıyordu.
 */

/** Sahte alıcı MX: konuşmayı tamamlar ve aldığı iletiyi saklar. */
function startFakeMx({ port, rejectWith = null }) {
  const received = [];
  const server = net.createServer((socket) => {
    let stage = 'greeting';
    let buffer = '';
    let body = '';
    const envelope = { from: '', to: [] };

    socket.setEncoding('latin1');
    socket.write('220 sahte-mx.example ESMTP\r\n');

    socket.on('data', (chunk) => {
      buffer += chunk;
      let idx;
      while ((idx = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, idx).replace(/\r$/, '');
        buffer = buffer.slice(idx + 1);

        if (stage === 'data') {
          if (line === '.') {
            stage = 'greeting';
            received.push({ envelope: { from: envelope.from, to: [...envelope.to] }, body });
            body = '';
            envelope.to.length = 0;
            socket.write('250 2.0.0 kabul edildi\r\n');
          } else {
            // Nokta doldurma geri alınır (RFC 5321 §4.5.2).
            body += `${line.startsWith('..') ? line.slice(1) : line}\n`;
          }
          continue;
        }

        const upper = line.toUpperCase();
        if (upper.startsWith('EHLO') || upper.startsWith('HELO')) {
          socket.write('250-sahte-mx.example\r\n250-8BITMIME\r\n250 SIZE 52428800\r\n');
        } else if (upper.startsWith('MAIL FROM')) {
          if (rejectWith) { socket.write(`${rejectWith}\r\n`); continue; }
          envelope.from = (line.match(/<([^>]*)>/) || [])[1] || '';
          socket.write('250 2.1.0 gönderen kabul edildi\r\n');
        } else if (upper.startsWith('RCPT TO')) {
          envelope.to.push((line.match(/<([^>]*)>/) || [])[1] || '');
          socket.write('250 2.1.5 alıcı kabul edildi\r\n');
        } else if (upper === 'DATA') {
          stage = 'data';
          socket.write('354 gövdeyi gönderin\r\n');
        } else if (upper === 'QUIT') {
          socket.write('221 2.0.0 hoşça kalın\r\n');
          socket.end();
        } else if (upper === 'RSET') {
          socket.write('250 2.0.0 sıfırlandı\r\n');
        } else {
          socket.write('500 5.5.1 anlaşılmadı\r\n');
        }
      }
    });
    socket.on('error', () => {});
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({
      server, received,
      close: () => new Promise((done) => server.close(done)),
    }));
  });
}

/** Kuyruk bir koşula ulaşana kadar gerçek turları çalıştırır. */
async function runQueueUntil(queue, predicate, { timeoutMs = 20_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    await queue.tick();
    if (predicate()) return Date.now();
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`kuyruk ${timeoutMs}ms içinde beklenen duruma ulaşmadı`);
}

const runner = new TestRunner('giden teslimat (uçtan uca)');

for (const driver of ['file', 'fitfak']) {
  runner.test(`[${driver}] kuyruğa alınan ileti gerçekten teslim edilir`, async () => {
    const mxPort = await freePort();
    const mx = await startFakeMx({ port: mxPort });
    const ctx = await createContext({ driver, liveQueue: true });
    try {
      // Teslimat DNS'e çıkmaz: alıcı MX'i doğrudan yerel sahte sunucu.
      ctx.queue.deliveryOptions = { mxOverride: '127.0.0.1', port: mxPort };

      const raw = Buffer.from(
        'From: network@fitfak.net\r\n'
        + 'To: alici@example.com\r\n'
        + 'Subject: uctan uca deneme\r\n'
        + 'Message-ID: <e2e-1@fitfak.net>\r\n'
        + '\r\n'
        + 'Gövde.\r\n',
        'utf8',
      );

      await ctx.queue.enqueue({
        rawBuffer: raw,
        envelopeFrom: 'network@fitfak.net',
        recipients: ['alici@example.com'],
        subject: 'uctan uca deneme',
        messageId: '<e2e-1@fitfak.net>',
      });

      // ZAMAN SINIRI ASIL DENETİM. Aralık sorgusu kovaları tek tek taradığı
      // sürece bu tur, tek satırlık bir kuyrukta bile iki dakikadan uzun
      // sürüyordu; sonuç doğru olsa bile bu bir arıza.
      const startedAt = Date.now();
      await runQueueUntil(ctx.queue, () => mx.received.length > 0, { timeoutMs: 20_000 });
      const elapsed = Date.now() - startedAt;

      assertEqual(mx.received.length, 1, 'sahte MX iletiyi tam olarak bir kez almalı');
      assertEqual(mx.received[0].envelope.from, 'network@fitfak.net', 'zarf göndereni');
      assertEqual(mx.received[0].envelope.to[0], 'alici@example.com', 'zarf alıcısı');
      assert(mx.received[0].body.includes('uctan uca deneme'), 'gövde konuyu içermeli');
      assert(elapsed < 10_000, `kuyruk turu ${elapsed}ms sürdü; teslimat aralık sorgusunun arkasında beklememeli`);

      // Kuyruk satırı 'sent' olmalı ve teslimat kaydı MX ile kodu taşımalı.
      const queued = await ctx.stores.outbound.byQueueId(
        (await ctx.stores.outbound.listByMailbox('', { limit: 50 }))[0]?.queueId
        || mx.received[0].queueId || '',
      ).catch(() => null);
      const stats = await ctx.stores.outbound.stats();
      assertEqual(stats.sent, 1, 'kuyrukta bir satır gönderilmiş olarak işaretlenmeli');
      assertEqual(stats.queued + stats.deferred + stats.sending, 0, 'bekleyen satır kalmamalı');
      if (queued) {
        assert(Array.isArray(queued.deliveryLog), 'teslimat kaydı bir dizi olmalı');
      }
    } finally {
      await ctx.close();
      await mx.close();
    }
  });

  runner.test(`[${driver}] ham ileti gövdesi blob turundan birebir geçer`, async () => {
    const ctx = await createContext({ driver, liveQueue: true });
    try {
      // Çok parçalı olsun diye parça boyutundan büyük: kuyruğa alınan ham
      // ileti okunamazsa teslimat "ham ileti bulunamadı" ile ölür ve posta
      // hiç gitmez — uzak sürücüde tam olarak bu oluyordu.
      const raw = Buffer.concat([
        Buffer.from('Subject: buyuk ileti\r\nMessage-ID: <blob-1@fitfak.net>\r\n\r\n', 'utf8'),
        require('node:crypto').randomBytes(700 * 1024),
      ]);

      const result = await ctx.stores.outbound.enqueue({
        rawBuffer: raw,
        envelopeFrom: 'network@fitfak.net',
        recipients: ['blob@example.com'],
      });

      const row = await ctx.stores.outbound.byQueueId(result.queued[0]);
      const readBack = await ctx.stores.outbound.getRaw(row);

      assert(readBack, 'kuyruğa alınan ham ileti geri okunabilmeli');
      assertEqual(readBack.length, raw.length, 'uzunluk birebir olmalı');
      assert(readBack.equals(raw), 'baytlar birebir olmalı');
    } finally { await ctx.close(); }
  });

  runner.test(`[${driver}] eşzamanlı turlar iletiyi iki kez teslim etmez`, async () => {
    const mxPort = await freePort();
    const mx = await startFakeMx({ port: mxPort });
    const ctx = await createContext({ driver, liveQueue: true });
    try {
      ctx.queue.deliveryOptions = { mxOverride: '127.0.0.1', port: mxPort };
      await ctx.queue.enqueue({
        rawBuffer: Buffer.from('Subject: tek kez\r\n\r\ngövde\r\n', 'utf8'),
        envelopeFrom: 'network@fitfak.net',
        recipients: ['tekrar@example.com'],
      });

      // `claimDue` satırları önce okuyup sonra kilitliyor ve arada bir `await`
      // var: paralel turlar aynı satırı iki kez talep edip iki kez teslim
      // ediyordu. Üretimde bu, `enqueue()`in başlattığı tur ile yoklama
      // zamanlayıcısının turu çakıştığında oluyor.
      await Promise.all([
        ctx.queue.tick(), ctx.queue.tick(), ctx.queue.tick(), ctx.queue.tick(),
      ]);
      // Bekleyen tur varsa onun da bitmesine izin ver.
      await new Promise((r) => setTimeout(r, 300));
      await ctx.queue.tick();

      assertEqual(mx.received.length, 1, 'ileti alıcıya TAM OLARAK BİR KEZ ulaşmalı');
      const stats = await ctx.stores.outbound.stats();
      assertEqual(stats.sent, 1, 'kuyrukta tek bir gönderilmiş satır olmalı');
    } finally {
      await ctx.close();
      await mx.close();
    }
  });

  runner.test(`[${driver}] geçici hata kalıcı sayılmaz ve yeniden denenir`, async () => {
    const mxPort = await freePort();
    // 451: geçici hata. Kalıcı sayılırsa satır FAILED'a düşer ve bir daha
    // denenmez — sessizce kaybolan posta bu şekilde oluyor.
    const mx = await startFakeMx({ port: mxPort, rejectWith: '451 4.3.0 şimdi olmaz' });
    const ctx = await createContext({ driver, liveQueue: true });
    try {
      ctx.queue.deliveryOptions = { mxOverride: '127.0.0.1', port: mxPort };
      await ctx.queue.enqueue({
        rawBuffer: Buffer.from('Subject: ertelenecek\r\n\r\ngövde\r\n', 'utf8'),
        envelopeFrom: 'network@fitfak.net',
        recipients: ['gecici@example.com'],
      });

      await ctx.queue.tick();

      const stats = await ctx.stores.outbound.stats();
      assertEqual(stats.failed, 0, '4xx kalıcı hata sayılmamalı');
      assertEqual(stats.deferred, 1, '4xx satırı ertelenmiş olmalı');
    } finally {
      await ctx.close();
      await mx.close();
    }
  });

  runner.test(`[${driver}] alan adı geri çekilmesi deneme hakkı harcamaz`, async () => {
    const ctx = await createContext({ driver, liveQueue: true });
    try {
      await ctx.queue.enqueue({
        rawBuffer: Buffer.from('Subject: beklet\r\n\r\ngövde\r\n', 'utf8'),
        envelopeFrom: 'network@fitfak.net',
        recipients: ['bekleyen@example.com'],
      });

      // Alan adını geri çekilmeye al: tur, satırı alıp bırakmalı.
      ctx.queue._backoffDomain('example.com', 60_000);

      // maxAttempts'ten fazla tur çevir. Eskiden her tur bir deneme
      // harcıyordu ve satır, hiçbir sunucuya bağlanılmadan KALICI OLARAK
      // başarısız işaretleniyordu.
      const rounds = ctx.config.queue.maxAttempts + 3;
      for (let i = 0; i < rounds; i++) await ctx.queue.tick();

      const stats = await ctx.stores.outbound.stats();
      assertEqual(stats.failed, 0,
        `${rounds} tur geri çekilmeden sonra satır kalıcı başarısız olmamalı`);
      assertEqual(stats.queued + stats.deferred, 1, 'satır hâlâ gönderilmeyi beklemeli');

      const [row] = await ctx.stores.outbound.listByMailbox('', { limit: 10 });
      if (row) assertEqual(row.attempts, 0, 'hiç denenmemiş bir satırın deneme sayısı 0 kalmalı');
    } finally {
      await ctx.close();
    }
  });
}

if (require.main === module) {
  runner.run().then((ok) => cleanupAll().then(() => process.exit(ok ? 0 : 1)));
}

module.exports = { runner };
