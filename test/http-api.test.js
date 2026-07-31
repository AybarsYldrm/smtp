'use strict';

const crypto = require('node:crypto');
const http = require('node:http');

const {
  createContext, cleanupAll, TestRunner, freePort,
  assert, assertEqual, assertMatch,
} = require('./helpers');

const runner = new TestRunner('HTTP API');

let ctx;
let servers;
let baseUrl;
let siteUrl;
let session;
let mailbox;

/* ── küçük HTTP istemcisi ──────────────────────────────────── */

function request(url, { method = 'GET', headers = {}, body = null, cookie = null } = {}) {
  const target = new URL(url);
  return new Promise((resolve, reject) => {
    const req = http.request({
      method,
      hostname: target.hostname,
      port: target.port,
      path: `${target.pathname}${target.search}`,
      headers: {
        host: headers.host || target.hostname,
        ...(cookie ? { cookie } : {}),
        ...headers,
      },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        const type = res.headers['content-type'] || '';
        let parsed = null;
        if (type.includes('json')) { try { parsed = JSON.parse(raw.toString('utf8')); } catch { /* ham kalsın */ } }
        resolve({ status: res.statusCode, headers: res.headers, json: parsed, raw, text: raw.toString('utf8') });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function json(url, options = {}) {
  return request(url, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(options.csrf ? { 'x-csrf-token': options.csrf } : {}),
      ...(options.headers || {}),
    },
    body: options.data ? JSON.stringify(options.data) : null,
  });
}

async function setup() {
  ctx = await createContext();

  // Vhost'ları test portlarına bağla; ikisi de 127.0.0.1 üzerinde ama ayrı port.
  const webmailPort = await freePort();
  const sitePort = await freePort();
  ctx.config.vhosts.length = 0;
  ctx.config.vhosts.push(
    { kind: 'webmail', host: 'mail.fitfak.net', bind: '127.0.0.1', port: webmailPort, aliases: [] },
    { kind: 'site', host: 'aybars.net.tr', bind: '127.0.0.1', port: sitePort, aliases: [] },
  );
  ctx.config.http.secureCookies = false;

  const ensured = await ctx.stores.mailboxes.ensure('network@fitfak.net', {
    displayName: 'Fitfak Ağ', ownerSub: 'sub-network',
  });
  mailbox = ensured.mailbox;
  await ctx.stores.mailboxes.ensure('ikinci@fitfak.net', { displayName: 'İkinci' });

  const { SessionManager } = require('../src/auth/session-manager');
  const { PushService } = require('../src/http/push');
  const { RealtimeHub } = require('../src/http/realtime');
  const { HttpServers } = require('../src/http/server');

  const sessions = new SessionManager({ config: ctx.config, logger: ctx.logger, stores: ctx.stores });
  const push = new PushService({ config: ctx.config, logger: ctx.logger, stores: ctx.stores });
  const realtime = new RealtimeHub({ logger: ctx.logger, stores: ctx.stores, config: ctx.config });
  ctx.pipeline.realtime = realtime;
  ctx.pipeline.notifier = push;

  servers = new HttpServers({
    config: ctx.config,
    logger: ctx.logger,
    stores: ctx.stores,
    sessions,
    pipeline: ctx.pipeline,
    queue: ctx.queue,
    push,
    realtime,
    signer: ctx.signer,
    certificates: null,
    dnsAuditor: null,
    smtpServer: null,
    startedAt: Date.now(),
  });
  await servers.start();

  baseUrl = `http://127.0.0.1:${webmailPort}`;
  siteUrl = `http://127.0.0.1:${sitePort}`;
  ctx.sessions = sessions;
  ctx.realtime = realtime;

  // Oturumu doğrudan depo üzerinden aç: IdP akışı ayrı testte doğrulanıyor.
  const created = await ctx.stores.sessions.create({
    idpSub: 'sub-network',
    idpEmail: 'network@fitfak.net',
    mailboxes: [{
      ref: mailbox.ref, address: mailbox.address, displayName: mailbox.displayName,
      role: 'owner', accessSource: 'local_address',
    }],
    scope: 'openid email mail',
    isAdmin: false,
  });
  session = created;
}

/* ── testler ───────────────────────────────────────────────── */

runner.test('kimlik doğrulamasız API 401 döner', async () => {
  const res = await request(`${baseUrl}/api/v1/me`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(res.status, 401, 'oturumsuz erişim');
  assertEqual(res.json.code, 'UNAUTHENTICATED', 'hata kodu');
});

runner.test('/api/v1/me kutuları ve sınırları döner', async () => {
  const res = await request(`${baseUrl}/api/v1/me`, {
    headers: { host: 'mail.fitfak.net' },
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
  });
  assertEqual(res.status, 200, 'durum');
  assertEqual(res.json.email, 'network@fitfak.net', 'adres');
  assertEqual(res.json.mailboxes.length, 1, 'kutu sayısı');
  assertEqual(res.json.mailboxes[0].role, 'owner', 'rol');
  assert(res.json.limits.maxAttachmentBytes > 0, 'ek sınırı bildirilmeli');
  assert(res.json.csrfToken, 'CSRF jetonu');
});

runner.test('beklenmeyen Host başlığı reddedilir', async () => {
  const res = await request(`${baseUrl}/api/v1/me`, {
    headers: { host: 'kotu.example' },
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
  });
  assertEqual(res.status, 421, 'yanlış Host reddedilmeli');
});

runner.test('ileti listesi ve okuma çalışır', async () => {
  await ctx.stores.messages.store({
    mailbox,
    parsed: {
      messageId: '<http-1@example.com>', subject: 'HTTP testi',
      from: { address: 'gonderen@example.com', name: 'Gönderen' },
      to: [{ address: mailbox.address }],
      text: 'Gövde metni burada.',
      html: '<p>Gövde <b>metni</b> burada.</p><script>alert(1)</script><img src="https://izleme.example/p.gif">',
      attachments: [{
        fileName: 'belge.pdf', contentType: 'application/pdf',
        content: Buffer.concat([Buffer.from('%PDF-'), Buffer.alloc(900, 1)]),
        scanStatus: 'accepted', partId: '2',
      }],
      references: [],
    },
    rawBuffer: Buffer.from('From: gonderen@example.com\r\n\r\nGövde'),
    envelopeFrom: 'gonderen@example.com',
    envelopeTo: mailbox.address,
  });

  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const list = await request(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/messages?folder=inbox`, {
    headers: { host: 'mail.fitfak.net' }, cookie,
  });
  assertEqual(list.status, 200, 'liste durumu');
  assertEqual(list.json.messages.length, 1, 'bir ileti');
  const ref = list.json.messages[0].ref;

  const message = await request(`${baseUrl}/api/v1/messages/${ref}`, {
    headers: { host: 'mail.fitfak.net' }, cookie,
  });
  assertEqual(message.status, 200, 'ileti durumu');
  assertEqual(message.json.subject, 'HTTP testi', 'konu');

  // Temizleme: betik gitmeli, uzak görsel engellenmeli.
  assert(!/<script/i.test(message.json.html), 'script etiketi temizlenmeli');
  assertMatch(message.json.html, /data-blocked-src="https:\/\/izleme\.example/, 'uzak görsel engellenmeli');
  assertMatch(message.json.html, /<b>metni<\/b>/, 'güvenli biçimlendirme korunmalı');

  // Ek bağlantısı jeton taşımalı.
  const attachment = message.json.attachments[0];
  assert(attachment.url && attachment.url.includes('?t='), 'ek bağlantısında jeton olmalı');

  const download = await request(`${baseUrl}${attachment.url}`, {
    headers: { host: 'mail.fitfak.net' }, cookie,
  });
  assertEqual(download.status, 200, 'ek indirme');
  assertEqual(download.raw.length, 905, 'ek boyutu');
  assertMatch(download.headers['content-disposition'], /belge\.pdf/, 'dosya adı');
  assertEqual(download.headers['x-content-type-options'], 'nosniff', 'sniff koruması');

  ctx.messageRef = ref;
  ctx.attachmentUrl = attachment.url;
});

runner.test('ek bağlantısı oturumsuz kullanılamaz', async () => {
  const res = await request(`${baseUrl}${ctx.attachmentUrl}`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(res.status, 401, 'jeton tek başına yetmemeli');
});

runner.test('ek jetonu başka oturumda geçersizdir', async () => {
  const other = await ctx.stores.sessions.create({
    idpSub: 'sub-other', idpEmail: 'ikinci@fitfak.net',
    mailboxes: [{ ref: mailbox.ref, address: mailbox.address, role: 'owner', accessSource: 'grant' }],
  });
  const res = await request(`${baseUrl}${ctx.attachmentUrl}`, {
    headers: { host: 'mail.fitfak.net' },
    cookie: `${ctx.config.http.sessionCookieName}=${other.sid}`,
  });
  assertEqual(res.status, 403, 'başka oturumun jetonu kabul edilmemeli');
});

runner.test('CSRF jetonu olmadan durum değiştirilemez', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const res = await json(`${baseUrl}/api/v1/messages/${ctx.messageRef}/flags`, {
    method: 'POST', cookie, data: { flagged: true },
    headers: { host: 'mail.fitfak.net' },
  });
  assertEqual(res.status, 403, 'CSRF olmadan reddedilmeli');
  assertEqual(res.json.code, 'CSRF_INVALID', 'hata kodu');
});

runner.test('CSRF jetonuyla bayrak değiştirilebilir', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const res = await json(`${baseUrl}/api/v1/messages/${ctx.messageRef}/flags`, {
    method: 'POST', cookie, csrf: session.csrfToken, data: { flagged: true },
    headers: { host: 'mail.fitfak.net' },
  });
  assertEqual(res.status, 200, 'bayrak güncellenmeli');
  const message = await ctx.stores.messages.get(ctx.messageRef);
  assertEqual(message.flagged, true, 'kayıt güncellenmeli');
});

runner.test('erişilmeyen kutuya istek 403 döner', async () => {
  const other = await ctx.stores.mailboxes.getByAddress('ikinci@fitfak.net');
  const res = await request(`${baseUrl}/api/v1/mailboxes/${other.ref}/messages`, {
    headers: { host: 'mail.fitfak.net' },
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
  });
  assertEqual(res.status, 403, 'yetkisiz kutu');
  assertEqual(res.json.code, 'MAILBOX_FORBIDDEN', 'hata kodu');
});

runner.test('gönderim JSON ile çalışır ve DKIM imzalar', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const res = await json(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/send`, {
    method: 'POST', cookie, csrf: session.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: {
      to: 'alici@example.com',
      subject: 'API üzerinden gönderim',
      text: 'Merhaba, bu API üzerinden gönderildi.',
      attachments: [{
        fileName: 'not.txt', contentType: 'text/plain',
        content: Buffer.from('küçük bir not').toString('base64'),
      }],
    },
  });
  assertEqual(res.status, 200, 'gönderim durumu');
  assertEqual(res.json.dkimSigned, true, 'DKIM imzalanmalı');
  assertEqual(res.json.queued.length, 1, 'kuyruğa alınmalı');
  assert(res.json.sentRef, 'gönderilenler kopyası olmalı');
});

runner.test('yasaklı uzantı gönderimde reddedilir', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const res = await json(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/send`, {
    method: 'POST', cookie, csrf: session.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: {
      to: 'alici@example.com', subject: 'kötü ek', text: 'x',
      attachments: [{
        fileName: 'kurulum.exe', contentType: 'application/octet-stream',
        content: Buffer.from('MZ').toString('base64'),
      }],
    },
  });
  assertEqual(res.status, 415, 'uzantı reddedilmeli');
  assertEqual(res.json.code, 'EXTENSION_BLOCKED', 'hata kodu');
});

runner.test('S/MIME sertifikası yokken imzalı gönderim açık hata verir', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const res = await json(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/send`, {
    method: 'POST', cookie, csrf: session.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: { to: 'alici@example.com', subject: 'imzalı', text: 'x', smime: true },
  });
  assertEqual(res.status, 409, 'sertifika yoksa 409');
  assertEqual(res.json.code, 'NO_SMIME_CERT', 'hata kodu');
});

runner.test('iletme (forward) uç noktası çalışır', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const res = await json(`${baseUrl}/api/v1/messages/${ctx.messageRef}/forward`, {
    method: 'POST', cookie, csrf: session.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: { to: 'baskasi@example.org', comment: 'Bilgine.' },
  });
  assertEqual(res.status, 200, 'iletme durumu');
  assertEqual(res.json.queued.length, 1, 'kuyruğa alınmalı');
  assertEqual(res.json.hasOriginalRaw, true, 'ham ileti ek olarak gitmeli');
});

runner.test('gönderim hız sınırı uygulanır', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const original = ctx.config.http.rateLimit.sendMax;
  // Sınırlayıcı kurulumda oluşturuldu; doğrudan onun üzerinden daraltıyoruz.
  servers.sendLimiter.max = 2;
  servers.sendLimiter.buckets.clear();

  const send = () => json(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/send`, {
    method: 'POST', cookie, csrf: session.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: { to: 'alici@example.com', subject: 'hız', text: 'x' },
  });
  await send();
  await send();
  const third = await send();
  assertEqual(third.status, 429, 'üçüncü istek sınırlanmalı');
  assertEqual(third.json.code, 'SEND_RATE_LIMITED', 'hata kodu');

  servers.sendLimiter.max = original;
  servers.sendLimiter.buckets.clear();
});

runner.test('durum uçları: healthz açık, ayrıntı korumalı', async () => {
  const health = await request(`${baseUrl}/healthz`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(health.status, 200, 'healthz açık olmalı');
  assertEqual(health.json.status, 'ok', 'sağlık durumu');
  assert(!health.text.includes('fitfak.net'), 'healthz alan adı sızdırmamalı');

  const anonymous = await request(`${baseUrl}/api/v1/status`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(anonymous.status, 401, 'ayrıntılı durum korumalı');

  const authenticated = await request(`${baseUrl}/api/v1/status`, {
    headers: { host: 'mail.fitfak.net' },
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
  });
  assertEqual(authenticated.status, 200, 'oturumla erişilebilmeli');
  // Yönetici olmayan kuyruk ayrıntısını görmemeli.
  assert(!authenticated.json.domains, 'yönetici olmayana alan adı listesi verilmemeli');
});

runner.test('yönetici olmayan, kimlik bağı kuramaz', async () => {
  const res = await json(`${baseUrl}/api/v1/admin/identity-links`, {
    method: 'POST',
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
    csrf: session.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: { externalEmail: 'x@gmail.com', mailbox: mailbox.address, reason: 'deneme' },
  });
  assertEqual(res.status, 403, 'yönetici gerekli');
  assertEqual(res.json.code, 'ADMIN_REQUIRED', 'hata kodu');
});

runner.test('yönetici kimlik bağı kurarken gerekçe zorunlu', async () => {
  const admin = await ctx.stores.sessions.create({
    idpSub: 'sub-admin', idpEmail: 'admin@fitfak.net', mailboxes: [], isAdmin: true,
  });
  const cookie = `${ctx.config.http.sessionCookieName}=${admin.sid}`;

  const missing = await json(`${baseUrl}/api/v1/admin/identity-links`, {
    method: 'POST', cookie, csrf: admin.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: { externalEmail: 'aybarsyildirim.mail@gmail.com', mailbox: mailbox.address },
  });
  assertEqual(missing.status, 400, 'gerekçesiz reddedilmeli');
  assertEqual(missing.json.code, 'REASON_REQUIRED', 'hata kodu');

  const created = await json(`${baseUrl}/api/v1/admin/identity-links`, {
    method: 'POST', cookie, csrf: admin.csrfToken,
    headers: { host: 'mail.fitfak.net' },
    data: {
      externalEmail: 'aybarsyildirim.mail@gmail.com',
      mailbox: mailbox.address,
      allowSendAs: true,
      reason: 'kişisel adres bağlanıyor',
    },
  });
  assertEqual(created.status, 201, 'bağ kurulmalı');

  const links = await request(`${baseUrl}/api/v1/admin/identity-links`, {
    headers: { host: 'mail.fitfak.net' }, cookie,
  });
  assertEqual(links.json.links.length, 1, 'bağ listelenmeli');
  assertEqual(links.json.links[0].allowSendAs, true, 'gönderme yetkisi');
});

runner.test('kişisel site ana sayfası açılır', async () => {
  const res = await request(`${siteUrl}/`, { headers: { host: 'aybars.net.tr' } });
  assertEqual(res.status, 200, 'site durumu');
  assertMatch(res.text, /Aybars Yıldırım/, 'içerik');
  assertMatch(res.headers['content-security-policy'], /default-src 'self'/, 'CSP başlığı');
});

runner.test('Instagram ziyareti kaydedilir, diğerleri kaydedilmez', async () => {
  await request(`${siteUrl}/`, {
    headers: {
      host: 'aybars.net.tr',
      'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Instagram 300.0.0.0',
    },
  });
  await request(`${siteUrl}/`, {
    headers: { host: 'aybars.net.tr', 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120' },
  });
  // Kayıt yanıt yolunu bekletmiyor; kısa bir bekleme gerekiyor.
  await new Promise((r) => setTimeout(r, 120));

  const visits = await ctx.stores.visits.recent({ limit: 10 });
  assertEqual(visits.length, 1, 'yalnızca Instagram ziyareti kaydedilmeli');
  assertEqual(visits[0].source, 'instagram', 'kaynak');
  assertEqual(visits[0].os, 'iOS', 'işletim sistemi');
});

runner.test('bildirim paneli oturum ister', async () => {
  const anonymous = await request(`${siteUrl}/bildirimler`, { headers: { host: 'aybars.net.tr' } });
  assertEqual(anonymous.status, 401, 'oturumsuz erişim');

  const withSession = await request(`${siteUrl}/bildirimler`, {
    headers: { host: 'aybars.net.tr' },
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
  });
  assertEqual(withSession.status, 200, 'oturumla erişim');
  assertMatch(withSession.text, /Bildirimler/, 'başlık');
  assert(!withSession.text.includes('{{ROWS}}'), 'şablon doldurulmalı');
});

runner.test('gerçek zamanlı SSE akışı olay yayınlar', async () => {
  const target = new URL(`${baseUrl}/api/v1/events`);
  const received = [];
  const done = new Promise((resolve, reject) => {
    const req = http.request({
      hostname: target.hostname, port: target.port, path: target.pathname,
      headers: {
        host: 'mail.fitfak.net',
        cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
        accept: 'text/event-stream',
      },
    }, (res) => {
      assertEqual(res.statusCode, 200, 'SSE durumu');
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        for (const line of chunk.split('\n')) {
          if (!line.startsWith('data: ')) continue;
          const payload = JSON.parse(line.slice(6));
          received.push(payload);
          if (payload.type === 'message') { req.destroy(); resolve(); }
        }
      });
    });
    req.on('error', (err) => { if (received.length) resolve(); else reject(err); });
    req.end();
    setTimeout(() => {
      // Akış kurulduktan sonra bir ileti yayınla.
      ctx.realtime.publishMessage(mailbox.ref, { ref: 'x1', subject: 'Canlı ileti', seq: 99 });
    }, 150);
    setTimeout(() => { req.destroy(); reject(new Error('SSE olayı gelmedi')); }, 4000);
  });

  await done;
  assert(received.some((p) => p.type === 'hello'), 'hello olayı');
  const message = received.find((p) => p.type === 'message');
  assert(message, 'ileti olayı');
  assertEqual(message.message.subject, 'Canlı ileti', 'olay içeriği');
});

runner.test('kaçırılan iletiler sıra numarasıyla alınır', async () => {
  const cookie = `${ctx.config.http.sessionCookieName}=${session.sid}`;
  const before = await request(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/counts`, {
    headers: { host: 'mail.fitfak.net' }, cookie,
  });
  assertEqual(before.status, 200, 'sayaç');

  // Devam noktası KUTU genelindedir, klasör başına değil: gönderilenler de
  // sıra numarası tüketir ve istemci kaçırdığı her şeyi ister.
  const everything = await ctx.stores.messages.since({ mailboxRef: mailbox.ref, seq: 0, limit: 500 });
  const highestSeq = Math.max(...everything.map((m) => m.seq), 0);

  await ctx.stores.messages.store({
    mailbox,
    parsed: {
      messageId: '<catchup-1@example.com>', subject: 'Kaçırılan',
      from: { address: 'x@example.com' }, to: [], text: 'sonradan', references: [],
    },
    rawBuffer: Buffer.from('x'),
    envelopeFrom: 'x@example.com', envelopeTo: mailbox.address,
  });

  const since = await request(`${baseUrl}/api/v1/mailboxes/${mailbox.ref}/since/${highestSeq}`, {
    headers: { host: 'mail.fitfak.net' }, cookie,
  });
  assertEqual(since.status, 200, 'devam sorgusu');
  assertEqual(since.json.messages.length, 1, 'yalnızca yeni ileti');
  assertEqual(since.json.messages[0].subject, 'Kaçırılan', 'içerik');
  assert(since.json.lastSeq > highestSeq, 'son sıra numarası ilerlemeli');
});

runner.test('bilinmeyen API yolu JSON 404 döner', async () => {
  const res = await request(`${baseUrl}/api/v1/yok`, {
    headers: { host: 'mail.fitfak.net' },
    cookie: `${ctx.config.http.sessionCookieName}=${session.sid}`,
  });
  assertEqual(res.status, 404, 'durum');
  assertEqual(res.json.code, 'NOT_FOUND', 'JSON hata biçimi');
});

runner.test('arayüz dosyaları sunulur', async () => {
  const app = await request(`${baseUrl}/`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(app.status, 200, 'arayüz');
  assertMatch(app.text, /Fitfak Posta/, 'başlık');

  const css = await request(`${baseUrl}/static/fitfak-ui.css`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(css.status, 200, 'ortak CSS shared/ dizininden gelmeli');
  assertMatch(css.headers['content-type'], /text\/css/, 'içerik türü');

  const sw = await request(`${baseUrl}/sw.js`, { headers: { host: 'mail.fitfak.net' } });
  assertEqual(sw.status, 200, 'servis işçisi');
  assertMatch(sw.headers['cache-control'], /no-store/, 'servis işçisi önbelleklenmemeli');
});

runner.test('statik dosyada yol kaçışı engellenir', async () => {
  const res = await request(`${baseUrl}/static/....//....//src/config.js`, {
    headers: { host: 'mail.fitfak.net' },
  });
  assert(res.status === 404 || res.status === 400, `yol kaçışı engellenmeli (${res.status})`);
  assert(!res.text.includes('FITFAK_MAIL_VAULT_SECRET'), 'kaynak sızmamalı');
});

(async () => {
  try {
    await setup();
    const ok = await runner.run();
    ctx.realtime.close();
    await servers.stop();
    await ctx.close();
    await cleanupAll();
    process.exit(ok ? 0 : 1);
  } catch (err) {
    process.stderr.write(`kurulum hatası: ${err.stack}\n`);
    if (servers) await servers.stop().catch(() => {});
    if (ctx) await ctx.close().catch(() => {});
    await cleanupAll();
    process.exit(1);
  }
})();
