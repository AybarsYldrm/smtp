'use strict';

const crypto = require('node:crypto');
const http = require('node:http');

const {
  createContext, cleanupAll, TestRunner, freePort,
  assert, assertEqual, assertThrows,
} = require('./helpers');

const runner = new TestRunner('Fitfak IdP kimlik doğrulama ve kimlik bağları');

let ctx;
let idpServer;
let sessions;
let networkMailbox;

/**
 * Sahte IdP. Gerçek session.fitfak.net'e bağlanmadan akışın tamamı
 * denenebilsin diye; testin doğruluğu ağ erişimine bağlı olmamalı.
 */
function startStubIdp(port) {
  const codes = new Map();
  const tokens = new Map();
  const users = {
    'sub-network': { sub: 'sub-network', email: 'network@fitfak.net', name: 'Fitfak Ağ', roles: ['user'] },
    'sub-admin': { sub: 'sub-admin', email: 'admin@fitfak.net', name: 'Yönetici', roles: ['admin'] },
    'sub-gmail': { sub: 'sub-gmail', email: 'aybarsyildirim.mail@gmail.com', name: 'Aybars', roles: ['user'] },
  };

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      const form = new URLSearchParams(body);
      const send = (code, obj) => {
        const payload = JSON.stringify(obj);
        res.writeHead(code, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
        res.end(payload);
      };

      if (url.pathname === '/oauth/token') {
        const grant = form.get('grant_type');
        if (grant === 'authorization_code') {
          const entry = codes.get(form.get('code'));
          if (!entry) return send(400, { error: 'invalid_grant' });
          // PKCE doğrulaması: sunucu tarafında da yapılıyor ki istemcinin
          // doğrulayıcıyı gerçekten gönderdiğini test edelim.
          const challenge = crypto.createHash('sha256').update(form.get('code_verifier') || '')
            .digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
          if (challenge !== entry.codeChallenge) return send(400, { error: 'invalid_grant', reason: 'pkce' });
          codes.delete(form.get('code'));
          const accessToken = `at_${crypto.randomBytes(12).toString('hex')}`;
          tokens.set(accessToken, entry.sub);
          return send(200, {
            access_token: accessToken,
            refresh_token: `rt_${crypto.randomBytes(8).toString('hex')}`,
            token_type: 'Bearer',
            expires_in: 3600,
            scope: 'openid profile email mail',
          });
        }
        if (grant === 'client_credentials') {
          const accessToken = `svc_${crypto.randomBytes(12).toString('hex')}`;
          tokens.set(accessToken, 'service');
          return send(200, { access_token: accessToken, token_type: 'Bearer', expires_in: 600, scope: 'cert:issue' });
        }
        return send(400, { error: 'unsupported_grant_type' });
      }

      if (url.pathname === '/oauth/userinfo') {
        const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
        const sub = tokens.get(token);
        if (!sub || !users[sub]) return send(401, { error: 'invalid_token' });
        return send(200, users[sub]);
      }

      if (url.pathname === '/oauth/introspect') {
        const token = form.get('token');
        const sub = tokens.get(token);
        if (!sub) return send(200, { active: false });
        return send(200, { active: true, ...users[sub], scope: 'openid profile email mail' });
      }

      if (url.pathname === '/.well-known/jwks.json') return send(200, { keys: [] });

      send(404, { error: 'not_found' });
    });
  });

  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve({
      server,
      /** Tarayıcı yönlendirmesini benzetir: state için bir kod üretir. */
      authorize(state, codeChallenge, sub) {
        const code = `code_${crypto.randomBytes(10).toString('hex')}`;
        codes.set(code, { state, codeChallenge, sub });
        return code;
      },
      revokeToken(token) { tokens.delete(token); },
      tokens,
    }));
  });
}

async function setup() {
  const port = await freePort();
  idpServer = await startStubIdp(port);

  ctx = await createContext();
  ctx.config.idp.baseUrl = `http://127.0.0.1:${port}`;
  ctx.config.idp.clientId = 'mail-client';
  ctx.config.idp.clientSecret = 'mail-secret';

  const { SessionManager } = require('../src/auth/session-manager');
  sessions = new SessionManager({
    config: ctx.config, logger: ctx.logger, stores: ctx.stores,
  });

  networkMailbox = (await ctx.stores.mailboxes.ensure('network@fitfak.net', {
    displayName: 'Fitfak Ağ', ownerSub: 'sub-network',
  })).mailbox;
  await ctx.stores.mailboxes.ensure('admin@fitfak.net', { ownerSub: 'sub-admin' });
}

/** Uçtan uca giriş: yetkilendirme -> kod -> oturum. */
async function login(sub) {
  const begin = await sessions.beginLogin({ ip: '203.0.113.5', userAgent: 'test-agent' });
  const url = new URL(begin.url);
  const state = url.searchParams.get('state');
  const codeChallenge = url.searchParams.get('code_challenge');
  assertEqual(url.searchParams.get('code_challenge_method'), 'S256', 'PKCE yöntemi');
  assert(url.searchParams.get('scope').includes('email'), 'email kapsamı istenmeli');

  const code = idpServer.authorize(state, codeChallenge, sub);
  return sessions.completeLogin({ code, state, ip: '203.0.113.5', userAgent: 'test-agent' });
}

runner.test('yerel adresle giriş kendi kutusuna erişim verir', async () => {
  const result = await login('sub-network');
  assertEqual(result.profile.email, 'network@fitfak.net', 'profil adresi');
  assertEqual(result.mailboxes.length, 1, 'bir kutu');
  assertEqual(result.mailboxes[0].address, 'network@fitfak.net', 'kutu adresi');
  assertEqual(result.mailboxes[0].role, 'owner', 'sahip rolü');
  assertEqual(result.isAdmin, false, 'yönetici değil');

  const session = await sessions.authenticate({ sid: result.sid });
  assert(session, 'oturum çözülmeli');
  assertEqual(session.idpEmail, 'network@fitfak.net', 'oturum adresi');
});

runner.test('state tek kullanımlıktır', async () => {
  const begin = await sessions.beginLogin({});
  const url = new URL(begin.url);
  const state = url.searchParams.get('state');
  const challenge = url.searchParams.get('code_challenge');
  const code1 = idpServer.authorize(state, challenge, 'sub-network');
  await sessions.completeLogin({ code: code1, state });

  const code2 = idpServer.authorize(state, challenge, 'sub-network');
  await assertThrows(
    () => sessions.completeLogin({ code: code2, state }),
    /state geçersiz/,
    'aynı state ikinci kez kullanılamamalı',
  );
});

runner.test('gmail adresiyle giren, bağ olmadan hiçbir kutuya erişemez', async () => {
  const result = await login('sub-gmail');
  assertEqual(result.mailboxes.length, 0, 'kutu olmamalı');
});

runner.test('kimlik bağı yönetici olmayan tarafından kurulamaz', async () => {
  const user = await login('sub-network');
  const session = await sessions.authenticate({ sid: user.sid });
  const err = await assertThrows(
    () => sessions.linkExternalIdentity({
      session,
      externalEmail: 'aybarsyildirim.mail@gmail.com',
      mailboxAddress: 'network@fitfak.net',
    }),
    /yönetici yetkisi/,
    'yönetici olmayan reddedilmeli',
  );
  assertEqual(err.code, 'ADMIN_REQUIRED', 'hata kodu');
});

runner.test('yönetici gmail adresini yerel kutuya bağlar', async () => {
  const admin = await login('sub-admin');
  assertEqual(admin.isAdmin, true, 'admin rolü tanınmalı');
  const adminSession = await sessions.authenticate({ sid: admin.sid });

  const link = await sessions.linkExternalIdentity({
    session: adminSession,
    externalEmail: 'aybarsyildirim.mail@gmail.com',
    mailboxAddress: 'network@fitfak.net',
    allowSendAs: true,
    reason: 'kişisel adres, kutu paylaşımı',
    ip: '203.0.113.9',
  });
  assertEqual(link.mailbox, 'network@fitfak.net', 'bağlanan kutu');

  // Bağ kurulduktan sonra gmail kimliği kutuyu görmeli.
  const gmail = await login('sub-gmail');
  assertEqual(gmail.mailboxes.length, 1, 'kutu görünmeli');
  assertEqual(gmail.mailboxes[0].address, 'network@fitfak.net', 'bağlı kutu');
  assertEqual(gmail.mailboxes[0].role, 'delegate', 'allowSendAs -> delegate');
  assertEqual(gmail.mailboxes[0].accessSource, 'identity_link', 'erişim kaynağı');

  // Denetim kaydı bağı kimin kurduğunu taşımalı.
  const audit = await ctx.stores.audit.list({ action: 'identity_link.create' });
  assert(audit.length >= 1, 'denetim kaydı olmalı');
  assertEqual(audit[0].actorEmail, 'admin@fitfak.net', 'bağı kuran');
  assertEqual(audit[0].detail.allowSendAs, true, 'gönderme yetkisi kayda geçmeli');
});

runner.test('bağlı kimlik kutu adına gönderebilir, bağsız gönderemez', async () => {
  const { MailPipeline } = require('../src/mail/pipeline');
  const pipeline = new MailPipeline({
    config: ctx.config, logger: ctx.logger, stores: ctx.stores, signer: ctx.signer, queue: ctx.queue,
  });

  const allowed = await pipeline.senderAllowed({
    mailbox: networkMailbox, address: 'network@fitfak.net',
  });
  assertEqual(allowed.allowed, true, 'kutu kendi adresiyle gönderebilir');

  const other = await pipeline.senderAllowed({
    mailbox: networkMailbox, address: 'admin@fitfak.net',
  });
  assertEqual(other.allowed, false, 'başka kutunun adresiyle gönderilemez');
});

runner.test('bağ kaldırıldığında erişim ve oturumlar kapanır', async () => {
  const gmail = await login('sub-gmail');
  assertEqual(gmail.mailboxes.length, 1, 'önce erişim var');

  const admin = await login('sub-admin');
  const adminSession = await sessions.authenticate({ sid: admin.sid });
  const removed = await sessions.revokeExternalIdentity({
    session: adminSession,
    externalEmail: 'aybarsyildirim.mail@gmail.com',
    reason: 'artık gerekmiyor',
  });
  assertEqual(removed, true, 'bağ kaldırılmalı');

  // Var olan oturum kapatılmış olmalı — yeniden doğrulama beklenmez.
  const stale = await sessions.authenticate({ sid: gmail.sid });
  assertEqual(stale, null, 'oturum kapatılmalı');

  const again = await login('sub-gmail');
  assertEqual(again.mailboxes.length, 0, 'erişim kalmamalı');
});

runner.test('IdP jetonu iptal edilirse oturum kapanır', async () => {
  const user = await login('sub-network');
  const session = await sessions.authenticate({ sid: user.sid });
  assert(session, 'oturum açık');

  // IdP'de jetonu iptal et; yeniden doğrulama zorlanınca oturum düşmeli.
  const token = await ctx.stores.sessions.getAccessToken(session);
  idpServer.revokeToken(token);

  const after = await sessions.authenticate({ sid: user.sid, requireFresh: true });
  assertEqual(after, null, 'iptal edilmiş jetonla oturum sürmemeli');
});

runner.test('IdP erişilemezse oturum yerel süreyle sürer', async () => {
  const user = await login('sub-network');
  const originalBase = ctx.config.idp.baseUrl;
  // Erişilemeyen bir adrese yönlendir: kesinti, yetkilendirme kararına
  // dönüşmemeli.
  sessions.idp.baseUrl = 'http://127.0.0.1:1';
  const session = await sessions.authenticate({ sid: user.sid, requireFresh: true });
  assert(session, 'IdP kesintisinde oturum sürmeli');
  sessions.idp.baseUrl = originalBase;
});

runner.test('CSRF jetonu doğrulanır', async () => {
  const user = await login('sub-network');
  const session = await sessions.authenticate({ sid: user.sid });
  assertEqual(sessions.verifyCsrf(session, user.csrfToken), true, 'doğru jeton');
  assertEqual(sessions.verifyCsrf(session, 'yanlis'), false, 'yanlış jeton');
  assertEqual(sessions.verifyCsrf(session, ''), false, 'boş jeton');
});

runner.test('kutu erişimi rol düzeyine göre kısıtlanır', async () => {
  const admin = await login('sub-admin');
  const adminSession = await sessions.authenticate({ sid: admin.sid });
  await sessions.linkExternalIdentity({
    session: adminSession,
    externalEmail: 'salt.okuyucu@gmail.com',
    mailboxAddress: 'network@fitfak.net',
    allowSendAs: false,
    reason: 'yalnızca okuma',
  });

  await ctx.stores.mailboxes.ensure('salt.okuyucu@gmail.com', {}).catch(() => {});
  const readerAccess = await ctx.stores.mailboxes.mailboxesForIdentity({
    idpSub: 'sub-reader', email: 'salt.okuyucu@gmail.com',
  });
  const networkAccess = readerAccess.find((m) => m.address === 'network@fitfak.net');
  assert(networkAccess, 'kutu görünmeli');
  assertEqual(networkAccess.role, 'reader', 'allowSendAs yoksa reader');

  const fakeSession = { mailboxes: [{ ref: networkMailbox.ref, address: 'network@fitfak.net', role: 'reader' }] };
  sessions.requireAccess(fakeSession, networkMailbox.ref, 'reader');
  let threw = false;
  try { sessions.requireAccess(fakeSession, networkMailbox.ref, 'sender'); }
  catch (err) { threw = err.code === 'ROLE_INSUFFICIENT'; }
  assert(threw, 'reader gönderim yapamamalı');
});

runner.test('yerel adres kimlik bağı olarak eklenemez', async () => {
  const admin = await login('sub-admin');
  const adminSession = await sessions.authenticate({ sid: admin.sid });
  await assertThrows(
    () => sessions.linkExternalIdentity({
      session: adminSession,
      externalEmail: 'admin@fitfak.net',
      mailboxAddress: 'network@fitfak.net',
    }),
    /yetki devri \(grant\) kullanılmalı/,
    'yerel adres için bağ reddedilmeli',
  );
});

(async () => {
  try {
    await setup();
    const ok = await runner.run();
    idpServer.server.close();
    await ctx.close();
    await cleanupAll();
    process.exit(ok ? 0 : 1);
  } catch (err) {
    process.stderr.write(`kurulum hatası: ${err.stack}\n`);
    if (idpServer) idpServer.server.close();
    if (ctx) await ctx.close().catch(() => {});
    await cleanupAll();
    process.exit(1);
  }
})();
