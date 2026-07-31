'use strict';

const { HttpError } = require('../router');

/**
 * Oturum uçları: Fitfak kimliğiyle giriş, geri dönüş, çıkış.
 *
 * Microsoft OAuth'un yerini alan kısım. Akış tarayıcıda şöyle görünüyor:
 *
 *   /giris          -> IdP'ye yönlendirme (PKCE ile)
 *   /oauth/callback -> kod jetona çevrilir, oturum çerezi konur
 *   /cikis          -> yerel oturum ve (istenirse) IdP oturumu kapatılır
 */
function registerAuthRoutes(router, deps) {
  const { config, logger, sessions, stores } = deps;

  router.get('/login', async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    if (sid) {
      const existing = await sessions.authenticate({ sid, ip: ctx.ip });
      if (existing) { ctx.redirect(safePath(ctx.query.get('donus')) || '/'); return; }
    }
    const begin = await sessions.beginLogin({
      ip: ctx.ip,
      userAgent: ctx.header('user-agent') || '',
      returnTo: ctx.query.get('donus') || '/',
      loginHint: ctx.query.get('eposta') || null,
    });
    ctx.redirect(begin.url);
  });

  router.get(config.idp.redirectPath, async (ctx) => {
    const error = ctx.query.get('error');
    if (error) {
      // IdP'nin reddi kullanıcıya anlaşılır biçimde gösterilir; ham hata
      // sayfaya basılmaz.
      logger.warn({ error, description: ctx.query.get('error_description'), msg: 'IdP hatası' });
      ctx.html(400, errorPage('Giriş tamamlanamadı', 'Kimlik sağlayıcı isteği reddetti. Lütfen tekrar deneyin.'));
      return;
    }

    const code = ctx.query.get('code');
    const state = ctx.query.get('state');
    if (!code || !state) {
      ctx.html(400, errorPage('Eksik yanıt', 'Kimlik sağlayıcıdan beklenen bilgiler gelmedi.'));
      return;
    }

    try {
      const result = await sessions.completeLogin({
        code, state, ip: ctx.ip, userAgent: ctx.header('user-agent') || '',
      });
      ctx.setCookie(config.http.sessionCookieName, result.sid, {
        maxAge: Math.floor((result.expiresAt - Date.now()) / 1000),
        httpOnly: true,
        sameSite: 'Lax',
      });
      if (!result.mailboxes.length) {
        // Erişilebilir kutu yok: bu bir hata değil, bir yetki durumu. Ne
        // yapılması gerektiğini söylemek, "boş kutu" göstermekten iyi.
        ctx.html(200, noMailboxPage(result.profile.email, config));
        return;
      }
      ctx.redirect(safePath(result.returnTo) || '/');
    } catch (err) {
      logger.warn({ error: err.message, msg: 'giriş tamamlanamadı' });
      ctx.html(400, errorPage('Giriş tamamlanamadı', err.message));
    }
  });

  router.get('/logout', async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    if (sid) {
      await sessions.logout({ sid, revokeIdpSessions: ctx.query.get('hepsi') === '1' }).catch(() => {});
    }
    ctx.clearCookie(config.http.sessionCookieName);
    ctx.redirect('/');
  });

  router.post('/logout', async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    if (sid) {
      const session = await sessions.authenticate({ sid, ip: ctx.ip });
      const input = await ctx.input();
      if (session && !sessions.verifyCsrf(session, ctx.header('x-csrf-token') || input.fields.csrfToken)) {
        throw new HttpError(403, 'CSRF jetonu geçersiz');
      }
      await sessions.logout({ sid, revokeIdpSessions: true }).catch(() => {});
    }
    ctx.clearCookie(config.http.sessionCookieName);
    ctx.json(200, { ok: true });
  });

  /** Açık oturumlar — kullanıcı kendi oturumlarını görebilmeli. */
  router.get('/api/v1/sessions', async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    if (!session) throw new HttpError(401, 'Oturum gerekli');
    const list = await stores.sessions.listForSub(session.idpSub);
    ctx.json(200, {
      sessions: list.map((s) => ({
        ref: s.ref,
        current: s.ref === session.ref,
        createdAt: s.createdAt,
        lastSeenAt: s.lastSeenAt,
        expiresAt: s.expiresAt,
        ip: s.ip,
        userAgent: s.userAgent,
      })),
    });
  });

  router.delete('/api/v1/sessions/:ref', async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    if (!session) throw new HttpError(401, 'Oturum gerekli');
    if (!sessions.verifyCsrf(session, ctx.header('x-csrf-token'))) {
      throw new HttpError(403, 'CSRF jetonu geçersiz');
    }
    // Yalnızca kendi oturumları kapatılabilir.
    const own = await stores.sessions.listForSub(session.idpSub);
    if (!own.some((s) => s.ref === ctx.params.ref)) throw new HttpError(404, 'Oturum bulunamadı');
    await stores.sessions.revoke(ctx.params.ref, 'user_revoked');
    ctx.json(200, { ok: true });
  });
}

function safePath(value) {
  const s = String(value || '');
  if (!s.startsWith('/') || s.startsWith('//')) return null;
  return s;
}

function errorPage(title, detail) {
  return page(title, `
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(detail)}</p>
    <p><a class="btn" href="/login">Tekrar dene</a></p>
  `);
}

function noMailboxPage(email, config) {
  return page('Posta kutusu yok', `
    <h1>Hesabınıza bağlı posta kutusu yok</h1>
    <p><strong>${escapeHtml(email)}</strong> ile giriş yaptınız, ancak bu kimliğe
       tanımlı bir posta kutusu bulunmuyor.</p>
    <p>Kendi alan adımızdaki bir adresle giriş yaptıysanız kutunuz henüz
       oluşturulmamış olabilir. Harici bir adresle (ör. Gmail) giriş
       yaptıysanız, bir yöneticinin bu adresi bir posta kutusuna
       <em>bağlaması</em> gerekir.</p>
    <p>Yönetici ile iletişim: <a href="mailto:postmaster@${escapeHtml(config.primaryDomain)}">postmaster@${escapeHtml(config.primaryDomain)}</a></p>
    <p><a class="btn" href="/logout">Çıkış yap</a></p>
  `);
}

function page(title, body) {
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — Fitfak Posta</title>
<link rel="stylesheet" href="/static/fitfak-ui.css">
</head><body class="ff-center"><main class="ff-card">${body}</main></body></html>`;
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

module.exports = { registerAuthRoutes };
