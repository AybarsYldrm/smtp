'use strict';

const { HttpError } = require('../router');

/**
 * Oturum uçları: Fitfak kimliğiyle giriş, geri dönüş, çıkış.
 *
 * Microsoft OAuth'un yerini alan kısım. Akış tarayıcıda şöyle görünüyor:
 *
 *   /login                 -> IdP'ye yönlendirme (PKCE ile)
 *   /oauth/callback        -> kod jetona çevrilir, oturum çerezi konur
 *   /oauth/upgrade-scope   -> eksik bir kapsam için tek turluk onay
 *   /logout                -> yerel oturum ve (istenirse) IdP oturumu kapatılır
 *
 * Türkçe adlar (/giris, /cikis, /yetki-yukselt) eski bağlantılar için
 * yönlendirme olarak duruyor.
 */
function registerAuthRoutes(router, deps) {
  const { config, logger, sessions, stores } = deps;

  /**
   * Yollar ve parametreler İNGİLİZCE.
   *
   * Kod tabanının geri kalanı (değişkenler, alan adları, API yolları) zaten
   * İngilizce; yalnızca oturum yolları Türkçeydi ve bu iki soruna yol
   * açıyordu. Birincisi tutarsızlık: `/giris` ile `/api/v1/messages` aynı
   * uygulamada. İkincisi ve asıl olanı, arayüzün `/giris`e bağlanıp
   * sunucunun yalnızca `/login`i tanıması — düğme, tek sayfa yakalayıcısına
   * düşüp aynı sayfayı geri veriyordu.
   *
   * Türkçe adlar KALDIRILMADI, kalıcı yönlendirmeye çevrildi: yer imleri ve
   * dışarıdaki bağlantılar (kişisel sitedeki düğmeler dâhil) kırılmasın.
   */
  const beginLogin = async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    if (sid) {
      const existing = await sessions.authenticate({ sid, ip: ctx.ip });
      if (existing) { ctx.redirect(safePath(returnToOf(ctx)) || '/'); return; }
    }
    const begin = await sessions.beginLogin({
      ip: ctx.ip,
      userAgent: ctx.header('user-agent') || '',
      returnTo: returnToOf(ctx) || '/',
      loginHint: ctx.query.get('login_hint') || ctx.query.get('eposta') || null,
    });
    ctx.redirect(begin.url);
  };
  router.get('/login', beginLogin);
  router.get('/giris', (ctx) => ctx.redirect(`/login${ctx.url.search || ''}`));

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

      // Kapsam yükseltmesi: oturum zaten var, yeni çerez yazılmaz. Kullanıcı
      // yarıda bıraktığı yere döner.
      if (result.scopeUpgrade) {
        logger.info({ scope: result.scope, msg: 'kapsam yükseltme tamamlandı' });
        ctx.redirect(safePath(result.returnTo) || '/');
        return;
      }

      ctx.setCookie(config.http.sessionCookieName, result.sid, {
        maxAge: Math.floor((result.expiresAt - Date.now()) / 1000),
        httpOnly: true,
        sameSite: 'Lax',
      });
      if (!result.mailboxes.length) {
        // Erişilebilir kutu yok: bu bir hata değil, bir yetki durumu.
        //
        // Oturum yine de AÇILIYOR ve çerez yazılıyor. Önceki sürümde de
        // öyleydi ama kullanıcı bu sayfada kalıyordu; oysa arayüz aynı
        // durumu kendi ekranında gösterebiliyor ve oradan çıkış yapılabiliyor.
        // Burada kalmanın tek anlamı, tarayıcıya JavaScript'siz de bir yanıt
        // verebilmek.
        logger.info({
          email: result.profile.email,
          reason: result.noMailbox && result.noMailbox.code,
          msg: 'giriş başarılı ama erişilebilir posta kutusu yok',
        });
        ctx.html(200, noMailboxPage(result.noMailbox, config));
        return;
      }
      ctx.redirect(safePath(result.returnTo) || '/');
    } catch (err) {
      logger.warn({ error: err.message, msg: 'giriş tamamlanamadı' });
      ctx.html(400, errorPage('Giriş tamamlanamadı', err.message));
    }
  });

  const doLogout = async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const all = ctx.query.get('all') === '1' || ctx.query.get('hepsi') === '1';
    if (sid) await sessions.logout({ sid, revokeIdpSessions: all }).catch(() => {});
    ctx.clearCookie(config.http.sessionCookieName);
    ctx.redirect('/');
  };
  router.get('/logout', doLogout);
  router.get('/cikis', (ctx) => ctx.redirect(`/logout${ctx.url.search || ''}`));

  /**
   * Kapsam yükseltme başlatıcı.
   *
   * Sertifika istemek `cert:issue` kapsamı gerektiriyor ve o kapsam ilk
   * girişte istenmemiş olabilir (ya da kullanıcı onaylamamış olabilir).
   * Kullanıcıyı giriş ekranına atmak yerine yalnızca EKSİK olan için onay
   * istiyoruz; dönüşte aynı oturum devam eder.
   */
  const upgradeScope = async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    const returnTo = returnToOf(ctx) || '/';
    if (!session) { ctx.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`); return; }

    const scope = String(ctx.query.get('scope') || ctx.query.get('kapsam') || config.trust.issueScope);
    const allowed = new Set([...config.idp.scopes, config.trust.issueScope]);
    if (!allowed.has(scope)) throw new HttpError(400, 'Bilinmeyen kapsam');

    const begin = await sessions.beginScopeUpgrade({
      session, scope, returnTo, ip: ctx.ip, userAgent: ctx.header('user-agent') || '',
    });
    logger.info({ email: session.idpEmail, scope, msg: 'kapsam yükseltme başlatıldı' });
    ctx.redirect(begin.url);
  };
  router.get('/oauth/upgrade-scope', upgradeScope);
  router.get('/yetki-yukselt', (ctx) => ctx.redirect(`/oauth/upgrade-scope${ctx.url.search || ''}`));

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

/** `return_to` — Türkçe `donus` eski bağlantılar için kabul edilmeye devam eder. */
function returnToOf(ctx) {
  return ctx.query.get('return_to') || ctx.query.get('donus') || '';
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

function noMailboxPage(reason, config) {
  const info = reason || { message: 'Bu kimliğe tanımlı bir posta kutusu bulunmuyor.', action: '' };
  return page('Posta kutusu yok', `
    <h1>Hesabınıza bağlı posta kutusu yok</h1>
    <p>${escapeHtml(info.message)}</p>
    ${info.action ? `<p>${escapeHtml(info.action)}</p>` : ''}
    <p>Yönetici ile iletişim:
      <a href="mailto:network@${escapeHtml(config.primaryDomain)}">network@${escapeHtml(config.primaryDomain)}</a></p>
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
