'use strict';

const { HttpError } = require('../router');

/**
 * Oturum uçları: Fitfak kimliğiyle giriş, geri dönüş, çıkış.
 *
 * Microsoft OAuth'un yerini alan kısım. Akış tarayıcıda şöyle görünüyor:
 *
 *   /login           -> IdP'ye yönlendirme (PKCE ile)
 *   /oauth/callback  -> kod jetona çevrilir, oturum çerezi konur
 *   /authorize-scope -> eksik bir kapsam için onay turu (ör. cert:issue)
 *   /logout          -> yerel oturum ve (istenirse) IdP oturumu kapatılır
 *
 * ── YOLLAR VE PARAMETRELER İNGİLİZCE ─────────────────────────────────────
 * Bunlar arayüz metni değil, bir SÖZLEŞME: belgelerde, kayıtlarda, IdP
 * yapılandırmasında (redirect_uri) ve üçüncü taraf istemcilerde geçiyorlar.
 * `/yetki-yukselt?kapsam=…&donus=…` gibi bir adres, onu okuyan herkesin
 * Türkçe bilmesini gerektiriyordu.
 *
 * Türkçe adlar KALDIRILMADI, takma ad olarak duruyor: kayıtlı yer imleri,
 * eski istemciler ve halihazırda gönderilmiş bağlantılar kırılmasın.
 */
function registerAuthRoutes(router, deps) {
  const { config, logger, sessions, stores } = deps;

  /** İngilizce ad öncelikli, Türkçe ad takma ad. */
  const param = (ctx, english, turkish) => ctx.query.get(english) || ctx.query.get(turkish) || null;

  const beginLogin = async (ctx) => {
    const returnTo = param(ctx, 'return_to', 'donus') || ctx.query.get('return') || '/';
    const sid = ctx.cookies()[config.http.sessionCookieName];
    if (sid) {
      const existing = await sessions.authenticate({ sid, ip: ctx.ip });
      if (existing) { ctx.redirect(safePath(returnTo) || '/'); return; }
    }
    const begin = await sessions.beginLogin({
      ip: ctx.ip,
      userAgent: ctx.header('user-agent') || '',
      returnTo,
      loginHint: param(ctx, 'login_hint', 'eposta'),
    });
    ctx.redirect(begin.url);
  };
  router.get('/login', beginLogin);
  router.get('/giris', beginLogin);

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
      // Kapsam yükseltmesi BAŞKA bir hesapla onaylanmışsa bu bir giriş
      // hatası değil, bir uyarı: kullanıcı hangi hesapla devam etmesi
      // gerektiğini bilmeli, yoksa aynı yanlışı tekrarlar.
      if (err.code === 'SCOPE_UPGRADE_SUBJECT_MISMATCH') {
        logger.warn({ error: err.message, msg: 'kapsam yükseltmesi yanlış hesapla onaylandı' });
        ctx.html(err.status || 403, errorPage('Yanlış hesapla onaylandı', err.message));
        return;
      }
      logger.warn({ error: err.message, msg: 'giriş tamamlanamadı' });
      ctx.html(err.status && err.status < 500 ? err.status : 400, errorPage('Giriş tamamlanamadı', err.message));
    }
  });

  const doLogout = async (ctx) => {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    if (sid) {
      const everywhere = (param(ctx, 'all', 'hepsi') || '') === '1';
      await sessions.logout({ sid, revokeIdpSessions: everywhere }).catch(() => {});
    }
    ctx.clearCookie(config.http.sessionCookieName);
    ctx.redirect('/');
  };
  router.get('/logout', doLogout);
  router.get('/cikis', doLogout);

  /**
   * Kapsam yükseltme başlatıcı.
   *
   * Sertifika istemek `cert:issue` kapsamı gerektiriyor ve o kapsam ilk
   * girişte istenmemiş olabilir (ya da kullanıcı onaylamamış olabilir).
   * Kullanıcıyı giriş ekranına atmak yerine yalnızca EKSİK olan için onay
   * istiyoruz; dönüşte aynı oturum devam eder.
   */
  const beginScopeUpgrade = async (ctx) => {
    const returnTo = param(ctx, 'return_to', 'donus') || ctx.query.get('return') || '/';
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    if (!session) { ctx.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`); return; }

    const scope = String(param(ctx, 'scope', 'kapsam') || config.trust.issueScope);
    const allowed = new Set([...config.idp.scopes, config.trust.issueScope]);
    if (!allowed.has(scope)) throw new HttpError(400, 'Bilinmeyen kapsam');

    const begin = await sessions.beginScopeUpgrade({
      session,
      scope,
      returnTo,
      ip: ctx.ip,
      userAgent: ctx.header('user-agent') || '',
    });
    logger.info({
      email: session.idpEmail, scope, requestedScopes: begin.scopes,
      msg: 'kapsam yükseltme başlatıldı — onay AYNI hesapla verilmeli',
    });
    ctx.redirect(begin.url);
  };
  router.get('/authorize-scope', beginScopeUpgrade);
  router.get('/yetki-yukselt', beginScopeUpgrade);

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
