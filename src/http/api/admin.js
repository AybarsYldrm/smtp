'use strict';

const { HttpError } = require('../router');
const { normalizeAddress } = require('../../util/encoding');

/**
 * Yönetici API'si.
 *
 * Buradaki her uç, bir kimliğe başkasının postasına erişim verebilir. Bu
 * yüzden üçü birden zorunlu: yönetici yetkisi, CSRF jetonu ve denetim kaydı.
 * Denetim kaydı olmayan bir yetki verme işlemi, aylar sonra "bunu kim
 * yaptı" sorusuna cevap bırakmaz.
 */
function registerAdminRoutes(router, deps) {
  const { config, logger, stores, sessions, certificates, pipeline } = deps;

  async function requireAdmin(ctx) {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    const session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    if (!session) throw new HttpError(401, 'Oturum gerekli', { code: 'UNAUTHENTICATED' });
    sessions.requireAdmin(session);
    ctx.state.session = session;
    return session;
  }

  function requireCsrf(ctx, session) {
    const token = ctx.header('x-csrf-token') || (ctx.state.input && ctx.state.input.fields && ctx.state.input.fields.csrfToken);
    if (!sessions.verifyCsrf(session, token)) {
      throw new HttpError(403, 'CSRF jetonu geçersiz', { code: 'CSRF_INVALID' });
    }
  }

  /* ── posta kutuları ────────────────────────────────────────── */

  router.get('/api/v1/admin/mailboxes', async (ctx) => {
    await requireAdmin(ctx);
    const mailboxes = await stores.mailboxes.listAll();
    const out = [];
    for (const mailbox of mailboxes) {
      const cert = await stores.certificates.getActive('smime', mailbox.address);
      out.push({
        ref: mailbox.ref,
        address: mailbox.address,
        displayName: mailbox.displayName,
        kind: mailbox.kind,
        status: mailbox.status,
        ownerSub: mailbox.ownerSub,
        usedBytes: mailbox.usedBytes,
        quotaBytes: mailbox.quotaBytes,
        messageCount: mailbox.messageCount,
        unreadCount: mailbox.unreadCount,
        createdAt: mailbox.createdAt,
        lastDeliveryAt: mailbox.lastDeliveryAt,
        smime: cert ? { notAfter: cert.notAfter, serialHex: cert.serialHex } : null,
      });
    }
    ctx.json(200, { mailboxes: out });
  });

  router.post('/api/v1/admin/mailboxes', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const fields = ctx.state.input.fields;

    const address = normalizeAddress(fields.address);
    if (!address.includes('@')) throw new HttpError(400, 'Geçerli bir adres gerekir');
    const domain = address.split('@')[1];
    if (!config.isLocalDomain(domain)) {
      throw new HttpError(400, `${domain} bu sunucunun alan adı değil`);
    }

    const result = await stores.mailboxes.ensure(address, {
      displayName: fields.displayName || '',
      kind: fields.kind || 'user',
      ownerSub: fields.ownerSub || '',
      ownerEmail: fields.ownerEmail || '',
      quotaBytes: fields.quotaBytes ? Number(fields.quotaBytes) : undefined,
      smimeEnabled: fields.smimeEnabled == null ? true : toBool(fields.smimeEnabled),
    });

    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: result.created ? 'mailbox.create' : 'mailbox.update',
      targetType: 'mailbox', targetId: result.mailbox.ref, ip: ctx.ip,
      detail: { address, kind: result.mailbox.kind },
    });

    // Yeni kutu için sertifika hemen istenir: "her kayıtlı adres için
    // sertifika" gereğinin karşılığı, kutu oluşturma anında başlar.
    let certificate = null;
    if (result.created && certificates) {
      certificate = await certificates.ensureForMailbox(result.mailbox, {
        requestedBySub: session.idpSub,
      }).catch((err) => ({ status: 'failed', reason: err.message }));
    }

    ctx.json(result.created ? 201 : 200, { ok: true, mailbox: result.mailbox, certificate });
  });

  router.post('/api/v1/admin/mailboxes/:address/status', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const status = String(ctx.state.input.fields.status || '');
    if (!['active', 'suspended', 'closed'].includes(status)) throw new HttpError(400, 'Geçersiz durum');

    const mailbox = await stores.mailboxes.getByAddress(ctx.params.address);
    if (!mailbox) throw new HttpError(404, 'Posta kutusu bulunamadı');
    await stores.mailboxes.ensure(mailbox.address, { status });

    if (status !== 'active') {
      // Kutu kapatıldığında o kutuya erişen oturumlar da kapanır.
      await stores.sessions.revokeAllForMailbox(mailbox.ref, `mailbox_${status}`);
    }
    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail, action: 'mailbox.status',
      targetType: 'mailbox', targetId: mailbox.ref, ip: ctx.ip, detail: { status },
    });
    ctx.json(200, { ok: true, status });
  });

  /* ── harici kimlik bağları ─────────────────────────────────── */
  // "gmail adresini network@fitfak.net ile bağla" — yalnızca buradan.

  router.get('/api/v1/admin/identity-links', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.json(200, {
      links: await sessions.listExternalIdentities({
        session,
        mailboxAddress: ctx.query.get('mailbox') || null,
      }),
    });
  });

  router.post('/api/v1/admin/identity-links', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const fields = ctx.state.input.fields;

    if (!fields.externalEmail || !fields.mailbox) {
      throw new HttpError(400, 'externalEmail ve mailbox gerekli');
    }
    // Gerekçe zorunlu: aylar sonra bağın neden kurulduğunu hatırlayan
    // olmuyor ve kayıtta yalnızca "kim" olması yetmiyor.
    if (!String(fields.reason || '').trim()) {
      throw new HttpError(400, 'Bu yetkinin gerekçesi (reason) yazılmalı', { code: 'REASON_REQUIRED' });
    }

    const result = await sessions.linkExternalIdentity({
      session,
      externalEmail: fields.externalEmail,
      mailboxAddress: fields.mailbox,
      allowSendAs: toBool(fields.allowSendAs),
      reason: String(fields.reason).slice(0, 500),
      expiresAt: fields.expiresAt ? Number(fields.expiresAt) : 0,
      ip: ctx.ip,
    });
    ctx.json(201, { ok: true, ...result });
  });

  router.delete('/api/v1/admin/identity-links/:email', async (ctx) => {
    const session = await requireAdmin(ctx);
    requireCsrf(ctx, session);
    const removed = await sessions.revokeExternalIdentity({
      session,
      externalEmail: ctx.params.email,
      reason: ctx.query.get('reason') || 'yönetici kaldırdı',
      ip: ctx.ip,
    });
    if (!removed) throw new HttpError(404, 'Bağ bulunamadı');
    ctx.json(200, { ok: true });
  });

  /* ── yetki devri ───────────────────────────────────────────── */

  router.post('/api/v1/admin/grants', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const fields = ctx.state.input.fields;
    const result = await sessions.grantMailboxAccess({
      session,
      mailboxAddress: fields.mailbox,
      idpSub: fields.idpSub,
      idpEmail: fields.idpEmail || '',
      role: fields.role || 'reader',
      note: fields.note || '',
      ip: ctx.ip,
    });
    ctx.json(201, { ok: true, ...result });
  });

  router.get('/api/v1/admin/grants/:mailbox', async (ctx) => {
    await requireAdmin(ctx);
    const mailbox = await stores.mailboxes.getByAddress(ctx.params.mailbox);
    if (!mailbox) throw new HttpError(404, 'Posta kutusu bulunamadı');
    ctx.json(200, { grants: await stores.mailboxes.listGrantsForMailbox(mailbox.ref) });
  });

  router.delete('/api/v1/admin/grants/:mailbox/:sub', async (ctx) => {
    const session = await requireAdmin(ctx);
    requireCsrf(ctx, session);
    const mailbox = await stores.mailboxes.getByAddress(ctx.params.mailbox);
    if (!mailbox) throw new HttpError(404, 'Posta kutusu bulunamadı');
    const removed = await stores.mailboxes.revokeGrant({
      mailboxRef: mailbox.ref, idpSub: ctx.params.sub, revokedBySub: session.idpSub,
    });
    if (removed) {
      await stores.sessions.revokeAllForSub(ctx.params.sub, 'grant_revoked');
      await stores.audit.record({
        actorSub: session.idpSub, actorEmail: session.idpEmail, action: 'mailbox.grant_revoke',
        targetType: 'mailbox', targetId: mailbox.ref, ip: ctx.ip, detail: { idpSub: ctx.params.sub },
      });
    }
    ctx.json(200, { ok: removed });
  });

  /* ── sertifikalar ──────────────────────────────────────────── */

  router.get('/api/v1/admin/certificates', async (ctx) => {
    await requireAdmin(ctx);
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');
    ctx.json(200, await certificates.status());
  });

  router.post('/api/v1/admin/certificates/sweep', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');
    const summary = await certificates.ensureAll({ force: toBool(ctx.state.input.fields.force) });
    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail, action: 'certificate.sweep',
      targetType: 'system', targetId: 'smime', ip: ctx.ip, detail: summary,
    });
    ctx.json(200, { ok: true, ...summary });
  });

  router.post('/api/v1/admin/certificates/revoke', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');
    const fields = ctx.state.input.fields;
    const done = await certificates.revoke({
      address: fields.address,
      usage: fields.usage || 'smime',
      reason: fields.reason || 'unspecified',
      actorSub: session.idpSub,
    });
    ctx.json(200, { ok: done });
  });

  /* ── API jetonları ─────────────────────────────────────────── */

  router.post('/api/v1/admin/api-tokens', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const fields = ctx.state.input.fields;

    let mailboxRef = '';
    if (fields.mailbox) {
      const mailbox = await stores.mailboxes.getByAddress(fields.mailbox);
      if (!mailbox) throw new HttpError(404, 'Posta kutusu bulunamadı');
      mailboxRef = mailbox.ref;
    }
    const scopes = fields.scopes
      ? (typeof fields.scopes === 'string' ? fields.scopes.split(/[,\s]+/).filter(Boolean) : fields.scopes)
      : ['mail:read'];

    const result = await stores.sessions.createApiToken({
      label: fields.label || 'api',
      ownerSub: fields.ownerSub || session.idpSub,
      mailboxRef,
      scopes,
      expiresInMs: fields.expiresInDays ? Number(fields.expiresInDays) * 86400_000 : null,
      createdBySub: session.idpSub,
      ipAllow: fields.ipAllow ? [].concat(fields.ipAllow) : [],
    });
    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail, action: 'api_token.create',
      targetType: 'token', targetId: result.label, ip: ctx.ip, detail: { scopes, mailbox: fields.mailbox || null },
    });
    ctx.json(201, {
      ok: true,
      token: result.token,
      note: 'Bu jeton yalnızca şimdi gösterilir; sunucuda özeti saklanır.',
      scopes,
    });
  });

  router.get('/api/v1/admin/api-tokens', async (ctx) => {
    const session = await requireAdmin(ctx);
    ctx.json(200, { tokens: await stores.sessions.listApiTokens(session.idpSub) });
  });

  router.delete('/api/v1/admin/api-tokens/:ref', async (ctx) => {
    const session = await requireAdmin(ctx);
    requireCsrf(ctx, session);
    ctx.json(200, { ok: await stores.sessions.revokeApiToken(ctx.params.ref) });
  });
}

function toBool(value) {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'evet', 'yes', 'on'].includes(String(value).toLowerCase());
}

module.exports = { registerAdminRoutes };
