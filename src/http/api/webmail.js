'use strict';

const { HttpError } = require('../router');
const { normalizeAddress, safeFileName, htmlEscape } = require('../../util/encoding');
const { signHs, verifyHs } = require('../../util/jwt');

/**
 * Webmail API'si.
 *
 * Tasarım kuralları:
 *
 *   - HER İSTEK KUTU YETKİSİNİ YENİDEN DENETLER. Oturumda kutu listesi
 *     olması yetmez; istenen kutu o listede mi, hangi rolle, her seferinde
 *     bakılır. Yetkiyi yalnızca giriş anında denetlemek, yetki geri alındıktan
 *     sonra açık kalan sekmenin çalışmaya devam etmesi demek.
 *
 *   - EK BAĞLANTILARI KISA ÖMÜRLÜ JETON TAŞIR VE OTURUM DA GEREKTİRİR.
 *     Yalnızca jeton yeterli olsaydı, paylaşılan bir bağlantı kimin elinde
 *     olursa ona eki verirdi. Yalnızca oturum yeterli olsaydı, bağlantı
 *     tahmin edilebilir olurdu.
 *
 *   - HTML GÖVDE SUNUCUDA TEMİZLENİR. İstemciye "sen temizle" demek,
 *     temizlemeyi unutan tek bir istemcide XSS demektir.
 */

const FOLDERS = new Set(['inbox', 'sent', 'drafts', 'archive', 'spam', 'trash', 'outbox']);

function registerWebmailRoutes(router, deps) {
  const {
    config, logger, stores, sessions, pipeline, queue, push, realtime, signer, certificates,
  } = deps;

  /** Oturumu çözer; yoksa 401. */
  async function requireSession(ctx) {
    if (ctx.state.session) return ctx.state.session;
    const sid = ctx.cookies()[config.http.sessionCookieName];
    let session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;

    if (!session) {
      // API jetonu ile de erişilebilir: betikler ve "durum API'si" için.
      const auth = String(ctx.header('authorization') || '');
      const bearer = auth.replace(/^Bearer\s+/i, '');
      if (bearer && bearer !== auth) {
        const verdict = await stores.sessions.verifyApiToken(bearer, { ip: ctx.ip });
        if (verdict.ok) {
          const mailbox = verdict.token.mailboxRef
            ? await stores.mailboxes.getByRef(verdict.token.mailboxRef)
            : null;
          session = {
            ref: `token:${verdict.token.ref}`,
            idpSub: verdict.token.ownerSub,
            idpEmail: mailbox ? mailbox.address : '',
            isAdmin: verdict.token.scopes.includes('admin'),
            mailboxes: mailbox ? [{
              ref: mailbox.ref, address: mailbox.address, displayName: mailbox.displayName,
              role: verdict.token.scopes.includes('mail:send') ? 'sender' : 'reader',
              accessSource: 'api_token',
            }] : [],
            csrfToken: null,
            isApiToken: true,
            scopes: verdict.token.scopes,
          };
        }
      }
    }

    if (!session) throw new HttpError(401, 'Oturum gerekli', { code: 'UNAUTHENTICATED' });
    ctx.state.session = session;
    return session;
  }

  /** Durum değiştiren istekler için CSRF. API jetonunda gerekmez. */
  function requireCsrf(ctx, session) {
    if (session.isApiToken) return;
    const token = ctx.header('x-csrf-token') || (ctx.state.input && ctx.state.input.fields && ctx.state.input.fields.csrfToken);
    if (!sessions.verifyCsrf(session, token)) {
      throw new HttpError(403, 'CSRF jetonu geçersiz', { code: 'CSRF_INVALID' });
    }
  }

  async function resolveMailbox(ctx, session, addressOrRef, minimumRole = 'reader') {
    const access = sessions.requireAccess(session, addressOrRef, minimumRole);
    const mailbox = await stores.mailboxes.getByRef(access.ref);
    if (!mailbox) throw new HttpError(404, 'Posta kutusu bulunamadı');
    return { mailbox, access };
  }

  /* ── kimlik ve kutular ─────────────────────────────────────── */

  router.get('/api/v1/me', async (ctx) => {
    const session = await requireSession(ctx);
    const mailboxes = [];
    for (const entry of session.mailboxes || []) {
      const mailbox = await stores.mailboxes.getByRef(entry.ref);
      if (!mailbox) continue;
      const counts = await stores.messages.counts(mailbox.ref);
      const cert = await stores.certificates.getActive('smime', mailbox.address);
      mailboxes.push({
        ref: mailbox.ref,
        address: mailbox.address,
        displayName: mailbox.displayName,
        role: entry.role,
        accessSource: entry.accessSource,
        quotaBytes: mailbox.quotaBytes,
        usedBytes: mailbox.usedBytes,
        counts,
        notifyPrefs: mailbox.notifyPrefs,
        smime: cert ? {
          available: true, notAfter: cert.notAfter, serialHex: cert.serialHex,
          subject: cert.subjectDn,
        } : { available: false },
      });
    }
    ctx.json(200, {
      email: session.idpEmail,
      sub: session.idpSub,
      isAdmin: !!session.isAdmin,
      csrfToken: session.csrfToken,
      mailboxes,
      limits: {
        maxAttachmentBytes: config.limits.maxAttachmentBytes,
        maxTotalAttachmentBytes: config.limits.maxTotalAttachmentBytes,
        maxAttachments: config.limits.maxAttachmentsPerMessage,
        blockedExtensions: config.limits.blockedAttachmentExtensions,
      },
    });
  });

  /* ── ileti listesi ─────────────────────────────────────────── */

  router.get('/api/v1/mailboxes/:mailbox/messages', async (ctx) => {
    const session = await requireSession(ctx);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox);

    const folder = String(ctx.query.get('folder') || 'inbox');
    if (!FOLDERS.has(folder)) throw new HttpError(400, 'Bilinmeyen klasör');

    const limit = Math.min(200, Math.max(1, Number(ctx.query.get('limit') || 50)));
    const cursor = ctx.query.get('cursor');

    const result = await stores.messages.list({
      mailboxRef: mailbox.ref,
      folder,
      limit,
      beforeReceivedAt: cursor ? Number(cursor) : null,
      unreadOnly: ctx.query.get('unread') === '1',
      flaggedOnly: ctx.query.get('flagged') === '1',
      query: ctx.query.get('q') || null,
      hasAttachments: ctx.query.get('attachments') === '1' ? true : null,
      threadKey: ctx.query.get('thread') || null,
    });

    ctx.json(200, {
      mailbox: { ref: mailbox.ref, address: mailbox.address },
      folder,
      messages: result.messages,
      nextCursor: result.nextCursor,
      total: result.total,
    });
  });

  router.get('/api/v1/mailboxes/:mailbox/counts', async (ctx) => {
    const session = await requireSession(ctx);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox);
    ctx.json(200, await stores.messages.counts(mailbox.ref));
  });

  /** Kaçırılan iletiler — gerçek zamanlı bağlantı koptuysa. */
  router.get('/api/v1/mailboxes/:mailbox/since/:seq', async (ctx) => {
    const session = await requireSession(ctx);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox);
    const messages = await stores.messages.since({
      mailboxRef: mailbox.ref,
      seq: Number(ctx.params.seq || 0),
      limit: Math.min(500, Number(ctx.query.get('limit') || 200)),
    });
    ctx.json(200, {
      messages,
      lastSeq: messages.length ? messages[messages.length - 1].seq : Number(ctx.params.seq || 0),
    });
  });

  /* ── tek ileti ─────────────────────────────────────────────── */

  router.get('/api/v1/messages/:ref', async (ctx) => {
    const session = await requireSession(ctx);
    const message = await stores.messages.getFull(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    const { mailbox } = await resolveMailbox(ctx, session, message.mailboxRef);

    if (ctx.query.get('markRead') !== '0' && !message.seen) {
      await stores.messages.setFlags(message.ref, { seen: true });
      message.seen = true;
      realtime.publishUpdate(mailbox.ref, { messageRef: message.ref, seen: true });
    }

    ctx.json(200, {
      ...message,
      // HTML gövde sunucuda temizlenmiş olarak gider; ham hâli ayrı uçtan.
      html: message.html ? sanitizeHtml(message.html) : '',
      htmlSanitized: !!message.html,
      attachments: message.attachments.map((att) => ({
        ...att,
        url: att.scanStatus === 'accepted'
          ? `/api/v1/messages/${message.ref}/attachments/${att.ref}?t=${attachmentToken(att, session)}`
          : null,
      })),
    });
  });

  router.get('/api/v1/messages/:ref/raw', async (ctx) => {
    const session = await requireSession(ctx);
    const message = await stores.messages.get(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    await resolveMailbox(ctx, session, message.mailboxRef);

    const raw = await stores.messages.getRaw(ctx.params.ref);
    if (!raw) throw new HttpError(404, 'Ham ileti saklanmamış');
    ctx.send(200, raw, 'message/rfc822');
  });

  /** Ek indirme: kısa ömürlü jeton + açık oturum, ikisi birden. */
  router.get('/api/v1/messages/:ref/attachments/:attRef', async (ctx) => {
    const session = await requireSession(ctx);
    const attachment = await stores.messages.getAttachment(ctx.params.attRef);
    if (!attachment || attachment.messageRef !== String(ctx.params.ref)) {
      throw new HttpError(404, 'Ek bulunamadı');
    }
    await resolveMailbox(ctx, session, attachment.mailboxRef);

    const token = ctx.query.get('t');
    const verdict = verifyHs(token, () => [attachmentKey(session)], { requiredClaims: ['a'] });
    if (!verdict.ok || verdict.payload.a !== attachment.ref) {
      throw new HttpError(403, 'Ek bağlantısı geçersiz ya da süresi dolmuş', { code: 'ATTACHMENT_TOKEN_INVALID' });
    }
    if (attachment.scanStatus !== 'accepted' || !attachment.blobId) {
      throw new HttpError(410, `Bu ek teslim edilmedi: ${attachment.scanStatus}`);
    }

    const meta = await stores.blobs.head(attachment.blobId);
    if (!meta) throw new HttpError(404, 'Ek içeriği bulunamadı');

    const range = parseRange(ctx.header('range'), meta.totalBytes);
    // Tarayıcıda çalıştırılabilir hiçbir tür INLINE gösterilmez: bir ek,
    // kendi kaynağımızda betik çalıştırmanın en kolay yoludur.
    const inlineSafe = /^(image\/(?!svg)|video\/|audio\/|application\/pdf|text\/plain)/i.test(attachment.contentType);
    const disposition = ctx.query.get('download') === '1' || !inlineSafe ? 'attachment' : 'inline';
    const fileName = safeFileName(attachment.fileName);

    const headers = {
      'content-type': inlineSafe ? attachment.contentType : 'application/octet-stream',
      'content-disposition': `${disposition}; filename="${fileName}"; filename*=UTF-8''${encodeURIComponent(fileName)}`,
      'cache-control': 'private, max-age=300',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; sandbox",
      'accept-ranges': 'bytes',
    };

    if (range) {
      headers['content-range'] = `bytes ${range.start}-${range.end}/${meta.totalBytes}`;
      headers['content-length'] = range.end - range.start + 1;
      ctx.responded = true;
      ctx.res.writeHead(206, headers);
      for await (const chunk of stores.blobs.readStream(attachment.blobId, range)) ctx.res.write(chunk);
      ctx.res.end();
      return;
    }

    headers['content-length'] = meta.totalBytes;
    ctx.responded = true;
    ctx.res.writeHead(200, headers);
    for await (const chunk of stores.blobs.readStream(attachment.blobId)) ctx.res.write(chunk);
    ctx.res.end();
  });

  /* ── ileti durumu ──────────────────────────────────────────── */

  router.post('/api/v1/messages/:ref/flags', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const message = await stores.messages.get(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    const { mailbox } = await resolveMailbox(ctx, session, message.mailboxRef);

    const fields = ctx.state.input.fields;
    const updated = await stores.messages.setFlags(ctx.params.ref, {
      seen: fields.seen != null ? toBool(fields.seen) : null,
      flagged: fields.flagged != null ? toBool(fields.flagged) : null,
      answered: fields.answered != null ? toBool(fields.answered) : null,
    });
    realtime.publishUpdate(mailbox.ref, { messageRef: ctx.params.ref, flags: updated });
    ctx.json(200, { ok: true, message: updated });
  });

  router.post('/api/v1/messages/:ref/move', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const message = await stores.messages.get(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    const { mailbox } = await resolveMailbox(ctx, session, message.mailboxRef, 'delegate');

    const folder = String(ctx.state.input.fields.folder || '');
    if (!FOLDERS.has(folder)) throw new HttpError(400, 'Bilinmeyen klasör');
    const moved = await stores.messages.move(ctx.params.ref, folder);
    realtime.publishUpdate(mailbox.ref, { messageRef: ctx.params.ref, folder });
    ctx.json(200, { ok: true, message: moved });
  });

  router.delete('/api/v1/messages/:ref', async (ctx) => {
    const session = await requireSession(ctx);
    requireCsrf(ctx, session);
    const message = await stores.messages.get(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    const { mailbox } = await resolveMailbox(ctx, session, message.mailboxRef, 'delegate');

    // Kalıcı silme yalnızca çöp kutusundakiler için ve açık istekle.
    const permanent = ctx.query.get('permanent') === '1';
    if (permanent) {
      if (message.folder !== 'trash') {
        throw new HttpError(400, 'Kalıcı silme yalnızca çöp kutusundaki iletiler için');
      }
      await stores.messages.purge(ctx.params.ref);
    } else {
      await stores.messages.softDelete(ctx.params.ref);
    }
    realtime.publishUpdate(mailbox.ref, { messageRef: ctx.params.ref, deleted: true, permanent });
    ctx.json(200, { ok: true, permanent });
  });

  router.post('/api/v1/mailboxes/:mailbox/read-all', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox);
    const folder = String(ctx.state.input.fields.folder || 'inbox');
    const changed = await stores.messages.markAllSeen(mailbox.ref, folder);
    realtime.publishUpdate(mailbox.ref, { readAll: true, folder, changed });
    ctx.json(200, { ok: true, changed });
  });

  /* ── gönderim ──────────────────────────────────────────────── */

  router.post('/api/v1/mailboxes/:mailbox/send', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'sender');

    const { fields, files } = ctx.state.input;
    const attachments = collectAttachments(fields, files, config);

    try {
      const result = await pipeline.send({
        mailbox,
        fromAddress: fields.from ? normalizeAddress(fields.from) : null,
        fromName: fields.fromName || mailbox.displayName,
        to: parseAddressField(fields.to),
        cc: parseAddressField(fields.cc),
        bcc: parseAddressField(fields.bcc),
        subject: String(fields.subject || ''),
        text: String(fields.text || ''),
        html: String(fields.html || ''),
        attachments,
        inReplyTo: fields.inReplyTo || '',
        references: parseAddressField(fields.references).map((r) => r.address || r),
        smime: toBool(fields.smime),
        priority: fields.priority || null,
        actorSub: session.idpSub,
      });
      ctx.json(200, { ok: true, ...result });
    } catch (err) {
      if (err.code === 'NO_SMIME_CERT') throw new HttpError(409, err.message, { code: err.code });
      if (err.code === 'SENDER_NOT_ALLOWED') throw new HttpError(403, err.message, { code: err.code });
      if (String(err.code || '').startsWith('ATTACHMENT') || err.code === 'TOO_MANY_ATTACHMENTS') {
        throw new HttpError(413, err.message, { code: err.code });
      }
      throw err;
    }
  });

  /** İletme — "eposta görme iletme http olarak" isteğinin karşılığı. */
  router.post('/api/v1/messages/:ref/forward', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const message = await stores.messages.get(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    const { mailbox } = await resolveMailbox(ctx, session, message.mailboxRef, 'sender');

    const to = parseAddressField(ctx.state.input.fields.to).map((r) => r.address);
    if (!to.length) throw new HttpError(400, 'En az bir alıcı gerekir');

    const result = await pipeline.forward({
      mailbox,
      messageRef: ctx.params.ref,
      to,
      comment: String(ctx.state.input.fields.comment || ''),
      smime: toBool(ctx.state.input.fields.smime),
      actorSub: session.idpSub,
    });
    ctx.json(200, { ok: true, ...result });
  });

  /* ── toplu gönderim ────────────────────────────────────────── */

  router.post('/api/v1/mailboxes/:mailbox/campaigns', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');

    const { fields, files } = ctx.state.input;
    const recipients = parseAddressField(fields.recipients).map((r) => r.address);
    if (!recipients.length) throw new HttpError(400, 'Alıcı listesi boş');

    const result = await queue.startCampaign({
      mailbox,
      name: String(fields.name || 'kampanya'),
      subject: String(fields.subject || ''),
      text: String(fields.text || ''),
      html: String(fields.html || ''),
      recipients,
      attachments: collectAttachments(fields, files, config),
      smime: toBool(fields.smime),
      fromAddress: fields.from ? normalizeAddress(fields.from) : null,
      ratePerSecond: fields.ratePerSecond ? Number(fields.ratePerSecond) : null,
      listUnsubscribe: fields.listUnsubscribe || null,
      actorSub: session.idpSub,
    });
    ctx.json(202, { ok: true, ...result });
  });

  router.get('/api/v1/campaigns/:campaignId', async (ctx) => {
    const session = await requireSession(ctx);
    const campaign = await stores.outbound.getCampaign(ctx.params.campaignId);
    if (!campaign) throw new HttpError(404, 'Kampanya bulunamadı');
    await resolveMailbox(ctx, session, campaign.mailboxRef);
    const failures = (await stores.outbound.listByCampaign(campaign.campaignId, { status: 'failed', limit: 50 }))
      .map((item) => ({ rcptTo: item.rcptTo, error: item.lastError, code: item.lastSmtpCode }));
    ctx.json(200, { ...campaign, failures });
  });

  router.get('/api/v1/mailboxes/:mailbox/campaigns', async (ctx) => {
    const session = await requireSession(ctx);
    await resolveMailbox(ctx, session, ctx.params.mailbox);
    ctx.json(200, { campaigns: await stores.outbound.listCampaigns({ ownerSub: session.idpSub }) });
  });

  router.post('/api/v1/campaigns/:campaignId/pause', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const campaign = await stores.outbound.getCampaign(ctx.params.campaignId);
    if (!campaign) throw new HttpError(404, 'Kampanya bulunamadı');
    await resolveMailbox(ctx, session, campaign.mailboxRef, 'owner');
    ctx.json(200, { ok: true, ...(await queue.pauseCampaign(ctx.params.campaignId)) });
  });

  /* ── kuyruk görünürlüğü ────────────────────────────────────── */

  router.get('/api/v1/mailboxes/:mailbox/outbox', async (ctx) => {
    const session = await requireSession(ctx);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox);
    const items = await stores.outbound.listByMailbox(mailbox.ref, { limit: 100 });
    ctx.json(200, {
      items: items.map((item) => ({
        queueId: item.queueId, status: item.status, rcptTo: item.rcptTo,
        subject: item.subject, attempts: item.attempts, lastError: item.lastError,
        nextAttemptAt: item.nextAttemptAt, sentAt: item.sentAt, mxUsed: item.mxUsed,
        tlsUsed: item.tlsUsed, dkimSigned: item.dkimSigned, smimeSigned: item.smimeSigned,
      })),
    });
  });

  /* ── ayarlar ───────────────────────────────────────────────── */

  router.post('/api/v1/mailboxes/:mailbox/settings', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    const fields = ctx.state.input.fields;

    const patch = {};
    if (fields.displayName != null) patch.displayName = String(fields.displayName).slice(0, 120);
    if (fields.notifyPrefs != null) {
      patch.notifyPrefs = typeof fields.notifyPrefs === 'string' ? JSON.parse(fields.notifyPrefs) : fields.notifyPrefs;
    }
    if (fields.forwardTo != null) {
      const targets = parseAddressField(fields.forwardTo).map((r) => r.address);
      patch.forwardTo = targets;
      patch.keepLocalCopy = fields.keepLocalCopy == null ? true : toBool(fields.keepLocalCopy);
    }
    if (fields.filterRules != null) {
      patch.filterRules = typeof fields.filterRules === 'string' ? JSON.parse(fields.filterRules) : fields.filterRules;
    }
    if (fields.smimeEnabled != null) patch.smimeEnabled = toBool(fields.smimeEnabled);

    const updated = await stores.mailboxes.ensure(mailbox.address, patch);
    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail, action: 'mailbox.settings',
      targetType: 'mailbox', targetId: mailbox.ref, ip: ctx.ip, detail: Object.keys(patch),
    });
    ctx.json(200, { ok: true, mailbox: updated.mailbox });
  });

  /** SMTP istemci parolası — düz metin YALNIZCA burada, bir kez döner. */
  router.post('/api/v1/mailboxes/:mailbox/smtp-credentials', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');

    const credential = await stores.mailboxes.createSmtpCredential({
      mailboxRef: mailbox.ref,
      label: String(ctx.state.input.fields.label || 'posta istemcisi'),
      createdBySub: session.idpSub,
    });
    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail, action: 'smtp_credential.create',
      targetType: 'mailbox', targetId: mailbox.ref, ip: ctx.ip,
    });
    ctx.json(201, {
      ok: true,
      username: credential.username,
      password: credential.password,
      note: 'Bu parola yalnızca şimdi gösterilir; sunucuda yalnızca türevi saklanır.',
      servers: {
        submission: { host: config.hostname, port: config.smtp.ports.submission, security: 'STARTTLS' },
        smtps: { host: config.hostname, port: config.smtp.ports.smtps, security: 'TLS' },
      },
    });
  });

  router.get('/api/v1/mailboxes/:mailbox/smtp-credentials', async (ctx) => {
    const session = await requireSession(ctx);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    ctx.json(200, { credentials: await stores.mailboxes.listSmtpCredentials(mailbox.ref) });
  });

  /* ── S/MIME sertifikaları ──────────────────────────────────── */

  router.get('/api/v1/mailboxes/:mailbox/certificate', async (ctx) => {
    const session = await requireSession(ctx);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox);
    const cert = await stores.certificates.get('smime', mailbox.address);
    if (!cert) { ctx.json(200, { available: false }); return; }
    ctx.json(200, {
      available: cert.status === 'active',
      status: cert.status,
      subject: cert.subjectDn,
      issuer: cert.issuerDn,
      serialHex: cert.serialHex,
      fingerprint: cert.fingerprint,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      renewAfter: cert.renewAfter,
      // Sertifika açık veridir; özel anahtar DÖNMEZ ve dönmemeli.
      certPem: cert.certPem,
      chainPem: cert.chainPem,
    });
  });

  // 1. Adım: Cihaz kodu akışını başlat
  router.post('/api/v1/mailboxes/:mailbox/certificate/device-start', async (ctx) => {
    const session = await requireSession(ctx);
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    
    // IdpClient kullanarak cihaz kodu isteği atıyoruz
    const { IdpClient } = require('../../auth/idp-client');
    const idp = new IdpClient({
      baseUrl: config.idp.baseUrl,
      clientId: config.idp.deviceClientId || config.idp.clientId,
      clientSecret: config.idp.clientSecret || '',
      scopes: ['openid', 'profile', 'email', 'cert:issue'],
      config,
    });

    const start = await idp.startDeviceAuthorization({
      scopes: ['openid', 'profile', 'email', 'cert:issue'],
      clientId: idp.clientId,
    });

    // Kullanıcıya ve ön yüze gerekli bilgileri dönüyoruz
    ctx.json(200, {
      deviceCode: start.deviceCode,
      userCode: start.userCode,
      verificationUri: start.verificationUri,
      verificationUriComplete: start.verificationUriComplete,
      interval: start.interval || 5,
      expiresIn: start.expiresIn || 600,
    });
  });

  // 2. Adım: Onay geldikten sonra token'ı al ve sertifikayı üret
  router.post('/api/v1/mailboxes/:mailbox/certificate/device-complete', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    
    const deviceCode = ctx.state.input.fields.deviceCode;
    if (!deviceCode) throw new HttpError(400, 'deviceCode gerekli');

    const { IdpClient } = require('../../auth/idp-client');
    const idp = new IdpClient({
      baseUrl: config.idp.baseUrl,
      clientId: config.idp.deviceClientId || config.idp.clientId,
      clientSecret: config.idp.deviceClientSecret || '',
      scopes: ['openid', 'profile', 'email', 'cert:issue'],
      config,
    });

    let tokens;
    try {
      tokens = await idp.pollDeviceToken({
        deviceCode,
        interval: 5,
        expiresIn: 60, 
        clientId: idp.clientId,
        onPending: () => {},
      });
    } catch (err) {
      throw new HttpError(400, 'Onay henüz verilmedi veya süre doldu: ' + err.message);
    }

    // 🟢 SİHİRLİ DOKUNUŞ BURADA: `accessToken` değil, `access_token`!
    // JSON'dan gelen ham adı kullanıyoruz ki undefined olmasın.
    const result = await certificates.ensureForMailbox(mailbox, {
      force: true,
      requestedBySub: session.idpSub,
      userAccessToken: tokens.access_token || tokens.accessToken, // İhtiyatlı davranıp ikisini de kontrol ediyoruz
    });

    if (result.status === 'failed') throw new HttpError(502, `Sertifika alınamadı: ${result.reason}`);
    ctx.json(200, { ok: true, ...result });
  });

  router.post('/api/v1/mailboxes/:mailbox/certificate/issue', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');

    const result = await certificates.ensureForMailbox(mailbox, {
      force: toBool(ctx.state.input.fields.force),
      requestedBySub: session.idpSub,
    });
    if (result.status === 'failed') throw new HttpError(502, `Sertifika alınamadı: ${result.reason}`);
    ctx.json(200, { ok: true, ...result });
  });

  /* ── bildirim abonelikleri ─────────────────────────────────── */

  router.get('/api/v1/push/public-key', async (ctx) => {
    ctx.json(200, { publicKey: await push.publicKey() });
  });

  router.post('/api/v1/push/subscribe', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const fields = ctx.state.input.fields;
    const subscription = typeof fields.subscription === 'string'
      ? JSON.parse(fields.subscription) : (fields.subscription || fields);

    if (!subscription.endpoint || !subscription.keys) throw new HttpError(400, 'Abonelik eksik');

    let mailboxRef = '';
    if (fields.mailbox) {
      const { mailbox } = await resolveMailbox(ctx, session, fields.mailbox);
      mailboxRef = mailbox.ref;
    } else if ((session.mailboxes || []).length) {
      mailboxRef = session.mailboxes[0].ref;
    }

    const topics = fields.topics
      ? (typeof fields.topics === 'string' ? JSON.parse(fields.topics) : fields.topics)
      : ['mail', 'security'];

    const result = await stores.push.subscribe({
      endpoint: subscription.endpoint,
      keys: subscription.keys,
      mailboxRef,
      idpSub: session.idpSub,
      userAgent: ctx.header('user-agent') || '',
      topics,
    });
    ctx.json(result.created ? 201 : 200, { ok: true, topics, mailboxRef });
  });

  router.post('/api/v1/push/unsubscribe', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const endpoint = ctx.state.input.fields.endpoint;
    if (!endpoint) throw new HttpError(400, 'endpoint gerekli');
    ctx.json(200, { ok: await stores.push.unsubscribe(endpoint) });
  });

  /** Test bildirimi: kullanıcı ayarı doğru mu, denemeden anlaşılmıyor. */
  router.post('/api/v1/push/test', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.state.input.fields.mailbox || session.mailboxes[0].ref);
    const result = await push.sendToMailbox(mailbox.ref, {
      title: 'Fitfak Posta',
      body: 'Bildirimler çalışıyor.',
      icon: '/icon-192.png',
      data: { kind: 'test', url: '/' },
    }, { topic: 'mail' });
    ctx.json(200, { ok: true, ...result });
  });

  /* ── gerçek zamanlı (SSE) ──────────────────────────────────── */

  router.get('/api/v1/events', async (ctx) => {
    const session = await requireSession(ctx);
    realtime.handleSse(ctx, session);
  });

  /* ── yardımcılar ───────────────────────────────────────────── */

  function attachmentKey(session) {
    // Jeton anahtarı oturuma bağlı: başka bir oturumda üretilmiş bağlantı
    // burada doğrulanamaz, yani bağlantı paylaşmak işe yaramaz.
    return `${config.vaultSecret.toString('hex')}:${session.ref}`;
  }

  function attachmentToken(attachment, session) {
    return signHs({ a: attachment.ref }, attachmentKey(session), {
      expiresInMs: config.http.attachmentTokenTtlMs,
    });
  }
}

/* ── saf yardımcılar ───────────────────────────────────────── */

function toBool(value) {
  if (typeof value === 'boolean') return value;
  return ['1', 'true', 'evet', 'yes', 'on'].includes(String(value).toLowerCase());
}

function parseAddressField(value) {
  if (!value) return [];
  const list = Array.isArray(value) ? value : String(value).split(/[,;\n]/);
  const out = [];
  for (const entry of list) {
    if (!entry) continue;
    if (typeof entry === 'object') {
      if (entry.address) out.push({ address: normalizeAddress(entry.address), name: entry.name || '' });
      continue;
    }
    const address = normalizeAddress(String(entry).replace(/^.*<|>.*$/g, '').trim());
    if (address.includes('@')) out.push({ address, name: '' });
  }
  return out;
}

/** Hem multipart dosyalarını hem JSON base64 eklerini tek biçime getirir. */
function collectAttachments(fields, files, config) {
  const out = [];
  for (const file of files || []) {
    out.push({
      fileName: file.fileName,
      contentType: file.contentType,
      content: file.content,
      contentId: file.contentId || '',
      inline: file.inline && !!file.contentId,
    });
  }
  const declared = fields.attachments
    ? (typeof fields.attachments === 'string' ? JSON.parse(fields.attachments) : fields.attachments)
    : [];
  for (const entry of [].concat(declared || [])) {
    if (!entry || !entry.content) continue;
    out.push({
      fileName: safeFileName(entry.fileName || 'ek.bin'),
      contentType: entry.contentType || 'application/octet-stream',
      content: Buffer.from(entry.content, 'base64'),
      contentId: entry.contentId || '',
      inline: !!entry.inline && !!entry.contentId,
    });
  }
  // Sunucu tarafı sınır denetimi: istemcinin uyguladığı sınır bir öneridir.
  for (const att of out) {
    const ext = String(att.fileName).match(/(\.[A-Za-z0-9]{1,12})$/);
    if (ext && config.limits.blockedAttachmentExtensions.includes(ext[1].toLowerCase())) {
      const err = new HttpError(415, `Bu uzantı gönderilemez: ${ext[1]}`, { code: 'EXTENSION_BLOCKED' });
      throw err;
    }
  }
  return out;
}

function parseRange(header, totalBytes) {
  if (!header) return null;
  const m = String(header).match(/^bytes=(\d*)-(\d*)$/);
  if (!m) return null;
  let start = m[1] ? Number(m[1]) : null;
  let end = m[2] ? Number(m[2]) : null;
  if (start == null && end == null) return null;
  if (start == null) { start = Math.max(0, totalBytes - end); end = totalBytes - 1; }
  else if (end == null) end = totalBytes - 1;
  end = Math.min(end, totalBytes - 1);
  if (start > end || start < 0) return null;
  return { start, end };
}

/**
 * Gelen HTML gövdenin temizlenmesi.
 *
 * İzin listesi yaklaşımı: bilinen güvenli etiketler ve öznitelikler kalır,
 * geri kalan her şey gider. Kara liste ("script'i sil") her zaman eksik
 * kalır — `onerror`, `javascript:` protokolü, `<svg><script>` gibi
 * varyantlar sürekli yeniden keşfedilir.
 *
 * Uzak görseller de engellenir: bir e-postadaki uzak görsel, iletinin
 * açıldığını gönderene bildiren bir izleme pikselidir.
 */
function sanitizeHtml(html) {
  let out = String(html);

  out = out.replace(/<!--[\s\S]*?-->/g, '');
  out = out.replace(/<\s*(script|style|iframe|object|embed|applet|meta|link|base|form|input|button|textarea|select|frame|frameset|noscript|template)\b[\s\S]*?<\s*\/\s*\1\s*>/gi, '');
  out = out.replace(/<\s*(script|style|iframe|object|embed|applet|meta|link|base|form|input|button|frame|frameset)\b[^>]*>/gi, '');

  // Olay işleyicileri ve tehlikeli protokoller.
  out = out.replace(/\son[a-z]+\s*=\s*"[^"]*"/gi, '');
  out = out.replace(/\son[a-z]+\s*=\s*'[^']*'/gi, '');
  out = out.replace(/\son[a-z]+\s*=\s*[^\s>]+/gi, '');
  out = out.replace(/(href|src|action|formaction|xlink:href)\s*=\s*("|')?\s*(javascript|vbscript|data:text\/html)[^"'\s>]*("|')?/gi, '$1="#"');

  // Uzak kaynaklar: `cid:` (ileti içi) ve `data:image` kalır, dış adres
  // gitmez. Kullanıcı isterse arayüzden "görselleri göster" diyebilir.
  out = out.replace(/<img([^>]*?)\ssrc\s*=\s*("|')(https?:\/\/[^"']*)\2([^>]*)>/gi,
    '<img$1 data-blocked-src="$3" alt="(uzak görsel engellendi)"$4>');

  // <a> bağlantıları yeni sekmede ve referrer'sız açılır.
  out = out.replace(/<a\s/gi, '<a rel="noopener noreferrer nofollow" target="_blank" ');
  return out;
}

module.exports = { registerWebmailRoutes, sanitizeHtml, parseAddressField, parseRange, collectAttachments };
