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

// .pfx parolası: kap dosya olarak taşınacağı için parola tek savunma. Sekiz
// karakter düşük bir eşik ama bir SINIR — hiç sınır koymamak, tek tıkla
// parolasız bir özel anahtar dosyası üretilmesi demekti.
const MIN_PFX_PASSWORD = 8;
// İçe aktarılan .pfx boyutu. Bir kimlik kabı birkaç kilobayt; bundan büyüğü
// ya yanlış dosya ya da belleği tüketmeye çalışan bir istek.
const MAX_PFX_BYTES = 256 * 1024;

/** Zincir PEM'ini tek tek sertifikalara ayırır. */
function splitPemChain(pem) {
  return String(pem).split(/(?=-----BEGIN CERTIFICATE-----)/)
    .map((s) => s.trim())
    .filter((s) => s.includes('BEGIN CERTIFICATE'));
}

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

  /** Eksik kapsam için onay adresi — hem yerel hem IdP kaynaklı retlerde aynı. */
  function scopeUpgradeUrl(returnTo) {
    return `/oauth/upgrade-scope?scope=${encodeURIComponent(config.trust.issueScope)}`
      + `&return_to=${encodeURIComponent(returnTo || '/')}`;
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
      // Kutu yoksa arayüz "boş gelen kutusu" göstermek yerine NEDENİNİ ve ne
      // yapılması gerektiğini gösterebilsin. Gmail gibi harici bir adresle
      // giren kullanıcı için bu, tek anlamlı ekran.
      noMailbox: mailboxes.length ? null : sessions.describeNoMailbox({
        email: session.idpEmail,
        sub: session.idpSub,
        emailVerified: true,
      }),
      scopes: String(session.scope || '').split(/\s+/).filter(Boolean),
      certIssueScope: config.trust.issueScope,
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

  /**
   * Ham ileti kaynağı.
   *
   * Üç biçim, üç ayrı ihtiyaç:
   *   - `?format=text` (öntanımlı): tarayıcıda OKUNUR. `message/rfc822`
   *     göndermek tarayıcıyı dosyayı indirmeye zorluyordu; "kaynağı gör"
   *     bağlantısı bu yüzden hiçbir şey göstermiyordu, indiriyordu.
   *   - `?format=eml`: indirme (posta istemcisine aktarmak, arşivlemek).
   *   - `?format=json`: arayüzün kaynak panelinde göstereceği biçim,
   *     doğrulama izi ve başlık listesiyle birlikte.
   *
   * Her biçimde `Content-Security-Policy: sandbox` var: ham ileti HTML
   * içerebiliyor ve tarayıcı onu kendi kaynağımızda çalıştırmamalı.
   */
  router.get('/api/v1/messages/:ref/raw', async (ctx) => {
    const session = await requireSession(ctx);
    const message = await stores.messages.getFull(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    await resolveMailbox(ctx, session, message.mailboxRef);

    const raw = await stores.messages.getRaw(ctx.params.ref);
    if (!raw) throw new HttpError(404, 'Ham ileti saklanmamış', { code: 'RAW_NOT_STORED' });

    const format = String(ctx.query.get('format') || 'text');
    ctx.setHeader('x-content-type-options', 'nosniff');
    ctx.setHeader('content-security-policy', "default-src 'none'; sandbox");

    if (format === 'json') {
      const text = raw.toString('utf8');
      const split = text.search(/\r?\n\r?\n/);
      ctx.json(200, {
        ref: message.ref,
        sizeBytes: raw.length,
        headers: split === -1 ? text : text.slice(0, split),
        body: split === -1 ? '' : text.slice(split).replace(/^\r?\n\r?\n/, ''),
        raw: text,
        authResults: message.authResults || null,
        smime: message.smimeStatus ? { status: message.smimeStatus, signer: message.smimeSigner || null } : null,
        spamScore: message.spamScore ?? null,
      });
      return;
    }

    if (format === 'eml') {
      const name = safeFileName(`${(message.subject || 'ileti').slice(0, 60)}.eml`);
      ctx.setHeader('content-disposition', `attachment; filename="${name}"`);
      ctx.send(200, raw, 'message/rfc822');
      return;
    }

    ctx.send(200, raw, 'text/plain; charset=utf-8');
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

  /**
   * İstenmeyen / istenmeyen değil.
   *
   * `move` ile klasör değiştirmekten AYRI bir uç nokta, çünkü karar
   * yalnızca bu iletiyi değil GÖNDERENİ de ilgilendiriyor: kullanıcı bir
   * adresi "istenmeyen değil" diye işaretlediğinde, aynı adresten gelen
   * sonraki iletilerin de puanı düşmeli. Aksi hâlde kullanıcı aynı işareti
   * her hafta yeniden koyuyor ve sistem hiçbir şey öğrenmiyor.
   *
   * Karar kutu başına saklanıyor: bir kullanıcının "istenmeyen" dediği
   * gönderen, başka bir kullanıcının beklediği gönderen olabilir.
   */
  router.post('/api/v1/messages/:ref/spam', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const message = await stores.messages.getFull(ctx.params.ref);
    if (!message) throw new HttpError(404, 'İleti bulunamadı');
    const { mailbox } = await resolveMailbox(ctx, session, message.mailboxRef, 'delegate');

    const isSpam = ctx.state.input.fields.spam == null ? true : toBool(ctx.state.input.fields.spam);
    const sender = normalizeAddress((message.from && message.from.address) || message.envelopeFrom || '');
    const folder = isSpam ? 'spam' : 'inbox';

    await stores.messages.move(message.ref, folder);
    if (isSpam) await stores.messages.setFlags(message.ref, { seen: true });

    let verdictSaved = false;
    if (sender) {
      // Kutunun süzme kuralları listesine gönderen bazlı bir karar yazılır.
      // Kural motoru zaten `fromEquals` destekliyor (bkz. chooseFolder);
      // ayrı bir mekanizma icat etmek yerine onu besliyoruz.
      const rules = (mailbox.filterRules || []).filter((r) => normalizeAddress(r.fromEquals || '') !== sender);
      rules.push({ fromEquals: sender, folder, source: 'user', at: Date.now() });
      await stores.mailboxes.ensure(mailbox.address, { filterRules: rules.slice(-200) });
      verdictSaved = true;
    }

    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: isSpam ? 'message.mark_spam' : 'message.mark_not_spam',
      targetType: 'message', targetId: message.ref, ip: ctx.ip,
      detail: { sender, folder },
    });
    logger.info({
      mailbox: mailbox.address, sender, folder, msg: isSpam ? 'istenmeyen olarak işaretlendi' : 'istenmeyen değil olarak işaretlendi',
    });

    realtime.publishUpdate(mailbox.ref, { messageRef: message.ref, folder });
    ctx.json(200, { ok: true, folder, sender, verdictSaved });
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

  /**
   * S/MIME sertifikası iste — KULLANICININ KENDİ KİMLİĞİYLE.
   *
   * ── BİLDİRİLEN HATA VE SEBEBİ ──────────────────────────────────────────
   * Arayüzden sertifika istendiğinde IdP "Kullanıcı bulunamadı" diyordu.
   * Sebep, isteğin sunucunun SERVİS jetonuyla (client_credentials)
   * gönderilmesiydi: IdP sertifikanın sahibini yalnızca jetonun `sub`
   * alanından belirliyor ve o alanda bir kullanıcı değil, istemcinin kendisi
   * yazıyor. `users.get(sub)` boş dönüyor, hata "kullanıcı yok" olarak
   * görünüyor — oysa sorulan kimlik yanlıştı.
   *
   * Doğru kimlik zaten elimizde: kullanıcı tarayıcıda IdP ile giriş yaptı ve
   * erişim jetonu kasada duruyor. Onu kullanıyoruz. Sertifika böylece IdP'de
   * o kullanıcıya yazılıyor, yönetim panelinde görünüyor ve RBAC
   * (`certProfiles`) doğru kişiye uygulanıyor.
   *
   * Cihaz kodu akışı KALDIRILMADI ama artık gerekli değil: aynı sonucu
   * kullanıcıyı ikinci bir ekrana göndermeden veriyoruz. Kapsam eksikse
   * (yalnızca o zaman) bir onay turu gerekiyor.
   */
  router.post('/api/v1/mailboxes/:mailbox/certificate/issue', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');
    if (!certificates.available) {
      throw new HttpError(503, '@fitfak/ssl yüklü değil — sertifika isteği hazırlanamıyor', { code: 'SSL_MISSING' });
    }

    const delegated = await sessions.idpAccessTokenFor(session, {
      requiredScope: config.trust.issueScope,
    });
    if (!delegated.ok) {
      // Kapsam eksik: kullanıcıyı onay turuna yönlendirebilmesi için arayüze
      // adresi veriyoruz. 403 ile "yetkiniz yok" demek yanlış olurdu —
      // yetkisi var, henüz istemedik.
      throw new HttpError(409, delegated.message, {
        code: delegated.code === 'scope_required' ? 'CERT_SCOPE_REQUIRED' : 'IDP_REAUTH_REQUIRED',
        detail: {
          requiredScope: config.trust.issueScope,
          authorizeUrl: scopeUpgradeUrl(String(ctx.state.input.fields.returnTo || '/')),
        },
      });
    }

    const result = await certificates.ensureForMailbox(mailbox, {
      force: toBool(ctx.state.input.fields.force),
      requestedBySub: session.idpSub,
      userAccessToken: delegated.accessToken,
    });

    if (result.status === 'failed' || result.status === 'skipped') {
      logger.warn({
        mailbox: mailbox.address, status: result.status, code: result.code,
        reason: result.reason, msg: 'sertifika isteği başarısız',
      });
      // Kapsamı eksik olduğunu bize IdP söyledi: yerelde tahmin etmediğimiz
      // için buraya kadar geldik ve şimdi kesin bilgiyle onay turuna
      // gönderebiliyoruz.
      if (result.scopeRequired) {
        throw new HttpError(409, result.reason, {
          code: 'CERT_SCOPE_REQUIRED',
          detail: {
            requiredScope: config.trust.issueScope,
            authorizeUrl: scopeUpgradeUrl(String(ctx.state.input.fields.returnTo || '/')),
          },
        });
      }
      throw new HttpError(result.retryable ? 503 : 502, result.reason, {
        code: (result.code || 'CERT_FAILED').toUpperCase(),
        detail: result.hint ? { hint: result.hint } : null,
      });
    }
    ctx.json(200, { ok: true, ...result });
  });

  /**
   * Kullanıcının kendi cihazında ürettiği sertifikayı kaydeder.
   *
   * Özel anahtar İSTENMEZ. Bu yol, anahtarını sunucuya bırakmak istemeyen
   * kullanıcı için: imzalamayı kendi istemcisi yapar, sunucu yalnızca
   * doğrulama tarafı için sertifikayı tanır.
   */
  router.post('/api/v1/mailboxes/:mailbox/certificate/register', async (ctx) => {
    const session = await requireSession(ctx);
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');

    const certPem = String(ctx.state.input.fields.certPem || '');
    if (!certPem.includes('BEGIN CERTIFICATE')) throw new HttpError(400, 'PEM biçiminde bir sertifika bekleniyor');
    try {
      const result = await certificates.registerUserCertificate({
        address: mailbox.address,
        certPem,
        chainPem: String(ctx.state.input.fields.chainPem || ''),
        requestedBySub: session.idpSub,
        ip: ctx.ip,
      });
      ctx.json(200, { ok: true, ...result });
    } catch (err) {
      throw new HttpError(err.status || 400, err.message, { code: 'CERT_REGISTER_FAILED' });
    }
  });

  /**
   * S/MIME kimliğini .pfx olarak dışa aktarır.
   *
   * ── GÜVENLİK ────────────────────────────────────────────────────────────
   * Bu uç nokta ÖZEL ANAHTARI dışarı veren tek yer; kısıtlar buna göre:
   *
   *   - Yalnızca TARAYICI OTURUMU. API jetonu kabul edilmiyor: uzun ömürlü
   *     bir jetonun sızması, o kutunun imzalama kimliğinin sızması olurdu.
   *   - Kutu üzerinde `owner` yetkisi. Okuma ya da gönderme yetkisi yetmez.
   *   - CSRF jetonu (durum değiştirmiyor ama gövdede parola taşıyor; GET
   *     olsaydı parola adres çubuğuna ve kayıtlara düşerdi).
   *   - Parola İSTEMCİDEN gelir ve HİÇBİR YERE yazılmaz — ne kayda, ne
   *     denetim kaydına, ne diske. Kap bellekte üretilip doğrudan yanıta
   *     yazılır.
   *   - Yanıt `no-store`: bir ara önbellek .pfx'i tutarsa parola korumalı
   *     bile olsa çevrimdışı deneme için elde kalır.
   *   - Denetim kaydı düşülür: özel anahtarın ne zaman ve kimin tarafından
   *     dışarı alındığı sonradan mutlaka sorulur.
   */
  router.post('/api/v1/mailboxes/:mailbox/certificate/export', async (ctx) => {
    const session = await requireSession(ctx);
    if (session.isApiToken) {
      throw new HttpError(403, 'Özel anahtar dışa aktarımı tarayıcı oturumu gerektirir', { code: 'INTERACTIVE_REQUIRED' });
    }
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');

    const password = String(ctx.state.input.fields.password || '');
    if (password.length < MIN_PFX_PASSWORD) {
      throw new HttpError(400, `Parola en az ${MIN_PFX_PASSWORD} karakter olmalı`, { code: 'PASSWORD_TOO_SHORT' });
    }

    const pair = await stores.certificates.getSigningPair('smime', mailbox.address);
    if (!pair || !pair.privateKeyPem) {
      throw new HttpError(404, 'Bu adres için özel anahtarı sunucuda olan bir sertifika yok', { code: 'NO_EXPORTABLE_KEY' });
    }

    const { build } = require('../../certs/pkcs12');
    let pfx;
    try {
      pfx = build({
        certPem: pair.certPem,
        privateKeyPem: pair.privateKeyPem,
        chainPems: pair.chainPem ? splitPemChain(pair.chainPem) : [],
        password,
        friendlyName: `${mailbox.displayName || mailbox.address} (S/MIME)`,
      });
    } catch (err) {
      logger.error({ mailbox: mailbox.address, error: err.message, msg: 'pfx üretilemedi' });
      throw new HttpError(500, `PFX üretilemedi: ${err.message}`, { code: 'PFX_BUILD_FAILED' });
    }

    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: 'certificate.export_pfx', targetType: 'mailbox', targetId: mailbox.ref, ip: ctx.ip,
      detail: { serialHex: pair.serialHex, sizeBytes: pfx.length },
    });
    logger.warn({
      mailbox: mailbox.address, actor: session.idpEmail, bytes: pfx.length,
      msg: 'S/MIME özel anahtarı .pfx olarak dışa aktarıldı',
    });

    const fileName = safeFileName(`${mailbox.address}.pfx`);
    ctx.setHeader('content-disposition', `attachment; filename="${fileName}"`);
    ctx.setHeader('cache-control', 'no-store, no-cache, must-revalidate, private');
    ctx.setHeader('pragma', 'no-cache');
    ctx.setHeader('x-content-type-options', 'nosniff');
    ctx.send(200, pfx, 'application/x-pkcs12');
  });

  /**
   * Başka bir yerde üretilmiş bir .pfx'i içe aktarır.
   *
   * Kabul etmeden önce ÜÇ şey kanıtlanır ve üçü de gerekli:
   *   1. Kap açılıyor (parola doğru, MAC tutuyor).
   *   2. Sertifika BU adrese ait — SAN'ında rfc822Name olarak var. Aksi
   *      hâlde bir kullanıcı, başkasının adresine ait bir sertifikayı kendi
   *      kutusuna bağlayıp onun adına imza attırabilirdi.
   *   3. Özel anahtar SERTİFİKAYA ait — bir imza atılıp doğrulanarak. Açık
   *      anahtarları karşılaştırmak yetmez; eşleşmeyen bir çifti kabul etmek,
   *      imzalayamayan bir kimlik kaydetmek olurdu.
   */
  router.post('/api/v1/mailboxes/:mailbox/certificate/import', async (ctx) => {
    const session = await requireSession(ctx);
    if (session.isApiToken) {
      throw new HttpError(403, 'Sertifika içe aktarımı tarayıcı oturumu gerektirir', { code: 'INTERACTIVE_REQUIRED' });
    }
    ctx.state.input = await ctx.input();
    requireCsrf(ctx, session);
    const { mailbox } = await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');

    const { fields, files } = ctx.state.input;
    const upload = (files || [])[0];
    const raw = upload ? upload.content
      : (fields.pfxBase64 ? Buffer.from(String(fields.pfxBase64), 'base64') : null);
    if (!raw || !raw.length) throw new HttpError(400, 'Bir .pfx dosyası gerekiyor', { code: 'FILE_REQUIRED' });
    if (raw.length > MAX_PFX_BYTES) {
      throw new HttpError(413, `.pfx dosyası çok büyük (en fazla ${MAX_PFX_BYTES} bayt)`, { code: 'FILE_TOO_LARGE' });
    }

    const password = String(fields.password || '');
    const { parse, keyMatchesCertificate } = require('../../certs/pkcs12');

    let parsed;
    try {
      parsed = parse(raw, password);
    } catch (err) {
      // Parola hatası ile bozuk dosya AYRILMIYOR: ikisini ayırmak, doğru
      // parolayı arayan birine geri bildirim vermek olurdu.
      logger.warn({ mailbox: mailbox.address, error: err.message, msg: 'pfx okunamadı' });
      throw new HttpError(400, 'Dosya açılamadı — parola yanlış ya da dosya desteklenmeyen biçimde', {
        code: 'PFX_UNREADABLE',
      });
    }

    const certPem = parsed.certificates[0];
    const privateKeyPem = parsed.privateKeys[0];
    if (!certPem || !privateKeyPem) {
      throw new HttpError(400, 'Dosyada sertifika ve özel anahtar birlikte bulunmalı', { code: 'PFX_INCOMPLETE' });
    }

    let x509;
    try { x509 = new (require('node:crypto').X509Certificate)(certPem); }
    catch { throw new HttpError(400, 'Sertifika okunamadı', { code: 'CERT_UNREADABLE' }); }

    const address = mailbox.address;
    const san = String(x509.subjectAltName || '').toLowerCase();
    const subject = String(x509.subject || '').toLowerCase();
    if (!san.includes(`email:${address}`) && !subject.includes(`emailaddress=${address}`)) {
      throw new HttpError(400, `Sertifika ${address} adresini içermiyor`, { code: 'ADDRESS_MISMATCH' });
    }
    if (new Date(x509.validTo).getTime() < Date.now()) {
      throw new HttpError(400, 'Sertifikanın süresi dolmuş', { code: 'CERT_EXPIRED' });
    }
    if (!keyMatchesCertificate(privateKeyPem, certPem)) {
      throw new HttpError(400, 'Özel anahtar bu sertifikaya ait değil', { code: 'KEY_MISMATCH' });
    }

    const stored = await stores.certificates.store({
      usage: 'smime',
      subjectAddress: address,
      mailboxRef: mailbox.ref,
      certPem,
      chainPem: parsed.certificates.slice(1).join('\n'),
      privateKeyPem,
      issuedVia: 'imported',
      requestedBySub: session.idpSub,
      renewAtRatio: config.trust.renewAtLifetimeRatio,
    });
    if (signer) signer.invalidate(address);

    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: 'certificate.import_pfx', targetType: 'mailbox', targetId: mailbox.ref, ip: ctx.ip,
      detail: {
        fingerprint: String(x509.fingerprint256 || '').replace(/:/g, '').toLowerCase(),
        notAfter: new Date(x509.validTo).getTime(),
        chainLength: parsed.certificates.length - 1,
      },
    });
    logger.info({ mailbox: address, version: stored.version, msg: 'S/MIME kimliği .pfx dosyasından içe aktarıldı' });

    ctx.json(200, {
      ok: true,
      version: stored.version,
      subject: x509.subject,
      issuer: x509.issuer,
      notAfter: new Date(x509.validTo).getTime(),
      chainLength: parsed.certificates.length - 1,
    });
  });

  /** IdP'nin bu kullanıcı adına verdiği tüm sertifikalar (uzaktan). */
  router.get('/api/v1/mailboxes/:mailbox/certificate/remote', async (ctx) => {
    const session = await requireSession(ctx);
    await resolveMailbox(ctx, session, ctx.params.mailbox, 'owner');
    if (!certificates) throw new HttpError(503, 'Sertifika yöneticisi yapılandırılmamış');

    const delegated = await sessions.idpAccessTokenFor(session);
    if (!delegated.ok) throw new HttpError(409, delegated.message, { code: 'IDP_REAUTH_REQUIRED' });
    try {
      ctx.json(200, { certificates: await certificates.listRemoteCertificates(delegated.accessToken) });
    } catch (err) {
      throw new HttpError(502, err.message, { code: err.code || 'IDP_UNAVAILABLE' });
    }
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
