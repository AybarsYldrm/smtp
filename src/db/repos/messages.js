'use strict';

const crypto = require('node:crypto');

const { makePreview, htmlToText, normalizeAddress, safeFileName } = require('../../util/encoding');

const FOLDERS = new Set(['inbox', 'sent', 'drafts', 'archive', 'spam', 'trash', 'outbox']);
// Bu boyutun altındaki gövdeler kaydın içinde durur: liste görünümü ve tek
// ileti okuma tek turda tamamlanır. Üstündekiler blob'a gider.
const INLINE_BODY_MAX = 24 * 1024;

/**
 * İletiler ve ekler.
 *
 * Saklama düzeni üç parçalı ve her parçanın ayrı bir nedeni var:
 *
 *   messages     — liste görünümünün ihtiyaç duyduğu her şey (konu, gönderen,
 *                  önizleme, bayraklar). Bir kutunun son 50 iletisini
 *                  göstermek için ek okuma gerekmez.
 *   blobs        — büyük gövdeler ve ham RFC822. Ham iletiyi saklamak
 *                  pahalıdır ama S/MIME ve DKIM doğrulamasının sonradan
 *                  yeniden yapılabilmesi ve "kaynağı göster" için tek yol.
 *   attachments  — ek üstverisi; baytlar blob'ta. Böylece bir eki indirmek
 *                  ileti kaydını hiç okumaz.
 */
class MessageRepo {
  constructor(db, { config, blobs, mailboxes, logger = null } = {}) {
    this.db = db;
    this.config = config;
    this.blobStore = blobs;
    this.mailboxRepo = mailboxes;
    this.logger = logger;
  }

  get messages() { return this.db.collection('messages'); }
  get attachments() { return this.db.collection('attachments'); }

  static shapeSummary(row) {
    if (!row) return null;
    return {
      ref: String(row._id),
      mailboxRef: row.mailboxRef,
      mailboxAddress: row.mailboxAddress || '',
      folder: row.folder || 'inbox',
      messageId: row.messageIdHeader || '',
      threadKey: row.threadKey || '',
      subject: row.subject || '',
      from: { address: row.fromAddress || '', name: row.fromName || '' },
      to: parseJson(row.toJson, []),
      cc: parseJson(row.ccJson, []),
      replyTo: row.replyTo || '',
      date: row.dateHeader || '',
      receivedAt: Number(row.receivedAt || 0),
      sizeBytes: Number(row.sizeBytes || 0),
      seen: !!row.seen,
      flagged: !!row.flagged,
      answered: !!row.answered,
      draft: !!row.draft,
      hasAttachments: !!row.hasAttachments,
      attachmentCount: Number(row.attachmentCount || 0),
      preview: row.previewText || '',
      authResults: parseJson(row.authResultsJson, null),
      spamScore: Number(row.spamScore || 0),
      smimeStatus: row.smimeStatus || 'none',
      smimeSigner: parseJson(row.smimeSignerJson, null),
      labels: parseJson(row.labelsJson, []),
      listId: row.listId || '',
      seq: Number(row.seq || 0),
      updatedAt: Number(row.updatedAt || 0),
      deletedAt: Number(row.deletedAt || 0),
      campaignId: row.campaignId || '',
      bodyTruncated: !!row.bodyTruncated,
      dsn: parseJson(row.dsnJson, null),
    };
  }

  /**
   * Ayrıştırılmış bir iletiyi bir posta kutusuna yazar.
   *
   * Sıra: blob'lar -> ekler -> ileti kaydı -> sayaçlar. İleti kaydı EN SONA
   * yazılır, çünkü onun varlığı "bu ileti tamamdır" anlamına gelir: arada bir
   * çökme, sahipsiz blob bırakır (süpürücü toplar), yarım görünen bir ileti
   * bırakmaz.
   */
  async store({
    mailbox, parsed, rawBuffer = null, folder = 'inbox',
    envelopeFrom = '', envelopeTo = '', remoteIp = '',
    authResults = null, smime = null, campaignId = '', seen = false,
    keepRaw = true, spamScore = 0, dsn = null,
  }) {
    if (!FOLDERS.has(folder)) throw new Error(`[messages] bilinmeyen klasör: ${folder}`);
    const now = Date.now();
    const mailboxRef = String(mailbox.ref);

    const textBody = parsed.text || (parsed.html ? htmlToText(parsed.html) : '');
    const htmlBody = parsed.html || '';

    let bodyTextInline = '';
    let bodyHtmlInline = '';
    let bodyTextBlobId = '';
    let bodyHtmlBlobId = '';

    if (Buffer.byteLength(textBody, 'utf8') <= INLINE_BODY_MAX) bodyTextInline = textBody;
    else {
      const w = await this.blobStore.write(Buffer.from(textBody, 'utf8'), {
        kind: 'body', ownerRef: mailboxRef, contentType: 'text/plain; charset=utf-8', dedupe: false,
      });
      bodyTextBlobId = w.blobId;
    }

    if (htmlBody) {
      if (Buffer.byteLength(htmlBody, 'utf8') <= INLINE_BODY_MAX) bodyHtmlInline = htmlBody;
      else {
        const w = await this.blobStore.write(Buffer.from(htmlBody, 'utf8'), {
          kind: 'body', ownerRef: mailboxRef, contentType: 'text/html; charset=utf-8', dedupe: false,
        });
        bodyHtmlBlobId = w.blobId;
      }
    }

    let rawBlobId = '';
    if (keepRaw && rawBuffer && rawBuffer.length) {
      const w = await this.blobStore.write(rawBuffer, {
        kind: 'raw', ownerRef: mailboxRef, contentType: 'message/rfc822',
      });
      rawBlobId = w.blobId;
    }

    const seq = await this.mailboxRepo.nextSeq(mailboxRef);
    const accepted = (parsed.attachments || []).filter((a) => a.scanStatus === 'accepted' || !a.scanStatus);
    const sizeBytes = Number(parsed.sizeBytes || (rawBuffer ? rawBuffer.length : Buffer.byteLength(textBody, 'utf8')));

    const record = {
      mailboxRef,
      mailboxAddress: mailbox.address,
      folder,
      messageIdHeader: parsed.messageId || '',
      threadKey: MessageRepo.threadKeyFor(parsed),
      subject: parsed.subject || '',
      fromAddress: parsed.from ? parsed.from.address : '',
      fromName: parsed.from ? parsed.from.name : '',
      toJson: JSON.stringify(parsed.to || []),
      ccJson: JSON.stringify(parsed.cc || []),
      replyTo: parsed.replyTo || '',
      dateHeader: parsed.date || '',
      receivedAt: now,
      sizeBytes,
      seen: !!seen,
      flagged: false,
      answered: false,
      draft: folder === 'drafts',
      hasAttachments: accepted.length > 0,
      attachmentCount: accepted.length,
      previewText: makePreview(textBody || htmlToText(htmlBody)),
      bodyTextInline,
      bodyHtmlInline,
      bodyTextBlobId,
      bodyHtmlBlobId,
      rawBlobId,
      authResultsJson: authResults ? JSON.stringify(authResults) : '',
      spamScore: Number(spamScore) || 0,
      envelopeFrom: normalizeAddress(envelopeFrom),
      envelopeTo: normalizeAddress(envelopeTo),
      remoteIp: remoteIp || '',
      smimeStatus: smime ? smime.status : 'none',
      smimeSignerJson: smime && smime.signer ? JSON.stringify(smime.signer) : '',
      deletedAt: 0,
      labelsJson: JSON.stringify(parsed.labels || []),
      inReplyTo: parsed.inReplyTo || '',
      referencesJson: JSON.stringify(parsed.references || []),
      listId: parsed.listId || '',
      seq,
      updatedAt: now,
      headersJson: JSON.stringify(pickHeaders(parsed.headers)),
      campaignId: campaignId || '',
      partsJson: JSON.stringify((parsed.parts || []).map((p) => ({
        partId: p.partId, contentType: p.contentType, sizeBytes: p.sizeBytes,
      }))),
      snoozedUntil: 0,
      bodyTruncated: !!parsed.bodyTruncated,
      dsnJson: dsn ? JSON.stringify(dsn) : '',
    };

    const messageRef = await this.messages.insert(record);

    // Ekler ileti kaydından SONRA: `messageRef` gerekiyor. Reddedilen ekler de
    // kaydedilir — kullanıcı "bir ek vardı ama gelmedi" durumunu görebilmeli,
    // yoksa sessizce kaybolmuş sayılır.
    for (const att of (parsed.attachments || [])) {
      let blobId = '';
      if (att.scanStatus === 'accepted' && att.content && att.content.length) {
        const w = await this.blobStore.write(att.content, {
          kind: 'attachment', ownerRef: messageRef, contentType: att.contentType,
        });
        blobId = w.blobId;
      }
      await this.attachments.insert({
        messageRef,
        mailboxRef,
        partId: att.partId || '',
        fileName: safeFileName(att.fileName || 'ek.bin'),
        contentType: att.contentType || 'application/octet-stream',
        contentId: att.contentId || '',
        disposition: att.disposition || 'attachment',
        sizeBytes: Number(att.sizeBytes || (att.content ? att.content.length : 0)),
        sha256Hex: att.content ? crypto.createHash('sha256').update(att.content).digest('hex') : '',
        blobId,
        createdAt: now,
        scanStatus: att.scanStatus || 'accepted',
        rejectedReason: att.rejectedReason || '',
        isInline: !!att.isInline,
        width: Number(att.width || 0),
        height: Number(att.height || 0),
        declaredType: att.declaredType || att.contentType || '',
        sniffedType: att.sniffedType || '',
      });
    }

    await this.mailboxRepo.applyCounters(mailboxRef, {
      usedBytes: sizeBytes,
      messages: 1,
      unread: seen ? 0 : 1,
      lastDeliveryAt: now,
    });

    return { ref: messageRef, seq, sizeBytes };
  }

  static threadKeyFor(parsed) {
    // Konu bazlı gruplama yerine References/In-Reply-To zincirinin KÖKÜ.
    // Konuya göre gruplamak, "Re: merhaba" yazan iki alakasız kişiyi aynı
    // konuşmaya koyar.
    const refs = parsed.references || [];
    const root = refs[0] || parsed.inReplyTo || parsed.messageId || '';
    if (!root) return '';
    return crypto.createHash('sha256').update(String(root)).digest('hex').slice(0, 32);
  }

  async get(messageRef) {
    return MessageRepo.shapeSummary(await this.messages.get(String(messageRef)));
  }

  /** Gövdeleri ve ek listesini de içeren tam ileti. */
  async getFull(messageRef) {
    const row = await this.messages.get(String(messageRef));
    if (!row) return null;
    const summary = MessageRepo.shapeSummary(row);
    const text = row.bodyTextInline || (row.bodyTextBlobId ? (await this.blobStore.read(row.bodyTextBlobId) || Buffer.alloc(0)).toString('utf8') : '');
    const html = row.bodyHtmlInline || (row.bodyHtmlBlobId ? (await this.blobStore.read(row.bodyHtmlBlobId) || Buffer.alloc(0)).toString('utf8') : '');
    const atts = await this.listAttachments(messageRef);
    return {
      ...summary,
      text,
      html,
      attachments: atts,
      headers: parseJson(row.headersJson, {}),
      hasRaw: !!row.rawBlobId,
      rawBlobId: row.rawBlobId || '',
      inReplyTo: row.inReplyTo || '',
      references: parseJson(row.referencesJson, []),
      envelopeFrom: row.envelopeFrom || '',
      envelopeTo: row.envelopeTo || '',
      remoteIp: row.remoteIp || '',
    };
  }

  async getRaw(messageRef) {
    const row = await this.messages.get(String(messageRef));
    if (!row || !row.rawBlobId) return null;
    return this.blobStore.read(row.rawBlobId);
  }

  async listAttachments(messageRef) {
    const rows = await this.attachments.find('messageRef', String(messageRef));
    rows.sort((a, b) => String(a.partId).localeCompare(String(b.partId)));
    return rows.map((r) => ({
      ref: String(r._id),
      partId: r.partId,
      fileName: r.fileName,
      contentType: r.contentType,
      contentId: r.contentId,
      disposition: r.disposition,
      sizeBytes: Number(r.sizeBytes || 0),
      sha256Hex: r.sha256Hex,
      blobId: r.blobId,
      scanStatus: r.scanStatus,
      rejectedReason: r.rejectedReason,
      isInline: !!r.isInline,
      width: Number(r.width || 0),
      height: Number(r.height || 0),
      declaredType: r.declaredType || '',
      sniffedType: r.sniffedType || '',
    }));
  }

  async getAttachment(attachmentRef) {
    const row = await this.attachments.get(String(attachmentRef));
    if (!row) return null;
    return {
      ref: String(row._id),
      messageRef: row.messageRef,
      mailboxRef: row.mailboxRef,
      fileName: row.fileName,
      contentType: row.contentType,
      sizeBytes: Number(row.sizeBytes || 0),
      blobId: row.blobId,
      scanStatus: row.scanStatus,
      isInline: !!row.isInline,
    };
  }

  /**
   * Liste sorgusu. Sıralama alıcı tarafta değil burada yapılır ve `receivedAt`
   * azalan; `cursor` son görülen `receivedAt` değeridir.
   */
  async list({
    mailboxRef, folder = 'inbox', limit = 50, beforeReceivedAt = null,
    unreadOnly = false, flaggedOnly = false, threadKey = null, includeDeleted = false,
    query = null, hasAttachments = null,
  }) {
    const rows = await this.messages.find('mailboxRef', String(mailboxRef));
    const q = query ? String(query).toLowerCase().trim() : null;
    const filtered = [];
    for (const row of rows) {
      if (!includeDeleted && Number(row.deletedAt || 0)) continue;
      if (folder && row.folder !== folder) continue;
      if (unreadOnly && row.seen) continue;
      if (flaggedOnly && !row.flagged) continue;
      if (threadKey && row.threadKey !== threadKey) continue;
      if (hasAttachments != null && !!row.hasAttachments !== !!hasAttachments) continue;
      if (beforeReceivedAt != null && Number(row.receivedAt || 0) >= Number(beforeReceivedAt)) continue;
      if (q) {
        // Arama sunucu tarafında ve düz metin üzerinde: kör dizin
        // "içeriyor mu" sorusunu cevaplayamaz, cevaplayabilse zaten kör
        // olmazdı. Bu yüzden arama, kutunun kayıtları çözüldükten sonra
        // yapılıyor ve maliyeti açıkça kutu boyutuyla artıyor.
        const hay = `${row.subject || ''} ${row.fromAddress || ''} ${row.fromName || ''} ${row.previewText || ''} ${row.toJson || ''}`.toLowerCase();
        if (!hay.includes(q)) continue;
      }
      filtered.push(row);
    }
    filtered.sort((a, b) => Number(b.receivedAt || 0) - Number(a.receivedAt || 0)
      || Number(b.seq || 0) - Number(a.seq || 0));
    const page = filtered.slice(0, limit);
    return {
      messages: page.map(MessageRepo.shapeSummary),
      nextCursor: filtered.length > limit ? Number(page[page.length - 1].receivedAt || 0) : null,
      total: filtered.length,
    };
  }

  /** Gerçek zamanlı yakalama: `seq` sonrası gelenler. */
  async since({ mailboxRef, seq = 0, limit = 200 }) {
    const rows = await this.messages.find('mailboxRef', String(mailboxRef));
    const out = rows
      .filter((r) => Number(r.seq || 0) > Number(seq))
      .sort((a, b) => Number(a.seq || 0) - Number(b.seq || 0))
      .slice(0, limit);
    return out.map(MessageRepo.shapeSummary);
  }

  async counts(mailboxRef) {
    const rows = await this.messages.find('mailboxRef', String(mailboxRef));
    const out = { total: 0, unread: 0, byFolder: {} };
    for (const r of rows) {
      if (Number(r.deletedAt || 0)) continue;
      const folder = r.folder || 'inbox';
      out.byFolder[folder] = out.byFolder[folder] || { total: 0, unread: 0 };
      out.byFolder[folder].total++;
      out.total++;
      if (!r.seen) { out.byFolder[folder].unread++; out.unread++; }
    }
    return out;
  }

  async setFlags(messageRef, { seen = null, flagged = null, answered = null }) {
    const row = await this.messages.get(String(messageRef));
    if (!row) return null;
    const patch = { updatedAt: Date.now() };
    let unreadDelta = 0;
    if (seen != null && !!row.seen !== !!seen) {
      patch.seen = !!seen;
      unreadDelta = seen ? -1 : 1;
    }
    if (flagged != null) patch.flagged = !!flagged;
    if (answered != null) patch.answered = !!answered;
    await this.messages.update(String(messageRef), patch);
    if (unreadDelta) await this.mailboxRepo.applyCounters(row.mailboxRef, { unread: unreadDelta });
    return { ...MessageRepo.shapeSummary(row), ...patch };
  }

  async markAllSeen(mailboxRef, folder = 'inbox') {
    const rows = await this.messages.find('mailboxRef', String(mailboxRef));
    let changed = 0;
    for (const row of rows) {
      if (row.folder !== folder || row.seen || Number(row.deletedAt || 0)) continue;
      await this.messages.update(String(row._id), { seen: true, updatedAt: Date.now() });
      changed++;
    }
    if (changed) await this.mailboxRepo.applyCounters(String(mailboxRef), { unread: -changed });
    return changed;
  }

  async move(messageRef, folder) {
    if (!FOLDERS.has(folder)) throw new Error(`[messages] bilinmeyen klasör: ${folder}`);
    const row = await this.messages.get(String(messageRef));
    if (!row) return null;
    await this.messages.update(String(messageRef), { folder, updatedAt: Date.now() });
    return { ...MessageRepo.shapeSummary(row), folder };
  }

  /**
   * Yumuşak silme: çöp kutusuna taşır ve `deletedAt` işaretler. Baytlar
   * korunur; "sil" düğmesinin geri alınamaz olması beklenmeyen bir davranış.
   */
  async softDelete(messageRef) {
    const row = await this.messages.get(String(messageRef));
    if (!row) return false;
    if (Number(row.deletedAt || 0)) return true;
    await this.messages.update(String(messageRef), {
      deletedAt: Date.now(), folder: 'trash', updatedAt: Date.now(),
    });
    await this.mailboxRepo.applyCounters(row.mailboxRef, {
      messages: -1, unread: row.seen ? 0 : -1,
    });
    return true;
  }

  async restore(messageRef, folder = 'inbox') {
    const row = await this.messages.get(String(messageRef));
    if (!row || !Number(row.deletedAt || 0)) return false;
    await this.messages.update(String(messageRef), { deletedAt: 0, folder, updatedAt: Date.now() });
    await this.mailboxRepo.applyCounters(row.mailboxRef, { messages: 1, unread: row.seen ? 0 : 1 });
    return true;
  }

  /** Kalıcı silme: blob göndergelerini de düşürür. */
  async purge(messageRef) {
    const row = await this.messages.get(String(messageRef));
    if (!row) return false;
    const atts = await this.attachments.find('messageRef', String(messageRef));
    for (const a of atts) {
      if (a.blobId) await this.blobStore.release(a.blobId);
      await this.attachments.delete(String(a._id));
    }
    for (const blobId of [row.rawBlobId, row.bodyTextBlobId, row.bodyHtmlBlobId]) {
      if (blobId) await this.blobStore.release(blobId);
    }
    if (!Number(row.deletedAt || 0)) {
      await this.mailboxRepo.applyCounters(row.mailboxRef, {
        usedBytes: -Number(row.sizeBytes || 0), messages: -1, unread: row.seen ? 0 : -1,
      });
    } else {
      await this.mailboxRepo.applyCounters(row.mailboxRef, { usedBytes: -Number(row.sizeBytes || 0) });
    }
    await this.messages.delete(String(messageRef));
    return true;
  }

  /** Çöp kutusunda `ttlMs`'ten uzun süre kalanları kalıcı siler. */
  async purgeTrash({ ttlMs = 30 * 86400_000, limit = 200 } = {}) {
    const cutoff = Date.now() - ttlMs;
    let purged = 0;
    for await (const row of this.messages.scan()) {
      const deletedAt = Number(row.deletedAt || 0);
      if (!deletedAt || deletedAt > cutoff) continue;
      await this.purge(String(row._id));
      if (++purged >= limit) break;
    }
    return purged;
  }

  /** Aynı Message-ID'nin aynı kutuya iki kez yazılmasını engeller. */
  async existsByMessageId(mailboxRef, messageId) {
    if (!messageId) return false;
    const rows = await this.messages.find('messageIdHeader', String(messageId));
    return rows.some((r) => r.mailboxRef === String(mailboxRef));
  }
}

function pickHeaders(headers) {
  if (!headers) return {};
  const keep = [
    'from', 'to', 'cc', 'subject', 'date', 'message-id', 'in-reply-to', 'references',
    'reply-to', 'return-path', 'list-id', 'list-unsubscribe', 'content-type',
    'dkim-signature', 'authentication-results', 'received-spf', 'x-mailer', 'user-agent',
    'auto-submitted', 'precedence', 'x-priority', 'importance',
  ];
  const out = {};
  for (const k of keep) if (headers[k] != null) out[k] = headers[k];
  return out;
}

function parseJson(s, fallback) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

module.exports = { MessageRepo, FOLDERS, INLINE_BODY_MAX };
