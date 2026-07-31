'use strict';

const crypto = require('node:crypto');

const { normalizeAddress, splitAddress } = require('../../util/encoding');

const STATUS = {
  QUEUED: 'queued', SENDING: 'sending', SENT: 'sent',
  DEFERRED: 'deferred', FAILED: 'failed', CANCELLED: 'cancelled',
};

/**
 * Giden kuyruğu ve toplu gönderim kampanyaları.
 *
 * Kuyruk kalıcı ve ALICI BAŞINA bir satır. Tek satırda çok alıcı tutmak,
 * bir alıcının kalıcı hatası (550) yüzünden diğerlerinin de yeniden
 * denenmesine ya da tersine, geçici hata alan birinin diğerleri yüzünden
 * atlanmasına yol açar. Alıcı başına satır, teslimat durumunun alıcı başına
 * doğru olmasını sağlar — ve toplu gönderimde asıl ihtiyaç duyulan şey bu.
 *
 * Ham ileti blob'ta, kuyruk satırında yalnızca göndergesi: aynı gövde 50 bin
 * alıcıya gidiyorsa 50 bin kopya saklamak anlamsız. Blob gönderge sayacıyla
 * korunuyor, son alıcı da gönderildiğinde serbest kalıyor.
 */
class OutboundRepo {
  constructor(db, { config, blobs, logger = null } = {}) {
    this.db = db;
    this.config = config;
    this.blobStore = blobs;
    this.logger = logger;
  }

  get queue() { return this.db.collection('outbound_queue'); }
  get campaigns() { return this.db.collection('campaigns'); }

  static shape(row) {
    if (!row) return null;
    return {
      ref: String(row._id),
      queueId: row.queueId,
      status: row.status,
      nextAttemptAt: Number(row.nextAttemptAt || 0),
      attempts: Number(row.attempts || 0),
      envelopeFrom: row.envelopeFrom,
      rcptTo: row.rcptTo,
      rcptDomain: row.rcptDomain,
      rawBlobId: row.rawBlobId,
      campaignId: row.campaignId || '',
      mailboxRef: row.mailboxRef || '',
      createdAt: Number(row.createdAt || 0),
      updatedAt: Number(row.updatedAt || 0),
      lastError: row.lastError || '',
      lastSmtpCode: Number(row.lastSmtpCode || 0),
      sentAt: Number(row.sentAt || 0),
      messageId: row.messageIdHeader || '',
      priority: Number(row.priority || 0),
      sizeBytes: Number(row.sizeBytes || 0),
      subject: row.subject || '',
      mxUsed: row.mxUsed || '',
      tlsUsed: !!row.tlsUsed,
      dkimSigned: !!row.dkimSigned,
      smimeSigned: !!row.smimeSigned,
      sourceMessageRef: row.sourceMessageRef || '',
      deliveryLog: parseJson(row.deliveryLogJson, []),
      lockedBy: row.lockedBy || '',
      lockedUntil: Number(row.lockedUntil || 0),
    };
  }

  /**
   * Ham iletiyi bir kez saklar, her alıcı için bir kuyruk satırı açar.
   * @returns {{blobId: string, queued: string[], rejected: object[]}}
   */
  async enqueue({
    rawBuffer, envelopeFrom, recipients, mailboxRef = '', campaignId = '',
    messageId = '', subject = '', priority = 0, dkimSigned = false, smimeSigned = false,
    sourceMessageRef = '', delayMs = 0, dsnRequested = false,
  }) {
    if (!rawBuffer || !rawBuffer.length) throw new Error('[outbound] ham ileti boş');
    const list = [...new Set((recipients || []).map(normalizeAddress).filter(Boolean))];
    if (!list.length) throw new Error('[outbound] alıcı yok');

    // Ham ileti tek kopya. Gönderge sayacı alıcı sayısına eşitlenir; her
    // sonuçlanan satır bir gönderge düşürür.
    const written = await this.blobStore.write(rawBuffer, {
      kind: 'outbound',
      ownerRef: mailboxRef || campaignId || 'system',
      contentType: 'message/rfc822',
      // Kuyruktan çıkmış ham iletiler bir hafta sonra süpürülür: teslimat
      // sorunlarını incelemek için yeterli, sonsuza kadar tutmak için değil.
      expiresAt: Date.now() + 7 * 86400_000,
      dedupe: false,
    });
    for (let i = 1; i < list.length; i++) await this.blobStore.retain(written.blobId);

    const now = Date.now();
    const queued = [];
    for (const rcpt of list) {
      const { domain } = splitAddress(rcpt);
      const queueId = crypto.randomBytes(12).toString('hex');
      await this.queue.insert({
        queueId,
        status: STATUS.QUEUED,
        nextAttemptAt: now + Math.max(0, delayMs),
        attempts: 0,
        envelopeFrom: normalizeAddress(envelopeFrom),
        rcptTo: rcpt,
        rcptDomain: domain,
        rawBlobId: written.blobId,
        campaignId: campaignId || '',
        mailboxRef: String(mailboxRef || ''),
        createdAt: now,
        updatedAt: now,
        lastError: '',
        lastSmtpCode: 0,
        sentAt: 0,
        messageIdHeader: messageId || '',
        dsnRequested: !!dsnRequested,
        priority: Number(priority) || 0,
        lockedBy: '',
        lockedUntil: 0,
        sizeBytes: rawBuffer.length,
        subject: subject || '',
        mxUsed: '',
        tlsUsed: false,
        dkimSigned: !!dkimSigned,
        smimeSigned: !!smimeSigned,
        sourceMessageRef: String(sourceMessageRef || ''),
        deliveryLogJson: '[]',
      });
      queued.push(queueId);
    }
    return { blobId: written.blobId, queued, recipients: list };
  }

  /**
   * Gönderilmeye hazır satırları kilitleyerek alır.
   *
   * Kilit, birden fazla işçinin (ve ileride birden fazla sunucunun) aynı
   * iletiyi iki kez göndermesini engeller. Kilidin süresi var: kilidi alan
   * süreç çökerse satır sonsuza kadar "sending" durumunda kalmaz.
   */
  async claimDue({ workerId, limit = 10, now = Date.now(), lockMs = 300_000, domainFilter = null }) {
    const due = await this.queue.findRange('nextAttemptAt', 0, now, { limit: limit * 8 });
    const claimed = [];
    // Öncelik sırası: yüksek öncelik, sonra en eski. Kampanya postası
    // öntanımlı 0 önceliğinde; işlemsel posta (parola sıfırlama, güvenlik
    // uyarısı) daha yüksek öncelikle girer ve toplu gönderimin arkasında
    // saatlerce beklemez.
    due.sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0)
      || Number(a.nextAttemptAt || 0) - Number(b.nextAttemptAt || 0));

    for (const row of due) {
      if (claimed.length >= limit) break;
      if (row.status !== STATUS.QUEUED && row.status !== STATUS.DEFERRED) {
        // "sending" ama kilidi düşmüş: sahibi çökmüş, geri alınır.
        if (row.status === STATUS.SENDING && Number(row.lockedUntil || 0) < now) { /* devam */ }
        else continue;
      }
      if (domainFilter && row.rcptDomain !== domainFilter) continue;
      try {
        await this.queue.update(String(row._id), {
          status: STATUS.SENDING,
          lockedBy: String(workerId),
          lockedUntil: now + lockMs,
          updatedAt: now,
        });
        claimed.push(OutboundRepo.shape(await this.queue.get(String(row._id))));
      } catch (err) {
        // Başka bir işçi önce aldı: yarış kaybedildi, sıradakine geç.
        if (this.logger) this.logger.debug({ queueId: row.queueId, error: err.message, msg: 'kilit alınamadı' });
      }
    }
    return claimed;
  }

  async markSent(ref, { mx = '', tlsUsed = false, smtpCode = 250, logEntry = null }) {
    const row = await this.queue.get(String(ref));
    if (!row) return false;
    const log = parseJson(row.deliveryLogJson, []);
    if (logEntry) log.push(logEntry);
    await this.queue.update(String(ref), {
      status: STATUS.SENT,
      sentAt: Date.now(),
      updatedAt: Date.now(),
      mxUsed: mx,
      tlsUsed: !!tlsUsed,
      lastSmtpCode: smtpCode,
      lockedBy: '',
      lockedUntil: 0,
      deliveryLogJson: JSON.stringify(log.slice(-20)),
    });
    if (row.rawBlobId) await this.blobStore.release(row.rawBlobId);
    if (row.campaignId) await this.bumpCampaign(row.campaignId, { sent: 1 });
    return true;
  }

  /**
   * Başarısızlık. Geçici (4xx) ise geri çekilme ile yeniden denenir; kalıcı
   * (5xx) ise bir daha denenmez. Kalıcı hatayı yeniden denemek yalnızca
   * alıcı sunucuda itibar kaybettirir.
   */
  async markFailure(ref, { error, smtpCode = 0, permanent = false, mx = '', logEntry = null }) {
    const row = await this.queue.get(String(ref));
    if (!row) return null;
    const attempts = Number(row.attempts || 0) + 1;
    const backoff = this.config.queue.backoffMs;
    const isPermanent = permanent || attempts >= this.config.queue.maxAttempts;
    const log = parseJson(row.deliveryLogJson, []);
    if (logEntry) log.push(logEntry);

    const patch = {
      attempts,
      lastError: String(error || '').slice(0, 500),
      lastSmtpCode: Number(smtpCode) || 0,
      updatedAt: Date.now(),
      mxUsed: mx || row.mxUsed || '',
      lockedBy: '',
      lockedUntil: 0,
      deliveryLogJson: JSON.stringify(log.slice(-20)),
    };

    if (isPermanent) {
      patch.status = STATUS.FAILED;
      await this.queue.update(String(ref), patch);
      if (row.rawBlobId) await this.blobStore.release(row.rawBlobId);
      if (row.campaignId) await this.bumpCampaign(row.campaignId, { failed: 1 });
      return { status: STATUS.FAILED, attempts };
    }

    const delay = backoff[Math.min(attempts - 1, backoff.length - 1)];
    patch.status = STATUS.DEFERRED;
    patch.nextAttemptAt = Date.now() + delay;
    await this.queue.update(String(ref), patch);
    return { status: STATUS.DEFERRED, attempts, nextAttemptAt: patch.nextAttemptAt };
  }

  async cancel(ref, reason = '') {
    const row = await this.queue.get(String(ref));
    if (!row) return false;
    if (row.status === STATUS.SENT) return false;
    await this.queue.update(String(ref), {
      status: STATUS.CANCELLED, lastError: reason, updatedAt: Date.now(), lockedBy: '', lockedUntil: 0,
    });
    if (row.rawBlobId) await this.blobStore.release(row.rawBlobId);
    return true;
  }

  async getRaw(queueRow) {
    if (!queueRow.rawBlobId) return null;
    return this.blobStore.read(queueRow.rawBlobId);
  }

  async byQueueId(queueId) {
    return OutboundRepo.shape(await this.queue.findOne('queueId', String(queueId)));
  }

  async stats() {
    const out = { queued: 0, sending: 0, deferred: 0, sent: 0, failed: 0, cancelled: 0, oldestQueuedAt: 0 };
    for (const status of Object.values(STATUS)) {
      const rows = await this.queue.find('status', status);
      out[status] = rows.length;
      if (status === STATUS.QUEUED || status === STATUS.DEFERRED) {
        for (const r of rows) {
          const t = Number(r.createdAt || 0);
          if (t && (!out.oldestQueuedAt || t < out.oldestQueuedAt)) out.oldestQueuedAt = t;
        }
      }
    }
    return out;
  }

  async listByCampaign(campaignId, { limit = 200, status = null } = {}) {
    const rows = await this.queue.find('campaignId', String(campaignId));
    const filtered = status ? rows.filter((r) => r.status === status) : rows;
    return filtered.slice(0, limit).map(OutboundRepo.shape);
  }

  async listByMailbox(mailboxRef, { limit = 100 } = {}) {
    const rows = await this.queue.find('mailboxRef', String(mailboxRef));
    rows.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
    return rows.slice(0, limit).map(OutboundRepo.shape);
  }

  /** Tamamlanmış satırları temizler; kuyruk sonsuza kadar büyümemeli. */
  async sweepCompleted({ ttlMs = 14 * 86400_000, limit = 500 } = {}) {
    const cutoff = Date.now() - ttlMs;
    let removed = 0;
    for await (const row of this.queue.scan()) {
      if (row.status !== STATUS.SENT && row.status !== STATUS.FAILED && row.status !== STATUS.CANCELLED) continue;
      if (Number(row.updatedAt || 0) > cutoff) continue;
      await this.queue.delete(String(row._id));
      if (++removed >= limit) break;
    }
    return removed;
  }

  /* ── kampanyalar ──────────────────────────────────────────── */

  async createCampaign({
    name, ownerSub, mailboxRef, subject = '', total = 0,
    ratePerSecond = null, meta = null, smimeSign = false, templateBlobId = '',
  }) {
    const campaignId = crypto.randomBytes(10).toString('hex');
    const now = Date.now();
    await this.campaigns.insert({
      campaignId,
      name: String(name || 'kampanya'),
      ownerSub: String(ownerSub || ''),
      mailboxRef: String(mailboxRef || ''),
      status: 'draft',
      totalRecipients: Number(total) || 0,
      queuedCount: 0,
      sentCount: 0,
      failedCount: 0,
      createdAt: now,
      startedAt: 0,
      finishedAt: 0,
      subject,
      templateBlobId: templateBlobId || '',
      ratePerSecond: Number(ratePerSecond || this.config.queue.campaignRatePerSecond),
      metaJson: meta ? JSON.stringify(meta) : '',
      smimeSign: !!smimeSign,
      lastError: '',
    });
    return campaignId;
  }

  async bumpCampaign(campaignId, { queued = 0, sent = 0, failed = 0, status = null, lastError = null } = {}) {
    const row = await this.campaigns.findOne('campaignId', String(campaignId));
    if (!row) return null;
    const patch = {};
    if (queued) patch.queuedCount = Number(row.queuedCount || 0) + queued;
    if (sent) patch.sentCount = Number(row.sentCount || 0) + sent;
    if (failed) patch.failedCount = Number(row.failedCount || 0) + failed;
    if (status) patch.status = status;
    if (lastError != null) patch.lastError = String(lastError).slice(0, 500);

    const total = Number(row.totalRecipients || 0);
    const done = (patch.sentCount ?? Number(row.sentCount || 0)) + (patch.failedCount ?? Number(row.failedCount || 0));
    if (total && done >= total && row.status !== 'completed') {
      patch.status = 'completed';
      patch.finishedAt = Date.now();
    }
    if (Object.keys(patch).length) await this.campaigns.update(String(row._id), patch);
    return patch;
  }

  async setCampaignStatus(campaignId, status, extra = {}) {
    const row = await this.campaigns.findOne('campaignId', String(campaignId));
    if (!row) return false;
    const patch = { status, ...extra };
    if (status === 'running' && !Number(row.startedAt || 0)) patch.startedAt = Date.now();
    if (status === 'completed' || status === 'cancelled') patch.finishedAt = Date.now();
    await this.campaigns.update(String(row._id), patch);
    return true;
  }

  async getCampaign(campaignId) {
    const row = await this.campaigns.findOne('campaignId', String(campaignId));
    if (!row) return null;
    return {
      campaignId: row.campaignId,
      name: row.name,
      ownerSub: row.ownerSub,
      mailboxRef: row.mailboxRef,
      status: row.status,
      total: Number(row.totalRecipients || 0),
      queued: Number(row.queuedCount || 0),
      sent: Number(row.sentCount || 0),
      failed: Number(row.failedCount || 0),
      createdAt: Number(row.createdAt || 0),
      startedAt: Number(row.startedAt || 0),
      finishedAt: Number(row.finishedAt || 0),
      subject: row.subject || '',
      ratePerSecond: Number(row.ratePerSecond || 0),
      smimeSign: !!row.smimeSign,
      meta: parseJson(row.metaJson, null),
      lastError: row.lastError || '',
    };
  }

  async listCampaigns({ ownerSub = null, limit = 50 } = {}) {
    const rows = ownerSub
      ? await this.campaigns.find('ownerSub', String(ownerSub))
      : await this.campaigns.all();
    rows.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
    const out = [];
    for (const r of rows.slice(0, limit)) out.push(await this.getCampaign(r.campaignId));
    return out;
  }
}

function parseJson(s, fallback) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

module.exports = { OutboundRepo, QUEUE_STATUS: STATUS };
