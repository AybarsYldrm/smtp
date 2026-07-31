'use strict';

const crypto = require('node:crypto');

const { sha256Hex } = require('../../util/encoding');

/** Bildirim abonelikleri. */
class PushRepo {
  constructor(db, { logger = null } = {}) { this.db = db; this.logger = logger; }

  get subs() { return this.db.collection('push_subscriptions'); }

  static shape(row) {
    if (!row) return null;
    return {
      ref: String(row._id),
      mailboxRef: row.mailboxRef || '',
      idpSub: row.idpSub || '',
      endpoint: row.endpoint,
      keys: { p256dh: row.p256dh, auth: row.authSecret },
      userAgent: row.userAgent || '',
      topics: parseJson(row.topicsJson, ['mail']),
      createdAt: Number(row.createdAt || 0),
      lastSuccessAt: Number(row.lastSuccessAt || 0),
      lastFailureAt: Number(row.lastFailureAt || 0),
      failureCount: Number(row.failureCount || 0),
      status: row.status || 'active',
      lastError: row.lastError || '',
    };
  }

  async subscribe({ endpoint, keys, mailboxRef = '', idpSub = '', userAgent = '', topics = ['mail'] }) {
    if (!endpoint || !keys || !keys.p256dh || !keys.auth) throw new Error('[push] eksik abonelik');
    const endpointHash = sha256Hex(endpoint);
    const existing = await this.subs.findOne('endpointHash', endpointHash);
    const payload = {
      mailboxRef: String(mailboxRef || ''),
      idpSub: String(idpSub || ''),
      endpoint: String(endpoint),
      p256dh: String(keys.p256dh),
      authSecret: String(keys.auth),
      userAgent: String(userAgent || '').slice(0, 300),
      topicsJson: JSON.stringify(topics),
      status: 'active',
      failureCount: 0,
      lastError: '',
    };
    if (existing) {
      await this.subs.update(String(existing._id), payload);
      return { ref: String(existing._id), created: false };
    }
    const ref = await this.subs.insert({
      endpointHash, ...payload,
      createdAt: Date.now(), lastSuccessAt: 0, lastFailureAt: 0,
    });
    return { ref, created: true };
  }

  async unsubscribe(endpoint) {
    const row = await this.subs.findOne('endpointHash', sha256Hex(String(endpoint)));
    if (!row) return false;
    await this.subs.delete(String(row._id));
    return true;
  }

  async listForMailbox(mailboxRef, topic = null) {
    const rows = await this.subs.find('mailboxRef', String(mailboxRef));
    return rows
      .filter((r) => r.status === 'active')
      .map(PushRepo.shape)
      .filter((s) => !topic || s.topics.includes(topic));
  }

  async listByTopic(topic) {
    const rows = await this.subs.find('status', 'active');
    return rows.map(PushRepo.shape).filter((s) => s.topics.includes(topic));
  }

  async listAll() {
    const rows = await this.subs.find('status', 'active');
    return rows.map(PushRepo.shape);
  }

  async recordSuccess(ref) {
    await this.subs.update(String(ref), { lastSuccessAt: Date.now(), failureCount: 0, lastError: '' });
  }

  /**
   * Başarısızlık. 404/410 anında düşürülür (abonelik gerçekten yok); geçici
   * hatalar sayılır ve eşiği aşınca devre dışı bırakılır. Her hatada silmek,
   * push servisinin kısa bir kesintisinde bütün abonelikleri kaybetmek olurdu.
   */
  async recordFailure(ref, { statusCode = 0, error = '', dropThreshold = 5 }) {
    const row = await this.subs.get(String(ref));
    if (!row) return false;
    if (statusCode === 404 || statusCode === 410) {
      await this.subs.delete(String(ref));
      return 'dropped';
    }
    const failureCount = Number(row.failureCount || 0) + 1;
    const patch = { failureCount, lastFailureAt: Date.now(), lastError: String(error || `HTTP ${statusCode}`).slice(0, 200) };
    if (failureCount >= dropThreshold) patch.status = 'disabled';
    await this.subs.update(String(ref), patch);
    return patch.status === 'disabled' ? 'disabled' : 'counted';
  }
}

/** Kişisel site ziyaretleri (Instagram takibi). */
class SiteVisitRepo {
  constructor(db) { this.db = db; }

  get visits() { return this.db.collection('site_visits'); }

  async record(visit) {
    const visitId = crypto.randomBytes(10).toString('hex');
    await this.visits.insert({
      visitId,
      ts: Number(visit.ts || Date.now()),
      source: String(visit.source || 'direct'),
      ip: String(visit.ip || ''),
      os: String(visit.os || ''),
      deviceModel: String(visit.deviceModel || ''),
      browser: String(visit.browser || ''),
      isp: String(visit.isp || ''),
      asn: String(visit.asn || ''),
      country: String(visit.country || ''),
      city: String(visit.city || ''),
      path: String(visit.path || '/'),
      referrer: String(visit.referrer || '').slice(0, 300),
      userAgent: String(visit.userAgent || '').slice(0, 300),
      notified: !!visit.notified,
    });
    return visitId;
  }

  async recent({ limit = 100, source = null, sinceMs = null } = {}) {
    const rows = source
      ? await this.visits.find('source', source)
      : await this.visits.findRange('ts', sinceMs || 0, Date.now() + 1000);
    rows.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
    return rows.slice(0, limit).map((r) => ({
      visitId: r.visitId,
      ts: Number(r.ts || 0),
      source: r.source,
      ip: r.ip,
      os: r.os,
      deviceModel: r.deviceModel,
      browser: r.browser,
      isp: r.isp,
      asn: r.asn,
      country: r.country,
      city: r.city,
      path: r.path,
      referrer: r.referrer,
    }));
  }

  async prune({ keep = 500 } = {}) {
    const all = [];
    for await (const row of this.visits.scan()) all.push(row);
    if (all.length <= keep) return 0;
    all.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
    let removed = 0;
    for (const row of all.slice(keep)) { await this.visits.delete(String(row._id)); removed++; }
    return removed;
  }

  async stats({ sinceMs = Date.now() - 30 * 86400_000 } = {}) {
    const rows = await this.visits.findRange('ts', sinceMs, Date.now() + 1000);
    const out = { total: rows.length, bySource: {}, byCountry: {}, byOs: {} };
    for (const r of rows) {
      out.bySource[r.source] = (out.bySource[r.source] || 0) + 1;
      if (r.country) out.byCountry[r.country] = (out.byCountry[r.country] || 0) + 1;
      if (r.os) out.byOs[r.os] = (out.byOs[r.os] || 0) + 1;
    }
    return out;
  }
}

/**
 * Denetim kaydı. Yalnızca ekleme — bir yetkinin kim tarafından verildiğini
 * sonradan öğrenmenin başka yolu yok, ve o kaydı değiştirebilen biri için
 * kaydın hiç değeri kalmaz.
 */
class AuditRepo {
  constructor(db, { logger = null } = {}) { this.db = db; this.logger = logger; }

  get log() { return this.db.collection('audit_log'); }

  async record({ actorSub = '', actorEmail = '', action, targetType = '', targetId = '', ip = '', detail = null, result = 'ok', userAgent = '' }) {
    await this.log.insert({
      ts: Date.now(),
      actorSub: String(actorSub || ''),
      actorEmail: String(actorEmail || ''),
      action: String(action),
      targetType: String(targetType || ''),
      targetId: String(targetId || ''),
      ip: String(ip || ''),
      detailJson: detail ? JSON.stringify(detail) : '',
      result: String(result || 'ok'),
      userAgent: String(userAgent || '').slice(0, 200),
    });
    if (this.logger) this.logger.info({ action, targetType, targetId, result, actor: actorEmail || actorSub });
  }

  async list({ actorSub = null, action = null, targetId = null, limit = 100, sinceMs = null } = {}) {
    let rows;
    if (actorSub) rows = await this.log.find('actorSub', String(actorSub));
    else if (action) rows = await this.log.find('action', String(action));
    else if (targetId) rows = await this.log.find('targetId', String(targetId));
    else rows = await this.log.findRange('ts', sinceMs || Date.now() - 7 * 86400_000, Date.now() + 1000);
    rows.sort((a, b) => Number(b.ts || 0) - Number(a.ts || 0));
    return rows.slice(0, limit).map((r) => ({
      ts: Number(r.ts || 0),
      actorSub: r.actorSub,
      actorEmail: r.actorEmail,
      action: r.action,
      targetType: r.targetType,
      targetId: r.targetId,
      ip: r.ip,
      detail: parseJson(r.detailJson, null),
      result: r.result,
    }));
  }
}

/** DNS denetim sonuçları — durum API'sinin okuduğu yer. */
class DnsAuditRepo {
  constructor(db) { this.db = db; }

  get audit() { return this.db.collection('dns_audit'); }

  async record({ recordType, name, expected, observed, status, domain, applied = false }) {
    const recordKey = `${recordType}|${name}`;
    const existing = await this.audit.findOne('recordKey', recordKey);
    const payload = {
      recordType: String(recordType),
      name: String(name),
      expected: String(expected || '').slice(0, 2000),
      observed: String(observed || '').slice(0, 2000),
      status: String(status),
      checkedAt: Date.now(),
      domain: String(domain || ''),
    };
    if (applied) payload.appliedAt = Date.now();
    if (existing) await this.audit.update(String(existing._id), payload);
    else await this.audit.insert({ recordKey, appliedAt: 0, ...payload });
  }

  async list() {
    const rows = await this.audit.all();
    rows.sort((a, b) => String(a.name).localeCompare(String(b.name)));
    return rows.map((r) => ({
      type: r.recordType,
      name: r.name,
      expected: r.expected,
      observed: r.observed,
      status: r.status,
      checkedAt: Number(r.checkedAt || 0),
      appliedAt: Number(r.appliedAt || 0),
      domain: r.domain,
    }));
  }
}

function parseJson(s, fallback) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

module.exports = { PushRepo, SiteVisitRepo, AuditRepo, DnsAuditRepo };
