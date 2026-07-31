'use strict';

const crypto = require('node:crypto');

const { KeyedQueue } = require('../../util/async');
const { normalizeAddress, splitAddress, canonicalLocalPart, timingSafeEqualStr } = require('../../util/encoding');

const ROLE_RANK = { reader: 1, sender: 2, delegate: 3, owner: 4 };
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 32 };

/**
 * Posta kutuları, yetkiler, harici kimlik bağları ve SMTP istemci kimlikleri.
 *
 * Buradaki merkezi karar: erişim yetkisi POSTA KUTUSU KAYDININ KİMLİĞİNE
 * (mailboxRef) bağlanır, adrese değil. Adres bir gün değişebilir (takma ad,
 * alan adı geçişi); yetkinin o değişimde kaybolması ya da yanlış kutuya
 * yapışması istenmez. Adres yalnızca kör dizinden arama anahtarıdır.
 */
class MailboxRepo {
  constructor(db, { config, logger = null, audit = null } = {}) {
    this.db = db;
    this.config = config;
    this.logger = logger;
    this.audit = audit;
    // Sayaç güncellemeleri kutu başına serileştirilir: aynı kutuya iki
    // paralel teslimat, okunmamış sayısını sessizce yanlış yapar.
    this.counterQueue = new KeyedQueue();
    this.seqQueue = new KeyedQueue();
  }

  get mailboxes() { return this.db.collection('mailboxes'); }
  get grants() { return this.db.collection('mailbox_grants'); }
  get links() { return this.db.collection('identity_links'); }
  get credentials() { return this.db.collection('smtp_credentials'); }

  /* ── posta kutuları ───────────────────────────────────────── */

  static shape(row) {
    if (!row) return null;
    return {
      ref: String(row._id),
      address: row.address,
      localPart: row.localPart,
      domain: row.domain,
      displayName: row.displayName || '',
      kind: row.kind || 'user',
      ownerSub: row.ownerSub || '',
      ownerEmail: row.ownerEmail || '',
      status: row.status || 'active',
      quotaBytes: Number(row.quotaBytes || 0),
      usedBytes: Number(row.usedBytes || 0),
      messageCount: Number(row.messageCount || 0),
      unreadCount: Number(row.unreadCount || 0),
      forwardTo: parseJson(row.forwardToJson, []),
      keepLocalCopy: row.keepLocalCopy !== false,
      autoReply: parseJson(row.autoReplyJson, null),
      notifyPrefs: parseJson(row.notifyPrefsJson, {}),
      filterRules: parseJson(row.filterRulesJson, []),
      createdAt: Number(row.createdAt || 0),
      updatedAt: Number(row.updatedAt || 0),
      lastDeliveryAt: Number(row.lastDeliveryAt || 0),
      seqCounter: Number(row.seqCounter || 0),
      aliasOfRef: row.aliasOfRef || '',
      smimeEnabled: row.smimeEnabled !== false,
      sendLimitPerHour: Number(row.sendLimitPerHour || 0),
    };
  }

  async getByAddress(address) {
    const addr = normalizeAddress(address);
    if (!addr) return null;
    return MailboxRepo.shape(await this.mailboxes.findOne('address', addr));
  }

  async getByRef(ref) {
    if (!ref) return null;
    return MailboxRepo.shape(await this.mailboxes.get(String(ref)));
  }

  async listByDomain(domain) {
    const rows = await this.mailboxes.find('domain', String(domain || '').toLowerCase());
    return rows.map(MailboxRepo.shape);
  }

  async listAll() {
    const out = [];
    for await (const row of this.mailboxes.scan()) out.push(MailboxRepo.shape(row));
    return out;
  }

  async listByOwner(ownerSub) {
    const rows = await this.mailboxes.find('ownerSub', String(ownerSub || ''));
    return rows.map(MailboxRepo.shape);
  }

  /**
   * Kutu yoksa oluşturur, varsa verilen alanları günceller.
   * @returns {{mailbox: object, created: boolean}}
   */
  async ensure(address, patch = {}) {
    const addr = normalizeAddress(address);
    if (!addr || !addr.includes('@')) throw new Error(`[mailbox] geçersiz adres: ${address}`);
    const { localPart, domain } = splitAddress(addr);
    const existing = await this.mailboxes.findOne('address', addr);
    const now = Date.now();

    if (existing) {
      const update = {};
      for (const [k, v] of Object.entries(patch)) {
        if (v === undefined) continue;
        if (k === 'forwardTo') { update.forwardToJson = JSON.stringify(v); continue; }
        if (k === 'autoReply') { update.autoReplyJson = v ? JSON.stringify(v) : ''; continue; }
        if (k === 'notifyPrefs') { update.notifyPrefsJson = JSON.stringify(v); continue; }
        if (k === 'filterRules') { update.filterRulesJson = JSON.stringify(v); continue; }
        update[k] = v;
      }
      if (Object.keys(update).length) {
        update.updatedAt = now;
        await this.mailboxes.update(String(existing._id), update);
      }
      return { mailbox: await this.getByRef(String(existing._id)), created: false };
    }

    const record = {
      address: addr,
      localPart,
      domain,
      displayName: patch.displayName || localPart,
      kind: patch.kind || 'user',
      ownerSub: patch.ownerSub || '',
      ownerEmail: patch.ownerEmail || '',
      status: patch.status || 'active',
      quotaBytes: Number(patch.quotaBytes || this.config.limits.mailboxQuotaBytes),
      usedBytes: 0,
      messageCount: 0,
      unreadCount: 0,
      forwardToJson: JSON.stringify(patch.forwardTo || []),
      keepLocalCopy: patch.keepLocalCopy !== false,
      autoReplyJson: patch.autoReply ? JSON.stringify(patch.autoReply) : '',
      createdAt: now,
      updatedAt: now,
      lastDeliveryAt: 0,
      notifyPrefsJson: JSON.stringify(patch.notifyPrefs || { mail: true, security: true, site: false }),
      filterRulesJson: JSON.stringify(patch.filterRules || []),
      seqCounter: 0,
      aliasOfRef: patch.aliasOfRef || '',
      smimeEnabled: patch.smimeEnabled !== false,
      sendLimitPerHour: Number(patch.sendLimitPerHour || 0),
    };
    const ref = await this.mailboxes.insert(record);
    if (this.logger) this.logger.info({ mailbox: addr, kind: record.kind, msg: 'posta kutusu oluşturuldu' });
    return { mailbox: await this.getByRef(ref), created: true };
  }

  /**
   * Teslimat hedefini çözer.
   *
   * Sıra önemli ve her adım bir gerçek soruya karşılık geliyor:
   *   1. tam adres        — normal durum
   *   2. etiket kırpılmış — "user+etiket@" aynı kutuya düşer (RFC 5233)
   *   3. takma ad         — aliasOfRef zinciri (tek adım, döngü koruması)
   *   4. catch-all        — alan adı için tanımlıysa
   * Hiçbiri tutmazsa teslimat REDDEDİLİR. "Bilinmeyen alıcıyı sessizce kabul
   * et" davranışı, spam gönderenlere adres doğrulama hizmeti vermek olur.
   */
  async resolveDelivery(address) {
    const addr = normalizeAddress(address);
    const { localPart, domain } = splitAddress(addr);
    if (!domain || !this.config.isLocalDomain(domain)) {
      return { mailbox: null, reason: 'not_local_domain' };
    }

    let row = await this.mailboxes.findOne('address', addr);

    if (!row) {
      const canonical = canonicalLocalPart(localPart);
      if (canonical && canonical !== localPart) {
        row = await this.mailboxes.findOne('address', `${canonical}@${domain}`);
      }
    }

    if (!row) {
      const catchAll = (await this.mailboxes.find('domain', domain)).find((m) => m.kind === 'catchall' && m.status === 'active');
      if (catchAll) return { mailbox: MailboxRepo.shape(catchAll), reason: 'catchall' };
      return { mailbox: null, reason: 'no_such_mailbox' };
    }

    let mailbox = MailboxRepo.shape(row);
    const seen = new Set([mailbox.ref]);
    while (mailbox && mailbox.kind === 'alias' && mailbox.aliasOfRef) {
      if (seen.has(mailbox.aliasOfRef)) return { mailbox: null, reason: 'alias_loop' };
      seen.add(mailbox.aliasOfRef);
      const target = await this.getByRef(mailbox.aliasOfRef);
      if (!target) return { mailbox: null, reason: 'alias_target_missing' };
      mailbox = target;
    }

    if (!mailbox) return { mailbox: null, reason: 'no_such_mailbox' };
    if (mailbox.status !== 'active') return { mailbox, reason: `mailbox_${mailbox.status}` };
    if (mailbox.quotaBytes > 0 && mailbox.usedBytes >= mailbox.quotaBytes) {
      return { mailbox, reason: 'over_quota' };
    }
    return { mailbox, reason: 'ok' };
  }

  /** Kutu içi tekdüze artan sıra numarası. Gerçek zamanlı devam noktası. */
  async nextSeq(mailboxRef) {
    return this.seqQueue.run(String(mailboxRef), async () => {
      const row = await this.mailboxes.get(String(mailboxRef));
      if (!row) throw new Error(`[mailbox] kutu yok: ${mailboxRef}`);
      const next = Number(row.seqCounter || 0) + 1;
      await this.mailboxes.update(String(mailboxRef), { seqCounter: next });
      return next;
    });
  }

  async applyCounters(mailboxRef, { usedBytes = 0, messages = 0, unread = 0, lastDeliveryAt = null } = {}) {
    return this.counterQueue.run(String(mailboxRef), async () => {
      const row = await this.mailboxes.get(String(mailboxRef));
      if (!row) return null;
      const patch = {
        usedBytes: Math.max(0, Number(row.usedBytes || 0) + usedBytes),
        messageCount: Math.max(0, Number(row.messageCount || 0) + messages),
        unreadCount: Math.max(0, Number(row.unreadCount || 0) + unread),
        updatedAt: Date.now(),
      };
      if (lastDeliveryAt) patch.lastDeliveryAt = lastDeliveryAt;
      await this.mailboxes.update(String(mailboxRef), patch);
      return patch;
    });
  }

  /** Sayaçları gerçek verilerden yeniden hesaplar (tutarsızlık onarımı). */
  async recomputeCounters(mailboxRef) {
    const messages = this.db.collection('messages');
    const rows = await messages.find('mailboxRef', String(mailboxRef));
    let used = 0;
    let count = 0;
    let unread = 0;
    for (const m of rows) {
      if (Number(m.deletedAt || 0)) continue;
      used += Number(m.sizeBytes || 0);
      count++;
      if (!m.seen) unread++;
    }
    return this.counterQueue.run(String(mailboxRef), async () => {
      await this.mailboxes.update(String(mailboxRef), {
        usedBytes: used, messageCount: count, unreadCount: unread, updatedAt: Date.now(),
      });
      return { usedBytes: used, messageCount: count, unreadCount: unread };
    });
  }

  /* ── yetkiler ─────────────────────────────────────────────── */

  static grantKey(mailboxRef, idpSub) { return `${mailboxRef}|${idpSub}`; }

  async grant({ mailboxRef, idpSub, idpEmail = '', role = 'reader', grantedBySub = '', note = '' }) {
    if (!ROLE_RANK[role]) throw new Error(`[mailbox] bilinmeyen rol: ${role}`);
    const key = MailboxRepo.grantKey(mailboxRef, idpSub);
    const existing = await this.grants.findOne('grantKey', key);
    const now = Date.now();
    if (existing) {
      await this.grants.update(String(existing._id), {
        role, status: 'active', revokedAt: 0, grantedBySub, idpEmail, note, grantedAt: now,
      });
      return { ref: String(existing._id), created: false };
    }
    const ref = await this.grants.insert({
      grantKey: key,
      mailboxRef: String(mailboxRef),
      idpSub: String(idpSub),
      idpEmail,
      role,
      grantedBySub,
      grantedAt: now,
      revokedAt: 0,
      status: 'active',
      note,
    });
    return { ref, created: true };
  }

  async revokeGrant({ mailboxRef, idpSub, revokedBySub = '' }) {
    const key = MailboxRepo.grantKey(mailboxRef, idpSub);
    const existing = await this.grants.findOne('grantKey', key);
    if (!existing) return false;
    await this.grants.update(String(existing._id), {
      status: 'revoked', revokedAt: Date.now(), note: `revoked_by:${revokedBySub}`,
    });
    return true;
  }

  async listGrantsForMailbox(mailboxRef) {
    const rows = await this.grants.find('mailboxRef', String(mailboxRef));
    return rows.filter((r) => r.status === 'active').map((r) => ({
      ref: String(r._id), idpSub: r.idpSub, idpEmail: r.idpEmail, role: r.role,
      grantedAt: Number(r.grantedAt || 0), grantedBySub: r.grantedBySub || '', note: r.note || '',
    }));
  }

  /* ── harici kimlik bağları ────────────────────────────────── */

  /**
   * Harici bir adresi yerel bir kutuya bağlar. YALNIZCA IdP yöneticisi
   * çağırabilir (yetki denetimi çağıran katmanda, kaydı burada).
   */
  async linkExternalIdentity({
    externalEmail, mailboxRef, idpSub = '', createdBySub, createdByEmail = '',
    allowSendAs = false, reason = '', expiresAt = 0,
  }) {
    const email = normalizeAddress(externalEmail);
    if (!email || !email.includes('@')) throw new Error(`[link] geçersiz harici adres: ${externalEmail}`);
    const mailbox = await this.getByRef(mailboxRef);
    if (!mailbox) throw new Error(`[link] posta kutusu yok: ${mailboxRef}`);

    const existing = await this.links.findOne('externalEmail', email);
    const now = Date.now();
    const payload = {
      mailboxRef: String(mailboxRef),
      mailboxAddress: mailbox.address,
      idpSub: String(idpSub || ''),
      status: 'active',
      createdBySub: String(createdBySub || ''),
      createdByEmail: String(createdByEmail || ''),
      createdAt: now,
      revokedAt: 0,
      revokedBySub: '',
      reason: String(reason || ''),
      allowSendAs: !!allowSendAs,
      expiresAt: Number(expiresAt) || 0,
    };
    if (existing) {
      await this.links.update(String(existing._id), payload);
      return { ref: String(existing._id), created: false, mailbox };
    }
    const ref = await this.links.insert({ externalEmail: email, ...payload });
    return { ref, created: true, mailbox };
  }

  async revokeExternalIdentity(externalEmail, { revokedBySub = '', reason = '' } = {}) {
    const email = normalizeAddress(externalEmail);
    const existing = await this.links.findOne('externalEmail', email);
    if (!existing) return false;
    await this.links.update(String(existing._id), {
      status: 'revoked', revokedAt: Date.now(), revokedBySub, reason: reason || existing.reason,
    });
    return true;
  }

  async resolveExternalIdentity(externalEmail) {
    const email = normalizeAddress(externalEmail);
    if (!email) return null;
    const row = await this.links.findOne('externalEmail', email);
    if (!row || row.status !== 'active') return null;
    if (Number(row.expiresAt || 0) && Date.now() > Number(row.expiresAt)) return null;
    return {
      ref: String(row._id),
      externalEmail: row.externalEmail,
      mailboxRef: row.mailboxRef,
      mailboxAddress: row.mailboxAddress,
      allowSendAs: !!row.allowSendAs,
      createdBySub: row.createdBySub,
      createdAt: Number(row.createdAt || 0),
      expiresAt: Number(row.expiresAt || 0),
    };
  }

  async listExternalIdentities({ mailboxRef = null } = {}) {
    const rows = mailboxRef
      ? await this.links.find('mailboxRef', String(mailboxRef))
      : await this.links.find('status', 'active');
    return rows.filter((r) => r.status === 'active').map((r) => ({
      ref: String(r._id),
      externalEmail: r.externalEmail,
      mailboxAddress: r.mailboxAddress,
      mailboxRef: r.mailboxRef,
      allowSendAs: !!r.allowSendAs,
      createdBySub: r.createdBySub,
      createdByEmail: r.createdByEmail,
      createdAt: Number(r.createdAt || 0),
      expiresAt: Number(r.expiresAt || 0),
      reason: r.reason || '',
    }));
  }

  /**
   * Bir IdP kimliğinin erişebildiği kutular.
   *
   * Üç kaynak birleşir:
   *   1. Giriş adresi yerel bir kutuysa — kendi kutusu (owner).
   *   2. Ona verilmiş açık yetkiler (grants).
   *   3. Harici adres bağı — "gmail ile giren, network@fitfak.net'i görür".
   *
   * (3) yalnızca yöneticinin kurduğu bir bağla mümkündür; kullanıcı kendi
   * kendine bu bağı kuramaz.
   */
  async mailboxesForIdentity({ idpSub, email }) {
    const out = new Map();
    const addAccess = (mailbox, role, source) => {
      if (!mailbox) return;
      const prev = out.get(mailbox.ref);
      if (prev && ROLE_RANK[prev.role] >= ROLE_RANK[role]) return;
      out.set(mailbox.ref, { ...mailbox, role, accessSource: source });
    };

    const loginAddress = normalizeAddress(email);
    if (loginAddress) {
      const own = await this.getByAddress(loginAddress);
      if (own) addAccess(own, own.ownerSub && own.ownerSub !== idpSub ? 'reader' : 'owner', 'local_address');
    }

    if (idpSub) {
      for (const g of await this.grants.find('idpSub', String(idpSub))) {
        if (g.status !== 'active') continue;
        const mailbox = await this.getByRef(g.mailboxRef);
        addAccess(mailbox, g.role || 'reader', 'grant');
      }
      for (const m of await this.mailboxes.find('ownerSub', String(idpSub))) {
        addAccess(MailboxRepo.shape(m), 'owner', 'owner_sub');
      }
    }

    const link = loginAddress ? await this.resolveExternalIdentity(loginAddress) : null;
    if (link) {
      const mailbox = await this.getByRef(link.mailboxRef);
      addAccess(mailbox, link.allowSendAs ? 'delegate' : 'reader', 'identity_link');
    }

    return [...out.values()].filter((m) => m.status === 'active');
  }

  /* ── SMTP istemci kimlikleri ──────────────────────────────── */

  /**
   * Yeni bir SMTP parolası üretir. Düz parola YALNIZCA burada, bir kez döner;
   * saklanan şey scrypt türevidir. Bir posta istemcisinin parolasını sunucudan
   * geri okuyabilmek, o parolanın veritabanı kopyasıyla birlikte sızması
   * demektir.
   */
  async createSmtpCredential({ mailboxRef, username = null, label = '', createdBySub = '', allowSubmission = true }) {
    const mailbox = await this.getByRef(mailboxRef);
    if (!mailbox) throw new Error(`[smtp-cred] posta kutusu yok: ${mailboxRef}`);
    const user = normalizeAddress(username || mailbox.address);
    const password = crypto.randomBytes(24).toString('base64url');
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(password, salt, SCRYPT_PARAMS.keylen, SCRYPT_PARAMS);

    const existing = await this.credentials.findOne('username', user);
    const payload = {
      mailboxRef: String(mailboxRef),
      secretHash: hash.toString('base64'),
      salt: salt.toString('base64'),
      kdf: `scrypt:${SCRYPT_PARAMS.N}:${SCRYPT_PARAMS.r}:${SCRYPT_PARAMS.p}`,
      label: label || 'posta istemcisi',
      createdAt: Date.now(),
      lastUsedAt: 0,
      lastUsedIp: '',
      revoked: false,
      status: 'active',
      createdBySub,
      useCount: 0,
      allowSubmission: !!allowSubmission,
    };
    if (existing) await this.credentials.update(String(existing._id), payload);
    else await this.credentials.insert({ username: user, ...payload });

    return { username: user, password, mailbox };
  }

  async verifySmtpCredential(username, password, { ip = '' } = {}) {
    const user = normalizeAddress(username);
    const row = await this.credentials.findOne('username', user);
    if (!row || row.revoked || row.status !== 'active') {
      // Kayıt yoksa da scrypt maliyeti ödenir: "kullanıcı var mı" sorusunun
      // cevabı yanıt süresinden okunabilmemeli.
      crypto.scryptSync(String(password || ''), crypto.randomBytes(16), SCRYPT_PARAMS.keylen, SCRYPT_PARAMS);
      return { ok: false, reason: 'no_such_credential' };
    }
    const salt = Buffer.from(row.salt, 'base64');
    const params = parseKdf(row.kdf);
    const derived = crypto.scryptSync(String(password || ''), salt, params.keylen, params);
    if (!timingSafeEqualStr(derived.toString('base64'), row.secretHash)) {
      return { ok: false, reason: 'bad_password' };
    }
    if (!row.allowSubmission) return { ok: false, reason: 'submission_not_allowed' };
    const mailbox = await this.getByRef(row.mailboxRef);
    if (!mailbox || mailbox.status !== 'active') return { ok: false, reason: 'mailbox_inactive' };

    await this.credentials.update(String(row._id), {
      lastUsedAt: Date.now(), lastUsedIp: ip, useCount: Number(row.useCount || 0) + 1,
    });
    return { ok: true, mailbox };
  }

  async revokeSmtpCredential(username) {
    const row = await this.credentials.findOne('username', normalizeAddress(username));
    if (!row) return false;
    await this.credentials.update(String(row._id), { revoked: true, status: 'revoked' });
    return true;
  }

  async listSmtpCredentials(mailboxRef) {
    const rows = await this.credentials.find('mailboxRef', String(mailboxRef));
    return rows.map((r) => ({
      username: r.username, label: r.label, status: r.status,
      createdAt: Number(r.createdAt || 0), lastUsedAt: Number(r.lastUsedAt || 0),
      lastUsedIp: r.lastUsedIp || '', useCount: Number(r.useCount || 0),
    }));
  }
}

function parseKdf(kdf) {
  const m = String(kdf || '').match(/^scrypt:(\d+):(\d+):(\d+)$/);
  if (!m) return SCRYPT_PARAMS;
  return { N: Number(m[1]), r: Number(m[2]), p: Number(m[3]), keylen: SCRYPT_PARAMS.keylen };
}

function parseJson(s, fallback) {
  if (!s) return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

module.exports = { MailboxRepo, ROLE_RANK };
