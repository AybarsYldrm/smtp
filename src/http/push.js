'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

const { b64url, b64urlDecode, clip } = require('../util/encoding');
const { createLimiter } = require('../util/async');

/**
 * Web Push (RFC 8291 şifreleme, RFC 8292 VAPID).
 *
 * Önceki sürümden taşınan iki şey değişti:
 *
 *   1. ABONELİKLER VE VAPID ANAHTARI VERİTABANINDA/KASADA. Önceki sürüm
 *      ikisini de `data/` altında düz JSON/PEM olarak tutuyordu. VAPID özel
 *      anahtarı, o dosyayı okuyan herkesin bu alan adı adına bildirim
 *      gönderebilmesi demek.
 *
 *   2. HEDEFLEME POSTA KUTUSUNA BAĞLI. Önceki sürümde abonelikte kutu yoksa
 *      bildirim HERKESE gidiyordu — yani bir kullanıcının yeni postası
 *      bütün abonelere duyuruluyordu. Artık kutu ve konu (topic) eşleşmesi
 *      zorunlu; eşleşme yoksa gönderilmiyor.
 */

const VAULT_KIND = 'vapid-key';
const VAULT_NAME = 'webpush/vapid';

class PushService {
  constructor({ config, logger, stores }) {
    this.config = config;
    this.logger = logger;
    this.stores = stores;
    this.vapid = null;
    this.limiter = createLimiter(config.push.concurrency);
    this.stats = { sent: 0, failed: 0, dropped: 0 };
  }

  /** VAPID anahtar çifti — yoksa üretilip kasaya yazılır. */
  async ensureVapid() {
    if (this.vapid) return this.vapid;

    const existing = await this.stores.vault.get(VAULT_KIND, VAULT_NAME);
    if (existing) {
      const privateKeyPem = existing.value.toString('utf8');
      const privateKey = crypto.createPrivateKey(privateKeyPem);
      const publicKey = crypto.createPublicKey(privateKey);
      this.vapid = {
        privateKeyPem,
        privateKey,
        publicKey,
        publicKeyBytes: jwkToUncompressed(publicKey.export({ format: 'jwk' })),
      };
      return this.vapid;
    }

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const publicKeyBytes = jwkToUncompressed(publicKey.export({ format: 'jwk' }));
    await this.stores.vault.put({
      kind: VAULT_KIND,
      name: VAULT_NAME,
      value: privateKeyPem,
      contentType: 'application/x-pem-file',
      meta: { publicKey: b64url(publicKeyBytes) },
    });
    this.vapid = { privateKeyPem, privateKey, publicKey, publicKeyBytes };
    this.logger.info({ msg: 'VAPID anahtarı üretildi ve kasaya yazıldı' });
    return this.vapid;
  }

  async publicKey() {
    const vapid = await this.ensureVapid();
    return b64url(vapid.publicKeyBytes);
  }

  /* ── şifreleme (RFC 8291, aes128gcm) ───────────────────────── */

  async encryptPayload(subscription, payload) {
    const uaPublic = ensureUncompressed(parseKeyFlexible(subscription.keys.p256dh));
    const authSecret = parseKeyFlexible(subscription.keys.auth);
    if (authSecret.length !== 16) throw new Error('auth sırrı 16 bayt olmalı');

    const salt = crypto.randomBytes(16);
    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const asPublic = ensureUncompressed(ecdh.getPublicKey());
    const sharedSecret = ecdh.computeSecret(uaPublic);

    // PRK_key = HKDF-Extract(auth_secret, ecdh_secret)
    const prkKey = hmac(authSecret, sharedSecret);
    const keyInfo = Buffer.concat([
      Buffer.from('WebPush: info\0', 'ascii'), uaPublic, asPublic,
    ]);
    const ikm = hkdfExpand(prkKey, keyInfo, 32);
    const prk = hmac(salt, ikm);
    const cek = hkdfExpand(prk, Buffer.from('Content-Encoding: aes128gcm\0', 'ascii'), 16);
    const nonce = hkdfExpand(prk, Buffer.from('Content-Encoding: nonce\0', 'ascii'), 12);

    // Tek kayıt: yük + 0x02 (son kayıt işaretçisi).
    const plaintext = Buffer.concat([payload, Buffer.from([0x02])]);
    const cipher = crypto.createCipheriv('aes-128-gcm', cek, nonce);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

    const recordSize = Buffer.alloc(4);
    recordSize.writeUInt32BE(4096, 0);
    const header = Buffer.concat([salt, recordSize, Buffer.from([asPublic.length]), asPublic]);
    return Buffer.concat([header, ciphertext]);
  }

  /** VAPID yetkilendirme başlığı (RFC 8292). */
  async authorizationHeader(audience) {
    const vapid = await this.ensureVapid();
    const header = { alg: 'ES256', typ: 'JWT' };
    const payload = {
      aud: audience,
      exp: Math.floor(Date.now() / 1000) + 12 * 3600,
      sub: this.config.push.subject,
    };
    const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(payload)))}`;
    // ES256 imzası ham (r||s) 64 bayt olmalı; DER kodlaması burada geçersiz
    // bir jeton üretir ve push servisi 401 döner.
    const signature = crypto.sign('sha256', Buffer.from(signingInput), {
      key: vapid.privateKey,
      dsaEncoding: 'ieee-p1363',
    });
    return `vapid t=${signingInput}.${b64url(signature)},k=${b64url(vapid.publicKeyBytes)}`;
  }

  /* ── gönderim ──────────────────────────────────────────────── */

  async sendToSubscription(subscription, message, { ttl = null } = {}) {
    const payload = Buffer.from(JSON.stringify(message), 'utf8');
    const endpoint = new URL(subscription.endpoint);
    const body = await this.encryptPayload(subscription, payload);
    const audience = `${endpoint.protocol}//${endpoint.host}`;

    const headers = {
      'content-type': 'application/octet-stream',
      'content-encoding': 'aes128gcm',
      'content-length': body.length,
      ttl: String(ttl == null ? this.config.push.ttlSeconds : ttl),
      urgency: message.urgency || 'normal',
      authorization: await this.authorizationHeader(audience),
    };
    // Apple, web push için bu başlıkları zorunlu kılıyor; olmadan 400 döner.
    if (endpoint.hostname.includes('apple.com')) {
      headers['apns-push-type'] = 'alert';
      headers['apns-priority'] = '10';
    }

    return new Promise((resolve, reject) => {
      const transport = endpoint.protocol === 'https:' ? https : http;
      const req = transport.request({
        method: 'POST',
        hostname: endpoint.hostname,
        port: endpoint.port || (endpoint.protocol === 'https:' ? 443 : 80),
        path: `${endpoint.pathname}${endpoint.search}`,
        headers,
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({
          statusCode: res.statusCode,
          body: Buffer.concat(chunks).toString('utf8').slice(0, 300),
        }));
      });
      req.setTimeout(15_000, () => { req.destroy(); reject(new Error('push zaman aşımı')); });
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  /**
   * Bir posta kutusunun abonelerine gönderir.
   *
   * Hedefleme AÇIK: kutu eşleşmesi olmayan abonelik atlanır. "Kutu bilgisi
   * yoksa herkese gönder" davranışı, bir kullanıcının postasını başkasının
   * ekranında göstermek demekti.
   */
  async sendToMailbox(mailboxRef, message, { topic = 'mail', ttl = null } = {}) {
    const subscriptions = await this.stores.push.listForMailbox(mailboxRef, topic);
    return this._dispatch(subscriptions, message, { ttl });
  }

  async sendToTopic(topic, message, { ttl = null } = {}) {
    const subscriptions = await this.stores.push.listByTopic(topic);
    return this._dispatch(subscriptions, message, { ttl });
  }

  async _dispatch(subscriptions, message, { ttl }) {
    if (!subscriptions.length) return { sent: 0, failed: 0, dropped: 0 };
    const results = { sent: 0, failed: 0, dropped: 0 };

    await Promise.all(subscriptions.map((subscription) => this.limiter(async () => {
      try {
        const result = await this.sendToSubscription(subscription, message, { ttl });
        if (result.statusCode >= 200 && result.statusCode < 300) {
          results.sent++;
          this.stats.sent++;
          await this.stores.push.recordSuccess(subscription.ref);
          return;
        }
        const outcome = await this.stores.push.recordFailure(subscription.ref, {
          statusCode: result.statusCode,
          error: result.body,
          dropThreshold: this.config.push.maxFailuresBeforeDrop,
        });
        if (outcome === 'dropped') { results.dropped++; this.stats.dropped++; }
        else { results.failed++; this.stats.failed++; }
      } catch (err) {
        results.failed++;
        this.stats.failed++;
        await this.stores.push.recordFailure(subscription.ref, {
          error: err.message,
          dropThreshold: this.config.push.maxFailuresBeforeDrop,
        }).catch(() => {});
      }
    })));

    return results;
  }

  /* ── uygulama olayları ─────────────────────────────────────── */

  async notifyNewMail({ mailbox, message }) {
    const prefs = mailbox.notifyPrefs || {};
    if (prefs.mail === false) return { sent: 0 };
    return this.sendToMailbox(mailbox.ref, {
      title: message.subject || '(konu yok)',
      body: `${message.from.name || message.from.address}: ${clip(message.preview || '', 120)}`,
      icon: '/icon-192.png',
      badge: '/badge.png',
      tag: `mail-${mailbox.ref}`,
      urgency: 'high',
      data: {
        kind: 'mail',
        mailboxRef: mailbox.ref,
        mailbox: mailbox.address,
        messageRef: message.ref,
        url: `/posta/${encodeURIComponent(mailbox.address)}/${message.ref}`,
      },
    }, { topic: 'mail' });
  }

  async notifySiteVisit(visit) {
    return this.sendToTopic('site', {
      title: 'Instagram üzerinden ziyaret',
      body: `${visit.deviceModel || visit.os || 'bilinmeyen cihaz'} — ${visit.city || ''} ${visit.country || ''}`.trim(),
      icon: '/icon-192.png',
      tag: 'site-visit',
      data: { kind: 'site', url: '/bildirimler', visitId: visit.visitId },
    });
  }

  async notifySecurity({ mailbox, title, body, data = {} }) {
    // Güvenlik uyarıları KAPATILAMAZ: tercih denetimi yok. Kullanıcının
    // kapatabildiği bir güvenlik uyarısı, kapatıldığı anda işe yaramaz.
    return this.sendToMailbox(mailbox.ref, {
      title, body, icon: '/icon-192.png', urgency: 'high', tag: 'security',
      data: { kind: 'security', ...data },
    }, { topic: 'security' });
  }

  snapshot() {
    return { ...this.stats, limiter: this.limiter.stats() };
  }
}

/* ── yardımcılar ────────────────────────────────────────────── */

function hmac(key, data) { return crypto.createHmac('sha256', key).update(data).digest(); }

function hkdfExpand(prk, info, length) {
  const blocks = [];
  let previous = Buffer.alloc(0);
  let counter = 0;
  let total = 0;
  while (total < length) {
    counter++;
    previous = hmac(prk, Buffer.concat([previous, info, Buffer.from([counter])]));
    blocks.push(previous);
    total += previous.length;
  }
  return Buffer.concat(blocks).subarray(0, length);
}

function parseKeyFlexible(value) {
  if (Buffer.isBuffer(value)) return value;
  const s = String(value || '');
  // Aboneliklerde base64url yaygın ama bazı istemciler düz base64 gönderiyor.
  if (s.includes('-') || s.includes('_')) return b64urlDecode(s);
  return Buffer.from(s, 'base64');
}

function ensureUncompressed(buf) {
  if (buf.length === 65 && buf[0] === 0x04) return buf;
  if (buf.length === 64) return Buffer.concat([Buffer.from([0x04]), buf]);
  throw new Error(`geçersiz P-256 anahtar uzunluğu: ${buf.length}`);
}

function jwkToUncompressed(jwk) {
  return Buffer.concat([
    Buffer.from([0x04]),
    b64urlDecode(jwk.x),
    b64urlDecode(jwk.y),
  ]);
}

module.exports = { PushService, VAULT_KIND, VAULT_NAME };
