'use strict';

const dns = require('node:dns').promises;
const https = require('node:https');

const { createInterval } = require('../util/async');

/**
 * DNS denetimi: posta için gerekli kayıtlar yayında mı?
 *
 * ÖNTANIMLI OLARAK SALT OKUNUR. Önceki sürüm açılışta Cloudflare'e yazıyor,
 * fazladan bulduğu kayıtları siliyordu. Bir posta sunucusunun açılışta DNS'i
 * sessizce yeniden yazması, elle yapılmış bilinçli bir değişikliği (ikinci
 * MX, geçiş dönemi SPF'i, başka bir hizmetin TXT kaydı) geri alır — ve bunu
 * fark etmek günler sürer. Yazma artık açık bir eylem (`apply: true`).
 *
 * Doğrulama iki bağımsız çözücüden yapılıyor: kendi çözücümüz önbelleğinde
 * eski değeri tutuyor olabilir ve "yayında" sanılan bir kayıt aslında henüz
 * yayılmamış olabilir.
 */
class DnsAuditor {
  constructor({ config, logger, stores, signer }) {
    this.config = config;
    this.logger = logger;
    this.stores = stores;
    this.signer = signer;
    this.timer = null;
    this.lastRun = 0;
  }

  /** Beklenen kayıtlar. */
  async expectedRecords() {
    const records = [];
    for (const domain of this.config.domains) {
      if (domain.receive) {
        records.push({
          type: 'MX', name: domain.name, domain: domain.name,
          expected: `10 ${this.config.hostname}`, priority: 10, content: this.config.hostname,
        });
      }
      const spf = this.config.smtp.publicIp
        ? `v=spf1 ip4:${this.config.smtp.publicIp} ${domain.receive ? 'mx ' : ''}-all`
        : `v=spf1 ${domain.receive ? 'mx ' : ''}-all`;
      records.push({ type: 'TXT', name: domain.name, domain: domain.name, expected: spf, content: spf });

      const dkim = await this.signer.dkimDnsRecord(domain.name).catch(() => null);
      if (dkim) {
        records.push({
          type: 'TXT', name: dkim.name, domain: domain.name,
          expected: dkim.value, content: dkim.value,
        });
      }

      const dmarc = `v=DMARC1; p=${this.config.dns.dmarcPolicy}; adkim=s; aspf=s; fo=1; `
        + `rua=mailto:${domain.dmarcRua}; ruf=mailto:${domain.dmarcRua}; ri=86400`;
      records.push({
        type: 'TXT', name: `_dmarc.${domain.name}`, domain: domain.name,
        expected: dmarc, content: dmarc,
      });

      // MTA-STS ve TLS raporlama: ikisi de isteğe bağlı ama TLS-RPT olmadan
      // teslimat sorunlarının TLS kaynaklı olup olmadığı hiç öğrenilemez.
      records.push({
        type: 'TXT', name: `_smtp._tls.${domain.name}`, domain: domain.name,
        expected: `v=TLSRPTv1; rua=mailto:${domain.dmarcRua}`,
        content: `v=TLSRPTv1; rua=mailto:${domain.dmarcRua}`,
        optional: true,
      });
    }
    return records;
  }

  /** Bir kaydın yayında olan hâlini iki kaynaktan okur. */
  async observe(record) {
    const observed = new Set();
    const readers = [
      () => this._systemLookup(record),
      () => this._dohLookup(record, 'https://cloudflare-dns.com/dns-query'),
      () => this._dohLookup(record, 'https://dns.google/resolve'),
    ];
    let errors = 0;
    for (const reader of readers) {
      try {
        for (const value of await reader()) observed.add(value);
      } catch { errors++; }
    }
    return { values: [...observed], allFailed: errors === readers.length };
  }

  async _systemLookup(record) {
    if (record.type === 'MX') {
      const rows = await dns.resolveMx(record.name);
      return rows.map((r) => `${r.priority} ${String(r.exchange).replace(/\.$/, '')}`);
    }
    const rows = await dns.resolveTxt(record.name);
    return rows.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
  }

  _dohLookup(record, endpoint) {
    return new Promise((resolve, reject) => {
      const url = `${endpoint}?name=${encodeURIComponent(record.name)}&type=${record.type}`;
      const req = https.request(url, {
        method: 'GET',
        headers: { accept: 'application/dns-json', 'user-agent': 'Fitfak-Mail/2.0' },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            const answers = (data.Answer || [])
              .filter((a) => (record.type === 'MX' ? a.type === 15 : a.type === 16))
              .map((a) => normalizeDohValue(a.data, record.type));
            resolve(answers);
          } catch (err) { reject(err); }
        });
      });
      req.setTimeout(6000, () => { req.destroy(); reject(new Error('DoH zaman aşımı')); });
      req.on('error', reject);
      req.end();
    });
  }

  /**
   * Denetimi çalıştırır.
   * @param {object} [opts]
   * @param {boolean} [opts.apply=false] eksik/yanlış kayıtları YAZ
   */
  async audit({ apply = false } = {}) {
    this.lastRun = Date.now();
    const expected = await this.expectedRecords();
    const summary = { checked: 0, ok: 0, drift: 0, missing: 0, error: 0, applied: 0 };

    for (const record of expected) {
      summary.checked++;
      const { values, allFailed } = await this.observe(record);

      let status;
      if (allFailed) status = 'error';
      else if (values.some((v) => valuesMatch(v, record.expected, record.type))) status = 'ok';
      else if (!values.length) status = record.optional ? 'optional_missing' : 'missing';
      else status = 'drift';

      if (status === 'ok') summary.ok++;
      else if (status === 'drift') summary.drift++;
      else if (status === 'missing') summary.missing++;
      else if (status === 'error') summary.error++;

      let applied = false;
      const needsWrite = status === 'missing' || status === 'drift';
      if (apply && needsWrite && this._canWrite()) {
        try {
          await this._applyRecord(record);
          applied = true;
          summary.applied++;
          this.logger.warn({ type: record.type, name: record.name, msg: 'DNS kaydı yazıldı' });
        } catch (err) {
          this.logger.error({ type: record.type, name: record.name, error: err.message, msg: 'DNS kaydı yazılamadı' });
        }
      } else if (needsWrite) {
        // Sapan kaydın KENDİSİ yazılır, yalnızca sayısı değil.
        //
        // Önceki hâli "drift=2" deyip susuyordu; hangi kayıt, ne bekleniyor,
        // ne bulundu — hiçbiri görünmüyordu. Bir DNS sapması elle
        // düzeltilecekse okunması gereken tek şey bu üçlü. Neden
        // yazılmadığını da söylüyoruz: çoğu zaman sebep bir hata değil,
        // otomatik yazmanın kapalı olması.
        summary.pending = (summary.pending || 0) + 1;
        this.logger.warn({
          type: record.type,
          name: record.name,
          expected: record.expected,
          observed: values.join(' | ') || '(kayıt yok)',
          reason: !apply
            ? 'otomatik yazma kapalı (FITFAK_DNS_AUTO_APPLY=1 ile açılır)'
            : 'sağlayıcı kimlik bilgileri eksik (CF_API_TOKEN ve CF_ZONE_ID)',
          msg: `DNS kaydı ${status === 'missing' ? 'eksik' : 'sapmış'}`,
        });
      }

      await this.stores.dnsAudit.record({
        recordType: record.type,
        name: record.name,
        expected: record.expected,
        observed: values.join(' | '),
        status,
        domain: record.domain,
        applied,
      });
    }

    const level = summary.missing || summary.drift ? 'warn' : 'info';
    this.logger[level]({ ...summary, msg: 'DNS denetimi tamamlandı' });
    return summary;
  }

  _canWrite() {
    return this.config.dns.provider === 'cloudflare'
      && !!this.config.dns.apiToken && !!this.config.dns.zoneId;
  }

  async _applyRecord(record) {
    const existing = await this._cloudflare('GET',
      `/zones/${this.config.dns.zoneId}/dns_records?type=${record.type}&name=${encodeURIComponent(record.name)}`);
    const rows = (existing.result || []);

    const payload = {
      type: record.type,
      name: record.name,
      content: record.type === 'MX' ? record.content : record.expected,
      ttl: 300,
      proxied: false,
    };
    if (record.type === 'MX') payload.priority = record.priority;

    if (rows.length) {
      // Var olan kayıt GÜNCELLENİR, fazlalıklar SİLİNMEZ. Silmek, aynı adda
      // başka bir hizmete ait kaydı yok etmek olabilir; ikinci bir MX ya da
      // ikinci bir TXT bilinçli konmuş olabilir.
      await this._cloudflare('PATCH', `/zones/${this.config.dns.zoneId}/dns_records/${rows[0].id}`, payload);
      if (rows.length > 1) {
        this.logger.warn({
          name: record.name, count: rows.length,
          msg: 'aynı adda birden fazla kayıt var; yalnızca ilki güncellendi, diğerleri elle gözden geçirilmeli',
        });
      }
      return;
    }
    await this._cloudflare('POST', `/zones/${this.config.dns.zoneId}/dns_records`, payload);
  }

  _cloudflare(method, path, body = null) {
    const payload = body ? JSON.stringify(body) : null;
    return new Promise((resolve, reject) => {
      const req = https.request({
        method,
        hostname: 'api.cloudflare.com',
        path: `/client/v4${path}`,
        headers: {
          authorization: `Bearer ${this.config.dns.apiToken}`,
          'content-type': 'application/json',
          ...(payload ? { 'content-length': Buffer.byteLength(payload) } : {}),
        },
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            if (!data.success) {
              reject(new Error(`Cloudflare: ${JSON.stringify(data.errors || data).slice(0, 200)}`));
              return;
            }
            resolve(data);
          } catch (err) { reject(err); }
        });
      });
      req.setTimeout(15_000, () => { req.destroy(); reject(new Error('Cloudflare zaman aşımı')); });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  start() {
    if (this.timer) return this;
    this.timer = createInterval(
      () => this.audit({ apply: this.config.dns.autoApply }),
      this.config.dns.intervalMs,
      { immediate: false, logger: this.logger, name: 'dns-audit' },
    );
    this.logger.info({
      intervalMs: this.config.dns.intervalMs,
      autoApply: this.config.dns.autoApply,
      msg: 'DNS denetimi planlandı',
    });
    return this;
  }

  stop() { if (this.timer) { this.timer.stop(); this.timer = null; } }
}

function normalizeDohValue(value, type) {
  let s = String(value || '').trim();
  if (type === 'TXT') {
    // DoH yanıtları TXT değerlerini tırnaklı ve parçalı verir.
    s = s.replace(/^"|"$/g, '').replace(/"\s+"/g, '');
    return s;
  }
  return s.replace(/\.$/, '');
}

function valuesMatch(observed, expected, type) {
  const a = String(observed).replace(/\s+/g, ' ').trim();
  const b = String(expected).replace(/\s+/g, ' ').trim();
  if (a === b) return true;
  if (type === 'MX') {
    return a.toLowerCase().replace(/\.$/, '') === b.toLowerCase().replace(/\.$/, '');
  }
  // DKIM kaydında etiket sırası değişebilir; anlamlı karşılaştırma etiket
  // bazında.
  if (/^v=DKIM1/i.test(b)) return compareTagged(a, b, ['p', 'k']);
  if (/^v=spf1/i.test(b)) return a.toLowerCase() === b.toLowerCase();
  if (/^v=DMARC1/i.test(b)) return compareTagged(a, b, ['p']);
  return false;
}

function compareTagged(observed, expected, requiredTags) {
  const parse = (s) => Object.fromEntries(String(s).split(';')
    .map((p) => p.trim()).filter(Boolean)
    .map((p) => { const i = p.indexOf('='); return i > 0 ? [p.slice(0, i).trim(), p.slice(i + 1).trim()] : [p, '']; }));
  const a = parse(observed);
  const b = parse(expected);
  return requiredTags.every((tag) => (a[tag] || '') === (b[tag] || ''));
}

module.exports = { DnsAuditor };
