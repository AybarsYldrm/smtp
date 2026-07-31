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

  /**
   * Beklenen kayıtlar.
   *
   * Her kaydın `purpose` alanı var: durum ekranında ve kayıtlarda "bu kayıt
   * ne işe yarıyor" sorusu, kaydın kendisine bakarak cevaplanamıyor.
   */
  async expectedRecords() {
    const records = [];
    for (const domain of this.config.domains) {
      if (domain.receive) {
        records.push({
          type: 'MX', name: domain.name, domain: domain.name, purpose: 'inbound-mx',
          expected: `10 ${this.config.hostname}`, priority: 10, content: this.config.hostname,
        });
      }
      const spf = this.config.smtp.publicIp
        ? `v=spf1 ip4:${this.config.smtp.publicIp} ${domain.receive ? 'mx ' : ''}-all`
        : `v=spf1 ${domain.receive ? 'mx ' : ''}-all`;
      records.push({
        type: 'TXT', name: domain.name, domain: domain.name, purpose: 'spf',
        expected: spf, content: spf,
      });

      // DKIM kaydı, kasadaki anahtardan TÜRETİLİR. Anahtar alınamıyorsa bu
      // sessizce atlanmamalı: DKIM kaydı olmadan giden her imza doğrulanamaz
      // ve sorun "DNS'te kayıt yok" olarak değil "postam spam'e düşüyor"
      // olarak fark edilir.
      let dkim = null;
      try {
        dkim = await this.signer.dkimDnsRecord(domain.name);
      } catch (err) {
        this.logger.error({
          domain: domain.name, error: err.message,
          msg: 'DKIM açık anahtarı üretilemedi — bu alan için DKIM kaydı denetlenemiyor',
        });
      }
      if (dkim) {
        records.push({
          type: 'TXT', name: dkim.name, domain: domain.name, purpose: 'dkim',
          expected: dkim.value, content: dkim.value,
        });
      } else {
        this.logger.warn({
          domain: domain.name,
          msg: 'DKIM kaydı beklenen listeye eklenemedi (anahtar yok)',
        });
      }

      const dmarc = `v=DMARC1; p=${this.config.dns.dmarcPolicy}; adkim=s; aspf=s; fo=1; `
        + `rua=mailto:${domain.dmarcRua}; ruf=mailto:${domain.dmarcRua}; ri=86400`;
      records.push({
        type: 'TXT', name: `_dmarc.${domain.name}`, domain: domain.name, purpose: 'dmarc',
        expected: dmarc, content: dmarc,
      });

      // MTA-STS ve TLS raporlama: ikisi de isteğe bağlı ama TLS-RPT olmadan
      // teslimat sorunlarının TLS kaynaklı olup olmadığı hiç öğrenilemez.
      records.push({
        type: 'TXT', name: `_smtp._tls.${domain.name}`, domain: domain.name, purpose: 'tls-rpt',
        expected: `v=TLSRPTv1; rua=mailto:${domain.dmarcRua}`,
        content: `v=TLSRPTv1; rua=mailto:${domain.dmarcRua}`,
        optional: true,
      });
    }
    return records;
  }

  /**
   * Bir kaydın yayında olan hâlini ÜÇ bağımsız çözücüden okur.
   *
   * Kaynak başına sonuç ayrıca döner: bir kayıt Cloudflare'de görünüp
   * Google'da görünmüyorsa bu "yayılma sürüyor" demektir ve "kayıt yok"tan
   * tamamen farklı bir durumdur. Birleştirilmiş listede bu ayrım kayboluyordu.
   */
  async observe(record) {
    const observed = new Set();
    const bySource = {};
    const readers = [
      { name: 'system', run: () => this._systemLookup(record) },
      { name: 'cloudflare-doh', run: () => this._dohLookup(record, 'https://cloudflare-dns.com/dns-query') },
      { name: 'google-doh', run: () => this._dohLookup(record, 'https://dns.google/resolve') },
    ];
    let errors = 0;
    for (const reader of readers) {
      try {
        const values = await reader.run();
        bySource[reader.name] = values;
        for (const value of values) observed.add(value);
      } catch (err) {
        bySource[reader.name] = { error: err.code || err.message };
        errors++;
      }
    }
    return { values: [...observed], allFailed: errors === readers.length, bySource };
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
    const summary = {
      checked: 0, ok: 0, drift: 0, missing: 0, error: 0,
      applied: 0, applyFailed: 0, records: [],
    };

    const writable = this._writeCapability();
    if (apply && !writable.ok) {
      // "dns.autoApply true ama hiçbir şey yazılmıyor" durumunun NEDENİ
      // söylenmeden bırakılmamalı: eksik olan bir jeton mu, bölge kimliği mi,
      // yoksa sağlayıcı mı — üçünün de çözümü farklı.
      this.logger.warn({
        provider: this.config.dns.provider,
        reason: writable.reason,
        msg: 'DNS otomatik yazma istendi ama yapılandırma eksik — yalnızca denetim yapılacak',
      });
    }

    for (const record of expected) {
      summary.checked++;
      const { values, allFailed, bySource } = await this.observe(record);

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
      let applyResult = null;
      if (apply && (status === 'missing' || status === 'drift') && writable.ok) {
        try {
          applyResult = await this._applyRecord(record);
          applied = true;
          summary.applied++;
          // Yazmanın SONUCU kayda geçer: Cloudflare kayıt kimliği, işlem
          // (oluşturuldu/güncellendi) ve sağlayıcının GERİ OKUNAN değeri.
          // "Cloudflare'e gerçekten eklendi mi" sorusunun cevabı bu satır.
          this.logger.warn({
            type: record.type,
            name: record.name,
            purpose: record.purpose,
            action: applyResult.action,
            cloudflareId: applyResult.id,
            confirmed: applyResult.confirmed,
            storedContent: snip(applyResult.storedContent),
            msg: applyResult.confirmed
              ? 'DNS kaydı yazıldı ve Cloudflare tarafından doğrulandı'
              : 'DNS kaydı yazıldı ama Cloudflare geri okumada beklenen değeri döndürmedi',
          });
        } catch (err) {
          summary.applyFailed++;
          this.logger.error({
            type: record.type, name: record.name, purpose: record.purpose,
            error: err.message, msg: 'DNS kaydı yazılamadı',
          });
        }
      }

      // Her kayıt, durumu ne olursa olsun, BEKLENEN ve GÖRÜLEN değeriyle
      // birlikte kayda geçer. Eskiden yalnızca özet sayılar yazılıyordu ve
      // "hangi kaydın nesi yanlış" sorusu ancak elle `dig` çekerek
      // cevaplanabiliyordu.
      this.logger[status === 'ok' ? 'debug' : 'info']({
        type: record.type,
        name: record.name,
        purpose: record.purpose,
        status,
        expected: snip(record.expected),
        observed: values.length ? values.map(snip) : null,
        sources: bySource,
        msg: `DNS kaydı: ${status}`,
      });

      summary.records.push({
        type: record.type,
        name: record.name,
        purpose: record.purpose,
        status,
        optional: !!record.optional,
        expected: record.expected,
        observed: values,
        applied,
        cloudflareId: applyResult ? applyResult.id : null,
        confirmed: applyResult ? applyResult.confirmed : null,
      });

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

    const level = summary.missing || summary.drift || summary.applyFailed ? 'warn' : 'info';
    this.logger[level]({
      checked: summary.checked, ok: summary.ok, drift: summary.drift,
      missing: summary.missing, error: summary.error,
      applied: summary.applied, applyFailed: summary.applyFailed,
      writable: writable.ok,
      msg: 'DNS denetimi tamamlandı',
    });

    // Yayımlanması gereken kayıtlar, elle eklenebilsin diye TEK BLOK hâlinde
    // yazılır. Otomatik yazma kapalıyken (öntanımlı) bu, listenin ulaşılabilir
    // olduğu tek yer.
    const pending = summary.records.filter((r) => r.status === 'missing' || r.status === 'drift');
    if (pending.length) {
      this.logger.warn({
        count: pending.length,
        msg: 'yayımlanması gereken DNS kayıtları:\n'
          + pending.map((r) => `  ${r.type.padEnd(4)} ${r.name}\n       ${r.expected}`).join('\n'),
      });
    }
    return summary;
  }

  /** Yazma yapılabilir mi, yapılamıyorsa NEDEN? */
  _writeCapability() {
    if (this.config.dns.provider !== 'cloudflare') {
      return { ok: false, reason: `sağlayıcı desteklenmiyor: ${this.config.dns.provider || '(yok)'}` };
    }
    if (!this.config.dns.apiToken) return { ok: false, reason: 'CF_API_TOKEN verilmemiş' };
    if (!this.config.dns.zoneId) return { ok: false, reason: 'CF_ZONE_ID verilmemiş' };
    return { ok: true, reason: '' };
  }

  _canWrite() { return this._writeCapability().ok; }

  /**
   * Bir kaydı Cloudflare'e yazar ve YAZDIĞINI GERİ OKUR.
   *
   * Geri okuma şart: Cloudflare `success: true` döndürüp içeriği kendi
   * normalleştirmesiyle (tırnaklama, sondaki nokta, TXT parçalama) farklı
   * saklayabiliyor. Doğrulamadan "yazıldı" demek, DNS'te olmayan bir kaydı
   * kayıtta varmış gibi göstermek olurdu — ve bildirilen belirsizlik
   * ("cloudflare'a gerçekten eklenip eklenmediğinden emin değilim") tam
   * olarak buydu.
   */
  async _applyRecord(record) {
    const zone = this.config.dns.zoneId;
    const existing = await this._cloudflare('GET',
      `/zones/${zone}/dns_records?type=${record.type}&name=${encodeURIComponent(record.name)}`);
    const rows = (existing.result || []);

    const payload = {
      type: record.type,
      name: record.name,
      content: record.type === 'MX' ? record.content : record.expected,
      ttl: 300,
      proxied: false,
    };
    if (record.type === 'MX') payload.priority = record.priority;

    let response;
    let action;
    if (rows.length) {
      // Var olan kayıt GÜNCELLENİR, fazlalıklar SİLİNMEZ. Silmek, aynı adda
      // başka bir hizmete ait kaydı yok etmek olabilir; ikinci bir MX ya da
      // ikinci bir TXT bilinçli konmuş olabilir.
      response = await this._cloudflare('PATCH', `/zones/${zone}/dns_records/${rows[0].id}`, payload);
      action = 'updated';
      if (rows.length > 1) {
        this.logger.warn({
          name: record.name, count: rows.length,
          ids: rows.map((r) => r.id),
          msg: 'aynı adda birden fazla kayıt var; yalnızca ilki güncellendi, diğerleri elle gözden geçirilmeli',
        });
      }
    } else {
      response = await this._cloudflare('POST', `/zones/${zone}/dns_records`, payload);
      action = 'created';
    }

    const id = (response.result && response.result.id) || (rows[0] && rows[0].id) || null;

    // GERİ OKUMA: sağlayıcı ne sakladı?
    let storedContent = '';
    let confirmed = false;
    try {
      const readBack = await this._cloudflare('GET', `/zones/${zone}/dns_records/${id}`);
      const stored = readBack.result || {};
      storedContent = record.type === 'MX'
        ? `${stored.priority} ${String(stored.content || '').replace(/\.$/, '')}`
        : String(stored.content || '').replace(/^"|"$/g, '');
      confirmed = valuesMatch(storedContent, record.expected, record.type);
    } catch (err) {
      this.logger.warn({
        name: record.name, id, error: err.message,
        msg: 'yazılan DNS kaydı geri okunamadı',
      });
    }

    return { id, action, confirmed, storedContent };
  }

  /**
   * Cloudflare kimlik bilgilerini ve bölgeyi doğrular.
   *
   * Açılışta bir kez çalışır. Yanlış bir jeton ya da bölge kimliği,
   * denetimin ilk yazma denemesine kadar sessiz kalıyordu; oysa ikisi de
   * anında sorulabilecek şeyler.
   */
  async verifyProvider() {
    const capability = this._writeCapability();
    if (!capability.ok) return { ok: false, reason: capability.reason };
    try {
      const res = await this._cloudflare('GET', `/zones/${this.config.dns.zoneId}`);
      const zone = res.result || {};
      this.logger.info({
        zone: zone.name, zoneId: zone.id, status: zone.status,
        nameServers: zone.name_servers,
        msg: 'Cloudflare bölgesi doğrulandı',
      });
      return { ok: true, zone: zone.name, zoneId: zone.id, status: zone.status };
    } catch (err) {
      this.logger.error({
        zoneId: this.config.dns.zoneId, error: err.message,
        msg: 'Cloudflare bölgesi doğrulanamadı — jeton ya da bölge kimliği hatalı olabilir',
      });
      return { ok: false, reason: err.message };
    }
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
          const body = Buffer.concat(chunks).toString('utf8');
          try {
            const data = JSON.parse(body);
            if (!data.success) {
              // Cloudflare'in hata kodu ve mesajı OLDUĞU GİBİ taşınır:
              // 10000 (kimlik doğrulama), 81044 (bölge yok) ve 9109 (izin
              // yetersiz) tamamen farklı düzeltmeler gerektiriyor ve
              // "yazılamadı" tek başına hiçbirini göstermiyor.
              reject(new Error(
                `Cloudflare ${method} ${path} -> HTTP ${res.statusCode}: `
                + JSON.stringify(data.errors || data).slice(0, 300),
              ));
              return;
            }
            resolve(data);
          } catch (err) {
            reject(new Error(
              `Cloudflare ${method} ${path} -> HTTP ${res.statusCode}, yanıt ayrıştırılamadı: `
              + `${body.slice(0, 200)} (${err.message})`,
            ));
          }
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
    const writable = this._writeCapability();
    this.logger.info({
      intervalMs: this.config.dns.intervalMs,
      autoApply: this.config.dns.autoApply,
      provider: this.config.dns.provider,
      // "autoApply açık ama yazma yapılamıyor" hâli açılışta görünür olmalı;
      // ilk denetime kadar (12 saat) beklemek, sorunu geç fark ettiriyordu.
      writable: writable.ok,
      writeBlockedBy: writable.ok ? undefined : writable.reason,
      msg: 'DNS denetimi planlandı',
    });
    if (this.config.dns.autoApply && writable.ok) {
      this.verifyProvider().catch(() => {});
    }
    return this;
  }

  stop() { if (this.timer) { this.timer.stop(); this.timer = null; } }
}

/** Kayıt satırlarını okunur tutar: bir DKIM p= değeri tek başına 400 karakter. */
function snip(value, max = 120) {
  const s = String(value == null ? '' : value);
  return s.length > max ? `${s.slice(0, max)}…(+${s.length - max})` : s;
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

module.exports = { DnsAuditor, valuesMatch, normalizeDohValue };
