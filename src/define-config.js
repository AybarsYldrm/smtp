'use strict';

const configSource = require('./config-source');

/**
 * Kütüphane kullanıcısı için sade yapılandırma yüzeyi.
 *
 * ── NEDEN ───────────────────────────────────────────────────────────────
 * `src/config.js` yaklaşık altmış ayar taşıyor ve hepsinin makul bir
 * öntanımlısı var. Bir posta sunucusu kurmak için gerçekten VERİLMESİ
 * gereken şey ise kısa bir liste: alan adı, veritabanına nasıl bağlanılacağı,
 * iki sır, kimlik sağlayıcı bilgileri ve (DNS denetimi isteniyorsa)
 * Cloudflare anahtarları. Geri kalanı ayarlanabilir olmalı ama görünür
 * olmak zorunda değil.
 *
 * Bu dosya o kısa listeyi tam yapılandırmaya çeviriyor. Kısa listenin
 * dışındaki her şey için `advanced` var — orada `src/config.js`'in bildiği
 * tüm yollar geçerli.
 *
 * ── KULLANIM ────────────────────────────────────────────────────────────
 *
 *   const { defineConfig, createServer } = require('@fitfak/smtp');
 *
 *   const config = defineConfig({
 *     domain: 'ornek.com',
 *     publicIp: '203.0.113.10',
 *     vaultSecret: process.env.VAULT_SECRET,
 *     database: {
 *       target: 'https://db.ornek.com:51572',
 *       caFingerprint: process.env.DB_CA_FINGERPRINT,
 *       rootSecret: process.env.DB_ROOT_SECRET,
 *       enrolmentSecret: process.env.DB_ENROLMENT_SECRET,
 *     },
 *     identity: {
 *       baseUrl: 'https://session.ornek.com',
 *       clientId: process.env.OAUTH_CLIENT_ID,
 *       clientSecret: process.env.OAUTH_CLIENT_SECRET,
 *     },
 *     cloudflare: { apiToken: process.env.CF_API_TOKEN, zoneId: process.env.CF_ZONE_ID },
 *   });
 *
 *   await createServer(config).start();
 *
 * `defineConfig` yapılandırmayı KAYDEDER ve `src/config.js`'i yeniden
 * yükleyerek geri döndürür. Bu yüzden uygulamanın en başında, başka hiçbir
 * modül yüklenmeden önce çağrılmalı.
 */

/** Kısa listede beklenen alanlar — yazım hatası sessizce yutulmasın diye. */
const KNOWN_KEYS = new Set([
  'domain', 'domains', 'hostname', 'publicIp', 'bind', 'env', 'dataDir',
  'vaultSecret', 'database', 'identity', 'trust', 'cloudflare', 'webmail',
  'site', 'ports', 'log', 'advanced',
]);

function defineConfig(options = {}) {
  const unknown = Object.keys(options).filter((k) => !KNOWN_KEYS.has(k));
  if (unknown.length) {
    // Bilinmeyen bir anahtarı yok saymak, "ayarladım ama etkisi yok"
    // durumunun en yaygın sebebi. Hata vermek, yazım hatasını kurulum
    // anında yakalıyor.
    throw new Error(
      `[defineConfig] bilinmeyen ayar: ${unknown.join(', ')}. `
      + `Beklenenler: ${[...KNOWN_KEYS].join(', ')}. `
      + 'Listede olmayan ayarlar için `advanced` kullanın.',
    );
  }

  const domain = String(options.domain || (options.domains && options.domains[0]) || '').toLowerCase();
  if (!domain) throw new Error('[defineConfig] `domain` zorunlu (ör. "ornek.com")');

  const db = options.database || {};
  const identity = options.identity || {};
  const trust = options.trust || {};
  const cloudflare = options.cloudflare || {};
  const webmail = options.webmail || {};
  const site = options.site || {};
  const ports = options.ports || {};

  const hostname = String(options.hostname || `mail.${domain}`).toLowerCase();
  const webmailHost = String(webmail.host || `posta.${domain}`).toLowerCase();

  const mapped = {
    env: options.env,
    dataDir: options.dataDir,

    mail: {
      domain,
      hostname,
      domains: normalizeDomains(options.domains, domain),
    },

    smtp: {
      bind: options.bind,
      publicIp: options.publicIp,
      ports: {
        mx: ports.mx,
        submission: ports.submission,
        smtps: ports.smtps,
      },
    },

    // Kasa sırrı: kasadaki özel anahtarlar (DKIM, S/MIME) bununla sarılıyor.
    vault: { secret: options.vaultSecret },

    db: {
      driver: db.driver,
      remoteTarget: db.target,
      caFingerprint: db.caFingerprint,
      caPath: db.caPath,
      rootSecret: db.rootSecret,
      enrolmentSecret: db.enrolmentSecret,
      serviceName: db.serviceName,
      ownerId: db.ownerId,
      dbId: db.dbId,
    },

    idp: {
      baseUrl: identity.baseUrl,
      clientId: identity.clientId,
      clientSecret: identity.clientSecret,
      redirectPath: identity.redirectPath,
      scopes: identity.scopes,
      adminEmails: identity.adminEmails,
      autoProvisionMailbox: identity.autoProvisionMailbox,
    },

    trust: {
      baseUrl: trust.baseUrl,
      smimeProfile: trust.profile,
      caBundlePath: trust.caBundlePath,
      autoIssue: trust.autoIssue,
      allowServiceIdentity: trust.allowServiceIdentity,
      issueScope: trust.issueScope,
    },

    dns: {
      provider: cloudflare.apiToken ? 'cloudflare' : undefined,
      apiToken: cloudflare.apiToken,
      zoneId: cloudflare.zoneId,
      autoApply: cloudflare.autoApply,
      dmarcPolicy: cloudflare.dmarcPolicy,
    },

    webmail: { origin: webmail.origin || `https://${webmailHost}` },
    site: { domain: site.domain, origin: site.origin },

    vhosts: buildVhosts({ webmailHost, webmail, site }),

    log: options.log,
  };

  const merged = mergeDefined(mapped, options.advanced || {});
  configSource.set(merged);

  // config.js açılışta okuduğu için yeniden yükleniyor. Uygulamanın en
  // başında çağrıldığı sürece bu bir kez olur.
  delete require.cache[require.resolve('./config')];
  return require('./config');
}

/** Yalnızca TANIMLI değerleri birleştirir: `undefined` bir ayarı silmemeli. */
function mergeDefined(base, patch) {
  const out = Array.isArray(base) ? base.slice() : { ...base };
  for (const [key, value] of Object.entries(patch || {})) {
    if (value === undefined) continue;
    if (value && typeof value === 'object' && !Array.isArray(value)
      && out[key] && typeof out[key] === 'object' && !Array.isArray(out[key])) {
      out[key] = mergeDefined(out[key], value);
    } else {
      out[key] = value;
    }
  }
  return stripUndefined(out);
}

function stripUndefined(object) {
  if (!object || typeof object !== 'object' || Array.isArray(object)) return object;
  const out = {};
  for (const [key, value] of Object.entries(object)) {
    if (value === undefined) continue;
    const cleaned = stripUndefined(value);
    // Tamamen boşalan bir nesneyi de atıyoruz: `{ smtp: { ports: {} } }`
    // config.js'te "ayarlanmış ama boş" gibi görünürdü.
    if (cleaned && typeof cleaned === 'object' && !Array.isArray(cleaned) && !Object.keys(cleaned).length) continue;
    out[key] = cleaned;
  }
  return out;
}

/**
 * Alan adı listesi.
 *
 * Kısa biçim: `domains: ['a.com', 'b.com']`. Uzun biçim, her alanın kendi
 * DKIM seçicisini ve posta alıp almadığını belirtmesine izin veriyor —
 * yalnızca gönderim yapan bir alanın MX'i olmaz ama DKIM'i olur.
 */
function normalizeDomains(domains, primary) {
  if (!domains || !domains.length) return undefined;
  return domains.map((entry) => {
    if (typeof entry === 'string') return { name: entry.toLowerCase(), dkimSelector: 'mail' };
    return {
      name: String(entry.name || primary).toLowerCase(),
      dkimSelector: String(entry.dkimSelector || 'mail').toLowerCase(),
      receive: entry.receive !== false,
      dmarcRua: entry.dmarcRua,
    };
  });
}

/**
 * vhost listesi.
 *
 * Webmail her zaman var. Kişisel site YALNIZCA istendiğinde: `site.domain`
 * verilmezse ikinci bir dinleyici açmıyoruz. Önceki öntanımlı, kimsenin
 * istemediği bir alan adına (aybars.net.tr) bağlanmayı deniyordu.
 */
function buildVhosts({ webmailHost, webmail, site }) {
  const vhosts = [{
    kind: 'webmail',
    host: webmailHost,
    bind: webmail.bind || '127.0.1.2',
    port: Number(webmail.port) || 80,
    aliases: webmail.aliases || [],
  }];
  if (site.domain) {
    vhosts.push({
      kind: 'site',
      host: String(site.domain).toLowerCase(),
      bind: site.bind || '127.0.1.1',
      port: Number(site.port) || 80,
      aliases: site.aliases || [`www.${site.domain}`],
    });
  }
  return vhosts;
}

module.exports = { defineConfig };
