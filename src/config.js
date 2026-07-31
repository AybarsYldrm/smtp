'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Yapılandırma tek noktadan okunur ve BİR KEZ doğrulanır.
//
// Önceki sürüm sırları kaynak kodun içinde taşıyordu (Cloudflare API token'ı,
// Microsoft client secret'ı, SMTP kullanıcı parolaları). Bunun iki ayrı sonucu
// var ve ikisi de geç fark ediliyor: sır git geçmişine giriyor (silmek yetmez,
// rotasyon gerekir) ve aynı kod iki ortamda çalıştığında hangi hesabın
// kullanıldığı belirsizleşiyor. Burada tüm sırlar ortamdan gelir; üretim
// modunda eksik olan bir sır sessizce atlanmaz, açılışta hata verir.
//
// Öncelik: ortam değişkeni > yapılandırma dosyası (FITFAK_MAIL_CONFIG) > öntanımlı.

const TRUE_SET = new Set(['1', 'true', 'yes', 'on', 'evet']);

function loadFileConfig() {
  const p = process.env.FITFAK_MAIL_CONFIG;
  if (!p) return {};
  try {
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (err) {
    throw new Error(`[config] FITFAK_MAIL_CONFIG okunamadı (${p}): ${err.message}`);
  }
}

const FILE_CFG = loadFileConfig();

function pick(envKey, filePath, fallback) {
  if (process.env[envKey] != null && process.env[envKey] !== '') return process.env[envKey];
  const parts = String(filePath || '').split('.').filter(Boolean);
  // Yol verilmemişse dosyaya hiç bakılmaz. (Boş yolu "kökü döndür" olarak
  // yorumlamak, ayarın değeri olarak bütün yapılandırma nesnesini verirdi.)
  if (!parts.length) return fallback;
  let cur = FILE_CFG;
  for (const part of parts) {
    if (cur == null || typeof cur !== 'object') { cur = undefined; break; }
    cur = cur[part];
  }
  return cur !== undefined ? cur : fallback;
}

function bool(envKey, filePath, fallback = false) {
  const v = pick(envKey, filePath, undefined);
  if (v === undefined || v === '') return fallback;
  if (typeof v === 'boolean') return v;
  return TRUE_SET.has(String(v).trim().toLowerCase());
}

function int(envKey, filePath, fallback) {
  const v = pick(envKey, filePath, undefined);
  if (v === undefined || v === '') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function list(envKey, filePath, fallback = []) {
  const v = pick(envKey, filePath, undefined);
  if (v === undefined || v === '') return fallback.slice();
  if (Array.isArray(v)) return v.map((s) => String(s).trim()).filter(Boolean);
  return String(v).split(/[,\s]+/).map((s) => s.trim()).filter(Boolean);
}

function lower(s) { return String(s == null ? '' : s).trim().toLowerCase(); }

const NODE_ENV = lower(pick('NODE_ENV', 'env', 'development'));
const IS_PROD = NODE_ENV === 'production';

const ROOT_DIR = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(pick('FITFAK_MAIL_DATA_DIR', 'dataDir', path.join(ROOT_DIR, 'data')));
const CERT_DIR = path.resolve(pick('FITFAK_MAIL_CERT_DIR', 'certDir', path.join(ROOT_DIR, 'certs')));
const PUBLIC_DIR = path.resolve(pick('FITFAK_MAIL_PUBLIC_DIR', 'publicDir', path.join(ROOT_DIR, 'public')));

/* ─────────────────────────────────────────────────────────────
   POSTA ALAN ADLARI
   Her alan adının kendi DKIM seçicisi ve kendi anahtarı olur.
   Tek anahtarı iki alan adı için kullanmak, birinin anahtarı
   sızdığında ikisini birden yenilemek zorunda bırakır.
   ───────────────────────────────────────────────────────────── */
const PRIMARY_DOMAIN = lower(pick('FITFAK_MAIL_DOMAIN', 'mail.domain', 'fitfak.net'));
const MAIL_HOSTNAME = lower(pick('FITFAK_MAIL_HOSTNAME', 'mail.hostname', `mail.${PRIMARY_DOMAIN}`));

function parseDomains() {
  const fromFile = FILE_CFG.mail && Array.isArray(FILE_CFG.mail.domains) ? FILE_CFG.mail.domains : null;
  const raw = fromFile || [
    { name: PRIMARY_DOMAIN, dkimSelector: lower(pick('FITFAK_MAIL_DKIM_SELECTOR', 'mail.dkimSelector', 'mail')) },
    // aybars.net.tr posta ALMIYOR ama gönderiyor (kişisel site bildirimleri,
    // parola sıfırlama vb.). Bu yüzden MX'i yok, DKIM'i var.
    { name: lower(pick('FITFAK_SITE_DOMAIN', 'site.domain', 'aybars.net.tr')), dkimSelector: 'mail', receive: false },
  ];
  return raw.map((d) => ({
    name: lower(d.name),
    dkimSelector: lower(d.dkimSelector || 'mail'),
    receive: d.receive !== false,
    dmarcRua: lower(d.dmarcRua || `dmarc@${lower(d.name)}`),
  })).filter((d) => d.name);
}

const DOMAINS = parseDomains();
const RECEIVE_DOMAINS = DOMAINS.filter((d) => d.receive).map((d) => d.name);

/* ─────────────────────────────────────────────────────────────
   VHOST'LAR — cloudflared çıkışları
   Her isim kendi loopback adresine bağlanır; cloudflared tüneli o
   adrese yönlenir. İkisini tek adrese koyup Host başlığıyla ayırmak
   da mümkündü, ama o zaman bir tünelin yanlış yapılandırılması
   diğerinin trafiğini görebilir hâle getirirdi. Ayrı adres, ayrı
   soket: yanlış tünel bağlanamaz bile.
   ───────────────────────────────────────────────────────────── */
function parseVhosts() {
  if (Array.isArray(FILE_CFG.vhosts) && FILE_CFG.vhosts.length) {
    return FILE_CFG.vhosts.map((v) => ({
      kind: lower(v.kind || 'webmail'),
      host: lower(v.host),
      bind: v.bind || '127.0.0.1',
      port: Number(v.port) || 80,
      aliases: (v.aliases || []).map(lower),
    }));
  }
  return [
    {
      kind: 'site',
      host: lower(pick('FITFAK_SITE_HOST', null, 'aybars.net.tr')),
      bind: pick('FITFAK_SITE_BIND', null, '127.0.1.1'),
      port: int('FITFAK_SITE_PORT', null, 80),
      aliases: list('FITFAK_SITE_ALIASES', null, ['www.aybars.net.tr']),
    },
    {
      kind: 'webmail',
      host: lower(pick('FITFAK_WEBMAIL_HOST', null, [`envelope.${PRIMARY_DOMAIN}`])),
      bind: pick('FITFAK_WEBMAIL_BIND', null, '127.0.1.2'),
      port: int('FITFAK_WEBMAIL_PORT', null, 80),
      aliases: list('FITFAK_WEBMAIL_ALIASES', null, [`envelope.${PRIMARY_DOMAIN}`]),
    },
  ];
}

const VHOSTS = parseVhosts();

function vhostFor(kind) { return VHOSTS.find((v) => v.kind === kind) || null; }

const WEBMAIL_VHOST = vhostFor('webmail');
const SITE_VHOST = vhostFor('site');

const WEBMAIL_ORIGIN = pick('FITFAK_WEBMAIL_ORIGIN', 'webmail.origin',
  WEBMAIL_VHOST ? `https://${WEBMAIL_VHOST.host}` : `https://${MAIL_HOSTNAME}`);
const SITE_ORIGIN = pick('FITFAK_SITE_ORIGIN', 'site.origin',
  SITE_VHOST ? `https://${SITE_VHOST.host}` : 'https://aybars.net.tr');

/* ─────────────────────────────────────────────────────────────
   SMTP
   ───────────────────────────────────────────────────────────── */
const SMTP = {
  // Dinlenecek adres. Loopback'e bağlanmak MX trafiğini imkânsız kılar;
  // 0.0.0.0 ise sunucudaki her arayüzü açar. Öntanımlı açık adres.
  bind: pick('FITFAK_SMTP_BIND', 'smtp.bind', '31.58.245.241'),
  publicIp: pick('FITFAK_MAIL_PUBLIC_IP', 'smtp.publicIp', '31.58.245.241'),
  // Giden bağlantıların çıkacağı yerel adres (birden fazla IP'li makinede
  // PTR kaydı olan adresten çıkmak zorunludur, yoksa alıcı reddeder).
  outboundLocalAddress: pick('FITFAK_SMTP_OUTBOUND_IP', 'smtp.outboundLocalAddress', ''),
  ports: {
    mx: int('FITFAK_SMTP_PORT_MX', 'smtp.ports.mx', 25),
    submission: int('FITFAK_SMTP_PORT_SUBMISSION', 'smtp.ports.submission', 587),
    smtps: int('FITFAK_SMTP_PORT_SMTPS', 'smtp.ports.smtps', 465),
  },
  maxMessageBytes: int('FITFAK_SMTP_MAX_MESSAGE_BYTES', 'smtp.maxMessageBytes', 40 * 1024 * 1024),
  maxRecipients: int('FITFAK_SMTP_MAX_RCPT', 'smtp.maxRecipients', 100),
  maxAuthFailures: int('FITFAK_SMTP_MAX_AUTH_FAILURES', 'smtp.maxAuthFailures', 5),
  authWindowMs: int('FITFAK_SMTP_AUTH_WINDOW_MS', 'smtp.authWindowMs', 60_000),
  commandTimeoutMs: int('FITFAK_SMTP_COMMAND_TIMEOUT_MS', 'smtp.commandTimeoutMs', 300_000),
  dataTimeoutMs: int('FITFAK_SMTP_DATA_TIMEOUT_MS', 'smtp.dataTimeoutMs', 600_000),
  maxConnectionsPerIp: int('FITFAK_SMTP_MAX_CONN_PER_IP', 'smtp.maxConnectionsPerIp', 20),
  maxConnections: int('FITFAK_SMTP_MAX_CONN', 'smtp.maxConnections', 500),
  // PROXY protokolü yalnızca güvenilen kaynaklardan kabul edilir: aksi hâlde
  // herhangi bir istemci "PROXY TCP4 1.2.3.4 ..." yazarak IP tabanlı her
  // kısıtlamayı (ban listesi, SPF) atlatabilir.
  trustedProxies: list('FITFAK_SMTP_TRUSTED_PROXIES', 'smtp.trustedProxies', ['127.0.0.1', '::1']),
  requireTlsForAuth: bool('FITFAK_SMTP_REQUIRE_TLS_FOR_AUTH', 'smtp.requireTlsForAuth', true),
  // Gelen postada SPF/DKIM/DMARC değerlendirmesi.
  inboundChecks: bool('FITFAK_SMTP_INBOUND_CHECKS', 'smtp.inboundChecks', true),
  // DMARC "reject" politikası olan alan adından gelen ve doğrulaması
  // başarısız olan postayı SMTP düzeyinde reddet.
  enforceDmarc: bool('FITFAK_SMTP_ENFORCE_DMARC', 'smtp.enforceDmarc', true),
  greetingDelayMs: int('FITFAK_SMTP_GREETING_DELAY_MS', 'smtp.greetingDelayMs', 0),
};

/* ─────────────────────────────────────────────────────────────
   POSTA KUTUSU SINIRLARI (ekler dâhil)
   ───────────────────────────────────────────────────────────── */
const LIMITS = {
  mailboxQuotaBytes: int('FITFAK_MAILBOX_QUOTA_BYTES', 'limits.mailboxQuotaBytes', 5 * 1024 * 1024 * 1024),
  maxAttachmentsPerMessage: int('FITFAK_MAX_ATTACHMENTS', 'limits.maxAttachmentsPerMessage', 25),
  maxAttachmentBytes: int('FITFAK_MAX_ATTACHMENT_BYTES', 'limits.maxAttachmentBytes', 25 * 1024 * 1024),
  maxInlineImageBytes: int('FITFAK_MAX_INLINE_IMAGE_BYTES', 'limits.maxInlineImageBytes', 8 * 1024 * 1024),
  maxTotalAttachmentBytes: int('FITFAK_MAX_TOTAL_ATTACHMENT_BYTES', 'limits.maxTotalAttachmentBytes', 35 * 1024 * 1024),
  maxBodyBytes: int('FITFAK_MAX_BODY_BYTES', 'limits.maxBodyBytes', 2 * 1024 * 1024),
  // Gövde/ek baytları bu boyutta parçalara ayrılıp saklanır. Kayıt başına
  // sınır, uzak (gRPC) sürücüde tek çerçevenin taşınabilir olmasını sağlar.
  blobChunkBytes: int('FITFAK_BLOB_CHUNK_BYTES', 'limits.blobChunkBytes', 256 * 1024),
  maxMimeParts: int('FITFAK_MAX_MIME_PARTS', 'limits.maxMimeParts', 200),
  maxMimeDepth: int('FITFAK_MAX_MIME_DEPTH', 'limits.maxMimeDepth', 20),
  // Ekleri hem MIME türüne hem uzantıya göre süzüyoruz: gönderen tarafın
  // beyan ettiği tür ile dosya adı çelişiyorsa dosya güvenilmezdir.
  allowedAttachmentTypes: list('FITFAK_ALLOWED_ATTACHMENT_TYPES', 'limits.allowedAttachmentTypes', [
    'application/pdf',
    'application/json', 'application/zip', 'application/gzip',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint',
    'application/pkcs7-signature', 'application/pkcs7-mime', 'application/pkcs10',
    'application/x-pkcs7-signature', 'application/x-pkcs7-mime',
    'text/plain', 'text/csv', 'text/calendar', 'text/vcard',
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif', 'image/svg+xml', 'image/heic',
    'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm', 'audio/aac',
    'video/mp4', 'video/webm', 'video/quicktime', 'video/x-matroska', 'video/ogg',
    'message/rfc822',
  ]),
  // Bu uzantılar taşıyıcı türü ne olursa olsun reddedilir. Bir eki "izinli
  // MIME türü" listesiyle korumak yetmez: sunucu image/png diyip .exe
  // gönderebilir, tarayıcı da uzantıya göre davranabilir.
  blockedAttachmentExtensions: list('FITFAK_BLOCKED_EXTENSIONS', 'limits.blockedAttachmentExtensions', [
    '.exe', '.scr', '.pif', '.com', '.bat', '.cmd', '.msi', '.msp', '.cpl', '.dll',
    '.jar', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1', '.lnk',
    '.reg', '.hta', '.chm', '.iso', '.img', '.apk', '.app', '.dmg', '.sh',
  ]),
  // Görsellerin webmail'de küçük önizlemesi üretilir; bundan büyük görseller
  // önizlenmez (yalnızca indirilir) — kod içinde çözümlemek istemediğimiz
  // boyut budur.
  previewMaxImageBytes: int('FITFAK_PREVIEW_MAX_IMAGE_BYTES', 'limits.previewMaxImageBytes', 4 * 1024 * 1024),
};

/* ─────────────────────────────────────────────────────────────
   KUYRUK / TOPLU GÖNDERİM
   ───────────────────────────────────────────────────────────── */
const QUEUE = {
  workers: int('FITFAK_QUEUE_WORKERS', 'queue.workers', 4),
  // Alan adı başına eşzamanlı bağlantı. Gmail'e 50 paralel bağlantı açmak
  // teslimatı hızlandırmaz, hız sınırına ve geçici bloklara yol açar.
  perDomainConcurrency: int('FITFAK_QUEUE_PER_DOMAIN', 'queue.perDomainConcurrency', 2),
  maxAttempts: int('FITFAK_QUEUE_MAX_ATTEMPTS', 'queue.maxAttempts', 8),
  // Yeniden deneme aralıkları (ms). Son değere ulaşınca kalıcı hata sayılır.
  backoffMs: list('FITFAK_QUEUE_BACKOFF_MS', 'queue.backoffMs',
    ['60000', '300000', '900000', '3600000', '7200000', '14400000', '28800000', '57600000'])
    .map(Number).filter(Number.isFinite),
  pollIntervalMs: int('FITFAK_QUEUE_POLL_MS', 'queue.pollIntervalMs', 5_000),
  // Kampanya başına saniyedeki ileti. Toplu gönderimde asıl risk teknik
  // değil itibar kaybıdır: ani hacim artışı doğrudan spam klasörü demek.
  campaignRatePerSecond: int('FITFAK_CAMPAIGN_RATE', 'queue.campaignRatePerSecond', 10),
  campaignBatchSize: int('FITFAK_CAMPAIGN_BATCH', 'queue.campaignBatchSize', 500),
  maxRecipientsPerCampaign: int('FITFAK_CAMPAIGN_MAX_RCPT', 'queue.maxRecipientsPerCampaign', 100_000),
  bounceMailbox: lower(pick('FITFAK_BOUNCE_MAILBOX', 'queue.bounceMailbox', `bounce@${PRIMARY_DOMAIN}`)),
  dsnFrom: lower(pick('FITFAK_DSN_FROM', 'queue.dsnFrom', `mailer-daemon@${PRIMARY_DOMAIN}`)),
};

/* ─────────────────────────────────────────────────────────────
   KİMLİK SAĞLAYICI (IdP) — session.fitfak.net
   ───────────────────────────────────────────────────────────── */
const IDP = {
  baseUrl: String(pick('FITFAK_IDP_BASE_URL', 'idp.baseUrl', 'https://session.fitfak.net')).replace(/\/+$/, ''),
  clientId: pick('FITFAK_MAIL_CLIENT_ID', 'idp.clientId', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
  clientSecret: pick('FITFAK_MAIL_CLIENT_SECRET', 'idp.clientSecret', ''),
  redirectPath: pick('FITFAK_MAIL_REDIRECT_PATH', 'idp.redirectPath', '/oauth/callback'),
  // `email` kapsamı olmadan IdP posta adresini döndürmez; posta kutusu
  // yetkilendirmesi tam olarak o adrese dayanıyor.
  scopes: list('FITFAK_MAIL_SCOPES', 'idp.scopes', ['openid', 'profile', 'email', 'cert:issue']),
  deviceClientId: pick('FITFAK_MAIL_DEVICE_CLIENT_ID', 'idp.deviceClientId', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'),
  // IdP'de admin sayılan roller/claim'ler. Harici adres bağlama yalnızca
  // bunlara açık.
  adminRoles: list('FITFAK_IDP_ADMIN_ROLES', 'idp.adminRoles', ['admin']),
  adminSubjects: list('FITFAK_IDP_ADMIN_SUBJECTS', 'idp.adminSubjects', []),
  // fitfak-idp'nin kendi yönetici kuralı TEK bir doğrulanmış adrese dayanır
  // (core/config.js -> adminEmail). Aynı adresi burada da tanımak, IdP'de
  // yönetici olan kişinin posta tarafında yönetici olmamasını engelliyor.
  adminEmails: list('FITFAK_IDP_ADMIN_EMAILS', 'idp.adminEmails', []).map(lower),
  // Kendi alan adımızdaki DOĞRULANMIŞ bir kimlik ilk kez giriş yaptığında
  // posta kutusunu aç. Harici adresler (gmail.com vb.) buna dâhil DEĞİLDİR;
  // onlar için yöneticinin kurduğu bir kimlik bağı gerekir.
  autoProvisionMailbox: bool('FITFAK_MAIL_AUTO_PROVISION', 'idp.autoProvisionMailbox', true),
  introspectPath: pick('FITFAK_IDP_INTROSPECT_PATH', 'idp.introspectPath', '/oauth/introspect'),
  userinfoPath: pick('FITFAK_IDP_USERINFO_PATH', 'idp.userinfoPath', '/oauth/userinfo'),
  tokenPath: pick('FITFAK_IDP_TOKEN_PATH', 'idp.tokenPath', '/oauth/token'),
  authorizePath: pick('FITFAK_IDP_AUTHORIZE_PATH', 'idp.authorizePath', '/oauth/authorize'),
  deviceAuthPath: pick('FITFAK_IDP_DEVICE_PATH', 'idp.deviceAuthPath', '/oauth/device/code'),
  jwksPath: pick('FITFAK_IDP_JWKS_PATH', 'idp.jwksPath', '/.well-known/jwks.json'),
  sessionTtlMs: int('FITFAK_MAIL_SESSION_TTL_MS', 'idp.sessionTtlMs', 12 * 60 * 60 * 1000),
  // Oturumun IdP'de hâlâ geçerli olup olmadığını bu aralıkla yeniden sorar.
  // Uzun ömürlü çerez + hiç kontrol etmemek, IdP'de kapatılmış bir hesabın
  // posta kutusunu okumaya devam etmesi demektir.
  revalidateIntervalMs: int('FITFAK_MAIL_REVALIDATE_MS', 'idp.revalidateIntervalMs', 5 * 60 * 1000),
};

/* ─────────────────────────────────────────────────────────────
   SERTİFİKA OTORİTESİ — trust.fitfak.net
   ───────────────────────────────────────────────────────────── */
const TRUST = {
  baseUrl: String(pick('FITFAK_TRUST_BASE_URL', 'trust.baseUrl', 'https://trust.fitfak.net')).replace(/\/+$/, ''),
  // Sertifika verme uç noktası. IdP tarafında tek bir yol var
  // (/device/certificate) ve sertifikanın SAHİBİ yola göre değil, taşınan
  // jetona göre belirleniyor — bkz. certs/manager.js başındaki not.
  devicePath: pick('FITFAK_TRUST_DEVICE_PATH', 'trust.devicePath', '/device/certificate'),
  certificatesPath: pick('FITFAK_TRUST_CERTS_PATH', 'trust.certificatesPath', '/device/certificates'),
  revokePath: pick('FITFAK_TRUST_REVOKE_PATH', 'trust.revokePath', '/device/certificate/revoke'),
  smimeProfile: pick('FITFAK_TRUST_SMIME_PROFILE', 'trust.smimeProfile', 'smime'),
  caBundlePath: pick('FITFAK_TRUST_CA_PATH', 'trust.caBundlePath', ''),
  // S/MIME sertifikaları ömrünün bu oranında yenilenir.
  renewAtLifetimeRatio: Number(pick('FITFAK_TRUST_RENEW_RATIO', 'trust.renewAtLifetimeRatio', 0.66)),
  autoIssue: bool('FITFAK_TRUST_AUTO_ISSUE', 'trust.autoIssue', false),
  checkIntervalMs: int('FITFAK_TRUST_CHECK_MS', 'trust.checkIntervalMs', 6 * 60 * 60 * 1000),
  // Servis (client_credentials) kimliğiyle sertifika istemeye izin. YALNIZCA
  // sistem kutuları için anlamlıdır: o jetonun öznesi bir kullanıcı değil,
  // uygulamanın kendisidir ve IdP kullanıcı kutularına o kimlikle sertifika
  // vermez ("Kullanıcı bulunamadı" hatasının kaynağı buydu).
  allowServiceIdentity: bool('FITFAK_TRUST_ALLOW_SERVICE_IDENTITY', 'trust.allowServiceIdentity', false),
  // Sertifika istemek için gereken kapsam. Kullanıcının oturum jetonunda bu
  // kapsam yoksa arayüz yeniden onay (consent) turuna yönlendirir.
  issueScope: pick('FITFAK_TRUST_ISSUE_SCOPE', 'trust.issueScope', 'cert:issue'),
};

/* ─────────────────────────────────────────────────────────────
   VERİTABANI
   Gömülü motor, uzak mTLS (gRPC) ya da bağımsız çalışma için
   şifreli dosya sürücüsü. Sürücü seçimi burada; üst katmanlar
   hangisinin kullanıldığını bilmez.
   ───────────────────────────────────────────────────────────── */
const DB = {
  driver: lower(pick('FITFAK_MAIL_DB_DRIVER', 'db.driver', 'auto')), // auto | fitfak | file
  dataDir: path.join(DATA_DIR, 'db'),
  identityDir: path.resolve(pick('FITFAK_MAIL_DB_IDENTITY_DIR', 'db.identityDir', path.join(DATA_DIR, 'identity'))),
  remoteTarget: pick('FITFAK_MAIL_DB_TARGET', 'db.remoteTarget', 'https://localhost:51572'),
  serviceName: pick('FITFAK_MAIL_DB_SERVICE_NAME', 'db.serviceName', 'smtp-service'),
  ownerId: pick('FITFAK_MAIL_DB_OWNER_ID', 'db.ownerId', 'fitfak-smtp-service'),
  dbId: pick('FITFAK_MAIL_DB_ID', 'db.dbId', ''),
  rootSecretRaw: pick('FITFAK_MAIL_DB_ROOT_SECRET', 'db.rootSecret', ''),
  enrolmentSecret: pick('FITFAK_MAIL_DB_ENROLMENT_SECRET', 'db.enrolmentSecret', ''),
  caPath: pick('FITFAK_MAIL_DB_CA_PATH', 'db.caPath', ''),
  caFingerprint: pick('FITFAK_MAIL_DB_CA_FINGERPRINT', 'db.caFingerprint', ''),
  snowflakeWorkerId: int('FITFAK_MAIL_DB_WORKER_ID', 'db.snowflakeWorkerId', 7),
};

/* ─────────────────────────────────────────────────────────────
   DNS (Cloudflare) — yalnızca denetim/upsert için
   ───────────────────────────────────────────────────────────── */
const DNS_CFG = {
  provider: lower(pick('FITFAK_DNS_PROVIDER', 'dns.provider', 'cloudflare')),
  apiToken: pick('CF_API_TOKEN', 'dns.apiToken', ''),
  zoneId: pick('CF_ZONE_ID', 'dns.zoneId', ''),
  // Denetim öntanımlı olarak SALT OKUNUR çalışır. Bir posta sunucusunun
  // açılışta DNS'i sessizce yeniden yazması, elle yapılmış bilinçli bir
  // değişikliği (ikinci MX, geçiş dönemi SPF'i) geri alır.
  autoApply: bool('FITFAK_DNS_AUTO_APPLY', 'dns.autoApply', false),
  intervalMs: int('FITFAK_DNS_AUDIT_MS', 'dns.intervalMs', 12 * 60 * 60 * 1000),
  dmarcPolicy: pick('FITFAK_DMARC_POLICY', 'dns.dmarcPolicy', 'quarantine'),
};

/* ─────────────────────────────────────────────────────────────
   BİLDİRİM (Web Push) + GİZLİ ANAHTAR SAKLAMA
   ───────────────────────────────────────────────────────────── */
const PUSH = {
  subject: pick('FITFAK_PUSH_SUBJECT', 'push.subject', `mailto:postmaster@${PRIMARY_DOMAIN}`),
  ttlSeconds: int('FITFAK_PUSH_TTL', 'push.ttlSeconds', 2419200),
  maxFailuresBeforeDrop: int('FITFAK_PUSH_MAX_FAILURES', 'push.maxFailuresBeforeDrop', 5),
  concurrency: int('FITFAK_PUSH_CONCURRENCY', 'push.concurrency', 8),
};

/* Anahtar kasası kök sırrı: kasadaki özel anahtarlar veritabanına bu sırla
   sarılarak yazılır. Veritabanı zaten şifreli; bu ikinci katman, veritabanı
   oturumu ele geçse bile özel anahtarların düz metin olmamasını sağlar. */
const VAULT_SECRET_RAW = pick('FITFAK_MAIL_VAULT_SECRET', 'vault.secret', '');

const HTTP_CFG = {
  // Ters proxy (cloudflared) arkasındayız: istemci IP'si başlıktan gelir.
  // Yalnızca aşağıdaki adreslerden gelen bağlantılarda bu başlıklara
  // güvenilir.
  trustedProxies: list('FITFAK_HTTP_TRUSTED_PROXIES', 'http.trustedProxies', ['127.0.0.1', '::1', '127.0.1.1', '127.0.1.2']),
  maxBodyBytes: int('FITFAK_HTTP_MAX_BODY_BYTES', 'http.maxBodyBytes', 64 * 1024 * 1024),
  attachmentTokenTtlMs: int('FITFAK_ATT_TOKEN_TTL_MS', 'http.attachmentTokenTtlMs', 4 * 60 * 60 * 1000),
  rateLimit: {
    windowMs: int('FITFAK_HTTP_RATE_WINDOW_MS', 'http.rateLimit.windowMs', 60_000),
    max: int('FITFAK_HTTP_RATE_MAX', 'http.rateLimit.max', 240),
    sendMax: int('FITFAK_HTTP_RATE_SEND_MAX', 'http.rateLimit.sendMax', 30),
  },
  // Statik dosyaları ve HTML'i her istekte diskten okumak yerine önbelleğe
  // al (geliştirmede kapatılır).
  cacheStatic: bool('FITFAK_HTTP_CACHE_STATIC', 'http.cacheStatic', IS_PROD),
  sessionCookieName: pick('FITFAK_SESSION_COOKIE', 'http.sessionCookieName', 'fitfak_mail_sid'),
  // Çerezler cloudflared TLS'i sonlandırdığı için Secure işaretlenir; yerel
  // düz HTTP geliştirmede kapatılabilir.
  secureCookies: bool('FITFAK_SECURE_COOKIES', 'http.secureCookies', true),
};

const SITE = {
  // Instagram'dan gelen ziyaretçilerin bildirimi. Kişisel sitedeki tek
  // "canlı" özellik bu.
  trackInstagram: bool('FITFAK_SITE_TRACK_INSTAGRAM', 'site.trackInstagram', true),
  visitRetention: int('FITFAK_SITE_VISIT_RETENTION', 'site.visitRetention', 500),
  notifyMailbox: lower(pick('FITFAK_SITE_NOTIFY_MAILBOX', 'site.notifyMailbox', `network@${PRIMARY_DOMAIN}`)),
  ipLookupUrl: pick('FITFAK_SITE_IP_LOOKUP', 'site.ipLookupUrl', 'https://ipwho.is'),
  ipLookupEnabled: bool('FITFAK_SITE_IP_LOOKUP_ENABLED', 'site.ipLookupEnabled', true),
};

const LOG = {
  // trace | debug | info | warn | error | silent
  // `trace` protokol seviyesini açar (SMTP komutları, IdP istek/yanıtları,
  // DKIM imza girdisi). Sırlar her seviyede maskelenir ama trace yine de
  // ileti üstverisi yazar; üretimde geçici olarak açılmalıdır.
  level: lower(pick('LOG_LEVEL', 'log.level', IS_PROD ? 'info' : 'debug')),
  json: bool('LOG_JSON', 'log.json', IS_PROD),
  color: bool('LOG_COLOR', 'log.color', !IS_PROD),
  // Kayıtlarda posta adreslerini maskeler. Üretimde açık: log dosyası,
  // veritabanının şifrelediği veriyi düz metin sızdıran yer olmamalı.
  redactAddresses: bool('LOG_REDACT_ADDRESSES', 'log.redactAddresses', IS_PROD),
};

function requireProdSecrets() {
  const missing = [];
  if (!IDP.clientId) missing.push('FITFAK_MAIL_CLIENT_ID');
  if (!IDP.clientSecret) missing.push('FITFAK_MAIL_CLIENT_SECRET');
  if (!VAULT_SECRET_RAW) missing.push('FITFAK_MAIL_VAULT_SECRET');
  if (DB.driver !== 'file' && !DB.rootSecretRaw && !DB.remoteTarget) missing.push('FITFAK_MAIL_DB_ROOT_SECRET');
  if (DB.remoteTarget && !DB.caPath && !DB.caFingerprint) {
    missing.push('FITFAK_MAIL_DB_CA_PATH veya FITFAK_MAIL_DB_CA_FINGERPRINT');
  }
  if (!SMTP.publicIp) missing.push('FITFAK_MAIL_PUBLIC_IP');
  if (missing.length) {
    throw new Error(
      '[config] Üretim modunda zorunlu ayarlar eksik:\n  - ' + missing.join('\n  - ')
      + '\n  Bu değerler kaynak kodda TUTULMAZ; ortamdan verilmelidir.',
    );
  }
}

function decodeSecret(raw, label) {
  if (!raw) return null;
  const s = String(raw).trim();
  // base64 ya da hex kabul edilir; ikisi de değilse ham UTF-8 kullanılır ama
  // en az 32 bayt olmalıdır.
  if (/^[A-Fa-f0-9]{64,}$/.test(s) && s.length % 2 === 0) return Buffer.from(s, 'hex');
  if (/^[A-Za-z0-9+/]{43,}={0,2}$/.test(s)) {
    const b = Buffer.from(s, 'base64');
    if (b.length >= 32) return b;
  }
  const buf = Buffer.from(s, 'utf8');
  if (buf.length < 32) {
    throw new Error(`[config] ${label} en az 32 bayt olmalı (base64/hex önerilir). Şu an: ${buf.length}`);
  }
  return buf;
}

const config = {
  env: NODE_ENV,
  isProd: IS_PROD,
  rootDir: ROOT_DIR,
  dataDir: DATA_DIR,
  certDir: CERT_DIR,
  publicDir: PUBLIC_DIR,
  hostname: MAIL_HOSTNAME,
  primaryDomain: PRIMARY_DOMAIN,
  domains: DOMAINS,
  receiveDomains: RECEIVE_DOMAINS,
  vhosts: VHOSTS,
  webmailOrigin: String(WEBMAIL_ORIGIN).replace(/\/+$/, ''),
  siteOrigin: String(SITE_ORIGIN).replace(/\/+$/, ''),
  smtp: SMTP,
  limits: LIMITS,
  queue: QUEUE,
  idp: IDP,
  trust: TRUST,
  db: DB,
  dns: DNS_CFG,
  push: PUSH,
  http: HTTP_CFG,
  site: SITE,
  log: LOG,
  instanceId: pick('FITFAK_MAIL_INSTANCE_ID', 'instanceId', `${os.hostname()}-${process.pid}`),

  isLocalDomain(domain) { return RECEIVE_DOMAINS.includes(lower(domain)); },
  domainConfig(name) { return DOMAINS.find((d) => d.name === lower(name)) || null; },
  redirectUri() { return `${config.webmailOrigin}${IDP.redirectPath}`; },
};

Object.defineProperty(config, 'vaultSecret', {
  enumerable: false,
  get() {
    if (!VAULT_SECRET_RAW) return null;
    return decodeSecret(VAULT_SECRET_RAW, 'FITFAK_MAIL_VAULT_SECRET');
  },
});

Object.defineProperty(config.db, 'rootSecret', {
  enumerable: false,
  get() {
    if (!DB.rootSecretRaw) return null;
    return decodeSecret(DB.rootSecretRaw, 'FITFAK_MAIL_DB_ROOT_SECRET');
  },
});

config.validate = function validate() {
  if (IS_PROD) requireProdSecrets();
  const seenBind = new Map();
  for (const v of VHOSTS) {
    const key = `${v.bind}:${v.port}`;
    if (seenBind.has(key)) {
      throw new Error(`[config] İki vhost aynı adrese bağlanıyor (${key}): ${seenBind.get(key)} ve ${v.host}`);
    }
    seenBind.set(key, v.host);
  }
  if (!DOMAINS.length) throw new Error('[config] En az bir posta alan adı gerekir.');
  if (!QUEUE.backoffMs.length) throw new Error('[config] queue.backoffMs boş olamaz.');
  return config;
};

module.exports = config;
