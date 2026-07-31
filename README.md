# @fitfak/mail

Fitfak posta sunucusu. SMTP alma/gönderme (25 / 465 / 587), DKIM, SPF, DMARC,
S/MIME imzalama, webmail arayüzü, gerçek zamanlı bildirim ve durum API'si.
Bütün kalıcı veri `@fitfak/database` üzerinde şifreli olarak durur; PKI işleri
`@fitfak/ssl` ile yapılır; oturum yetkilendirmesi Fitfak IdP
(`session.fitfak.net`) üzerinden yürür.

```
   ┌── cloudflared ──────────────────┐
   │  aybars.net.tr    -> 127.0.1.1  │   kişisel site
   │  mail.fitfak.net  -> 127.0.1.2  │   webmail + API
   └─────────────────────────────────┘
              │
   ┌──────────┴───────────────────────────────────────────────┐
   │  HTTP (vhost yönlendirme)     SMTP 25 / 465 / 587         │
   │        │                            │                    │
   │     pipeline  ── DKIM / SPF / DMARC / S/MIME ──┐          │
   │        │                            │          │          │
   │     depolar (repos) ── kasa (vault) ── kuyruk ─┘          │
   │        │                                                  │
   │     @fitfak/database  (gömülü | uzak mTLS | şifreli dosya) │
   └──────────────────────────────────────────────────────────┘
```

---

## İçindekiler

1. [Hızlı başlangıç](#hızlı-başlangıç)
2. [Mimari](#mimari)
3. [Düzeltilen hatalar](#düzeltilen-hatalar)
4. [Yapılandırma](#yapılandırma)
5. [Veritabanı bağlantısı](#veritabanı-bağlantısı)
6. [Anahtar kasası](#anahtar-kasası)
7. [Kimlik: Fitfak IdP](#kimlik-fitfak-idp)
8. [S/MIME sertifikaları](#smime-sertifikaları)
9. [SMTP](#smtp)
10. [HTTP API](#http-api)
11. [Gerçek zamanlılık ve bildirim](#gerçek-zamanlılık-ve-bildirim)
12. [Dağıtım (cloudflared)](#dağıtım-cloudflared)
13. [DNS kayıtları](#dns-kayıtları)
14. [İşletim](#i̇şletim)
15. [Testler](#testler)

---

## Hızlı başlangıç

```bash
# 1. Yan yana duran @fitfak paketlerini bağla (../ssl, ../database, ../grpc)
npm run link:deps

# 2. Ortamı hazırla
cp deploy/env.example .env && $EDITOR .env
set -a && . ./.env && set +a

# 3. Yapılandırmayı doğrula (hiçbir şey başlatmaz)
npm run check

# 4. Testler
npm test

# 5. Çalıştır
npm start
```

Geliştirme sırasında yalnızca arayüzle uğraşıyorsanız SMTP dinleyicilerini
açmaya gerek yok:

```bash
node bin/fitfak-mail.js --no-smtp --no-dns --no-certs
```

`bin/fitfak-mail.js` bayrakları: `--no-smtp`, `--no-http`, `--no-queue`,
`--no-certs`, `--no-dns`, `--check`, `--help`.

### Gereksinimler

| Bileşen | Sürüm / not |
| --- | --- |
| Node.js | ≥ 20 (yerleşik `node:` modülleri dışında bağımlılık yok) |
| `@fitfak/ssl` | isteğe bağlı; yoksa CSR/S/MIME kapanır, gerisi çalışır |
| `@fitfak/database` | isteğe bağlı; yoksa şifreli dosya sürücüsüne düşer |

İkisi de `peerDependenciesMeta.optional` işaretli: paket kurulu değilse sunucu
açılır, ilgili yetenek kapalı olduğunu kayda yazar. Bu bilinçli — arayüz
geliştirirken PKI yığınını kurmak zorunda kalmamak için.

---

## Mimari

Bağımlılık zinciri tek yönlü; her katman yalnızca kendinden öncekini tanır
(`src/app.js` bu sırayı kurar):

```
yapılandırma → veritabanı → depolar (+kasa) → imzalayıcı
   → sertifika yöneticisi → kuyruk → pipeline → SMTP + HTTP + gerçek zamanlı
```

| Dizin | Sorumluluk |
| --- | --- |
| `src/config.js` | Tüm ayarların tek okuma ve tek doğrulama noktası |
| `src/db/` | Sürücü seçimi, şema, depolar, blob deposu, anahtar kasası |
| `src/mail/` | DKIM, SPF, DMARC, MIME ayrıştırma/oluşturma, pipeline |
| `src/smtp/` | Oturum durum makinesi, dinleyiciler, teslimat, kuyruk |
| `src/certs/` | CSR üretimi, S/MIME CMS imzalama/doğrulama, sertifika yönetimi |
| `src/auth/` | IdP istemcisi, oturum yöneticisi, servis jetonu |
| `src/http/` | Yönlendirici, webmail API, yönetici API, durum API, site, push |
| `public/` | Webmail ve kişisel site istemcileri (yapı adımı yok) |

Katmanların tek başına kurulabilmesi kasıtlı: `test/helpers.js` tam olarak bu
zinciri kısmen kurup test ediyor.

### Verinin şekli

`src/db/schema.js` 18 koleksiyon tanımlar. Üç kural her yerde geçerli:

- **Posta adresleri düz indekse girmez.** Adresle arama gerektiğinde kör
  indeks (blind index) kullanılır; indeks anahtarının kendisi adresi sızdırmaz.
- **İlişkiler `mailboxRef` üzerinden kurulur**, adres üzerinden değil. Adres
  değişince ilişki kopmaz.
- **Gövdeler ve ekler `blobs` + `blob_chunks` içindedir**, ileti kaydında değil.
  Kayıt başına boyut sınırı, uzak (gRPC) sürücüde tek çerçevenin taşınabilir
  kalmasını sağlar (`limits.blobChunkBytes`, öntanımlı 256 KiB).

---

## Düzeltilen hatalar

Bu sürümde kapatılan, önceki `server.js` prototipinden gelen sorunlar:

**1. 465/587 üzerinden gönderilen postada DKIM imzası yoktu** *(bildirilen hata)*

Prototipte iki ayrı gönderim yolu vardı: panelin kendi `sendMail()`'i ve SMTP
istemcilerinin kullandığı `relayRawMail()`. İmzalama yalnızca birincisinde
yapılıyordu; 465 ya da 587'ye bağlanan bir posta istemcisinin gönderdiği ileti
hiç imzalanmadan çıkıyordu. Üstelik imzalayan yol da *yeniden kurulmuş* bir
başlık kümesini imzalıyordu — telin üstünden geçen baytları değil; başlık
sırası ya da katlanması değiştiğinde imza doğrulanmaz hâle geliyordu.

Şimdi tek bir gönderim kapısı var: `pipeline.handleSubmission()`. 25 dışındaki
her yol (465, 587, HTTP API, kuyruk, kampanya) buradan geçer ve imza
**gönderilecek baytların üstüne** eklenir (`src/mail/dkim.js:signMessage`).
`test/smtp-e2e.test.js` bunu üç port için ayrı ayrı doğruluyor.

**2. `sess.rcptTo` her RCPT'te üzerine yazılıyordu** — çok alıcılı bir iletide
yalnızca son alıcı teslim alıyordu. Artık alıcılar birikimli listede tutuluyor
ve `maxRecipients` ile sınırlanıyor.

**3. `setEncoding('utf8')` ikili ekleri bozuyordu.** DATA akışı artık ham
`Buffer` olarak okunuyor; nokta-açma (dot-unstuffing) da eksikti, eklendi.

**4. PROXY başlığına koşulsuz güveniliyordu.** Herhangi bir istemci
`PROXY TCP4 1.2.3.4 ...` yazarak IP tabanlı her kısıtlamayı (ban listesi, SPF)
atlatabilirdi. Artık yalnızca `smtp.trustedProxies` içindeki kaynaklardan
kabul ediliyor.

**5. Oturumlar bellekteydi ve JWT sırrı her açılışta yeniden üretiliyordu** —
yeniden başlatma bütün oturumları düşürüyordu. Oturumlar veritabanında.

**6. Canlı sırlar kaynak koddaydı** (Cloudflare API jetonu, OAuth istemci
sırrı, SMTP parolaları). Hepsi ortamdan geliyor; üretim modunda eksik bir sır
sessizce atlanmaz, açılışta hata verir.

**7. MIME ayrıştırması tek regex ile sınır bölüyordu** — iç içe `multipart`
yapıları ve `boundary` ön eki paylaşan sınırlar yanlış bölünüyordu. Yerine
derinlik ve parça sayısı sınırlı gerçek bir ayrıştırıcı kondu.

**8. Açılışta DNS otomatik yeniden yazılıyordu.** Elle yapılmış bilinçli bir
değişikliği (ikinci MX, geçiş dönemi SPF'i) geri alan bir davranış. Denetim
artık öntanımlı **salt okunur**; yazmak için `FITFAK_DNS_AUTO_APPLY=1` gerekir.

**9. Push bildirimleri bütün abonelere yayınlanıyordu.** Artık abonelik posta
kutusuna bağlı ve yalnızca ilgili kutunun aboneleri uyarılıyor.

---

## Yapılandırma

Öncelik sırası: **ortam değişkeni → yapılandırma dosyası → öntanımlı**.
Dosya yolu `FITFAK_MAIL_CONFIG` ile verilir (JSON). Üretimde eksik sır
açılışta hata verir; sessizce öntanımlıya düşülmez.

### Zorunlu (yalnızca `NODE_ENV=production`)

| Değişken | Açıklama |
| --- | --- |
| `FITFAK_MAIL_CLIENT_ID` | IdP istemci kimliği |
| `FITFAK_MAIL_CLIENT_SECRET` | IdP istemci sırrı |
| `FITFAK_MAIL_VAULT_SECRET` | Kasa kök sırrı (≥32 bayt; base64/hex önerilir) |
| `FITFAK_MAIL_DB_ROOT_SECRET` | Veritabanı kök sırrı (uzak sürücüde gerekmez) |
| `FITFAK_MAIL_PUBLIC_IP` | Giden IP — SPF kaydı buradan üretilir |

Uzak veritabanı kullanılıyorsa ayrıca `FITFAK_MAIL_DB_CA_PATH` **veya**
`FITFAK_MAIL_DB_CA_FINGERPRINT` zorunlu: sunucu doğrulaması olmadan mTLS'in
anlamı kalmaz.

Sır üretmek için:

```bash
openssl rand -base64 48        # FITFAK_MAIL_VAULT_SECRET
openssl rand -base64 48        # FITFAK_MAIL_DB_ROOT_SECRET
```

### Alan adları ve sunucu adı

| Değişken | Öntanımlı |
| --- | --- |
| `FITFAK_MAIL_DOMAIN` | `fitfak.net` |
| `FITFAK_MAIL_HOSTNAME` | `mail.fitfak.net` |
| `FITFAK_MAIL_DKIM_SELECTOR` | `mail` |
| `FITFAK_SITE_DOMAIN` | `aybars.net.tr` |

Öntanımlı olarak iki alan adı tanımlıdır: `fitfak.net` (alır ve gönderir) ve
`aybars.net.tr` (**yalnızca gönderir** — MX'i yok, DKIM'i var; kişisel site
bildirimleri buradan çıkar). Her alan adının kendi DKIM seçicisi ve kendi
anahtarı vardır: tek anahtarı paylaşmak, biri sızdığında ikisini birden
yenilemek zorunda bırakırdı.

Daha karmaşık bir küme gerekiyorsa `FITFAK_MAIL_CONFIG` dosyasında:

```json
{
  "mail": {
    "domains": [
      { "name": "fitfak.net",   "dkimSelector": "mail" },
      { "name": "aybars.net.tr","dkimSelector": "mail", "receive": false },
      { "name": "example.org",  "dkimSelector": "s2026", "dmarcRua": "raporlar@example.org" }
    ]
  }
}
```

### vhost'lar

| Değişken | Öntanımlı |
| --- | --- |
| `FITFAK_SITE_HOST` / `FITFAK_SITE_BIND` / `FITFAK_SITE_PORT` | `aybars.net.tr` / `127.0.1.1` / `80` |
| `FITFAK_WEBMAIL_HOST` / `FITFAK_WEBMAIL_BIND` / `FITFAK_WEBMAIL_PORT` | `mail.fitfak.net` / `127.0.1.2` / `80` |
| `FITFAK_SITE_ALIASES` | `www.aybars.net.tr` |
| `FITFAK_WEBMAIL_ALIASES` | `webmail.fitfak.net` |

Her isim **kendi loopback adresine** bağlanır. İkisini tek adrese koyup yalnızca
`Host` başlığıyla ayırmak da mümkündü, ama o zaman bir tünelin yanlış
yapılandırılması diğerinin trafiğini görebilir hâle gelirdi. Ayrı adres, ayrı
soket: yanlış tünel bağlanamaz bile. `config.validate()` iki vhost'un aynı
`bind:port` çiftine düşmesini açılışta hata sayar.

### SMTP

| Değişken | Öntanımlı | Not |
| --- | --- | --- |
| `FITFAK_SMTP_BIND` | `0.0.0.0` | Loopback'e bağlamak MX trafiğini imkânsız kılar |
| `FITFAK_SMTP_PORT_MX` / `_SUBMISSION` / `_SMTPS` | `25` / `587` / `465` | |
| `FITFAK_SMTP_OUTBOUND_IP` | — | Çok IP'li makinede **PTR kaydı olan** adres |
| `FITFAK_SMTP_MAX_MESSAGE_BYTES` | `41943040` (40 MiB) | |
| `FITFAK_SMTP_MAX_RCPT` | `100` | |
| `FITFAK_SMTP_MAX_CONN` / `_PER_IP` | `500` / `20` | |
| `FITFAK_SMTP_TRUSTED_PROXIES` | `127.0.0.1,::1` | PROXY protokolü yalnızca buradan |
| `FITFAK_SMTP_REQUIRE_TLS_FOR_AUTH` | `true` | |
| `FITFAK_SMTP_INBOUND_CHECKS` | `true` | SPF/DKIM/DMARC değerlendirmesi |
| `FITFAK_SMTP_ENFORCE_DMARC` | `true` | `p=reject` alanından gelen başarısız postayı reddet |

### Sınırlar (ekler dâhil)

| Değişken | Öntanımlı |
| --- | --- |
| `FITFAK_MAILBOX_QUOTA_BYTES` | 5 GiB |
| `FITFAK_MAX_ATTACHMENTS` | `25` |
| `FITFAK_MAX_ATTACHMENT_BYTES` | 25 MiB |
| `FITFAK_MAX_TOTAL_ATTACHMENT_BYTES` | 35 MiB |
| `FITFAK_MAX_INLINE_IMAGE_BYTES` | 8 MiB |
| `FITFAK_PREVIEW_MAX_IMAGE_BYTES` | 4 MiB |
| `FITFAK_MAX_BODY_BYTES` | 2 MiB |
| `FITFAK_MAX_MIME_PARTS` / `_DEPTH` | `200` / `20` |
| `FITFAK_ALLOWED_ATTACHMENT_TYPES` | PDF, Office, görsel, ses, video, `message/rfc822`, … |
| `FITFAK_BLOCKED_EXTENSIONS` | `.exe .scr .bat .cmd .msi .jar .vbs .js .ps1 .lnk .hta .iso .apk …` |

Ekler **hem MIME türüne hem uzantıya** göre süzülür ve içerik ayrıca sihirli
baytlarından tanınır. Yalnızca izinli tür listesine güvenmek yetmez: gönderen
`image/png` deyip `.exe` gönderebilir, tarayıcı da uzantıya göre davranabilir.
Beyan edilen tür ile dosya adı çelişiyorsa dosya güvenilmez sayılır.

### Kuyruk ve toplu gönderim

| Değişken | Öntanımlı | Not |
| --- | --- | --- |
| `FITFAK_QUEUE_WORKERS` | `4` | |
| `FITFAK_QUEUE_PER_DOMAIN` | `2` | Gmail'e 50 paralel bağlantı teslimatı hızlandırmaz, hız sınırına sokar |
| `FITFAK_QUEUE_MAX_ATTEMPTS` | `8` | |
| `FITFAK_QUEUE_BACKOFF_MS` | `1dk,5dk,15dk,1sa,2sa,4sa,8sa,16sa` | |
| `FITFAK_CAMPAIGN_RATE` | `10`/sn | Toplu gönderimde asıl risk teknik değil itibar kaybı |
| `FITFAK_CAMPAIGN_BATCH` | `500` | |
| `FITFAK_CAMPAIGN_MAX_RCPT` | `100000` | |
| `FITFAK_BOUNCE_MAILBOX` | `bounce@fitfak.net` | |
| `FITFAK_DSN_FROM` | `mailer-daemon@fitfak.net` | |

### HTTP

| Değişken | Öntanımlı |
| --- | --- |
| `FITFAK_HTTP_TRUSTED_PROXIES` | `127.0.0.1,::1,127.0.1.1,127.0.1.2` |
| `FITFAK_HTTP_MAX_BODY_BYTES` | 64 MiB |
| `FITFAK_HTTP_RATE_MAX` / `_SEND_MAX` | `240` / `30` (dakikada) |
| `FITFAK_ATT_TOKEN_TTL_MS` | 4 saat |
| `FITFAK_SESSION_COOKIE` | `fitfak_mail_sid` |
| `FITFAK_SECURE_COOKIES` | `true` |
| `FITFAK_HTTP_CACHE_STATIC` | üretimde `true` |

### Kayıt (log)

| Değişken | Öntanımlı |
| --- | --- |
| `LOG_LEVEL` | üretimde `info`, geliştirmede `debug` |
| `LOG_JSON` | üretimde `true` |
| `LOG_REDACT_ADDRESSES` | üretimde `true` |

Adres maskeleme üretimde açık: kayıt dosyası, veritabanının şifrelediği veriyi
düz metin sızdıran yer olmamalı.

---

## Veritabanı bağlantısı

`FITFAK_MAIL_DB_DRIVER` üç değer alır:

### `auto` (öntanımlı)

`@fitfak/database` kuruluysa onu, değilse şifreli dosya sürücüsünü kullanır.

### `fitfak` — gömülü ya da uzak

**Gömülü**: `FITFAK_MAIL_DB_ROOT_SECRET` ile veri `FITFAK_MAIL_DATA_DIR/db`
altında şifreli tutulur.

**Uzak (mTLS / gRPC)**: `FITFAK_MAIL_DB_TARGET` verilir. İlk açılışta kayıt
(enrolment) yapılır: `FITFAK_MAIL_DB_ENROLMENT_SECRET` ile EST-over-gRPC
üzerinden bir istemci sertifikası alınır ve `FITFAK_MAIL_DB_IDENTITY_DIR`
altına yazılır. Sonraki açılışlarda o kimlik kullanılır, kayıt sırrına gerek
kalmaz — kayıt sırrını ortamda tutmaya devam etmeyin.

```bash
FITFAK_MAIL_DB_DRIVER=fitfak
FITFAK_MAIL_DB_TARGET=db.fitfak.net:8443
FITFAK_MAIL_DB_SERVICE_NAME=mail-service
FITFAK_MAIL_DB_OWNER_ID=mail-service
FITFAK_MAIL_DB_ENROLMENT_SECRET=…     # yalnızca ilk açılış
FITFAK_MAIL_DB_CA_PATH=/etc/fitfak/db-ca.pem
FITFAK_MAIL_DB_IDENTITY_DIR=/var/lib/fitfak-mail/identity
```

Dikkat edilecek iki nokta:

- **Ekleme dönüşü `_id`.** `@fitfak/database` ekleme sonucunda `BigInt`
  döndürür, sorgular ise dizge bekler. Depolar bu dönüşümü tek yerde yapar
  (`src/db/repos/`); doğrudan sürücüye yazan kod eklerseniz aynısını yapın —
  `JSON.stringify` bir `BigInt` gördüğünde hata verir.
- **Kör indeks ile düz indeks aynı şey değil.** Adres alanları yalnızca kör
  indeksle aranır. Bir adresi düz indekse eklemek, şifrelemenin koruduğu şeyi
  indeks üstünden geri verir. Bu yüzden `sessions.idpEmail` indeksli değildir
  ve toplu iptal `scan()` ile yapılır (`revokeAllForEmail`).

### `file` — şifreli dosya sürücüsü

Bağımsız çalışma ve test için. Append-only çerçeve:

```
[op:1][flags:1][id:8BE][version:4BE][payloadLen:4BE][iv + tag + ct]
```

AAD sürümü bağlar, yani bir kaydın eski sürümü yenisinin yerine geçirilemez.
Tek süreç varsayar; birden fazla sunucu aynı dizine yazmamalı.

---

## Anahtar kasası

`src/db/vault.js`. Kasadaki her şey (S/MIME özel anahtarları, DKIM anahtarları,
VAPID push anahtarları, TLS malzemesi, servis yenileme jetonu) veritabanına
**`FITFAK_MAIL_VAULT_SECRET` ile sarılarak** yazılır. Veritabanı zaten şifreli;
bu ikinci katman, veritabanı oturumu ele geçse bile özel anahtarların düz metin
olmamasını sağlar.

Sürümler **asla üzerine yazılmaz**: `pending → active → retired`. Bir anahtarı
yenilemek eskisini silmez — dolaşımdaki imzaların doğrulanabilmesi için eski
sürüm `retired` olarak durur.

**Kasa sırrını döndürmek (rotasyon):** `rewrapAll()` bütün sırları yeni
anahtarla sarar, ama **yeni sırrı ortamda kalıcılaştırmak sizin işiniz.**
Yapmazsanız sonraki açılış `Unsupported state or unable to authenticate data`
ile düşer. Kasa bu durumu ayrıca tanır ve hangi kasa anahtarının beklendiğini
söyleyen bir hata verir:

```
[vault] bu sır başka bir kasa anahtarıyla sarılmış …
```

---

## Kimlik: Fitfak IdP

Kimlik doğrulama tamamen `session.fitfak.net` üzerinden yürür (Microsoft OAuth
kaldırıldı). Üç akış kullanılıyor:

| Akış | Nerede |
| --- | --- |
| Authorization code + PKCE | Webmail girişi (`/giris` → `/oauth/callback`) |
| Device code (RFC 8628) | `fitfak-mail-cert` CLI — sertifika alma |
| Token introspection (RFC 7662) + JWKS | Oturumun IdP'de hâlâ geçerli olduğunu doğrulamak |

Kapsamlar: `openid profile email mail`. **`email` kapsamı zorunlu** — posta
kutusu yetkilendirmesi doğrudan IdP'nin döndürdüğü adrese dayanıyor, o kapsam
olmadan hiçbir kutuya erişim verilemez.

Oturum çerezi uzun ömürlüdür ama `FITFAK_MAIL_REVALIDATE_MS` (öntanımlı 5 dk)
aralığıyla IdP'ye yeniden sorulur. Uzun ömürlü çerez + hiç kontrol etmemek,
IdP'de kapatılmış bir hesabın posta kutusunu okumaya devam etmesi demekti.
IdP'ye ulaşılamıyorsa oturum yerel süresiyle (`FITFAK_MAIL_SESSION_TTL_MS`,
12 saat) sınırlı olarak sürer — IdP kesintisi bütün kullanıcıları dışarı
atmaz, ama süresiz de yaşatmaz.

### Kimlik bağları (yerel olmayan adresler)

Yerel bir adresle giren kullanıcı kendi kutusuna erişir. Yerel **olmayan** bir
adresle giren (`aybarsyildirim.mail@gmail.com` gibi) bir bağ kurulmadıkça
hiçbir kutuya erişemez.

Bağı **yalnızca Fitfak IdP yöneticileri** kurabilir. Yönetici tanımı
`FITFAK_IDP_ADMIN_ROLES` (öntanımlı `admin,fitfak-admin`) ve
`FITFAK_IDP_ADMIN_SUBJECTS` ile yapılır.

```http
POST /api/v1/admin/identity-links
{
  "email": "aybarsyildirim.mail@gmail.com",
  "mailbox": "network@fitfak.net",
  "role": "sender",
  "reason": "saha ekibi geçici erişim"
}
```

`reason` zorunlu — kim, kime, neden erişim verdi sorusunun denetim kaydında
cevabı olsun diye. Bağ kaldırıldığında ilgili oturumlar da kapatılır; erişim
sonraki istekte değil, o anda biter. Yerel bir adres kimlik bağı olarak
eklenemez (kendi kutusuna zaten erişimi var; bağ, sahipliği bulanıklaştırırdı).

---

## S/MIME sertifikaları

Sertifikalar ana sertifika sağlayıcısından (`trust.fitfak.net`) alınır. Kendi
ASN.1/OID katmanımız **yok** — hepsi `@fitfak/ssl` üzerinden (`profiles.email`
profili S/MIME'a karşılık gelir).

İki yol var ve farkları önemli:

### Kullanıcı yolu — cihaz kodu (özel anahtar sunucuya hiç gelmez)

```bash
fitfak-mail-cert issue --address network@fitfak.net --out ./certs
```

Anahtar **kullanıcının makinesinde** üretilir ve orada kalır. Sunucuya yalnızca
CSR (açık anahtar + istek) gider, geri sertifika gelir. Sunucu bu anahtarla
imzalayamaz; imzalamayı kullanıcının posta istemcisi yapar. Posta istemcisine
eklemek için PKCS#12:

```bash
openssl pkcs12 -export -inkey certs/…/smime.key -in certs/…/smime.crt -out smime.p12
```

Kullanıcı kendi sertifikasını doğrulama için kaydettirmek isterse:

```bash
fitfak-mail-cert register --address network@fitfak.net --cert ./smime.crt
```

### Sunucu yolu — sistemdeki her kayıtlı adres için

Sunucunun kutular adına sertifika isteyebilmesi için bir kez yenileme jetonu
alınır ve kasaya yazılır:

```bash
FITFAK_MAIL_VAULT_SECRET=… fitfak-mail-cert bootstrap
```

Bundan sonra `FITFAK_TRUST_AUTO_ISSUE=1` (öntanımlı) ile sertifika yöneticisi
`FITFAK_TRUST_CHECK_MS` (6 saat) aralığıyla dolaşır: sertifikası olmayan her
kayıtlı adres için sertifika ister, ömrünün `FITFAK_TRUST_RENEW_RATIO` (0.66)
oranını geçmiş olanları yeniler. Durum:

```bash
fitfak-mail-cert status
# ya da
curl -H "Authorization: Bearer …" https://mail.fitfak.net/api/v1/admin/certificates
```

### İmzalı gönderim

Gönderim isteğine `smime=1` eklemek yeter. İleti detached CMS SignedData
(RFC 5652) ile imzalanır ve `multipart/signed` olarak sarılır (RFC 8551).
Sertifika yoksa istek sessizce imzasız gönderilmez — `409 NO_SMIME_CERT` döner.

İmzalanan içerik gönderilmeden önce kanonikleştirilir
(`src/certs/smime.js:canonicalizeSignedPart`): sınıra ait olan sondaki CRLF
imzaya girerse ileti bir aktarımdan geçtikten sonra geçersiz görünür. Üretilen
yapı `openssl cms -verify` ile doğrulanmıştır.

---

## SMTP

| Port | Mod | TLS | AUTH |
| --- | --- | --- | --- |
| 25 | MX (gelen) | STARTTLS (isteğe bağlı) | yok |
| 587 | Submission | STARTTLS (zorunlu) | PLAIN / LOGIN |
| 465 | SMTPS | örtük TLS | PLAIN / LOGIN |

**TLS malzemesi** önce kasadan, bulunamazsa `FITFAK_MAIL_CERT_DIR` altından
şu sırayla aranır: `privkey.pem`+`fullchain.pem`, `server.key`+`server.crt`,
`<hostname>.key`+`<hostname>.crt`. Hiçbiri yoksa **465 hiç açılmaz ve 587
STARTTLS duyurmaz** — sessizce düz metin kimlik doğrulamaya izin vermek,
parolaları ağa yazmak olurdu.

Gelen postada (25) sırasıyla SPF (RFC 7208; 10 DNS / 2 void arama sınırı ve
makrolar dâhil), DKIM (RFC 6376) ve DMARC (RFC 7489; hizalama, organizasyon
alan adı, `sp=`, `pct=`) değerlendirilir; sonuç `Authentication-Results`
başlığına yazılır. `FITFAK_SMTP_ENFORCE_DMARC` açıkken `p=reject` yayımlamış
bir alandan gelen başarısız posta SMTP düzeyinde reddedilir — sessizce
karantinaya alıp kullanıcıyı şaşırtmaktansa gönderene açık hata döndürmek
daha dürüst.

Giden postada MX araması, çoklu MX denemesi, fırsatçı TLS ve
`FITFAK_QUEUE_PER_DOMAIN` ile alan adı başına eşzamanlılık sınırı vardır.
Kalıcı başarısızlıklarda RFC 3464 uyumlu DSN üretilir.

Kutuya özel SMTP kimlik bilgileri (posta istemcisi için) webmail'den üretilir:

```http
POST /api/v1/mailboxes/:mailbox/smtp-credentials
```

Parola yalnızca üretildiği yanıtta bir kez görünür; saklanan yalnızca özetidir.

---

## HTTP API

Tüm uçlar `mail.fitfak.net` vhost'unda. Oturum çerezle; durum değiştiren her
istek `X-CSRF-Token` başlığı ister (`/api/v1/me` içindeki `csrfToken`).
Beklenmeyen `Host` başlığı reddedilir.

### Kimlik

| | |
| --- | --- |
| `GET /giris?donus=…&eposta=…` | IdP'ye yönlendirir |
| `GET /oauth/callback` | Kod değişimi (`state` tek kullanımlık) |
| `GET,POST /cikis?hepsi=1` | Çıkış (`hepsi=1` IdP oturumlarını da iptal eder) |
| `GET /api/v1/sessions` · `DELETE /api/v1/sessions/:ref` | Etkin oturumlar |

### Posta kutusu

| | |
| --- | --- |
| `GET /api/v1/me` | Kutular, roller, kotalar, S/MIME durumu, sınırlar, CSRF jetonu |
| `GET /api/v1/mailboxes/:mailbox/messages` | `folder, limit, cursor, unread, flagged, q, attachments, thread` |
| `GET /api/v1/mailboxes/:mailbox/counts` | Klasör sayaçları |
| `GET /api/v1/mailboxes/:mailbox/since/:seq` | Kaçırılan iletiler (sıra numarasıyla) |
| `GET /api/v1/messages/:ref` | İleti (`markRead=0` ile okundu işaretlemeden) |
| `GET /api/v1/messages/:ref/raw` | Ham RFC 5322 kaynağı |
| `GET /api/v1/messages/:ref/attachments/:attRef?t=…` | Ek indirme |
| `POST /api/v1/messages/:ref/flags` · `/move` · `DELETE …` | Bayrak, taşıma, silme |
| `POST /api/v1/mailboxes/:mailbox/read-all` | Tümünü okundu işaretle |

Ek bağlantıları **oturuma bağlı** kısa ömürlü jeton ister (`?t=`): jeton kasa
sırrı ile oturum referansından türetilir, başka bir oturumda geçersizdir.
Bağlantıyı kopyalayıp paylaşmak eki paylaşmaz. Güvenli olmayan türler her
zaman `Content-Disposition: attachment` ile döner.

### Gönderme ve iletme

```bash
curl -X POST https://mail.fitfak.net/api/v1/mailboxes/network@fitfak.net/send \
  -H 'Content-Type: application/json' \
  -H "X-CSRF-Token: $CSRF" -b "$COOKIE" \
  -d '{
        "to": "alici@example.com",
        "subject": "Merhaba",
        "text": "Düz metin gövde",
        "html": "<p>HTML gövde</p>",
        "smime": true
      }'
```

`multipart/form-data` da kabul edilir (ek yüklemek için). İletme:

```http
POST /api/v1/messages/:ref/forward   { "to": "…", "comment": "…", "smime": true }
```

Hata kodları: `403 SENDER_NOT_ALLOWED`, `409 NO_SMIME_CERT`,
`413 ATTACHMENT_*` / `TOO_MANY_ATTACHMENTS`, `429` (hız sınırı).

### Toplu gönderim

| | |
| --- | --- |
| `POST /api/v1/mailboxes/:mailbox/campaigns` | Kampanya oluştur |
| `GET /api/v1/campaigns/:campaignId` | İlerleme |
| `POST /api/v1/campaigns/:campaignId/pause` | Duraklat |
| `GET /api/v1/mailboxes/:mailbox/outbox` | Giden kuyruğu |

### Durum API

| | |
| --- | --- |
| `GET /healthz` | Kimlik doğrulamasız, sır içermez (yük dengeleyici / izleme) |
| `GET /api/v1/status` | Kuyruk, sertifika, DNS, alan adları, kutular — korumalı |
| `GET /api/v1/status/queue?status=…` | Kuyruk ayrıntısı |
| `GET /api/v1/status/dns?refresh=1` | DNS denetim sonucu |
| `POST /api/v1/status/dns/apply` | Eksik kayıtları yaz (yönetici) |
| `GET /api/v1/status/audit?action=&actor=&limit=` | Denetim kaydı |

### Yönetici

| | |
| --- | --- |
| `GET,POST /api/v1/admin/mailboxes` · `POST …/:address/status` | Kutu yönetimi |
| `GET,POST /api/v1/admin/identity-links` · `DELETE …/:email` | Kimlik bağları |
| `POST,GET /api/v1/admin/grants` · `DELETE …/:mailbox/:sub` | Kutu erişimleri |
| `GET /api/v1/admin/certificates` · `POST …/sweep` · `POST …/revoke` | Sertifikalar |
| `POST,GET /api/v1/admin/api-tokens` · `DELETE …/:ref` | API jetonları |

### Kişisel site (`aybars.net.tr`)

| | |
| --- | --- |
| `GET /` · `GET /bildirimler` | Site ve bildirim paneli (panel oturum ister) |
| `GET /api/v1/site/visits` | Ziyaret kayıtları |

Instagram'dan gelen ziyaretler kaydedilir ve `FITFAK_SITE_NOTIFY_MAILBOX`
kutusuna bildirim düşer; diğer yönlendiriciler kaydedilmez. Son
`FITFAK_SITE_VISIT_RETENTION` (500) kayıt tutulur.

---

## Gerçek zamanlılık ve bildirim

**SSE** (`GET /api/v1/events`) ve **WebSocket** (RFC 6455 çerçeveleme, aynı
yol üzerinden yükseltme) desteklenir. Her posta kutusunun kendi sıra numarası
vardır; istemci bağlantısı koptuğunda

```
GET /api/v1/mailboxes/:mailbox/since/:seq
```

ile kaçırdığı iletileri alır. Sıra numarası olmadan yeniden bağlanma "bağlantı
koptuğu sırada gelen postayı hiç görmemek" demekti.

**Web Push** RFC 8291 (aes128gcm) + RFC 8292 (VAPID ES256, ieee-p1363). VAPID
anahtar çifti kasada durur ve ilk açılışta üretilir.

| | |
| --- | --- |
| `GET /api/v1/push/public-key` | VAPID açık anahtarı |
| `POST /api/v1/push/subscribe` · `/unsubscribe` · `/test` | Abonelik |

Abonelikler posta kutusuna bağlıdır; bildirim yalnızca ilgili kutunun
abonelerine gider. `FITFAK_PUSH_MAX_FAILURES` (5) kez başarısız olan abonelik
düşürülür.

---

## Dağıtım (cloudflared)

### 1. Loopback adreslerini aç

`127.0.1.1` çoğu dağıtımda hazır, `127.0.1.2` genelde değil:

```bash
sudo ip addr add 127.0.1.2/8 dev lo
```

Kalıcı hâli için `deploy/systemd/fitfak-mail-loopback.service`.

### 2. Tünel

```bash
cloudflared tunnel login
cloudflared tunnel create fitfak-mail
cloudflared tunnel route dns fitfak-mail aybars.net.tr
cloudflared tunnel route dns fitfak-mail www.aybars.net.tr
cloudflared tunnel route dns fitfak-mail mail.fitfak.net
cloudflared tunnel route dns fitfak-mail webmail.fitfak.net
```

`deploy/cloudflared/config.yml` her ismi kendi loopback adresine yollar:

```yaml
ingress:
  - hostname: aybars.net.tr
    service: http://127.0.1.1:80
  - hostname: www.aybars.net.tr
    service: http://127.0.1.1:80
  - hostname: mail.fitfak.net
    service: http://127.0.1.2:80
  - hostname: webmail.fitfak.net
    service: http://127.0.1.2:80
  - service: http_status:404
```

**SMTP cloudflared'den geçmez.** 25/465/587 doğrudan sunucunun genel IP'sine
bağlanır; tünel yalnızca HTTP içindir. Bu yüzden `FITFAK_MAIL_PUBLIC_IP` gerçek
giden IP olmalı — SPF kaydı ve PTR bunun üzerine kurulu.

TLS'i cloudflared sonlandırdığı için HTTP tarafı düz metin dinler ve çerezler
`Secure` işaretlenir (`FITFAK_SECURE_COOKIES=1`). `FITFAK_HTTP_TRUSTED_PROXIES`
listesindeki adreslerden gelen `CF-Connecting-IP` / `X-Forwarded-For`
başlıklarına güvenilir; başka kaynaktan gelen aynı başlık yok sayılır.

### 3. Servis

```bash
sudo cp deploy/systemd/fitfak-mail.service /etc/systemd/system/
sudo cp deploy/env.example /etc/fitfak/mail.env    # düzenleyin, chmod 600
sudo systemctl daemon-reload
sudo systemctl enable --now fitfak-mail-loopback fitfak-mail
```

25/465/587'ye root olmadan bağlanmak için servis dosyası
`AmbientCapabilities=CAP_NET_BIND_SERVICE` kullanır; sunucuyu root olarak
çalıştırmak gerekmez.

---

## DNS kayıtları

`GET /api/v1/status/dns` beklenen ile yayımlanmış kayıtları karşılaştırır.
Alan adı başına beklenenler:

| Tür | Ad | Değer |
| --- | --- | --- |
| MX | `fitfak.net` | `10 mail.fitfak.net` (yalnızca alan alan adları) |
| TXT | `fitfak.net` | `v=spf1 ip4:<genel-ip> mx -all` |
| TXT | `mail._domainkey.fitfak.net` | `v=DKIM1; k=rsa; p=…` |
| TXT | `_dmarc.fitfak.net` | `v=DMARC1; p=quarantine; adkim=s; aspf=s; fo=1; rua=…; ri=86400` |
| TXT | `_smtp._tls.fitfak.net` | `v=TLSRPTv1; rua=mailto:…` (isteğe bağlı) |

`aybars.net.tr` posta almadığı için **MX yayımlanmaz**; SPF'i `mx` içermez ve
`-all` ile biter — o alan adından yalnızca bu sunucu gönderir.

DKIM açık anahtarını almak için:

```bash
curl -H "Authorization: Bearer …" https://mail.fitfak.net/api/v1/status | \
  python3 -c 'import json,sys; [print(d["dkimRecord"]) for d in json.load(sys.stdin)["domains"]]'
```

Denetim **salt okunur** çalışır. Yazması için `FITFAK_DNS_AUTO_APPLY=1` ve
`CF_API_TOKEN` + `CF_ZONE_ID` gerekir. Açmadan önce şunu bilin: otomatik
uygulama, elle konmuş bilinçli bir kaydı (ikinci MX, geçiş dönemi SPF'i) geri
alır. Öneri: kapalı bırakıp `POST /api/v1/status/dns/apply` ile elle tetikleyin.

`p=quarantine` ile başlayıp raporlar temizlendikten sonra `p=reject`'e geçmek
doğru sıra; ters sırası, gözden kaçan bir gönderim yolunun postasını sessizce
düşürür.

---

## İşletim

**Yeni posta kutusu**

```http
POST /api/v1/admin/mailboxes   { "address": "ekip@fitfak.net", "displayName": "Ekip" }
```

`postmaster@` ve DMARC rapor kutuları açılışta kendiliğinden oluşturulur —
RFC gereği çalışır olmalılar ve raporların gideceği bir yer yoksa rapor isteyen
bir kayıt yayımlamak anlamsız.

**Yedekleme.** Yedeklenmesi gerekenler: veritabanı dizini (ya da uzak
veritabanı), `FITFAK_MAIL_DB_IDENTITY_DIR` (mTLS kimliği) ve **`.env`**.
Kasa sırrı olmadan veritabanı yedeği tek başına işe yaramaz: içindeki özel
anahtarlar açılamaz. İkisini aynı yerde saklamak da iki katmanı tek katmana
indirger.

**Anahtar rotasyonu.** DKIM için: yeni seçici yayımla → doğrulanmasını bekle →
imzalamayı yeni seçiciye al → eskiyi bir süre yayımda tut, sonra kaldır. Kasa
sırrı için: `rewrapAll()` sonrası yeni sırrı ortamda kalıcılaştırın.

**Kayıtlar.** `LOG_JSON=1` ile satır başına bir JSON nesnesi. Adresler
maskelidir; hata ayıklarken `LOG_REDACT_ADDRESSES=0` yapabilirsiniz, ama üretim
kayıtlarında açık bırakmayın.

---

## Testler

```bash
npm test                 # altı paket, 141 denetim
node test/run-all.js crypto storage      # seçili paketler
node test/crypto.test.js                 # tek paket, ayrıntılı çıktı
```

| Paket | Kapsam | Denetim |
| --- | --- | --- |
| `crypto` | DKIM imzala/doğrula, SPF, DMARC, S/MIME CMS | 36 |
| `mime` | MIME oluşturma/ayrıştırma, ek politikası, kodlamalar | 24 |
| `storage` | Veritabanı sürücüsü, depolar, kasa, kuyruk | 31 |
| `smtp-e2e` | 25/465/587 uçtan uca, DKIM'in üç yolda da uygulanması | 13 |
| `auth-identity` | IdP oturumu, kimlik bağları, yönetici kısıtı | 12 |
| `http-api` | HTTP API, CSRF, ek jetonları, gerçek zamanlı, site | 25 |

Her paket **ayrı bir süreçte** çalışır: testler ortam değişkenlerini ve modül
önbelleğini değiştiriyor (yapılandırma açılışta okunuyor), aynı süreçte
çalıştırmak birinin ayarını diğerine sızdırır ve hata ilgisiz bir dosyada
görünür.

Testler ağa çıkmaz: DNS, IdP ve sertifika sağlayıcısı yerel sahtelerle
karşılanır, veritabanı geçici dizinde şifreli dosya sürücüsüyle kurulur.
