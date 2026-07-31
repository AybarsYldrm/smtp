'use strict';

// Posta sunucusunun şema kaydı. @fitfak/database'in `applySchemaRegistry`
// biçimiyle aynı: alan NUMARASI kimliktir, ad yalnızca şemada yaşar.
//
// İki kural bütün tabloları biçimlendirdi:
//
//   1. Adresler ASLA düz dizinde tutulmaz. Düz dizin sunucuya değeri
//      öğretir ve sıralanabilir kılar; "hangi adresler var" sorusunun
//      cevabı, veritabanı kopyasını ele geçiren için hazır bir adres
//      listesi olurdu. Adres aramaları kör dizinden (eşitlik, değeri
//      zaten bilerek) yapılır; ilişkilendirme ise `mailboxRef` üzerinden,
//      yani posta kutusu kaydının kimliğiyle. Kimlik, adresin kendisi
//      gibi anlam taşımaz.
//   2. Gövde ve ek baytları kayıt İÇİNDE tutulmaz. Uzak (gRPC) sürücüde
//      tek kayıt tek çerçeveye sığmak zorunda; 20 MB'lık bir ek bunu
//      imkânsız kılar. Bu yüzden `blobs` + `blob_chunks` var.
//
// Yeni alan eklemek serbesttir (numara artar). Alan SİLMEK ya da TÜR
// DEĞİŞTİRMEK motor tarafından reddedilir; bir numara bir kez kullanıldıysa
// sonsuza dek o anlamı taşır.

const DAY = 86_400_000;
const HOUR = 3_600_000;
const MINUTE = 60_000;

module.exports = {
  /* ── posta kutuları ──────────────────────────────────────── */
  mailboxes: {
    fields: [
      { no: 2, name: 'address', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'localPart', type: 'string' },
      { no: 4, name: 'domain', type: 'string', index: true },
      { no: 5, name: 'displayName', type: 'string' },
      // user | alias | system | list | catchall
      { no: 6, name: 'kind', type: 'string', index: true },
      { no: 7, name: 'ownerSub', type: 'string', index: true },
      { no: 8, name: 'ownerEmail', type: 'string' },
      { no: 9, name: 'status', type: 'string', index: true },
      { no: 10, name: 'quotaBytes', type: 'int64' },
      { no: 11, name: 'usedBytes', type: 'int64' },
      { no: 12, name: 'messageCount', type: 'int64' },
      { no: 13, name: 'unreadCount', type: 'int64' },
      // JSON dizi: yerel kopya tutulsun mu, nereye yönlendirilsin.
      { no: 14, name: 'forwardToJson', type: 'string' },
      { no: 15, name: 'keepLocalCopy', type: 'bool' },
      { no: 16, name: 'autoReplyJson', type: 'string' },
      { no: 17, name: 'createdAt', type: 'uint64' },
      { no: 18, name: 'updatedAt', type: 'uint64' },
      { no: 19, name: 'lastDeliveryAt', type: 'uint64' },
      { no: 20, name: 'notifyPrefsJson', type: 'string' },
      // Basit süzgeç kuralları (gönderene/konuya göre klasörleme, çöp).
      { no: 21, name: 'filterRulesJson', type: 'string' },
      // Posta kutusunun kendi ileti dizisi sayacı: gerçek zamanlı istemci
      // kaldığı yerden devam edebilsin.
      { no: 22, name: 'seqCounter', type: 'uint64' },
      { no: 23, name: 'aliasOfRef', type: 'string', index: true },
      { no: 24, name: 'smimeEnabled', type: 'bool' },
      { no: 25, name: 'sendLimitPerHour', type: 'int32' },
    ],
  },

  /* ── posta kutusu yetkileri ──────────────────────────────── */
  // Kimin hangi kutuya erişebileceği. Sertifika ya da parola değil, IdP
  // öznesi (sub) taşınır: kullanıcı parolasını değiştirdiğinde yetkilerinin
  // yeniden verilmesi gerekmez.
  mailbox_grants: {
    fields: [
      // `${mailboxRef}|${idpSub}` — tek anahtarla arama. İki alanı ayrı
      // sorgulayıp kesişim almak her istek için iki tur demek olurdu.
      { no: 2, name: 'grantKey', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'mailboxRef', type: 'string', index: true },
      { no: 4, name: 'idpSub', type: 'string', index: true },
      { no: 5, name: 'idpEmail', type: 'string' },
      // owner | delegate | reader | sender
      { no: 6, name: 'role', type: 'string' },
      { no: 7, name: 'grantedBySub', type: 'string' },
      { no: 8, name: 'grantedAt', type: 'uint64' },
      { no: 9, name: 'revokedAt', type: 'uint64' },
      { no: 10, name: 'status', type: 'string', index: true },
      { no: 11, name: 'note', type: 'string' },
    ],
  },

  /* ── harici kimlik bağları ───────────────────────────────── */
  // "aybarsyildirim.mail@gmail.com ile giren kişi network@fitfak.net
  // kutusunu kullanabilir" kaydı. YALNIZCA IdP yöneticisi oluşturur;
  // oluşturan özne ve gerekçe kayda yazılır, çünkü bu bağ bir kutunun
  // tamamını başka birine açar ve sonradan "bunu kim yaptı" sorusu
  // mutlaka sorulur.
  identity_links: {
    fields: [
      { no: 2, name: 'externalEmail', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'mailboxRef', type: 'string', index: true },
      { no: 4, name: 'idpSub', type: 'string', index: true },
      { no: 5, name: 'status', type: 'string', index: true },
      { no: 6, name: 'createdBySub', type: 'string' },
      { no: 7, name: 'createdByEmail', type: 'string' },
      { no: 8, name: 'createdAt', type: 'uint64' },
      { no: 9, name: 'revokedAt', type: 'uint64' },
      { no: 10, name: 'revokedBySub', type: 'string' },
      { no: 11, name: 'reason', type: 'string' },
      // Bağlı adres kutunun adına GÖNDEREBİLİR mi? Okuma ile gönderme ayrı
      // yetkiler: gönderme, alan adının itibarını harcar.
      { no: 12, name: 'allowSendAs', type: 'bool' },
      { no: 13, name: 'expiresAt', type: 'uint64' },
      { no: 14, name: 'mailboxAddress', type: 'string' },
    ],
  },

  /* ── iletiler ────────────────────────────────────────────── */
  messages: {
    fields: [
      { no: 2, name: 'mailboxRef', type: 'string', index: true, required: true },
      // inbox | sent | drafts | archive | spam | trash | outbox
      { no: 3, name: 'folder', type: 'string', index: true },
      { no: 4, name: 'messageIdHeader', type: 'string', blindIndex: true },
      { no: 5, name: 'threadKey', type: 'string', index: true },
      { no: 6, name: 'subject', type: 'string' },
      { no: 7, name: 'fromAddress', type: 'string' },
      { no: 8, name: 'fromName', type: 'string' },
      { no: 9, name: 'toJson', type: 'string' },
      { no: 10, name: 'ccJson', type: 'string' },
      { no: 11, name: 'replyTo', type: 'string' },
      { no: 12, name: 'dateHeader', type: 'string' },
      // Gün kovası: "son bir hafta" sorgusu için yeterli, tam zaman damgasını
      // sunucuya öğretmeden.
      { no: 13, name: 'receivedAt', type: 'uint64', rangeBucket: { width: DAY } },
      { no: 14, name: 'sizeBytes', type: 'int64' },
      { no: 15, name: 'seen', type: 'bool' },
      { no: 16, name: 'flagged', type: 'bool' },
      { no: 17, name: 'answered', type: 'bool' },
      { no: 18, name: 'draft', type: 'bool' },
      { no: 19, name: 'hasAttachments', type: 'bool' },
      { no: 20, name: 'attachmentCount', type: 'int32' },
      { no: 21, name: 'previewText', type: 'string' },
      // Küçük gövdeler kayıt içinde (tek okumada gelir), büyük olanlar blob'ta.
      { no: 22, name: 'bodyTextInline', type: 'string' },
      { no: 23, name: 'bodyHtmlInline', type: 'string' },
      { no: 24, name: 'bodyTextBlobId', type: 'string' },
      { no: 25, name: 'bodyHtmlBlobId', type: 'string' },
      { no: 26, name: 'rawBlobId', type: 'string' },
      { no: 27, name: 'authResultsJson', type: 'string' },
      { no: 28, name: 'spamScore', type: 'int32' },
      { no: 29, name: 'envelopeFrom', type: 'string' },
      { no: 30, name: 'envelopeTo', type: 'string' },
      { no: 31, name: 'remoteIp', type: 'string' },
      // none | signed-valid | signed-invalid | signed-untrusted | encrypted
      { no: 32, name: 'smimeStatus', type: 'string', index: true },
      { no: 33, name: 'smimeSignerJson', type: 'string' },
      { no: 34, name: 'deletedAt', type: 'uint64' },
      { no: 35, name: 'labelsJson', type: 'string' },
      { no: 36, name: 'inReplyTo', type: 'string' },
      { no: 37, name: 'referencesJson', type: 'string' },
      { no: 38, name: 'listId', type: 'string', index: true },
      // Kutu içi tekdüze artan sıra. Gerçek zamanlı istemci "seq > N" ile
      // kaçırdığını ister; zaman damgasıyla yapmak, aynı milisaniyede gelen
      // iki iletiden birini kaybettirir.
      { no: 39, name: 'seq', type: 'uint64', rangeBucket: { width: 1000 } },
      { no: 40, name: 'updatedAt', type: 'uint64' },
      { no: 41, name: 'headersJson', type: 'string' },
      { no: 42, name: 'campaignId', type: 'string', index: true },
      { no: 43, name: 'mailboxAddress', type: 'string' },
      { no: 44, name: 'partsJson', type: 'string' },
      { no: 45, name: 'snoozedUntil', type: 'uint64' },
      { no: 46, name: 'bodyTruncated', type: 'bool' },
      { no: 47, name: 'dsnJson', type: 'string' },
    ],
  },

  /* ── ekler ───────────────────────────────────────────────── */
  attachments: {
    fields: [
      { no: 2, name: 'messageRef', type: 'string', index: true, required: true },
      { no: 3, name: 'mailboxRef', type: 'string', index: true },
      { no: 4, name: 'partId', type: 'string' },
      // Dosya adı kör dizinde: "bu ada sahip ek var mı" cevaplanabilir,
      // "hangi dosyalar var" cevaplanamaz.
      { no: 5, name: 'fileName', type: 'string', blindIndex: true },
      { no: 6, name: 'contentType', type: 'string', index: true },
      { no: 7, name: 'contentId', type: 'string' },
      { no: 8, name: 'disposition', type: 'string' },
      { no: 9, name: 'sizeBytes', type: 'int64' },
      { no: 10, name: 'sha256Hex', type: 'string', index: true },
      { no: 11, name: 'blobId', type: 'string', index: true },
      { no: 12, name: 'createdAt', type: 'uint64' },
      // accepted | rejected_type | rejected_size | rejected_extension |
      // rejected_count | truncated
      { no: 13, name: 'scanStatus', type: 'string', index: true },
      { no: 14, name: 'rejectedReason', type: 'string' },
      { no: 15, name: 'isInline', type: 'bool' },
      { no: 16, name: 'width', type: 'int32' },
      { no: 17, name: 'height', type: 'int32' },
      { no: 18, name: 'declaredType', type: 'string' },
      { no: 19, name: 'sniffedType', type: 'string' },
    ],
  },

  /* ── ikili veri: üstbilgi + parçalar ─────────────────────── */
  blobs: {
    fields: [
      { no: 2, name: 'blobId', type: 'string', blindIndex: true, required: true },
      // raw | body | attachment | outbound | template
      { no: 3, name: 'kind', type: 'string', index: true },
      { no: 4, name: 'ownerRef', type: 'string', index: true },
      { no: 5, name: 'totalBytes', type: 'int64' },
      { no: 6, name: 'chunkCount', type: 'int32' },
      { no: 7, name: 'sha256Hex', type: 'string', index: true },
      { no: 8, name: 'contentType', type: 'string' },
      { no: 9, name: 'createdAt', type: 'uint64' },
      { no: 10, name: 'expiresAt', type: 'uint64', rangeBucket: { width: HOUR } },
      // Aynı ek iki alıcıya gittiğinde tek kopya tutulur; sayaç sıfırlanınca
      // parçalar silinir.
      { no: 11, name: 'refCount', type: 'int32' },
      { no: 12, name: 'compression', type: 'string' },
    ],
  },

  blob_chunks: {
    fields: [
      { no: 2, name: 'blobId', type: 'string', index: true, required: true },
      { no: 3, name: 'seq', type: 'int32' },
      { no: 4, name: 'bytes', type: 'bytes' },
      { no: 5, name: 'createdAt', type: 'uint64' },
    ],
  },

  /* ── giden kuyruğu ───────────────────────────────────────── */
  outbound_queue: {
    fields: [
      { no: 2, name: 'queueId', type: 'string', blindIndex: true, required: true },
      // queued | sending | sent | deferred | failed | cancelled
      { no: 3, name: 'status', type: 'string', index: true },
      // Dakika kovası: kuyruk yoklaması "şu ana kadar zamanı gelenler"i
      // sorar, bu çözünürlük yeter.
      { no: 4, name: 'nextAttemptAt', type: 'uint64', rangeBucket: { width: MINUTE } },
      { no: 5, name: 'attempts', type: 'int32' },
      { no: 6, name: 'envelopeFrom', type: 'string' },
      { no: 7, name: 'rcptTo', type: 'string', blindIndex: true },
      { no: 8, name: 'rcptDomain', type: 'string', index: true },
      { no: 9, name: 'rawBlobId', type: 'string' },
      { no: 10, name: 'campaignId', type: 'string', index: true },
      { no: 11, name: 'mailboxRef', type: 'string', index: true },
      { no: 12, name: 'createdAt', type: 'uint64' },
      { no: 13, name: 'updatedAt', type: 'uint64' },
      { no: 14, name: 'lastError', type: 'string' },
      { no: 15, name: 'lastSmtpCode', type: 'int32' },
      { no: 16, name: 'sentAt', type: 'uint64' },
      { no: 17, name: 'messageIdHeader', type: 'string' },
      { no: 18, name: 'dsnRequested', type: 'bool' },
      { no: 19, name: 'priority', type: 'int32' },
      // Birden fazla sunucu aynı kuyruğu işlerse aynı iletiyi iki kez
      // göndermesin: kim aldı, ne zamana kadar.
      { no: 20, name: 'lockedBy', type: 'string' },
      { no: 21, name: 'lockedUntil', type: 'uint64' },
      { no: 22, name: 'sizeBytes', type: 'int64' },
      { no: 23, name: 'subject', type: 'string' },
      { no: 24, name: 'mxUsed', type: 'string' },
      { no: 25, name: 'tlsUsed', type: 'bool' },
      { no: 26, name: 'dkimSigned', type: 'bool' },
      { no: 27, name: 'smimeSigned', type: 'bool' },
      { no: 28, name: 'sourceMessageRef', type: 'string', index: true },
      { no: 29, name: 'deliveryLogJson', type: 'string' },
    ],
  },

  /* ── toplu gönderim kampanyaları ─────────────────────────── */
  campaigns: {
    fields: [
      { no: 2, name: 'campaignId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'name', type: 'string' },
      { no: 4, name: 'ownerSub', type: 'string', index: true },
      { no: 5, name: 'mailboxRef', type: 'string', index: true },
      // draft | running | paused | completed | cancelled
      { no: 6, name: 'status', type: 'string', index: true },
      { no: 7, name: 'totalRecipients', type: 'int64' },
      { no: 8, name: 'queuedCount', type: 'int64' },
      { no: 9, name: 'sentCount', type: 'int64' },
      { no: 10, name: 'failedCount', type: 'int64' },
      { no: 11, name: 'createdAt', type: 'uint64' },
      { no: 12, name: 'startedAt', type: 'uint64' },
      { no: 13, name: 'finishedAt', type: 'uint64' },
      { no: 14, name: 'subject', type: 'string' },
      { no: 15, name: 'templateBlobId', type: 'string' },
      { no: 16, name: 'ratePerSecond', type: 'int32' },
      { no: 17, name: 'metaJson', type: 'string' },
      { no: 18, name: 'smimeSign', type: 'bool' },
      { no: 19, name: 'lastError', type: 'string' },
    ],
  },

  /* ── oturumlar ───────────────────────────────────────────── */
  // Oturumlar bellekte DEĞİL veritabanında: süreç yeniden başladığında
  // herkesi çıkışa zorlamak (önceki davranış) ve iki örnek arasında oturum
  // paylaşılamaması ikisi de kabul edilemez.
  sessions: {
    fields: [
      { no: 2, name: 'sidHash', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'idpSub', type: 'string', index: true },
      { no: 4, name: 'idpEmail', type: 'string' },
      { no: 5, name: 'mailboxesJson', type: 'string' },
      { no: 6, name: 'scope', type: 'string' },
      { no: 7, name: 'isAdmin', type: 'bool' },
      { no: 8, name: 'createdAt', type: 'uint64' },
      { no: 9, name: 'lastSeenAt', type: 'uint64' },
      { no: 10, name: 'expiresAt', type: 'uint64', rangeBucket: { width: HOUR } },
      { no: 11, name: 'revalidatedAt', type: 'uint64' },
      { no: 12, name: 'ip', type: 'string' },
      { no: 13, name: 'userAgent', type: 'string' },
      { no: 14, name: 'revoked', type: 'bool' },
      { no: 15, name: 'revokedReason', type: 'string' },
      // IdP jetonları kasada; burada yalnızca göndergesi durur.
      { no: 16, name: 'accessTokenSecretRef', type: 'string' },
      { no: 17, name: 'refreshTokenSecretRef', type: 'string' },
      { no: 18, name: 'csrfToken', type: 'string' },
      { no: 19, name: 'idpSessionId', type: 'string', index: true },
      { no: 20, name: 'deviceId', type: 'string', index: true },
    ],
  },

  /* ── programatik erişim ──────────────────────────────────── */
  api_tokens: {
    fields: [
      { no: 2, name: 'tokenHash', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'label', type: 'string' },
      { no: 4, name: 'ownerSub', type: 'string', index: true },
      { no: 5, name: 'mailboxRef', type: 'string', index: true },
      { no: 6, name: 'scopesJson', type: 'string' },
      { no: 7, name: 'createdAt', type: 'uint64' },
      { no: 8, name: 'expiresAt', type: 'uint64', rangeBucket: { width: HOUR } },
      { no: 9, name: 'lastUsedAt', type: 'uint64' },
      { no: 10, name: 'revoked', type: 'bool' },
      { no: 11, name: 'ipAllowJson', type: 'string' },
      { no: 12, name: 'createdBySub', type: 'string' },
      { no: 13, name: 'useCount', type: 'int64' },
    ],
  },

  /* ── SMTP istemci kimlikleri (Thunderbird vb.) ───────────── */
  // Parola DEĞİL, scrypt türevi saklanır. Sunucu düz parolayı hiç bilmez;
  // önceki sürüm bunları kaynak koda gömülü düz metin olarak taşıyordu.
  smtp_credentials: {
    fields: [
      { no: 2, name: 'username', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'mailboxRef', type: 'string', index: true },
      { no: 4, name: 'secretHash', type: 'string' },
      { no: 5, name: 'salt', type: 'string' },
      { no: 6, name: 'kdf', type: 'string' },
      { no: 7, name: 'label', type: 'string' },
      { no: 8, name: 'createdAt', type: 'uint64' },
      { no: 9, name: 'lastUsedAt', type: 'uint64' },
      { no: 10, name: 'lastUsedIp', type: 'string' },
      { no: 11, name: 'revoked', type: 'bool' },
      { no: 12, name: 'status', type: 'string', index: true },
      { no: 13, name: 'createdBySub', type: 'string' },
      { no: 14, name: 'useCount', type: 'int64' },
      { no: 15, name: 'allowSubmission', type: 'bool' },
    ],
  },

  /* ── sertifikalar (S/MIME + TLS) ─────────────────────────── */
  certificates: {
    fields: [
      // `${usage}|${subject}` — "bu adresin S/MIME sertifikası hangisi"
      // sorusunun tek anahtarı.
      { no: 2, name: 'certKey', type: 'string', blindIndex: true, required: true },
      // smime | tls | ca | client
      { no: 3, name: 'usage', type: 'string', index: true },
      { no: 4, name: 'subjectAddress', type: 'string' },
      { no: 5, name: 'mailboxRef', type: 'string', index: true },
      { no: 6, name: 'serialHex', type: 'string', index: true },
      { no: 7, name: 'skidHex', type: 'string', index: true },
      { no: 8, name: 'fingerprintSha256', type: 'string', index: true },
      { no: 9, name: 'certPem', type: 'string' },
      { no: 10, name: 'chainPem', type: 'string' },
      // Özel anahtar kasada; burada yalnızca göndergesi.
      { no: 11, name: 'privateKeySecretRef', type: 'string' },
      { no: 12, name: 'notBefore', type: 'uint64' },
      // Süresi dolanları taramak için kova: "30 gün içinde bitenler".
      { no: 13, name: 'notAfter', type: 'uint64', rangeBucket: { width: DAY } },
      // pending | active | retired | revoked | compromised
      { no: 14, name: 'status', type: 'string', index: true },
      { no: 15, name: 'issuedVia', type: 'string' },
      { no: 16, name: 'issuedAt', type: 'uint64' },
      { no: 17, name: 'revokedAt', type: 'uint64' },
      { no: 18, name: 'revocationReason', type: 'string' },
      { no: 19, name: 'keyAlgorithm', type: 'string' },
      { no: 20, name: 'requestedBySub', type: 'string' },
      { no: 21, name: 'version', type: 'int32' },
      { no: 22, name: 'renewAfter', type: 'uint64' },
      { no: 23, name: 'issuerDn', type: 'string' },
      { no: 24, name: 'subjectDn', type: 'string' },
      { no: 25, name: 'sanJson', type: 'string' },
    ],
  },

  /* ── anahtar kasası ──────────────────────────────────────── */
  // Sertifikalar, özel anahtarlar, DKIM ve VAPID anahtarları, bildirim
  // sırları, IdP jetonları. Sürüm ÜZERİNE YAZILMAZ: yeni sürüm `pending`
  // olarak konur, terfi ettirilir, eskisi `retired` olur. Yükünü henüz
  // yenilemeyen bir tüketicinin doğrulayacak gerçek bir şeyi kalır.
  secrets: {
    fields: [
      // `${kind}|${name}|v${version}`
      { no: 2, name: 'secretKey', type: 'string', blindIndex: true, required: true },
      // Tür DÜZ dizinde, ad KÖR dizinde: hangi tür sırların kullanıldığı
      // hassas değil, hangi adların kullanıldığı hassas.
      { no: 3, name: 'kind', type: 'string', index: true },
      { no: 4, name: 'name', type: 'string', blindIndex: true },
      { no: 5, name: 'version', type: 'int32' },
      { no: 6, name: 'status', type: 'string', index: true },
      // iv || tag || ciphertext — kasa anahtarı altında sarılmış.
      { no: 7, name: 'ciphertext', type: 'bytes' },
      { no: 8, name: 'wrapAlg', type: 'string' },
      { no: 9, name: 'wrapKeyId', type: 'string', index: true },
      { no: 10, name: 'contentType', type: 'string' },
      { no: 11, name: 'createdAt', type: 'uint64' },
      { no: 12, name: 'notAfter', type: 'uint64', rangeBucket: { width: DAY } },
      { no: 13, name: 'rotatedAt', type: 'uint64' },
      { no: 14, name: 'retiredAt', type: 'uint64' },
      { no: 15, name: 'metaJson', type: 'string' },
      { no: 16, name: 'sha256Hex', type: 'string' },
      { no: 17, name: 'createdBySub', type: 'string' },
      { no: 18, name: 'compromisedAt', type: 'uint64' },
      { no: 19, name: 'compromiseReason', type: 'string' },
      // Zarfın base64 hâli. `ciphertext` (bytes) ile AYNI veriyi taşıyor ve
      // okurken bu tercih ediliyor: `bytes` alanının tel üzerindeki temsili
      // sürücüye göre değişiyor (Buffer / base64 dizge / {type:'Buffer'}) ve
      // yanlış çözülen bir zarf, yazıldıktan saniyeler sonra açılamaz hâle
      // geliyordu. Dizgeyi hiçbir taşıma katmanı yeniden yorumlamıyor.
      { no: 20, name: 'ciphertextB64', type: 'string' },
    ],
  },

  /* ── bildirim abonelikleri ───────────────────────────────── */
  push_subscriptions: {
    fields: [
      { no: 2, name: 'endpointHash', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'mailboxRef', type: 'string', index: true },
      { no: 4, name: 'idpSub', type: 'string', index: true },
      { no: 5, name: 'endpoint', type: 'string' },
      { no: 6, name: 'p256dh', type: 'string' },
      { no: 7, name: 'authSecret', type: 'string' },
      { no: 8, name: 'userAgent', type: 'string' },
      // mail | site | security — kullanıcı hangi konuları istiyor.
      { no: 9, name: 'topicsJson', type: 'string' },
      { no: 10, name: 'createdAt', type: 'uint64' },
      { no: 11, name: 'lastSuccessAt', type: 'uint64' },
      { no: 12, name: 'lastFailureAt', type: 'uint64' },
      { no: 13, name: 'failureCount', type: 'int32' },
      { no: 14, name: 'status', type: 'string', index: true },
      { no: 15, name: 'lastError', type: 'string' },
    ],
  },

  /* ── kişisel site ziyaretleri ────────────────────────────── */
  site_visits: {
    fields: [
      { no: 2, name: 'visitId', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'ts', type: 'uint64', rangeBucket: { width: HOUR } },
      { no: 4, name: 'source', type: 'string', index: true },
      { no: 5, name: 'ip', type: 'string' },
      { no: 6, name: 'os', type: 'string' },
      { no: 7, name: 'deviceModel', type: 'string' },
      { no: 8, name: 'browser', type: 'string' },
      { no: 9, name: 'isp', type: 'string' },
      { no: 10, name: 'asn', type: 'string' },
      { no: 11, name: 'country', type: 'string' },
      { no: 12, name: 'city', type: 'string' },
      { no: 13, name: 'path', type: 'string' },
      { no: 14, name: 'referrer', type: 'string' },
      { no: 15, name: 'userAgent', type: 'string' },
      { no: 16, name: 'notified', type: 'bool' },
    ],
  },

  /* ── denetim kaydı ───────────────────────────────────────── */
  // Yalnızca EKLEME. Bir yetkinin kim tarafından, ne zaman verildiğini
  // sonradan öğrenmenin başka yolu yok.
  audit_log: {
    fields: [
      { no: 2, name: 'ts', type: 'uint64', rangeBucket: { width: HOUR } },
      { no: 3, name: 'actorSub', type: 'string', index: true },
      { no: 4, name: 'actorEmail', type: 'string' },
      { no: 5, name: 'action', type: 'string', index: true },
      { no: 6, name: 'targetType', type: 'string', index: true },
      { no: 7, name: 'targetId', type: 'string', index: true },
      { no: 8, name: 'ip', type: 'string' },
      { no: 9, name: 'detailJson', type: 'string' },
      { no: 10, name: 'result', type: 'string' },
      { no: 11, name: 'userAgent', type: 'string' },
    ],
  },

  /* ── DNS denetim sonuçları ───────────────────────────────── */
  dns_audit: {
    fields: [
      { no: 2, name: 'recordKey', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'recordType', type: 'string', index: true },
      { no: 4, name: 'name', type: 'string' },
      { no: 5, name: 'expected', type: 'string' },
      { no: 6, name: 'observed', type: 'string' },
      // ok | drift | missing | error
      { no: 7, name: 'status', type: 'string', index: true },
      { no: 8, name: 'checkedAt', type: 'uint64' },
      { no: 9, name: 'appliedAt', type: 'uint64' },
      { no: 10, name: 'domain', type: 'string', index: true },
    ],
  },

  /* ── kısa ömürlü durum ───────────────────────────────────── */
  // OAuth state/PKCE, cihaz kodu, ileti tekilleştirme anahtarları.
  ephemeral: {
    fields: [
      { no: 2, name: 'key', type: 'string', blindIndex: true, required: true },
      { no: 3, name: 'kind', type: 'string', index: true },
      { no: 4, name: 'valueJson', type: 'string' },
      { no: 5, name: 'expiresAt', type: 'uint64', rangeBucket: { width: MINUTE } },
      { no: 6, name: 'createdAt', type: 'uint64' },
      { no: 7, name: 'usedAt', type: 'uint64' },
    ],
  },
};
