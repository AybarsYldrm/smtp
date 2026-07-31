'use strict';

const crypto = require('node:crypto');

const {
  encodeHeaderValue, encodeAddress, encodeQuotedPrintable, b64Wrap,
  foldHeader, newMessageId, normalizeAddress, htmlToText, safeFileName,
} = require('../util/encoding');

const CRLF = '\r\n';

/**
 * MIME oluşturucu.
 *
 * Yapı kararı, imzalamanın gereğinden çıkıyor: ileti iki parçaya ayrılıyor —
 * ÜST BAŞLIKLAR (From, To, Subject, Date, Message-ID) ve İÇERİK VARLIĞI
 * (Content-Type ve gövde). S/MIME yalnızca içerik varlığını imzalar; üst
 * başlıklar imzanın dışındadır (onları DKIM korur). Bu ayrımı yapmayan bir
 * oluşturucu ile S/MIME imzalamak, imzalanacak baytları sonradan tahmin
 * etmeye çalışmak olurdu.
 *
 * Yapı seçimi (RFC 2046 §5.1):
 *
 *   yalnızca metin                     -> text/plain
 *   metin + html                       -> multipart/alternative
 *   + gömülü görsel (cid:)             -> multipart/related
 *   + ek                               -> multipart/mixed
 *   + S/MIME imza                      -> multipart/signed(yukarıdakiler, p7s)
 *
 * `multipart/related`ın `alternative` İÇİNDE değil ONU SARAN olması önemli:
 * gömülü görsel yalnızca HTML gövdeye aittir, düz metin alternatifine
 * değil. Yanlış sıra, düz metin okuyan istemcide görseli ek olarak gösterir.
 */

function boundary(tag) {
  return `----=_fitfak_${tag}_${crypto.randomBytes(12).toString('hex')}`;
}

/** Ek gövdesi: base64, 76 sütun. */
function buildAttachmentPart(att) {
  const fileName = safeFileName(att.fileName || 'ek.bin');
  const contentType = att.contentType || 'application/octet-stream';
  const content = Buffer.isBuffer(att.content) ? att.content : Buffer.from(String(att.content || ''), 'utf8');
  const disposition = att.inline || att.isInline ? 'inline' : 'attachment';

  const headers = [
    foldHeader('Content-Type', `${contentType}; name="${encodeHeaderValue(fileName)}"`),
    'Content-Transfer-Encoding: base64',
    foldHeader('Content-Disposition', `${disposition}; filename="${encodeHeaderValue(fileName)}"`),
  ];
  // Gömülü görselin Content-ID'si HTML'deki cid: göndergesiyle birebir
  // aynı olmalı; açılı parantezler kayıtta var, göndergede yok.
  if (att.contentId) headers.push(`Content-ID: <${String(att.contentId).replace(/[<>]/g, '')}>`);
  if (att.description) headers.push(foldHeader('Content-Description', encodeHeaderValue(att.description)));

  return `${headers.join(CRLF)}${CRLF}${CRLF}${b64Wrap(content)}`;
}

/** Metin parçası: {headers, body} olarak döner ki hem tek başına gövde
 *  olarak hem de bir multipart üyesi olarak kullanılabilsin. */
function textEntity(contentType, content) {
  return {
    headers: [`Content-Type: ${contentType}; charset=utf-8`, 'Content-Transfer-Encoding: quoted-printable'],
    body: encodeQuotedPrintable(Buffer.from(String(content), 'utf8')),
  };
}

function renderEntity(entity) {
  return `${entity.headers.join(CRLF)}${CRLF}${CRLF}${entity.body}`;
}

function buildTextPart(text) { return renderEntity(textEntity('text/plain', text)); }
function buildHtmlPart(html) { return renderEntity(textEntity('text/html', html)); }

function wrapMultipart(subtype, parts, extraParams = '') {
  const bnd = boundary(subtype.replace(/[^a-z]/gi, ''));
  const body = [
    ...parts.map((p) => `--${bnd}${CRLF}${p}`),
    `--${bnd}--`,
    '',
  ].join(CRLF);
  return {
    contentTypeHeader: `Content-Type: multipart/${subtype}; ${extraParams ? `${extraParams}; ` : ''}boundary="${bnd}"`,
    body,
    boundary: bnd,
  };
}

/**
 * İçerik varlığını kurar: Content-Type başlığı + gövde.
 * @returns {{headers: string[], body: string}}
 */
function buildContentEntity({ text = '', html = '', attachments = [] }) {
  const inlineAtts = attachments.filter((a) => (a.inline || a.isInline) && a.contentId);
  const fileAtts = attachments.filter((a) => !((a.inline || a.isInline) && a.contentId));

  const bodyText = text || (html ? htmlToText(html) : '');

  let entity;
  if (html && bodyText) {
    // Sıra anlamlı: en az tercih edilen alternatif ÖNCE gelir (RFC 2046
    // §5.1.4). Tersi, HTML anlayan istemcinin düz metni göstermesine yol açar.
    const alt = wrapMultipart('alternative', [buildTextPart(bodyText), buildHtmlPart(html)]);
    entity = { headers: [alt.contentTypeHeader], body: alt.body };
  } else if (html) {
    entity = textEntity('text/html', html);
  } else {
    entity = textEntity('text/plain', bodyText);
  }

  if (inlineAtts.length) {
    const innerType = entity.headers[0].replace(/^Content-Type:\s*/i, '').split(';')[0].trim();
    const related = wrapMultipart('related', [renderEntity(entity), ...inlineAtts.map(buildAttachmentPart)], `type="${innerType}"`);
    entity = { headers: [related.contentTypeHeader], body: related.body };
  }

  if (fileAtts.length) {
    const mixed = wrapMultipart('mixed', [renderEntity(entity), ...fileAtts.map(buildAttachmentPart)]);
    entity = { headers: [mixed.contentTypeHeader], body: mixed.body };
  }

  return entity;
}

/**
 * Tam bir ileti kurar.
 *
 * @param {object} p
 * @param {{address:string,name?:string}} p.from
 * @param {Array} p.to
 * @param {Array} [p.cc]
 * @param {Array} [p.bcc]          zarfa girer, BAŞLIĞA YAZILMAZ
 * @param {string} p.subject
 * @param {string} [p.text]
 * @param {string} [p.html]
 * @param {Array}  [p.attachments]
 * @param {object} [p.smime]       { certPem, privateKeyPem, chainPem } — verilirse imzalanır
 * @returns {{raw: Buffer, messageId: string, envelope: object, smimeSigned: boolean}}
 */
function buildMessage({
  from, to = [], cc = [], bcc = [], subject = '', text = '', html = '',
  attachments = [], inReplyTo = '', references = [], messageId = null,
  date = null, extraHeaders = {}, smime = null, listUnsubscribe = null,
  campaignId = null, autoSubmitted = null, priority = null, sender = null,
  returnPath = null,
}) {
  if (!from || !from.address) throw new Error('[mime] gönderen adresi zorunlu');
  const fromAddr = normalizeAddress(from.address);
  const domain = fromAddr.split('@')[1];

  const toList = normalizeRecipients(to);
  const ccList = normalizeRecipients(cc);
  const bccList = normalizeRecipients(bcc);
  if (!toList.length && !ccList.length && !bccList.length) throw new Error('[mime] en az bir alıcı gerekir');

  const finalMessageId = messageId || newMessageId(domain);
  const finalDate = (date instanceof Date ? date : new Date(date || Date.now())).toUTCString().replace('GMT', '+0000');

  const entity = buildContentEntity({ text, html, attachments });

  const topHeaders = [
    foldHeader('From', encodeAddress(fromAddr, from.name)),
    ...(toList.length ? [foldHeader('To', toList.map((r) => encodeAddress(r.address, r.name)).join(', '))] : []),
    ...(ccList.length ? [foldHeader('Cc', ccList.map((r) => encodeAddress(r.address, r.name)).join(', '))] : []),
    foldHeader('Subject', encodeHeaderValue(subject || '(konu yok)')),
    `Date: ${finalDate}`,
    `Message-ID: ${finalMessageId}`,
    'MIME-Version: 1.0',
  ];

  if (sender && normalizeAddress(sender) !== fromAddr) {
    // Sender başlığı, From'dan farklı biri adına gönderildiğinde konur
    // (RFC 5322 §3.6.2). Bunu atlamak, DMARC'ta sorun çıkarmasa da posta
    // istemcilerinde "adına gönderildi" bilgisinin kaybolmasına yol açar.
    topHeaders.push(foldHeader('Sender', encodeAddress(normalizeAddress(sender))));
  }
  if (inReplyTo) topHeaders.push(foldHeader('In-Reply-To', inReplyTo));
  if (references && references.length) topHeaders.push(foldHeader('References', references.join(' ')));
  if (listUnsubscribe) {
    // Toplu gönderimde List-Unsubscribe olmaması, alıcının tek çıkış yolunu
    // "spam" düğmesi bırakır ve itibarı doğrudan bu düşürür.
    topHeaders.push(foldHeader('List-Unsubscribe', listUnsubscribe));
    topHeaders.push('List-Unsubscribe-Post: List-Unsubscribe=One-Click');
  }
  if (campaignId) topHeaders.push(`X-Fitfak-Campaign: ${campaignId}`);
  if (autoSubmitted) topHeaders.push(`Auto-Submitted: ${autoSubmitted}`);
  if (priority === 'high') { topHeaders.push('X-Priority: 1', 'Importance: high'); }
  if (priority === 'low') { topHeaders.push('X-Priority: 5', 'Importance: low'); }

  for (const [name, value] of Object.entries(extraHeaders || {})) {
    if (value == null || value === '') continue;
    // Başlık enjeksiyonu: değerdeki CR/LF, gönderenin istediği kadar başlık
    // eklemesine (ve alıcı listesini değiştirmesine) izin verir.
    topHeaders.push(foldHeader(name, String(value).replace(/[\r\n]+/g, ' ')));
  }

  let bodyHeaders = entity.headers;
  let body = entity.body;
  let smimeSigned = false;

  if (smime && smime.certPem && smime.privateKeyPem) {
    const { signDetached, buildMultipartSigned, canonicalizeSignedPart } = require('../certs/smime');
    // İmzalanan şey: içerik varlığının başlıkları + boş satır + gövdesi.
    // Kanoniklik (CRLF + sondaki CRLF'in kırpılması) İMZALAMADAN ÖNCE bir kez
    // yapılır ve aynı dizge hem imzalanır hem tele verilir. İkisinin
    // ayrışması, doğrulamanın sessizce başarısız olduğu tek noktaydı.
    const contentPart = canonicalizeSignedPart(`${bodyHeaders.join(CRLF)}${CRLF}${CRLF}${body}`);
    const signatureDer = signDetached({
      content: Buffer.from(contentPart, 'utf8'),
      certPem: smime.certPem,
      privateKeyPem: smime.privateKeyPem,
      chainPem: smime.chainPem || '',
      hash: smime.hash || 'sha256',
    });
    const wrapped = buildMultipartSigned({ contentPart, signatureDer });
    bodyHeaders = wrapped.headers;
    body = wrapped.body;
    smimeSigned = true;
  }

  const raw = Buffer.from(
    `${[...topHeaders, ...bodyHeaders].join(CRLF)}${CRLF}${CRLF}${body}`.replace(/\r?\n/g, CRLF),
    'utf8',
  );

  return {
    raw,
    messageId: finalMessageId,
    date: finalDate,
    smimeSigned,
    envelope: {
      from: returnPath ? normalizeAddress(returnPath) : fromAddr,
      to: [...toList, ...ccList, ...bccList].map((r) => r.address),
    },
    recipients: { to: toList, cc: ccList, bcc: bccList },
  };
}

function normalizeRecipients(list) {
  const out = [];
  const seen = new Set();
  for (const entry of [].concat(list || [])) {
    if (!entry) continue;
    const address = normalizeAddress(typeof entry === 'string' ? entry : entry.address);
    if (!address || !address.includes('@') || seen.has(address)) continue;
    seen.add(address);
    out.push({ address, name: typeof entry === 'string' ? '' : (entry.name || '') });
  }
  return out;
}

/**
 * Bir iletiyi iletme (forward) biçiminde sarar.
 *
 * Özgün ileti message/rfc822 olarak EKLENİR, gövdeye kopyalanmaz: kopyalamak
 * ekleri ve imzayı kaybettirir, oysa ekleyerek alıcı özgün iletiyi olduğu
 * gibi (S/MIME imzası dâhil) doğrulayabilir.
 */
function buildForward({ from, to, subject, comment = '', originalRaw, originalSubject = '', smime = null, extraHeaders = {} }) {
  const prefix = /^fwd?:/i.test(subject || originalSubject || '') ? '' : 'Fwd: ';
  return buildMessage({
    from,
    to,
    subject: subject || `${prefix}${originalSubject}`,
    text: comment ? `${comment}\n\n--- İletilen ileti ---\n` : '--- İletilen ileti ---\n',
    attachments: [{
      fileName: 'iletilen-ileti.eml',
      contentType: 'message/rfc822',
      content: originalRaw,
      description: 'İletilen özgün ileti',
    }],
    smime,
    extraHeaders,
  });
}

/**
 * Teslim edilemedi bildirimi (DSN, RFC 3464).
 *
 * Biçimin önemi: alıcının posta istemcisi bunu bir hata raporu olarak
 * tanıyabilmeli. Düz metin bir "gönderilemedi" iletisi, otomatik işleyen
 * hiçbir sistem tarafından anlaşılmaz ve geri dönüş yönetimi imkânsız olur.
 */
function buildDsn({
  from, to, originalMessageId, originalRecipient, action = 'failed',
  status = '5.0.0', diagnostic = '', reportingMta, arrivalDate = null, originalRaw = null,
}) {
  const bnd = boundary('dsn');
  const humanText = [
    'Bu, gönderdiğiniz iletinin teslim edilemediğine dair otomatik bir bildirimdir.',
    '',
    `Alıcı:      ${originalRecipient}`,
    `Durum:      ${status}`,
    `Eylem:      ${action === 'failed' ? 'kalıcı hata' : action}`,
    diagnostic ? `Ayrıntı:    ${diagnostic}` : '',
    '',
    'Bu iletiye yanıt vermeniz gerekmiyor.',
  ].filter(Boolean).join(CRLF);

  const deliveryStatus = [
    `Reporting-MTA: dns; ${reportingMta}`,
    arrivalDate ? `Arrival-Date: ${new Date(arrivalDate).toUTCString().replace('GMT', '+0000')}` : '',
    '',
    `Final-Recipient: rfc822; ${originalRecipient}`,
    `Action: ${action}`,
    `Status: ${status}`,
    diagnostic ? `Diagnostic-Code: smtp; ${String(diagnostic).replace(/[\r\n]+/g, ' ')}` : '',
  ].filter(Boolean).join(CRLF);

  const parts = [
    `Content-Type: text/plain; charset=utf-8${CRLF}Content-Transfer-Encoding: quoted-printable${CRLF}${CRLF}${encodeQuotedPrintable(Buffer.from(humanText, 'utf8'))}`,
    `Content-Type: message/delivery-status${CRLF}${CRLF}${deliveryStatus}`,
  ];
  if (originalRaw) {
    // Yalnızca BAŞLIKLAR geri gönderilir (message/rfc822-headers): tam iletiyi
    // geri yollamak, teslim edilemeyen içeriği ikinci kez ağa vermek olur.
    const headerEnd = originalRaw.indexOf('\r\n\r\n');
    const headersOnly = headerEnd > 0 ? originalRaw.subarray(0, headerEnd) : originalRaw.subarray(0, Math.min(4096, originalRaw.length));
    parts.push(`Content-Type: text/rfc822-headers${CRLF}${CRLF}${headersOnly.toString('utf8')}`);
  }

  const body = [...parts.map((p) => `--${bnd}${CRLF}${p}`), `--${bnd}--`, ''].join(CRLF);
  const headers = [
    foldHeader('From', encodeAddress(normalizeAddress(from), 'Mail Delivery System')),
    foldHeader('To', `<${normalizeAddress(to)}>`),
    // Konu RFC 2047 ile kodlanmak zorunda: başlıklarda ham UTF-8 taşımak,
    // alıcının onu latin1 okuyup bozuk göstermesiyle sonuçlanır.
    foldHeader('Subject', encodeHeaderValue('Teslim edilemedi: iletiniz alıcıya ulaşmadı')),
    `Date: ${new Date().toUTCString().replace('GMT', '+0000')}`,
    `Message-ID: ${newMessageId(String(reportingMta).split('.').slice(-2).join('.'))}`,
    'MIME-Version: 1.0',
    'Auto-Submitted: auto-replied',
    ...(originalMessageId ? [foldHeader('In-Reply-To', originalMessageId), foldHeader('References', originalMessageId)] : []),
    `Content-Type: multipart/report; report-type=delivery-status; boundary="${bnd}"`,
  ];

  return Buffer.from(`${headers.join(CRLF)}${CRLF}${CRLF}${body}`, 'utf8');
}

module.exports = {
  buildMessage, buildContentEntity, buildForward, buildDsn,
  buildAttachmentPart, buildTextPart, buildHtmlPart, normalizeRecipients,
  textEntity, renderEntity,
};
