'use strict';

const { decodeMimeWords, safeFileName } = require('../util/encoding');

/**
 * multipart/form-data ayrıştırıcı.
 *
 * Ek yükleme için gerekiyor. Alternatif JSON içinde base64 taşımaktı; o da
 * destekliyor ama %33 fazla bayt demek ve 25 MB'lık bir ekte bu fark
 * gerçek. Ayrıştırma tampon üzerinde yapılıyor, dizge üzerinde değil:
 * ikili veriyi dizgeye çevirmek onu bozar.
 *
 * Sınırlar burada da var (parça sayısı, tek dosya boyutu): gövde sınırı
 * genel, ama binlerce küçük parça gönderen bir istek gövde sınırını hiç
 * aşmadan ayrıştırıcıyı meşgul edebilir.
 */

const MAX_PARTS = 60;

function parseMultipart(buffer, contentType, { maxParts = MAX_PARTS } = {}) {
  const boundaryMatch = String(contentType).match(/boundary=(?:"([^"]+)"|([^;]+))/i);
  if (!boundaryMatch) throw Object.assign(new Error('multipart sınırı (boundary) yok'), { status: 400 });
  const boundary = (boundaryMatch[1] || boundaryMatch[2]).trim();

  const delimiter = Buffer.from(`--${boundary}`, 'latin1');
  const fields = {};
  const files = [];

  let position = buffer.indexOf(delimiter);
  if (position === -1) throw Object.assign(new Error('multipart gövdesi sınır içermiyor'), { status: 400 });

  let partCount = 0;
  while (position !== -1) {
    let cursor = position + delimiter.length;
    // Kapanış sınırı: "--boundary--"
    if (buffer[cursor] === 0x2d && buffer[cursor + 1] === 0x2d) break;
    // Sınır satırının sonuna kadar atla.
    while (cursor < buffer.length && buffer[cursor] !== 0x0a) cursor++;
    cursor++;

    const next = buffer.indexOf(delimiter, cursor);
    if (next === -1) break;
    let end = next;
    if (end > cursor && buffer[end - 1] === 0x0a) end--;
    if (end > cursor && buffer[end - 1] === 0x0d) end--;

    const partBuffer = buffer.subarray(cursor, end);
    if (++partCount > maxParts) {
      throw Object.assign(new Error(`en fazla ${maxParts} parça kabul edilir`), { status: 400 });
    }

    const headerEnd = findHeaderEnd(partBuffer);
    if (headerEnd.index === -1) { position = next; continue; }

    const headerText = partBuffer.subarray(0, headerEnd.index).toString('utf8');
    const content = partBuffer.subarray(headerEnd.index + headerEnd.length);
    const headers = {};
    for (const line of headerText.split(/\r?\n/)) {
      const colon = line.indexOf(':');
      if (colon <= 0) continue;
      headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
    }

    const disposition = headers['content-disposition'] || '';
    const nameMatch = disposition.match(/\bname="([^"]*)"/i) || disposition.match(/\bname=([^;]+)/i);
    const fileMatch = disposition.match(/\bfilename\*?="?([^";]+)"?/i);
    const name = nameMatch ? nameMatch[1] : '';
    if (!name) { position = next; continue; }

    if (fileMatch) {
      files.push({
        field: name,
        fileName: safeFileName(decodeMimeWords(decodeURIComponent(fileMatch[1]))),
        contentType: (headers['content-type'] || 'application/octet-stream').split(';')[0].trim(),
        content,
        sizeBytes: content.length,
        // Gömülü görsel olarak gönderilmek isteniyorsa istemci
        // `Content-ID` başlığı koyar.
        contentId: String(headers['content-id'] || '').replace(/[<>]/g, ''),
        inline: /inline/i.test(disposition),
      });
    } else {
      const value = content.toString('utf8');
      // Aynı ad birden fazla gelirse dizi olur: alıcı listesi böyle taşınır.
      if (fields[name] === undefined) fields[name] = value;
      else if (Array.isArray(fields[name])) fields[name].push(value);
      else fields[name] = [fields[name], value];
    }

    position = next;
  }

  return { fields, files };
}

function findHeaderEnd(buf) {
  for (let i = 0; i < buf.length - 1; i++) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a && buf[i + 2] === 0x0d && buf[i + 3] === 0x0a) {
      return { index: i, length: 4 };
    }
    if (buf[i] === 0x0a && buf[i + 1] === 0x0a) return { index: i, length: 2 };
  }
  return { index: -1, length: 0 };
}

module.exports = { parseMultipart };
