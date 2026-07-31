'use strict';

/**
 * Sürücüden dönen "ikili alan" değerlerini tek biçime indirger.
 *
 * ── SORUNUN KAYNAĞI ──────────────────────────────────────────────────────
 * Bir `bytes` alanına yazılan değerin GERİ OKUNDUĞUNDA hangi JavaScript
 * türüyle geleceği sürücüye bağlı:
 *
 *   dosya sürücüsü (JSON)   Buffer -> {"type":"Buffer","data":[...]}
 *                           string -> string (olduğu gibi)
 *   gRPC/protobuf sürücüsü  Buffer -> Buffer ya da Uint8Array
 *                           string -> UTF-8'e kodlanıp Buffer olarak geri
 *   JSON köprüsü            Buffer -> base64 dizge
 *
 * Bu belirsizliğin bedeli somuttu: blob parçaları base64 DİZGE olarak
 * yazılıyor, sürücü onları bayta çeviriyor ve okuma tarafındaki
 * `Buffer.from(değer, 'base64')` çağrısı — girdisi zaten Buffer olduğu için
 * kodlamayı YOK SAYIP baytları kopyalıyordu. Sonuç: ekler base64 metni
 * olarak, üstelik `content-length` ham boyuta göre hesaplandığı için
 * KESİLMİŞ hâlde iniyordu.
 *
 * Buradaki iki işlev o belirsizliği kapatıyor: `toBuffer` her şekli baytlara
 * çevirir, `looksBase64` bir bayt dizisinin base64 metni olup olmadığını
 * söyler. Kimlik (hangi yorumun doğru olduğu) tahminle değil, çağıranın
 * elindeki uzunluk/özet bilgisiyle belirlenir.
 */

/**
 * Herhangi bir sürücü temsilini Buffer'a çevirir.
 * Dizgeler İÇERİK olarak ele alınır (latin1) — base64 çözümü ÇAĞIRANIN
 * kararıdır, çünkü burada tahmin etmek geri dönüşü olmayan bozulma üretir.
 *
 * @param {*} value
 * @returns {Buffer}
 */
function toBuffer(value) {
  if (value == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ArrayBuffer) return Buffer.from(value);
  if (typeof value === 'string') return Buffer.from(value, 'latin1');
  if (Array.isArray(value)) return Buffer.from(value);
  if (typeof value === 'object') {
    // Node'un JSON.stringify(Buffer) biçimi.
    if (value.type === 'Buffer' && Array.isArray(value.data)) return Buffer.from(value.data);
    if (Array.isArray(value.data)) return Buffer.from(value.data);
    // {"0":12,"1":34,...} — bir Uint8Array'in JSON'a düşmüş hâli.
    const keys = Object.keys(value);
    if (keys.length && keys.every((k) => /^\d+$/.test(k))) {
      const out = Buffer.alloc(keys.length);
      for (const k of keys) out[Number(k)] = Number(value[k]) & 0xff;
      return out;
    }
  }
  return Buffer.from(String(value), 'latin1');
}

const BASE64_BYTE = new Uint8Array(256);
for (const ch of 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n') {
  BASE64_BYTE[ch.charCodeAt(0)] = 1;
}

/**
 * Baytlar bir base64 METNİ mi?
 *
 * Uzunluk denetimi de yapılır: base64 gövdesi 4'ün katı olmalıdır. Rastgele
 * ikili verinin bu iki koşulu birden sağlaması pratikte imkânsız (256 baytlık
 * bir parçada olasılık ~10^-30), ama yine de tek başına KARAR olarak
 * kullanılmıyor — çağıran uzunluk ya da özet ile doğruluyor.
 */
function looksBase64(buf) {
  if (!buf || buf.length < 4) return false;
  let significant = 0;
  for (let i = 0; i < buf.length; i++) {
    if (!BASE64_BYTE[buf[i]]) return false;
    if (buf[i] !== 0x0d && buf[i] !== 0x0a) significant++;
  }
  return significant > 0 && significant % 4 === 0;
}

/** base64 metni olarak çöz; olamıyorsa null. */
function tryDecodeBase64(buf) {
  if (!looksBase64(buf)) return null;
  const text = buf.toString('latin1');
  const decoded = Buffer.from(text, 'base64');
  // Gidiş-dönüş denetimi: `Buffer.from(..., 'base64')` hoşgörülüdür ve
  // çöpü sessizce yutar. Yeniden kodlayıp karşılaştırmak, "base64 gibi
  // görünen ama olmayan" veriyi eler.
  const reencoded = decoded.toString('base64');
  const normalized = text.replace(/[\r\n]/g, '');
  return reencoded === normalized ? decoded : null;
}

module.exports = { toBuffer, looksBase64, tryDecodeBase64 };
