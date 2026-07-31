'use strict';

/**
 * Bellek içi yapılandırma kaynağı.
 *
 * `src/config.js` üç kaynaktan okuyor: ortam değişkenleri, `FITFAK_MAIL_CONFIG`
 * ile gösterilen JSON dosyası ve öntanımlılar. Kütüphane olarak kullanıldığında
 * (kimse `fitfak-mail` komutunu çalıştırmıyor, birisi `require('@fitfak/smtp')`
 * diyor) dördüncü bir kaynak gerekiyor: çağıranın koda yazdığı nesne.
 *
 * Ayrı bir dosya olmasının sebebi döngüsel bağımlılık: `defineConfig`
 * yapılandırmayı buraya yazar, `config.js` buradan okur. İkisi birbirini
 * doğrudan çağırsaydı hangisinin önce yükleneceği yükleme sırasına bağlı
 * olurdu.
 */

let source = null;

module.exports = {
  set(object) { source = object && typeof object === 'object' ? object : null; },
  get() { return source; },
  clear() { source = null; },
};
