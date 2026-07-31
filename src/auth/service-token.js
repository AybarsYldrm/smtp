'use strict';

/**
 * Servisin kendi adına IdP jetonu.
 *
 * Sertifika isterken trust.fitfak.net bir taşıyıcı jeton bekliyor. İki yol
 * var ve ikisi de destekleniyor:
 *
 *   1. client_credentials — servisin kendi kimliği. Tercih edilen yol:
 *      kullanıcı etkileşimi gerektirmez, süresi dolunca kendiliğinden yenilenir.
 *   2. Cihaz akışıyla bir kez alınmış yenileme jetonu (kasada). IdP
 *      client_credentials vermiyorsa ya da sertifika verme yetkisi bir
 *      kullanıcıya bağlıysa bu yol kullanılır.
 *
 * Jeton belleğe alınır ve süresinin dolmasından bir dakika önce yenilenir:
 * tam süre dolduğunda yenilemek, o sırada yapılan isteğin 401 almasına yol
 * açar ve hata "sertifika verilemedi" olarak görünür.
 */

const REFRESH_MARGIN_MS = 60_000;
const VAULT_KIND = 'idp-service-token';
const VAULT_NAME = 'service/refresh';

class ServiceTokenProvider {
  constructor({ idp, vault, logger, scopes = ['cert:issue'] }) {
    this.idp = idp;
    this.vault = vault;
    this.logger = logger;
    this.scopes = scopes;
    this.cached = null;
    this.inFlight = null;
  }

  /** @returns {Promise<string>} erişim jetonu */
  async getAccessToken() {
    if (this.cached && this.cached.expiresAt - REFRESH_MARGIN_MS > Date.now()) {
      return this.cached.accessToken;
    }
    // Eşzamanlı istekler tek yenilemeyi paylaşır: yirmi posta kutusu için
    // sertifika isterken yirmi kez jeton almak gereksiz ve IdP'de hız
    // sınırına takılır.
    if (this.inFlight) return this.inFlight;

    this.inFlight = this._fetch().finally(() => { this.inFlight = null; });
    return this.inFlight;
  }

  async _fetch() {
    const stored = await this.vault.get(VAULT_KIND, VAULT_NAME).catch(() => null);
    if (stored) {
      try {
        const tokens = await this.idp.refresh(stored.value.toString('utf8'));
        if (tokens.accessToken) {
          // Yenileme jetonu döndüyse yeni sürüm yazılır; dönmediyse eskisi
          // geçerli kalır.
          if (tokens.refreshToken && tokens.refreshToken !== stored.value.toString('utf8')) {
            await this.vault.put({
              kind: VAULT_KIND, name: VAULT_NAME, value: tokens.refreshToken,
              contentType: 'text/plain',
            });
          }
          this.cached = {
            accessToken: tokens.accessToken,
            expiresAt: tokens.expiresAt || Date.now() + 300_000,
            source: 'refresh_token',
          };
          return this.cached.accessToken;
        }
      } catch (err) {
        this.logger.warn({ error: err.message, msg: 'kasadaki yenileme jetonu kullanılamadı' });
      }
    }

    try {
      const tokens = await this.idp.clientCredentials({ scopes: this.scopes });
      if (!tokens.accessToken) throw new Error('access_token dönmedi');
      this.cached = {
        accessToken: tokens.accessToken,
        expiresAt: tokens.expiresAt || Date.now() + 300_000,
        source: 'client_credentials',
      };
      return this.cached.accessToken;
    } catch (err) {
      const wrapped = new Error(
        `servis jetonu alınamadı: ${err.message}. `
        + 'client_credentials desteklenmiyorsa "fitfak-mail-cert bootstrap" ile '
        + 'cihaz akışından bir yenileme jetonu kaydedin.',
      );
      wrapped.cause = err;
      throw wrapped;
    }
  }

  /** Cihaz akışından gelen yenileme jetonunu kasaya yazar. */
  async storeRefreshToken(refreshToken) {
    await this.vault.put({
      kind: VAULT_KIND, name: VAULT_NAME, value: refreshToken, contentType: 'text/plain',
    });
    this.cached = null;
    this.logger.info({ msg: 'servis yenileme jetonu kasaya yazıldı' });
  }

  invalidate() { this.cached = null; }

  status() {
    if (!this.cached) return { available: false };
    return {
      available: true,
      source: this.cached.source,
      expiresInMs: Math.max(0, this.cached.expiresAt - Date.now()),
    };
  }
}

module.exports = { ServiceTokenProvider, VAULT_KIND, VAULT_NAME };
