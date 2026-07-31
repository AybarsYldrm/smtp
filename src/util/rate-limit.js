'use strict';

/**
 * Kayan pencereli sayaç ve arka arkaya başarısızlık takibi.
 *
 * Tek bir Map'te sınırsız anahtar tutmak, IP başına anahtar üretilen bir
 * sunucuda bellek sızıntısıdır: saldırgan her istekte farklı bir kaynak IP'si
 * kullanır ve harita büyümeye devam eder. Bu yüzden `maxKeys` var ve dolduğunda
 * en eski girdiler atılır — sınırlayıcının kendisi bir kaynak tükenmesi
 * vektörü olmamalı.
 */
class SlidingWindowLimiter {
  constructor({ windowMs = 60_000, max = 60, maxKeys = 50_000 } = {}) {
    this.windowMs = windowMs;
    this.max = max;
    this.maxKeys = maxKeys;
    this.buckets = new Map(); // key => { start, count }
  }

  _evictIfNeeded() {
    if (this.buckets.size <= this.maxKeys) return;
    const drop = Math.ceil(this.maxKeys * 0.1);
    let i = 0;
    for (const key of this.buckets.keys()) {
      this.buckets.delete(key);
      if (++i >= drop) break;
    }
  }

  /** @returns {{allowed: boolean, remaining: number, retryAfterMs: number}} */
  check(key, cost = 1) {
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b || now - b.start >= this.windowMs) {
      b = { start: now, count: 0 };
      this.buckets.set(key, b);
      this._evictIfNeeded();
    }
    const would = b.count + cost;
    if (would > this.max) {
      return { allowed: false, remaining: 0, retryAfterMs: this.windowMs - (now - b.start) };
    }
    b.count = would;
    return { allowed: true, remaining: this.max - b.count, retryAfterMs: 0 };
  }

  reset(key) { this.buckets.delete(key); }

  sweep() {
    const now = Date.now();
    for (const [k, b] of this.buckets) if (now - b.start >= this.windowMs * 2) this.buckets.delete(k);
  }
}

/**
 * Kimlik doğrulama denemeleri için ayrı bir yapı: başarısızlık sayısı ve
 * artan ceza süresi. Sabit "5 denemede 1 dakika ban" bir sözlük saldırısını
 * yavaşlatır ama durdurmaz; ceza katlanmalı.
 */
class FailureTracker {
  constructor({ threshold = 5, windowMs = 60_000, basePenaltyMs = 60_000, maxPenaltyMs = 3_600_000, maxKeys = 50_000 } = {}) {
    this.threshold = threshold;
    this.windowMs = windowMs;
    this.basePenaltyMs = basePenaltyMs;
    this.maxPenaltyMs = maxPenaltyMs;
    this.maxKeys = maxKeys;
    this.entries = new Map(); // key => { count, firstAt, lockUntil, strikes }
  }

  isLocked(key) {
    const e = this.entries.get(key);
    if (!e) return false;
    if (e.lockUntil && Date.now() < e.lockUntil) return true;
    if (e.lockUntil && Date.now() >= e.lockUntil) { e.count = 0; e.lockUntil = 0; e.firstAt = Date.now(); }
    return false;
  }

  lockedForMs(key) {
    const e = this.entries.get(key);
    if (!e || !e.lockUntil) return 0;
    return Math.max(0, e.lockUntil - Date.now());
  }

  recordFailure(key) {
    const now = Date.now();
    let e = this.entries.get(key);
    if (!e) {
      if (this.entries.size >= this.maxKeys) {
        for (const k of this.entries.keys()) { this.entries.delete(k); break; }
      }
      e = { count: 0, firstAt: now, lockUntil: 0, strikes: 0 };
      this.entries.set(key, e);
    }
    if (now - e.firstAt > this.windowMs && !e.lockUntil) { e.count = 0; e.firstAt = now; }
    e.count++;
    if (e.count >= this.threshold) {
      e.strikes++;
      const penalty = Math.min(this.maxPenaltyMs, this.basePenaltyMs * 2 ** (e.strikes - 1));
      e.lockUntil = now + penalty;
      return { locked: true, penaltyMs: penalty, count: e.count };
    }
    return { locked: false, penaltyMs: 0, count: e.count };
  }

  recordSuccess(key) {
    // Başarılı girişte sayaç sıfırlanır ama "strikes" korunur: tekrar tekrar
    // kilitlenen bir kaynağın cezası her seferinde baştan başlamamalı.
    const e = this.entries.get(key);
    if (!e) return;
    e.count = 0;
    e.lockUntil = 0;
    e.firstAt = Date.now();
  }

  sweep() {
    const now = Date.now();
    for (const [k, e] of this.entries) {
      const idle = now - Math.max(e.firstAt, e.lockUntil || 0);
      if (!e.lockUntil && idle > this.windowMs * 4) this.entries.delete(k);
      else if (e.lockUntil && now > e.lockUntil + this.windowMs * 4) this.entries.delete(k);
    }
  }
}

/** Eşzamanlı bağlantı sayacı (IP başına + toplam). */
class ConnectionCounter {
  constructor({ maxPerKey = 20, maxTotal = 500 } = {}) {
    this.maxPerKey = maxPerKey;
    this.maxTotal = maxTotal;
    this.counts = new Map();
    this.total = 0;
  }

  tryAcquire(key) {
    if (this.total >= this.maxTotal) return { ok: false, reason: 'total' };
    const cur = this.counts.get(key) || 0;
    if (cur >= this.maxPerKey) return { ok: false, reason: 'per_key' };
    this.counts.set(key, cur + 1);
    this.total++;
    return { ok: true };
  }

  release(key) {
    const cur = this.counts.get(key) || 0;
    if (cur <= 1) this.counts.delete(key);
    else this.counts.set(key, cur - 1);
    this.total = Math.max(0, this.total - 1);
  }

  stats() { return { total: this.total, keys: this.counts.size }; }
}

module.exports = { SlidingWindowLimiter, FailureTracker, ConnectionCounter };
