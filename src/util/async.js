'use strict';

function sleep(ms, { unref = true } = {}) {
  return new Promise((resolve) => {
    const t = setTimeout(resolve, ms);
    if (unref && typeof t.unref === 'function') t.unref();
  });
}

/** Tam jitter'lı üstel geri çekilme. Sabit aralık, bir sunucu yeniden
 *  başladığında bütün istemcileri aynı saniyede geri getirir. */
function backoffDelay(attempt, { baseMs = 500, maxMs = 30_000 } = {}) {
  const ceiling = Math.min(maxMs, baseMs * 2 ** Math.max(0, attempt));
  return Math.floor(Math.random() * ceiling);
}

async function retry(fn, { attempts = 3, baseMs = 500, maxMs = 10_000, onError = null, shouldRetry = null } = {}) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try { return await fn(i); }
    catch (err) {
      lastErr = err;
      if (shouldRetry && !shouldRetry(err, i)) break;
      if (onError) onError(err, i);
      if (i < attempts - 1) await sleep(backoffDelay(i, { baseMs, maxMs }), { unref: false });
    }
  }
  throw lastErr;
}

/** Anahtar başına seri çalıştırma. Aynı posta kutusuna iki paralel yazma,
 *  sayaçları (kullanılan alan, okunmamış sayısı) sessizce bozar. */
class KeyedQueue {
  constructor() { this.tails = new Map(); }

  run(key, task) {
    const prev = this.tails.get(key) || Promise.resolve();
    const next = prev.then(task, task);
    // Kuyruk zincirini kısa tutmak için: bu anahtarın son işi bittiyse
    // haritadan düş. Aksi hâlde harita her kutu için sonsuza dek büyür.
    const guarded = next.catch(() => {});
    this.tails.set(key, guarded);
    guarded.then(() => { if (this.tails.get(key) === guarded) this.tails.delete(key); });
    return next;
  }

  get size() { return this.tails.size; }
}

/** Eşzamanlılık sınırlayıcı: `limit` kadar iş paralel çalışır. */
function createLimiter(limit) {
  let active = 0;
  const waiting = [];
  const next = () => {
    if (active >= limit || !waiting.length) return;
    active++;
    const { task, resolve, reject } = waiting.shift();
    Promise.resolve().then(task).then(resolve, reject).finally(() => { active--; next(); });
  };
  const run = (task) => new Promise((resolve, reject) => { waiting.push({ task, resolve, reject }); next(); });
  run.stats = () => ({ active, waiting: waiting.length, limit });
  return run;
}

/** Saniyede N iş. Toplu gönderimde asıl kısıt bu. */
function createRateLimiter(perSecond) {
  const intervalMs = perSecond > 0 ? 1000 / perSecond : 0;
  let nextAt = 0;
  return async function acquire() {
    if (intervalMs <= 0) return;
    const now = Date.now();
    const at = Math.max(now, nextAt);
    nextAt = at + intervalMs;
    if (at > now) await sleep(at - now, { unref: false });
  };
}

/** Zaman aşımı sarmalayıcı; hangi işin takıldığını söyleyen bir hata verir. */
function withTimeout(promise, ms, label = 'işlem') {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label}: ${ms}ms zaman aşımı`)), ms);
    if (typeof timer.unref === 'function') timer.unref();
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** Yeniden girilmeyen aralıklı görev: bir tur bitmeden ikincisi başlamaz. */
function createInterval(fn, intervalMs, { immediate = false, logger = null, name = 'task' } = {}) {
  let running = false;
  let stopped = false;
  let timer = null;

  const tick = async () => {
    if (stopped || running) return;
    running = true;
    try { await fn(); }
    catch (err) { if (logger) logger.error({ task: name, error: err.message }); }
    finally {
      running = false;
      if (!stopped) schedule();
    }
  };

  const schedule = () => {
    timer = setTimeout(tick, intervalMs);
    if (typeof timer.unref === 'function') timer.unref();
  };

  if (immediate) setImmediate(tick);
  else schedule();

  return {
    stop() { stopped = true; if (timer) clearTimeout(timer); },
    trigger() { return tick(); },
    get isRunning() { return running; },
  };
}

module.exports = { sleep, backoffDelay, retry, KeyedQueue, createLimiter, createRateLimiter, withTimeout, createInterval };
