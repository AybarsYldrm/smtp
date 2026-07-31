'use strict';

const os = require('node:os');

const { HttpError } = require('../router');

/**
 * Durum API'si.
 *
 * "Belki lazım olur, kullanırım" denilen uç. İki farklı okuyucu için iki
 * ayrı düzey var ve ayrım bilinçli:
 *
 *   /healthz          — kimlik doğrulaması YOK, yalnızca ayakta mı.
 *                       İzleme sistemleri buraya bakar; sır içermez.
 *   /api/v1/status    — kimlik doğrulamalı, ayrıntılı: kuyruk derinliği,
 *                       sertifika kapsamı, DNS uyumu, DKIM kayıtları.
 *
 * Ayrımın nedeni: ayrıntılı durum, saldırgan için keşif bilgisidir (hangi
 * alan adları var, kaç kutu, hangi sürüm). Ayakta olma bilgisi değildir.
 */
function registerStatusRoutes(router, deps) {
  const {
    config, logger, stores, sessions, smtpServer, queue, realtime, push,
    certificates, signer, dnsAuditor, startedAt,
  } = deps;

  /** Yük dengeleyici / izleme için: sır yok, kimlik doğrulaması yok. */
  router.get('/healthz', async (ctx) => {
    let dbOk = true;
    try { await stores.mailboxes.mailboxes.count('domain', config.primaryDomain); }
    catch { dbOk = false; }
    const healthy = dbOk;
    ctx.json(healthy ? 200 : 503, {
      status: healthy ? 'ok' : 'degraded',
      uptimeMs: Date.now() - startedAt,
      database: dbOk ? 'ok' : 'error',
    });
  });

  router.get('/api/v1/status', async (ctx) => {
    const session = await requireStatusAccess(ctx);

    const [queueStats, certStatus, dnsRecords] = await Promise.all([
      stores.outbound.stats(),
      certificates ? certificates.status().catch(() => null) : null,
      stores.dnsAudit.list().catch(() => []),
    ]);

    const domains = [];
    for (const domain of config.domains) {
      const record = await signer.dkimDnsRecord(domain.name).catch(() => null);
      domains.push({
        name: domain.name,
        receive: domain.receive,
        dkimSelector: domain.dkimSelector,
        dkimRecord: record ? { name: record.name, value: record.value } : null,
      });
    }

    const mailboxes = await stores.mailboxes.listAll();
    const body = {
      service: {
        hostname: config.hostname,
        instanceId: config.instanceId,
        env: config.env,
        uptimeMs: Date.now() - startedAt,
        nodeVersion: process.version,
        memoryMB: Math.round(process.memoryUsage().rss / 1048576),
        loadAvg: os.loadavg().map((n) => Number(n.toFixed(2))),
      },
      vhosts: config.vhosts.map((v) => ({ kind: v.kind, host: v.host, bind: v.bind, port: v.port })),
      smtp: smtpServer ? smtpServer.snapshot() : { running: false },
      queue: { ...queueStats, worker: queue ? queue.snapshot() : null },
      realtime: realtime ? realtime.snapshot() : null,
      push: push ? push.snapshot() : null,
      domains,
      dns: dnsRecords,
      certificates: certStatus,
      mailboxes: {
        total: mailboxes.length,
        active: mailboxes.filter((m) => m.status === 'active').length,
        totalUsedBytes: mailboxes.reduce((sum, m) => sum + m.usedBytes, 0),
      },
      database: stores.db.stats ? stores.db.stats() : { mode: 'unknown' },
    };

    // Yönetici olmayan, yalnızca kendi kutularının özetini görür: kuyruk
    // derinliği ve alan adı yapılandırması işletme bilgisidir.
    if (!session.isAdmin) {
      ctx.json(200, {
        service: { hostname: body.service.hostname, uptimeMs: body.service.uptimeMs },
        queue: { queued: body.queue.queued, deferred: body.queue.deferred },
        mailboxes: { mine: (session.mailboxes || []).length },
      });
      return;
    }
    ctx.json(200, body);
  });

  /** Kuyruk ayrıntısı — teslimat sorunlarını incelemek için. */
  router.get('/api/v1/status/queue', async (ctx) => {
    const session = await requireStatusAccess(ctx);
    sessions.requireAdmin(session);
    const status = ctx.query.get('status') || null;
    const items = [];
    for await (const row of stores.outbound.queue.scan()) {
      if (status && row.status !== status) continue;
      items.push({
        queueId: row.queueId, status: row.status, rcptDomain: row.rcptDomain,
        attempts: Number(row.attempts || 0), lastError: row.lastError,
        lastSmtpCode: Number(row.lastSmtpCode || 0),
        nextAttemptAt: Number(row.nextAttemptAt || 0), subject: row.subject,
        createdAt: Number(row.createdAt || 0),
      });
      if (items.length >= 200) break;
    }
    ctx.json(200, { items });
  });

  /** DNS uyum denetimi: beklenen kayıtlar ile yayında olanlar. */
  router.get('/api/v1/status/dns', async (ctx) => {
    const session = await requireStatusAccess(ctx);
    sessions.requireAdmin(session);
    if (ctx.query.get('refresh') === '1' && dnsAuditor) {
      await dnsAuditor.audit({ apply: false });
    }
    ctx.json(200, { records: await stores.dnsAudit.list() });
  });

  router.post('/api/v1/status/dns/apply', async (ctx) => {
    const session = await requireStatusAccess(ctx);
    sessions.requireAdmin(session);
    if (!dnsAuditor) throw new HttpError(503, 'DNS sağlayıcısı yapılandırılmamış');
    // Uygulamak açık bir eylem: denetim salt okunur, yazma ayrı bir istek.
    const result = await dnsAuditor.audit({ apply: true });
    await stores.audit.record({
      actorSub: session.idpSub, actorEmail: session.idpEmail,
      action: 'dns.apply', targetType: 'dns', targetId: config.primaryDomain, ip: ctx.ip,
      detail: result,
    });
    ctx.json(200, { ok: true, ...result });
  });

  /** Denetim kaydı — kim ne yaptı. */
  router.get('/api/v1/status/audit', async (ctx) => {
    const session = await requireStatusAccess(ctx);
    sessions.requireAdmin(session);
    ctx.json(200, {
      entries: await stores.audit.list({
        action: ctx.query.get('action') || null,
        actorSub: ctx.query.get('actor') || null,
        limit: Math.min(500, Number(ctx.query.get('limit') || 100)),
      }),
    });
  });

  async function requireStatusAccess(ctx) {
    const sid = ctx.cookies()[config.http.sessionCookieName];
    let session = sid ? await sessions.authenticate({ sid, ip: ctx.ip }) : null;
    if (!session) {
      const bearer = String(ctx.header('authorization') || '').replace(/^Bearer\s+/i, '');
      if (bearer) {
        const verdict = await stores.sessions.verifyApiToken(bearer, { ip: ctx.ip });
        if (verdict.ok) {
          session = {
            idpSub: verdict.token.ownerSub,
            idpEmail: '',
            isAdmin: verdict.token.scopes.includes('admin'),
            mailboxes: [],
            isApiToken: true,
          };
        }
      }
    }
    if (!session) throw new HttpError(401, 'Oturum ya da API jetonu gerekli', { code: 'UNAUTHENTICATED' });
    return session;
  }
}

module.exports = { registerStatusRoutes };
