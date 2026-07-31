'use strict';

const { BlobStore } = require('../blob-store');
const { KeyVault } = require('../vault');
const { MailboxRepo } = require('./mailboxes');
const { MessageRepo } = require('./messages');
const { OutboundRepo } = require('./outbound');
const { SessionRepo } = require('./sessions');
const { CertificateRepo } = require('./certificates');
const { PushRepo, SiteVisitRepo, AuditRepo, DnsAuditRepo } = require('./misc');
const log = require('../../util/log');

/**
 * Bütün depoları tek bir yerde kurar.
 *
 * Sıra bir bağımlılık zinciri: kasa -> blob deposu -> kutu deposu -> ileti
 * deposu. İleti deposu kutu deposuna ihtiyaç duyar (sayaçlar ve sıra
 * numarası), kutu deposu ise iletiye yalnızca onarım için bakar. Bu tek
 * yönlü bağımlılık, bir deponun testte tek başına kurulabilmesini sağlıyor.
 */
function createStores(db, { config, logger = log.child('store'), vaultSecret = null } = {}) {
  const secret = vaultSecret || config.vaultSecret;
  if (!secret) {
    throw new Error('[store] kasa sırrı yok (FITFAK_MAIL_VAULT_SECRET)');
  }

  const vault = new KeyVault(db, secret, { logger: logger.child('vault') });
  const blobs = new BlobStore(db, { chunkBytes: config.limits.blobChunkBytes, logger });
  const audit = new AuditRepo(db, { logger: logger.child('audit') });
  const mailboxes = new MailboxRepo(db, { config, logger: logger.child('mailbox'), audit });
  const messages = new MessageRepo(db, { config, blobs, mailboxes, logger: logger.child('message') });
  const outbound = new OutboundRepo(db, { config, blobs, logger: logger.child('queue') });
  const sessions = new SessionRepo(db, { config, vault, logger: logger.child('session') });
  const certificates = new CertificateRepo(db, { vault, logger: logger.child('cert') });
  const push = new PushRepo(db, { logger: logger.child('push') });
  const visits = new SiteVisitRepo(db);
  const dnsAudit = new DnsAuditRepo(db);

  return { db, vault, blobs, mailboxes, messages, outbound, sessions, certificates, push, visits, audit, dnsAudit };
}

module.exports = {
  createStores,
  MailboxRepo, MessageRepo, OutboundRepo, SessionRepo, CertificateRepo,
  PushRepo, SiteVisitRepo, AuditRepo, DnsAuditRepo, KeyVault, BlobStore,
};
