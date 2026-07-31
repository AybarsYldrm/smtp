'use strict';

const dnsModule = require('node:dns');

/**
 * DMARC değerlendirmesi (RFC 7489).
 *
 * DMARC, SPF ve DKIM sonuçlarını tek bir soruya bağlar: iletinin From
 * başlığındaki alan adı, geçen doğrulamalardan biriyle HİZALI mı? Bu soru
 * kritik, çünkü SPF zarfı doğrular, DKIM ise imzalayan alanı — ikisi de
 * kullanıcının gördüğü From'u doğrulamak zorunda değil. Hizalama olmadan
 * "SPF geçti" ifadesi, saldırganın kendi alan adıyla SPF'i geçip From'a
 * başkasını yazmasına açıktır ve tam olarak bu yüzden DMARC var.
 */

const POLICY = { NONE: 'none', QUARANTINE: 'quarantine', REJECT: 'reject' };
const RESULT = { PASS: 'pass', FAIL: 'fail', NONE: 'none', TEMPERROR: 'temperror', PERMERROR: 'permerror' };

/**
 * Kurumsal alan adı (organizational domain) çıkarımı.
 *
 * Doğrusu Public Suffix List'tir. Onu buraya gömmek (ya da çalışma anında
 * indirmek) bu projenin taşıyabileceğinden büyük bir yük; bu yüzden çok
 * etiketli sonekler için açık bir liste tutuyoruz ve SINIRI burada
 * söylüyoruz: listede olmayan çok etiketli bir sonek için hizalama gereğinden
 * katı hesaplanır (gevşek hizalama, sıkı gibi davranır). Bu yön güvenlidir —
 * ters yön, ilgisiz bir alt alanı hizalı saymak olurdu.
 *
 * `net.tr` listede: aybars.net.tr'nin kurumsal alanı "net.tr" DEĞİL
 * "aybars.net.tr" olmalı ve iki etiketli naif kural bunu yanlış yapar.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'bel.tr', 'pol.tr', 'k12.tr',
  'av.tr', 'dr.tr', 'name.tr', 'tsk.tr', 'biz.tr', 'tel.tr', 'gen.tr', 'web.tr', 'info.tr',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ad.jp', 'ed.jp', 'gr.jp', 'lg.jp',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in', 'ac.in',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.ec', 'com.uy',
  'co.za', 'org.za', 'net.za', 'gov.za', 'ac.za',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'co.kr', 'or.kr', 'ne.kr', 'go.kr', 're.kr', 'ac.kr',
  'com.sg', 'com.hk', 'com.tw', 'com.my', 'com.ph', 'com.vn', 'com.pk', 'com.bd',
  'com.sa', 'com.eg', 'com.ng', 'com.gh', 'com.ua', 'com.pl', 'com.ru',
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
  'com.es', 'com.pt', 'com.gr', 'com.cy', 'com.mt',
]);

function organizationalDomain(domain) {
  const labels = String(domain || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) return labels.slice(-3).join('.');
  return lastTwo;
}

/** Hizalama denetimi. `strict` ise tam eşitlik, `relaxed` ise kurumsal alan. */
function isAligned(fromDomain, authenticatedDomain, mode = 'r') {
  if (!fromDomain || !authenticatedDomain) return false;
  const a = String(fromDomain).toLowerCase().replace(/\.$/, '');
  const b = String(authenticatedDomain).toLowerCase().replace(/\.$/, '');
  if (a === b) return true;
  if (mode === 's') return false;
  return organizationalDomain(a) === organizationalDomain(b);
}

function parsePolicyRecord(text) {
  const tags = {};
  for (const part of String(text).split(';')) {
    const eq = part.indexOf('=');
    if (eq <= 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  if (!tags.v || tags.v.toUpperCase() !== 'DMARC1') return null;
  // p= yoksa kayıt geçersiz (§6.3): politika belirtmeyen bir DMARC kaydı
  // hiçbir şey söylemiyor demektir.
  if (!tags.p) return null;

  const policy = String(tags.p).toLowerCase();
  if (!Object.values(POLICY).includes(policy)) return null;

  return {
    version: 'DMARC1',
    policy,
    subdomainPolicy: tags.sp ? String(tags.sp).toLowerCase() : null,
    dkimAlignment: (tags.adkim || 'r').toLowerCase() === 's' ? 's' : 'r',
    spfAlignment: (tags.aspf || 'r').toLowerCase() === 's' ? 's' : 'r',
    percent: tags.pct != null ? Math.max(0, Math.min(100, Number(tags.pct))) : 100,
    reportUriAggregate: tags.rua ? tags.rua.split(',').map((s) => s.trim()).filter(Boolean) : [],
    reportUriForensic: tags.ruf ? tags.ruf.split(',').map((s) => s.trim()).filter(Boolean) : [],
    failureOptions: tags.fo || '0',
    reportInterval: tags.ri != null ? Number(tags.ri) : 86400,
    raw: text,
  };
}

/**
 * Politikayı bulur: önce tam alan adı, sonra kurumsal alan adı (§6.6.3).
 * Kurumsal alanda bulunan kayıt için `sp=` geçerlidir.
 */
async function fetchPolicy(domain, { resolver = dnsModule.promises } = {}) {
  const tryDomain = async (name) => {
    try {
      const records = await resolver.resolveTxt(`_dmarc.${name}`);
      const joined = (records || []).map((c) => (Array.isArray(c) ? c.join('') : String(c)));
      for (const text of joined) {
        const parsed = parsePolicyRecord(text);
        if (parsed) return parsed;
      }
      return null;
    } catch (err) {
      if (err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) return null;
      const e = new Error(`DMARC DNS: ${err.code || err.message}`);
      e.temporary = true;
      throw e;
    }
  };

  const exact = await tryDomain(domain);
  if (exact) return { ...exact, foundAt: domain, isOrgLevel: false };

  const org = organizationalDomain(domain);
  if (org && org !== domain) {
    const orgPolicy = await tryDomain(org);
    if (orgPolicy) return { ...orgPolicy, foundAt: org, isOrgLevel: true };
  }
  return null;
}

/**
 * DMARC değerlendirmesi.
 *
 * @param {object} p
 * @param {string} p.fromDomain      From başlığındaki alan adı
 * @param {object} p.spf             { result, domain } — spf.check çıktısı
 * @param {object} p.dkim            { results: [{domain, result}] } — dkim.verifyMessage çıktısı
 * @returns {Promise<{result, disposition, policy, alignment, reason}>}
 */
async function evaluate({ fromDomain, spf = null, dkim = null, resolver = dnsModule.promises, sampleRoll = null }) {
  const from = String(fromDomain || '').toLowerCase().replace(/\.$/, '');
  if (!from) {
    return { result: RESULT.PERMERROR, disposition: 'none', policy: null, alignment: {}, reason: 'From alan adı yok' };
  }

  let policy;
  try { policy = await fetchPolicy(from, { resolver }); }
  catch (err) {
    return {
      result: err.temporary ? RESULT.TEMPERROR : RESULT.PERMERROR,
      disposition: 'none', policy: null, alignment: {}, reason: err.message,
    };
  }

  if (!policy) {
    return { result: RESULT.NONE, disposition: 'none', policy: null, alignment: {}, reason: 'DMARC kaydı yok' };
  }

  // Alt alan adı için `sp=` geçerli — ama YALNIZCA politika kurumsal alanda
  // bulunduysa. Tam alanda bulunan kayıtta p= zaten o alan içindir.
  const effectivePolicy = (policy.isOrgLevel && policy.subdomainPolicy)
    ? policy.subdomainPolicy
    : policy.policy;

  const dkimResults = (dkim && dkim.results) || [];
  const dkimPasses = dkimResults.filter((r) => r.result === 'pass');
  const dkimAligned = dkimPasses.find((r) => isAligned(from, r.domain, policy.dkimAlignment)) || null;

  const spfPass = spf && spf.result === 'pass';
  const spfAligned = spfPass && isAligned(from, spf.domain, policy.spfAlignment);

  const alignment = {
    dkim: dkimAligned ? 'pass' : (dkimPasses.length ? 'fail_unaligned' : (dkimResults.length ? 'fail' : 'none')),
    dkimDomain: dkimAligned ? dkimAligned.domain : (dkimPasses[0] ? dkimPasses[0].domain : null),
    spf: spfAligned ? 'pass' : (spfPass ? 'fail_unaligned' : (spf ? spf.result : 'none')),
    spfDomain: spf ? spf.domain : null,
    dkimMode: policy.dkimAlignment,
    spfMode: policy.spfAlignment,
  };

  // DMARC geçer: hizalı bir DKIM ya da hizalı bir SPF. İkisi de gerekli
  // DEĞİL — biri yeter (§6.6.2), ve bu bilinçli: bir posta listesi SPF'i
  // bozar ama DKIM'i korur.
  const passed = !!dkimAligned || spfAligned;
  if (passed) {
    return {
      result: RESULT.PASS, disposition: 'none', policy: { ...policy, effectivePolicy },
      alignment, reason: dkimAligned ? 'hizalı DKIM' : 'hizalı SPF',
    };
  }

  // pct< 100 ise politikanın yalnızca o orana uygulanması gerekir; kalan
  // kısma bir alt kademe uygulanır (reject -> quarantine, quarantine -> none).
  // Bu, alan sahibinin kademeli geçiş yapabilmesi için var ve yok saymak
  // geçiş dönemindeki alanların postasını gereğinden sert reddetmek olur.
  let disposition = effectivePolicy;
  const roll = sampleRoll == null ? Math.random() * 100 : sampleRoll;
  if (policy.percent < 100 && roll >= policy.percent) {
    disposition = effectivePolicy === POLICY.REJECT ? POLICY.QUARANTINE : 'none';
  }

  return {
    result: RESULT.FAIL,
    disposition,
    policy: { ...policy, effectivePolicy },
    alignment,
    reason: 'hizalı doğrulama yok',
  };
}

/** Authentication-Results başlığı (RFC 8601). */
function authenticationResultsHeader({ hostname, spf = null, dkim = null, dmarc = null, iprev = null, smime = null }) {
  const parts = [hostname];
  if (spf) {
    const detail = [];
    if (spf.domain) detail.push(`smtp.mailfrom=${spf.domain}`);
    parts.push(`spf=${spf.result}${detail.length ? ` ${detail.join(' ')}` : ''}`);
  }
  if (dkim && dkim.results && dkim.results.length) {
    for (const r of dkim.results) {
      parts.push(`dkim=${r.result}${r.domain ? ` header.d=${r.domain}` : ''}${r.selector ? ` header.s=${r.selector}` : ''}`);
    }
  } else if (dkim) {
    parts.push(`dkim=${dkim.overall || 'none'}`);
  }
  if (dmarc) {
    parts.push(`dmarc=${dmarc.result}${dmarc.policy ? ` (p=${dmarc.policy.effectivePolicy || dmarc.policy.policy} dis=${dmarc.disposition})` : ''}`);
  }
  if (iprev) parts.push(`iprev=${iprev}`);
  // S/MIME sonucu standart bir yöntem değil ama aynı başlıkta taşımak,
  // webmail'in tek yerden okumasını sağlıyor.
  if (smime && smime.status && smime.status !== 'none') parts.push(`x-smime=${smime.status}`);
  return `Authentication-Results: ${parts.join('; ')}`;
}

module.exports = {
  evaluate, fetchPolicy, parsePolicyRecord, organizationalDomain, isAligned,
  authenticationResultsHeader, POLICY, RESULT, MULTI_LABEL_SUFFIXES,
};
