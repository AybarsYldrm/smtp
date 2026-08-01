#!/usr/bin/env node
'use strict';

/**
 * Kaydedilmiş bir ham iletiyi SPF/DKIM/DMARC açısından yeniden değerlendirir.
 *
 * Neden ayrı bir araç: gelen bir iletide "DKIM fail" gördüğünde sorulacak
 * soru, sunucunun kayda yazdığından daha ayrıntılıdır — hangi imza, hangi
 * seçici, gövde özeti mi tutmadı, DNS'te kayıt var mı. İletiyi bir dosyaya
 * alıp burada çalıştırmak, aynı kodu aynı baytlarla ama tam çıktıyla
 * koşturuyor. Webmail'deki "kaynağı gör" bağlantısı tam olarak bu dosyayı
 * veriyor.
 *
 *   fitfak-mail-verify ileti.eml
 *   fitfak-mail-verify ileti.eml --ip 209.85.220.41 --mail-from ali@gmail.com
 *   cat ileti.eml | fitfak-mail-verify -
 */

const fs = require('node:fs');

const dkim = require('../src/mail/dkim');
const smime = require('../src/certs/smime');
const spf = require('../src/mail/spf');
const dmarc = require('../src/mail/dmarc');
const { parseMessage } = require('../src/mail/mime-parser');

const argv = process.argv.slice(2);
if (!argv.length || argv.includes('--help') || argv.includes('-h')) {
  process.stdout.write([
    'fitfak-mail-verify <ileti.eml|-> [seçenekler]',
    '',
    '  --ip <adres>          bağlanan istemcinin IP\'si (SPF için)',
    '  --mail-from <adres>   zarf göndereni (SPF için)',
    '  --helo <ad>           HELO/EHLO adı',
    '  --ca <dosya>          S/MIME zincirini doğrulamak için güven çıpası (PEM demeti)',
    '  --json                sonucu JSON olarak yaz',
    '',
    'IP verilmezse SPF atlanır; DKIM ve DMARC yine değerlendirilir.',
    'İleti S/MIME imzalıysa imza her hâlükârda doğrulanır; --ca verilmezse',
    'yalnızca ZİNCİR doğrulanamaz, imzanın kendisi yine denetlenir.',
    '',
  ].join('\n'));
  process.exit(argv.length ? 0 : 1);
}

function option(name, fallback = '') {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
}

const source = argv[0];
const raw = source === '-' ? fs.readFileSync(0) : fs.readFileSync(source);
const asJson = argv.includes('--json');

const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';
const color = process.stdout.isTTY && process.env.NO_COLOR !== '1';
const paint = (code, s) => (color ? `${code}${s}${RESET}` : String(s));
const verdict = (r) => paint(r === 'pass' ? GREEN : (r === 'none' || r === 'neutral' ? YELLOW : RED), r);

async function main() {
  const parsed = parseMessage(raw, { limits: {} });
  const fromDomain = String(parsed.from.address || '').split('@')[1] || '';

  const dkimResult = await dkim.verifyMessage(raw, { diagnostics: true });

  let spfResult = null;
  const ip = option('--ip');
  if (ip) {
    spfResult = await spf.check({
      ip,
      sender: option('--mail-from', parsed.from.address || ''),
      heloDomain: option('--helo', ''),
    });
  }

  const dmarcResult = fromDomain
    ? await dmarc.evaluate({ fromDomain, spf: spfResult, dkim: dkimResult })
    : null;

  // S/MIME: imza DKIM'den bağımsız bir iddia. DKIM "bu ileti bu alan adından
  // çıktı" der ve aktarımda biter; S/MIME "bu ileti bu KİŞİ tarafından
  // yazıldı" der ve uçtan uca sürer. İkisinin ayrı raporlanması gerekiyor,
  // çünkü biri geçip diğeri kalabilir ve sebepleri hiç ilgisizdir.
  const caPath = option('--ca');
  let trustedCaPems = [];
  if (caPath) {
    try { trustedCaPems = [fs.readFileSync(caPath, 'utf8')]; }
    catch (err) { process.stderr.write(`[uyarı] güven çıpası okunamadı (${caPath}): ${err.message}\n`); }
  }
  const smimeResult = smime.verifyMessageSignature(parsed, {
    trustedCaPems,
    expectedAddress: parsed.from.address || null,
  });

  if (asJson) {
    process.stdout.write(`${JSON.stringify({
      from: parsed.from, subject: parsed.subject, messageId: parsed.messageId,
      spf: spfResult, dkim: dkimResult, dmarc: dmarcResult, smime: smimeResult,
    }, null, 2)}\n`);
    return;
  }

  const out = [];
  out.push(`${paint(DIM, 'ileti')}    ${parsed.subject || '(konu yok)'}`);
  out.push(`${paint(DIM, 'from')}     ${parsed.from.address || '(yok)'}  ${paint(DIM, `(alan: ${fromDomain || '—'})`)}`);
  out.push(`${paint(DIM, 'boyut')}    ${raw.length} bayt`);
  out.push('');

  if (spfResult) {
    out.push(`SPF    ${verdict(spfResult.result)}  ${paint(DIM, `alan=${spfResult.domain} mekanizma=${spfResult.mechanism || '—'} sorgu=${spfResult.lookups}`)}`);
    if (spfResult.result !== 'pass' && spfResult.explanation) {
      out.push(`       ${paint(DIM, spfResult.explanation)}`);
    }
  } else {
    out.push(`SPF    ${paint(YELLOW, 'atlandı')}  ${paint(DIM, '--ip verilmedi')}`);
  }

  out.push(`DKIM   ${verdict(dkimResult.overall)}  ${paint(DIM, `${dkimResult.results.length} imza`)}`);
  for (const signature of dkimResult.results) {
    out.push(`       ${verdict(signature.result)} d=${signature.domain} s=${signature.selector} a=${signature.algorithm}`);
    if (signature.reason) out.push(`         ${paint(DIM, signature.reason)}`);
    const d = signature.detail || {};
    out.push(`         ${paint(DIM, `kanoniklik=${d.canonicalization} imzalı-başlık=${(d.signedHeaders || []).length} imza-girdisi=${d.signingInputBytes}B`)}`);
    out.push(`         ${paint(DIM, `dns=${d.dnsName} bulundu=${d.dnsRecordFound ? 'evet' : 'hayır'}`)}`);
    if (!signature.bodyHashMatch && d.computedBodyHash) {
      out.push(`         ${paint(DIM, `bh bildirilen=${String(d.declaredBodyHash).slice(0, 24)}…`)}`);
      out.push(`         ${paint(DIM, `bh hesaplanan=${String(d.computedBodyHash).slice(0, 24)}…`)}`);
    }
  }

  if (dmarcResult) {
    out.push(`DMARC  ${verdict(dmarcResult.result)}  ${paint(DIM, `uygulama=${dmarcResult.disposition} sebep=${dmarcResult.reason}`)}`);
    const a = dmarcResult.alignment || {};
    out.push(`       ${paint(DIM, `dkim-hizalama=${a.dkim} (${a.dkimDomain || '—'}, mod ${a.dkimMode}) spf-hizalama=${a.spf} (${a.spfDomain || '—'}, mod ${a.spfMode})`)}`);
    if (dmarcResult.policy) {
      out.push(`       ${paint(DIM, `politika p=${dmarcResult.policy.effectivePolicy} (${dmarcResult.policy.foundAt})`)}`);
    }
  } else {
    out.push(`DMARC  ${paint(YELLOW, 'atlandı')}  ${paint(DIM, 'From alan adı çözümlenemedi')}`);
  }

  out.push(smimeLines(smimeResult, trustedCaPems.length > 0).join('\n'));

  out.push('');
  process.stdout.write(`${out.join('\n')}\n`);
}

/** S/MIME bölümü. `none` bir hata değil: iletilerin çoğu imzasızdır. */
function smimeLines(result, haveTrustAnchor) {
  const lines = [];
  if (!result || result.status === 'none') {
    lines.push(`S/MIME ${paint(DIM, 'yok')}     ${paint(DIM, 'ileti S/MIME imzalı değil')}`);
    return lines;
  }

  // Durum, "imza matematiksel olarak doğru mu" ile "bu imzaya güvenilir mi"
  // sorularını AYIRIYOR. İkisini tek bir pass/fail'e indirgemek, kendi
  // ürettiğimiz geçerli bir imzayı, yalnızca zinciri elimizde olmadığı için
  // başarısız göstermek olurdu.
  const label = {
    'signed-valid': paint(GREEN, 'pass'),
    'signed-untrusted': paint(YELLOW, 'güvenilmez'),
    'signed-address-mismatch': paint(RED, 'adres uyuşmaz'),
    'signed-expired': paint(YELLOW, 'süresi dolmuş'),
    'signed-invalid': paint(RED, 'fail'),
  }[result.status] || paint(RED, result.status);

  lines.push(`S/MIME ${label}  ${paint(DIM, `imza=${result.valid ? 'geçerli' : 'geçersiz'} özet=${result.digestMatch ? 'uyuşuyor' : 'uyuşmuyor'}`)}`);
  if (result.reason) lines.push(`       ${paint(DIM, result.reason)}`);

  const signer = result.signer;
  if (signer) {
    lines.push(`       ${paint(DIM, `imzalayan=${signer.subject}`)}`);
    lines.push(`       ${paint(DIM, `veren=${signer.issuer}`)}`);
    lines.push(`       ${paint(DIM, `seri=${signer.serialNumber} anahtar=${signer.keyType}`)}`);
    lines.push(`       ${paint(DIM, `adres=${[...new Set(signer.emails)].join(', ') || '—'} eşleşme=${result.addressMatch === null ? '—' : (result.addressMatch ? 'evet' : 'HAYIR')}`)}`);
    lines.push(`       ${paint(DIM, `geçerlilik=${new Date(signer.notBefore).toISOString().slice(0, 10)} → ${new Date(signer.notAfter).toISOString().slice(0, 10)} (${result.timeValid ? 'süresi içinde' : 'SÜRESİ DIŞINDA'})`)}`);
  }
  lines.push(`       ${paint(DIM, haveTrustAnchor
    ? `zincir=${result.chainTrusted ? 'doğrulandı' : 'DOĞRULANAMADI'} (ekli sertifika: ${result.certs.length})`
    : `zincir=denetlenmedi — güven çıpası verilmedi (--ca ile kök/ara sertifikayı verin), ekli sertifika: ${result.certs.length}`)}`);
  return lines;
}

main().catch((err) => {
  process.stderr.write(`${err.stack || err.message}\n`);
  process.exit(1);
});
