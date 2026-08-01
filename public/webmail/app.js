/**
 * Fitfak Posta — arayüz.
 *
 * Çerçeve yok; ihtiyaç duyulan yüzey küçük ve tek dosyada görülebilir.
 *
 * Gerçek zamanlılık iki katmanlı ve bu bilinçli:
 *   1. WebSocket açık olduğu sürece iletiler anında düşer.
 *   2. Bağlantı koptuğunda son görülen SIRA NUMARASI saklanır; yeniden
 *      bağlanınca "bu numaradan sonrasını ver" denir. Yalnızca WS'e güvenmek,
 *      kopukluk süresince gelen iletilerin sessizce kaybolması demekti.
 */

'use strict';

const state = {
  me: null,
  mailbox: null,
  folder: 'inbox',
  filter: 'all',
  query: '',
  messages: [],
  selected: null,
  current: null,
  cursor: null,
  lastSeq: 0,
  socket: null,
  reconnectAttempt: 0,
  attachments: [],
  loading: false,
  sourceOpen: false,
};

const el = (id) => document.getElementById(id);

const FOLDERS = [
  { key: 'inbox', label: 'Gelen kutusu' },
  { key: 'sent', label: 'Gönderilenler' },
  { key: 'drafts', label: 'Taslaklar' },
  { key: 'archive', label: 'Arşiv' },
  { key: 'spam', label: 'İstenmeyen' },
  { key: 'trash', label: 'Çöp kutusu' },
];

/* ── API ─────────────────────────────────────────────────────── */

async function api(path, options = {}) {
  const headers = { accept: 'application/json', ...(options.headers || {}) };
  if (state.me && state.me.csrfToken && options.method && options.method !== 'GET') {
    headers['x-csrf-token'] = state.me.csrfToken;
  }
  if (options.json !== undefined) {
    headers['content-type'] = 'application/json';
    options.body = JSON.stringify(options.json);
  }
  const res = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  if (res.status === 401) { showScreen('login-screen'); throw new Error('Oturum gerekli'); }

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const err = new Error((data && data.error) || `HTTP ${res.status}`);
    err.code = data && data.code;
    err.status = res.status;
    // Sunucu "ne yapılmalı" bilgisini `detail` içinde veriyor (ör. eksik bir
    // kapsam için yetkilendirme adresi). Arayüz onu gösterebilmeli.
    err.detail = data && data.detail;
    throw err;
  }
  return data;
}

/* ── önyükleme ───────────────────────────────────────────────── */

function showScreen(id) {
  for (const screen of ['boot', 'login-screen', 'no-mailbox-screen', 'app']) {
    el(screen).classList.toggle('hidden', screen !== id);
  }
}

async function boot() {
  try {
    state.me = await api('/api/v1/me');
  } catch {
    showScreen('login-screen');
    return;
  }

  if (!state.me.mailboxes.length) {
    const reason = state.me.noMailbox || {};
    el('no-mailbox-message').textContent = reason.message || 'Bu kimliğe tanımlı bir posta kutusu bulunmuyor.';
    el('no-mailbox-action').textContent = reason.action || '';
    el('no-mailbox-action').classList.toggle('hidden', !reason.action);
    el('no-mailbox-email').textContent = state.me.email || '—';
    showScreen('no-mailbox-screen');
    return;
  }

  showScreen('app');
  el('account-email').textContent = state.me.email;
  el('brand-host').textContent = location.host;

  state.mailbox = state.me.mailboxes[0];
  renderMailboxPicker();
  renderFolders();
  bindEvents();
  connectRealtime();
  await Promise.all([loadMessages({ reset: true }), refreshCounts()]);
  registerServiceWorker();

  // Yetki yükseltme (IdP onayı) sonrasında dönüldüyse bekleyen sertifika isteğini otomatik tamamla
  const pendingRef = sessionStorage.getItem('pending_cert_issue');
  if (pendingRef) {
    sessionStorage.removeItem('pending_cert_issue');
    const targetBox = state.me.mailboxes.find((m) => m.ref === pendingRef) || state.mailbox;
    if (targetBox) {
      state.mailbox = targetBox;
      renderMailboxPicker();
      try {
        await api(`/api/v1/mailboxes/${encodeURIComponent(targetBox.ref)}/certificate/issue`, {
          method: 'POST', json: { force: false, returnTo: location.pathname },
        });
        toast('S/MIME sertifikası başarıyla alındı ve kasaya işlendi', 'ok');
        state.me = await api('/api/v1/me');
        state.mailbox = state.me.mailboxes.find((m) => m.ref === targetBox.ref) || state.mailbox;
      } catch (err) {
        toast(`Otomatik sertifika oluşturulamadı: ${err.message}`, 'error');
      }
    }
  }
}

el('no-mailbox-retry').addEventListener('click', () => { showScreen('boot'); boot(); });

/* ── kenar çubuğu ────────────────────────────────────────────── */

function renderMailboxPicker() {
  const select = el('mailbox-select');
  select.innerHTML = state.me.mailboxes
    .map((m) => `<option value="${esc(m.ref)}">${esc(m.address)}</option>`).join('');
  select.value = state.mailbox.ref;
  renderAccessNote();
}

function renderAccessNote() {
  const sources = {
    local_address: 'kendi adresiniz',
    owner_sub: 'kutu sahibi',
    grant: 'yetki devri',
    identity_link: 'yönetici tarafından bağlandı',
    api_token: 'API jetonu',
  };
  const roles = { owner: 'sahip', delegate: 'vekil', sender: 'gönderici', reader: 'okuyucu' };
  const m = state.mailbox;
  el('mailbox-access').textContent = `${roles[m.role] || m.role} · ${sources[m.accessSource] || m.accessSource}`;
}

function renderFolders() {
  const counts = (state.mailbox && state.mailbox.counts) || { byFolder: {} };
  el('folders').innerHTML = FOLDERS.map((f) => {
    const stat = counts.byFolder[f.key] || { total: 0, unread: 0 };
    const n = (f.key === 'inbox' || f.key === 'spam') ? stat.unread : stat.total;
    return `<button class="folder${f.key === state.folder ? ' is-active' : ''}" data-folder="${f.key}">
      <span>${f.label}</span>${n ? `<span class="folder-count">${n}</span>` : ''}
    </button>`;
  }).join('');

  for (const button of document.querySelectorAll('.folder')) {
    button.addEventListener('click', () => {
      state.folder = button.dataset.folder;
      clearSelection();
      renderFolders();
      loadMessages({ reset: true });
    });
  }
  renderQuota();
}

function renderQuota() {
  const m = state.mailbox;
  if (!m || !m.quotaBytes) { el('quota').textContent = ''; return; }
  const pct = Math.min(100, Math.round((m.usedBytes / m.quotaBytes) * 100));
  el('quota').innerHTML = `${formatBytes(m.usedBytes)} / ${formatBytes(m.quotaBytes)}
    <div class="quota-bar"><div class="quota-fill${pct >= 90 ? ' is-full' : ''}" style="width:${pct}%"></div></div>`;
}

async function refreshCounts() {
  try {
    state.mailbox.counts = await api(`/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/counts`);
    renderFolders();
  } catch { /* sayaçlar kritik değil */ }
}

/* ── ileti listesi ───────────────────────────────────────────── */

async function loadMessages({ reset = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  if (reset) { state.messages = []; state.cursor = null; el('message-list').innerHTML = skeleton(); }

  const params = new URLSearchParams({ folder: state.folder, limit: '50' });
  if (state.cursor) params.set('cursor', String(state.cursor));
  if (state.query) params.set('q', state.query);
  if (state.filter === 'unread') params.set('unread', '1');
  if (state.filter === 'flagged') params.set('flagged', '1');
  if (state.filter === 'attachments') params.set('attachments', '1');

  try {
    const data = await api(`/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/messages?${params}`);
    state.messages = reset ? data.messages : state.messages.concat(data.messages);
    state.cursor = data.nextCursor;
    for (const message of data.messages) {
      if (message.seq > state.lastSeq) state.lastSeq = message.seq;
    }
    renderList();
    el('list-summary').textContent = `${state.messages.length} / ${data.total} ileti`;
    el('load-more').classList.toggle('hidden', !data.nextCursor);
  } catch (err) {
    toast(err.message, 'error');
    el('message-list').innerHTML = `<div class="empty">Yüklenemedi: ${esc(err.message)}</div>`;
  } finally {
    state.loading = false;
  }
}

function renderList() {
  if (!state.messages.length) {
    el('message-list').innerHTML = '<div class="empty">Bu klasörde ileti yok.</div>';
    return;
  }
  el('message-list').innerHTML = state.messages.map((m) => {
    const marks = [];
    if (m.hasAttachments) marks.push(badge('neutral', `${m.attachmentCount} ek`));
    if (m.flagged) marks.push(badge('info', 'işaretli'));
    if (m.smimeStatus === 'signed-valid' || m.smimeStatus === 'signed-local') marks.push(badge('ok', 'imzalı'));
    else if (m.smimeStatus && m.smimeStatus.startsWith('signed-')) marks.push(badge('bad', 'imza şüpheli'));
    if (m.folder === 'spam') marks.push(badge('bad', 'istenmeyen'));

    const who = state.folder === 'sent'
      ? ((m.to && m.to.length) ? m.to.map((t) => t.address).join(', ') : '—')
      : (m.from.name || m.from.address || '(bilinmiyor)');

    return `<button class="item${m.seen ? '' : ' is-unread'}${state.selected === m.ref ? ' is-selected' : ''}"
                    role="listitem" data-ref="${esc(m.ref)}">
      <div class="item-top">
        <span class="item-from truncate">${esc(who)}</span>
        <span class="item-date">${formatDate(m.receivedAt)}</span>
      </div>
      <div class="item-subject truncate">${esc(m.subject || '(konu yok)')}</div>
      <div class="item-preview truncate">${esc(m.preview || '')}</div>
      ${marks.length ? `<div class="item-marks">${marks.join('')}</div>` : ''}
    </button>`;
  }).join('');

  for (const item of document.querySelectorAll('.item')) {
    item.addEventListener('click', () => openMessage(item.dataset.ref));
  }
}

function skeleton() {
  return Array.from({ length: 6 }).map(() => `<div class="item">
    <div class="item-top"><span class="item-from dim">yükleniyor…</span></div>
    <div class="item-subject dim">&nbsp;</div></div>`).join('');
}

function clearSelection() {
  state.selected = null;
  state.current = null;
  state.sourceOpen = false;
  el('message-view').classList.add('hidden');
  el('read-placeholder').classList.remove('hidden');
  el('app').classList.remove('is-reading');
}

/* ── ileti okuma ─────────────────────────────────────────────── */

async function openMessage(ref) {
  state.selected = ref;
  state.sourceOpen = false;
  el('app').classList.add('is-reading');
  renderList();
  el('read-placeholder').classList.add('hidden');
  el('message-view').classList.remove('hidden');
  el('message-view').innerHTML = '<div class="empty"><span class="spinner"></span></div>';

  try {
    const message = await api(`/api/v1/messages/${encodeURIComponent(ref)}`);
    state.current = message;
    renderMessage(message);
    const listed = state.messages.find((m) => m.ref === ref);
    if (listed && !listed.seen) { listed.seen = true; renderList(); refreshCounts(); }
  } catch (err) {
    el('message-view').innerHTML = `<div class="empty">Açılamadı: ${esc(err.message)}</div>`;
  }
}

function renderMessage(message) {
  const auth = message.authResults || {};
  const badges = [];
  if (auth.spf) badges.push(authBadge('SPF', auth.spf.result, auth.spf.explanation));
  if (auth.dkim) badges.push(authBadge('DKIM', auth.dkim.overall, auth.dkim.reason));
  if (auth.dmarc) badges.push(authBadge('DMARC', auth.dmarc.result, auth.dmarc.reason));
  if (message.smimeStatus && message.smimeStatus !== 'none') badges.push(smimeBadge(message));
  if (message.spamScore) badges.push(badge(message.spamScore >= 5 ? 'bad' : 'warn', `spam puanı ${message.spamScore}`));

  const hasBlocked = /data-blocked-src=/.test(message.html || '');
  const body = message.html
    ? `<div class="msg-body" id="msg-html">${message.html}</div>`
    : `<div class="msg-body"><pre>${esc(message.text || '(boş ileti)')}</pre></div>`;

  const inSpam = message.folder === 'spam';

  el('message-view').innerHTML = `
    <div class="msg-actions">
      <button class="btn btn-sm back-btn" data-act="back">← Liste</button>
      <button class="btn btn-sm" data-act="reply">Yanıtla</button>
      <button class="btn btn-sm" data-act="forward">İlet</button>
      <button class="btn btn-sm" data-act="flag">${message.flagged ? 'İşareti kaldır' : 'İşaretle'}</button>
      <button class="btn btn-sm" data-act="unread">Okunmadı say</button>
      <button class="btn btn-sm" data-act="archive">Arşivle</button>
      <button class="btn btn-sm" data-act="spam">${inSpam ? 'İstenmeyen değil' : 'İstenmeyen'}</button>
      <button class="btn btn-sm" data-act="source">Kaynağı gör</button>
      <button class="btn btn-sm btn-danger" data-act="delete">Sil</button>
    </div>

    <h1 class="msg-subject">${esc(message.subject || '(konu yok)')}</h1>

    <dl class="msg-meta">
      <div class="msg-line"><dt>Gönderen</dt><dd>${esc(formatAddress(message.from))}</dd></div>
      <div class="msg-line"><dt>Alıcı</dt><dd>${esc((message.to || []).map(formatAddress).join(', ') || '—')}</dd></div>
      ${message.cc && message.cc.length ? `<div class="msg-line"><dt>Bilgi</dt><dd>${esc(message.cc.map(formatAddress).join(', '))}</dd></div>` : ''}
      <div class="msg-line"><dt>Tarih</dt><dd>${esc(new Date(message.receivedAt).toLocaleString('tr-TR'))}</dd></div>
      ${badges.length ? `<div class="auth-row">${badges.join('')}</div>` : ''}
    </dl>

    ${hasBlocked ? `<div class="blocked-images">
      <span>Uzak görseller engellendi — bunlar iletinin açıldığını gönderene bildirebilir.</span>
      <span class="spacer"></span>
      <button class="btn btn-sm" id="show-images">Görselleri göster</button>
    </div>` : ''}

    ${body}

    ${message.attachments && message.attachments.length
      ? `<div class="attach-grid">${message.attachments.map(renderAttachment).join('')}</div>`
      : ''}

    <div id="source-slot"></div>
  `;

  for (const button of el('message-view').querySelectorAll('[data-act]')) {
    button.addEventListener('click', () => messageAction(button.dataset.act, message));
  }
  const showImages = el('show-images');
  if (showImages) {
    showImages.addEventListener('click', () => {
      for (const img of el('msg-html').querySelectorAll('img[data-blocked-src]')) {
        img.src = img.dataset.blockedSrc;
        img.removeAttribute('data-blocked-src');
      }
      showImages.closest('.blocked-images').remove();
    });
  }
  for (const preview of el('message-view').querySelectorAll('[data-preview]')) {
    preview.addEventListener('click', (e) => {
      e.preventDefault();
      const img = document.createElement('img');
      img.src = preview.href;
      img.className = 'preview-img';
      preview.after(img);
      preview.remove();
    });
  }
}

function renderAttachment(att) {
  if (att.scanStatus !== 'accepted') {
    return `<div class="attach is-rejected" title="${esc(att.rejectedReason || '')}">
      <span class="attach-info">
        <span class="attach-name">${esc(att.fileName)}</span>
        <span class="attach-size">teslim edilmedi — ${esc(att.rejectedReason || att.scanStatus)}</span>
      </span></div>`;
  }
  const isImage = /^image\//.test(att.contentType) && !/svg/.test(att.contentType);
  return `<a class="attach" href="${esc(att.url)}" ${isImage ? 'data-preview="1"' : 'download'}>
    <span class="attach-info">
      <span class="attach-name">${esc(att.fileName)}</span>
      <span class="attach-size">${formatBytes(att.sizeBytes)}${isImage ? ' · önizle' : ''}</span>
    </span></a>`;
}

/* ── ham kaynak ──────────────────────────────────────────────── */

/**
 * İletinin ham hâlini AYNI SAYFADA gösterir.
 *
 * Önceki sürümde "kaynağı gör" bir bağlantıydı ve sunucu `message/rfc822`
 * döndürüyordu; tarayıcı bunu görüntülemiyor, indiriyordu. Bir imzanın neden
 * geçmediğini anlamak için indirilen dosyayı bir metin düzenleyicide açmak
 * gerekiyordu.
 */
async function toggleSource(message) {
  const slot = el('source-slot');
  if (state.sourceOpen) { slot.innerHTML = ''; state.sourceOpen = false; return; }

  state.sourceOpen = true;
  slot.innerHTML = '<div class="empty"><span class="spinner"></span></div>';
  try {
    const data = await api(`/api/v1/messages/${encodeURIComponent(message.ref)}/raw?format=json`);
    const downloadUrl = `/api/v1/messages/${encodeURIComponent(message.ref)}/raw?format=eml`;
    slot.innerHTML = `
      <div class="source-panel">
        <div class="source-head">
          <span>Ham ileti</span>
          <span class="tiny dim">${formatBytes(data.sizeBytes)}</span>
          <span class="spacer"></span>
          <a class="btn btn-sm" href="${esc(downloadUrl)}" download>.eml indir</a>
          <button class="btn btn-sm" id="source-copy">Kopyala</button>
        </div>
        <pre class="source-body"><span class="hdr">${esc(data.headers)}</span>

${esc(data.body)}</pre>
      </div>`;
    el('source-copy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(data.raw); toast('Kaynak panoya kopyalandı', 'ok'); }
      catch { toast('Panoya kopyalanamadı', 'error'); }
    });
  } catch (err) {
    slot.innerHTML = `<div class="note note-warn">${esc(
      err.code === 'RAW_NOT_STORED'
        ? 'Bu iletinin ham hâli saklanmamış.'
        : `Kaynak alınamadı: ${err.message}`,
    )}</div>`;
  }
}

/* ── ileti eylemleri ─────────────────────────────────────────── */

async function messageAction(action, message) {
  try {
    if (action === 'back') { clearSelection(); return; }
    if (action === 'source') { await toggleSource(message); return; }
    if (action === 'reply') { openCompose({ reply: message }); return; }
    if (action === 'forward') { openForward(message); return; }

    if (action === 'flag') {
      await api(`/api/v1/messages/${encodeURIComponent(message.ref)}/flags`, {
        method: 'POST', json: { flagged: !message.flagged },
      });
      message.flagged = !message.flagged;
      renderMessage(message);
      const listed = state.messages.find((m) => m.ref === message.ref);
      if (listed) { listed.flagged = message.flagged; renderList(); }
      return;
    }
    if (action === 'unread') {
      await api(`/api/v1/messages/${encodeURIComponent(message.ref)}/flags`, {
        method: 'POST', json: { seen: false },
      });
      const listed = state.messages.find((m) => m.ref === message.ref);
      if (listed) { listed.seen = false; renderList(); }
      refreshCounts();
      toast('Okunmadı olarak işaretlendi', 'ok');
      return;
    }
    if (action === 'archive') {
      await api(`/api/v1/messages/${encodeURIComponent(message.ref)}/move`, {
        method: 'POST', json: { folder: 'archive' },
      });
      removeFromList(message.ref);
      toast('Arşivlendi', 'ok');
      return;
    }
    if (action === 'spam') {
      const markSpam = message.folder !== 'spam';
      const result = await api(`/api/v1/messages/${encodeURIComponent(message.ref)}/spam`, {
        method: 'POST', json: { spam: markSpam },
      });
      removeFromList(message.ref);
      toast(
        markSpam
          ? `İstenmeyen olarak işaretlendi${result.verdictSaved ? ` — ${result.sender} artık doğrudan istenmeyene düşecek` : ''}`
          : `İstenmeyen değil${result.verdictSaved ? ` — ${result.sender} artık gelen kutusuna düşecek` : ''}`,
        'ok',
      );
      return;
    }
    if (action === 'delete') {
      const permanent = state.folder === 'trash';
      if (permanent && !await confirmDialog('Kalıcı olarak sil',
        'Bu ileti kalıcı olarak silinecek ve geri alınamayacak.')) return;
      await api(`/api/v1/messages/${encodeURIComponent(message.ref)}${permanent ? '?permanent=1' : ''}`, {
        method: 'DELETE',
      });
      removeFromList(message.ref);
      toast(permanent ? 'Kalıcı olarak silindi' : 'Çöp kutusuna taşındı', 'ok');
    }
  } catch (err) {
    toast(err.message, 'error');
  }
}

function removeFromList(ref) {
  state.messages = state.messages.filter((m) => m.ref !== ref);
  clearSelection();
  renderList();
  refreshCounts();
}

/* ── oluşturma ───────────────────────────────────────────────── */

function openCompose({ reply = null } = {}) {
  state.attachments = [];
  renderAttachChips();
  el('compose-error').classList.add('hidden');
  el('compose-status').textContent = '';

  const fromSelect = el('c-from');
  const sendable = state.me.mailboxes.filter((m) => ['owner', 'delegate', 'sender'].includes(m.role));
  if (!sendable.length) { toast('Bu kimlikle gönderim yetkiniz yok', 'error'); return; }
  fromSelect.innerHTML = sendable
    .map((m) => `<option value="${esc(m.address)}">${esc(m.address)}</option>`).join('');
  fromSelect.value = sendable.some((m) => m.address === state.mailbox.address)
    ? state.mailbox.address : sendable[0].address;

  if (reply) {
    el('c-to').value = reply.replyTo || reply.from.address;
    el('c-subject').value = /^re:/i.test(reply.subject || '') ? reply.subject : `Re: ${reply.subject || ''}`;
    const quoted = (reply.text || '').split('\n').map((l) => `> ${l}`).join('\n');
    el('c-text').value = `\n\n${new Date(reply.receivedAt).toLocaleString('tr-TR')} tarihinde `
      + `${reply.from.address} yazdı:\n${quoted}`;
    el('compose-form').dataset.inReplyTo = reply.messageId || '';
    el('c-text').setSelectionRange(0, 0);
  } else {
    el('compose-form').reset();
    el('compose-form').dataset.inReplyTo = '';
  }

  const smimeAvailable = state.mailbox.smime && state.mailbox.smime.available;
  el('c-smime').disabled = !smimeAvailable;
  el('c-smime').checked = false;
  el('smime-label').title = smimeAvailable
    ? 'İletiyi S/MIME sertifikanızla imzalar'
    : 'Bu adres için S/MIME sertifikası yok — Ayarlar > Sertifika';
  el('smime-label').classList.toggle('dim', !smimeAvailable);

  openModal('compose-modal');
  el('c-to').focus();
}

function renderAttachChips() {
  const total = state.attachments.reduce((sum, f) => sum + f.size, 0);
  el('attach-summary').textContent = state.attachments.length
    ? `${state.attachments.length} ek · ${formatBytes(total)}`
    : '';
  el('attach-list').innerHTML = state.attachments.map((file, i) => {
    const tooBig = file.size > state.me.limits.maxAttachmentBytes;
    return `<div class="attach-chip${tooBig ? ' is-error' : ''}">
      <span class="truncate" style="flex:1">${esc(file.name)}</span>
      <span class="tiny dim">${formatBytes(file.size)}</span>
      ${tooBig ? '<span class="tiny">çok büyük</span>' : ''}
      <button type="button" class="btn btn-ghost btn-sm" data-remove="${i}">✕</button>
    </div>`;
  }).join('');

  for (const button of el('attach-list').querySelectorAll('[data-remove]')) {
    button.addEventListener('click', () => {
      state.attachments.splice(Number(button.dataset.remove), 1);
      renderAttachChips();
    });
  }
}

async function sendCompose() {
  const button = el('compose-send');
  button.disabled = true;
  el('compose-error').classList.add('hidden');
  el('compose-status').innerHTML = '<span class="spinner"></span> gönderiliyor…';

  try {
    const form = new FormData();
    form.set('from', el('c-from').value);
    form.set('to', el('c-to').value);
    form.set('cc', el('c-cc').value);
    form.set('bcc', el('c-bcc').value);
    form.set('subject', el('c-subject').value);
    form.set('text', el('c-text').value);
    form.set('smime', el('c-smime').checked ? '1' : '0');
    form.set('csrfToken', state.me.csrfToken);
    const inReplyTo = el('compose-form').dataset.inReplyTo;
    if (inReplyTo) form.set('inReplyTo', inReplyTo);
    for (const file of state.attachments) form.append('files', file, file.name);

    const mailbox = state.me.mailboxes.find((m) => m.address === el('c-from').value) || state.mailbox;
    const result = await api(`/api/v1/mailboxes/${encodeURIComponent(mailbox.ref)}/send`, {
      method: 'POST',
      body: form,
      headers: { 'x-csrf-token': state.me.csrfToken },
    });

    closeModal('compose-modal');
    toast(`Gönderildi${result.smimeSigned ? ' · S/MIME imzalı' : ''}${result.dkimSigned ? ' · DKIM imzalı' : ''}`, 'ok');
    state.attachments = [];
    if (state.folder === 'sent') loadMessages({ reset: true });
  } catch (err) {
    showNote('compose-error', err.message, 'bad');
  } finally {
    button.disabled = false;
    el('compose-status').textContent = '';
  }
}

/* ── iletme ──────────────────────────────────────────────────── */

let forwardTarget = null;

function openForward(message) {
  forwardTarget = message;
  el('f-to').value = '';
  el('f-comment').value = '';
  el('forward-error').classList.add('hidden');
  el('f-smime').disabled = !(state.mailbox.smime && state.mailbox.smime.available);
  openModal('forward-modal');
  el('f-to').focus();
}

async function sendForward() {
  if (!forwardTarget) return;
  const button = el('forward-send');
  button.disabled = true;
  try {
    const result = await api(`/api/v1/messages/${encodeURIComponent(forwardTarget.ref)}/forward`, {
      method: 'POST',
      json: { to: el('f-to').value, comment: el('f-comment').value, smime: el('f-smime').checked },
    });
    closeModal('forward-modal');
    toast(result.hasOriginalRaw
      ? 'İletildi (özgün ileti ek olarak)'
      : 'İletildi (ham ileti yoktu, gövde yeniden kuruldu)', 'ok');
  } catch (err) {
    showNote('forward-error', err.message, 'bad');
  } finally {
    button.disabled = false;
  }
}

/* ── ayarlar ─────────────────────────────────────────────────── */

async function openSettings() {
  openModal('settings-modal');
  el('settings-body').innerHTML = '<div class="empty"><span class="spinner"></span></div>';

  const mailboxRef = encodeURIComponent(state.mailbox.ref);
  const [certificate, credentials] = await Promise.all([
    api(`/api/v1/mailboxes/${mailboxRef}/certificate`).catch(() => ({ available: false })),
    api(`/api/v1/mailboxes/${mailboxRef}/smtp-credentials`).catch(() => ({ credentials: [] })),
  ]);
  const prefs = state.mailbox.notifyPrefs || {};
  const pushState = await pushSubscriptionState();

  el('settings-body').innerHTML = `
    <section>
      <h3>Bildirimler</h3>
      <label class="check"><input type="checkbox" id="s-notify-mail" ${prefs.mail !== false ? 'checked' : ''}> Yeni posta bildirimi</label><br>
      <label class="check" style="margin-top:6px"><input type="checkbox" checked disabled> Güvenlik uyarıları (kapatılamaz)</label>
      <div class="btn-row" style="margin-top:12px">
        <button class="btn btn-sm" id="s-push-toggle">${pushState.subscribed ? 'Bu cihazda kapat' : 'Bu cihazda aç'}</button>
        <button class="btn btn-sm" id="s-push-test" ${pushState.subscribed ? '' : 'disabled'}>Test bildirimi</button>
      </div>
      ${pushState.reason ? `<p class="hint">${esc(pushState.reason)}</p>` : ''}
    </section>

    <section>
      <h3>S/MIME sertifikası</h3>
      <div id="cert-slot">${renderCertificate(certificate)}</div>
    </section>

    <section>
      <h3>Posta istemcisi</h3>
      <dl class="kv">
        <dt>Sunucu</dt><dd class="mono">${esc(location.hostname)}</dd>
        <dt>Gönderme</dt><dd>587 (STARTTLS) veya 465 (TLS)</dd>
        <dt>Kullanıcı adı</dt><dd class="mono">${esc(state.mailbox.address)}</dd>
      </dl>
      ${credentials.credentials.length ? `<p class="hint">${credentials.credentials.length} kayıtlı kimlik ·
        son kullanım: ${credentials.credentials[0].lastUsedAt ? new Date(credentials.credentials[0].lastUsedAt).toLocaleString('tr-TR') : 'hiç'}</p>` : ''}
      <button class="btn btn-sm" id="s-new-password">Yeni parola üret</button>
      <div id="s-password-out"></div>
    </section>

    <section>
      <h3>Hesap</h3>
      <dl class="kv">
        <dt>Kimlik</dt><dd class="mono">${esc(state.me.email)}</dd>
        <dt>Erişim</dt><dd>${esc(el('mailbox-access').textContent)}</dd>
        <dt>Kullanım</dt><dd>${formatBytes(state.mailbox.usedBytes)} / ${formatBytes(state.mailbox.quotaBytes)}</dd>
        <dt>Kapsamlar</dt><dd class="mono tiny">${esc((state.me.scopes || []).join(' ') || '—')}</dd>
      </dl>
    </section>
  `;

  bindSettings();
}

function renderCertificate(certificate) {
  if (certificate.available) {
    return `
      <dl class="kv">
        <dt>Konu</dt><dd class="mono tiny">${esc(certificate.subject || '—')}</dd>
        <dt>Veren</dt><dd class="mono tiny">${esc(certificate.issuer || '—')}</dd>
        <dt>Seri</dt><dd class="mono tiny">${esc(certificate.serialHex || '—')}</dd>
        <dt>Geçerlilik</dt><dd>${new Date(certificate.notBefore).toLocaleDateString('tr-TR')} — ${new Date(certificate.notAfter).toLocaleDateString('tr-TR')}</dd>
        <dt>Parmak izi</dt><dd class="mono tiny">${esc(certificate.fingerprint || '—')}</dd>
      </dl>
      <div class="btn-row">
        <button class="btn btn-sm" id="s-cert-renew">Yenile</button>
        <a class="btn btn-sm" download="smime.crt"
           href="data:application/x-pem-file;base64,${btoa(unescape(encodeURIComponent(certificate.certPem || '')))}">Sertifikayı indir</a>
        <button class="btn btn-sm" id="s-cert-export">.pfx olarak dışa aktar</button>
      </div>
      ${pfxPanel()}`;
  }
  return `
    <p class="muted">Bu adres için henüz sertifika yok. Sertifika olmadan giden postayı
      S/MIME ile imzalayamazsınız.</p>
    <p class="hint">Sertifika, fitfak kimlik hesabınız adına verilir ve kimlik yönetim
      panelinde görünür. Bunun için oturumunuzun sertifika izni taşıması gerekiyor;
      taşımıyorsa bir onay ekranına yönlendirilirsiniz.</p>
    <button class="btn btn-sm btn-primary" id="s-cert-issue">Sertifika iste</button>
    <div id="cert-error"></div>
    ${pfxPanel()}`;
}

/**
 * .pfx (PKCS#12) alışverişi.
 *
 * Dışa aktarma, ÖZEL ANAHTARIN sunucudan çıktığı tek yol; bu yüzden parola
 * zorunlu ve uyarı görünür yerde. İçe aktarma ise başka bir yerde üretilmiş
 * bir anahtarı sisteme tanıtmanın taşınabilir yolu — Thunderbird, Outlook ve
 * Apple Mail hep bu biçimi kullanıyor.
 */
function pfxPanel() {
  return `
    <details class="pfx-panel">
      <summary>Anahtar dosyası (.pfx) alışverişi</summary>
      <p class="hint">.pfx dosyası sertifikayı VE özel anahtarı birlikte taşır;
        Thunderbird, Outlook, Apple Mail ve telefon profilleri bu biçimi okur.
        Dosya parolayla şifrelenir — parolayı kaybederseniz dosya açılamaz.</p>

      <label class="field">
        <span>Dosya parolası (en az 8 karakter)</span>
        <input type="password" id="s-pfx-password" autocomplete="new-password" minlength="8">
      </label>

      <div class="btn-row">
        <button class="btn btn-sm" id="s-pfx-export">Dışa aktar (.pfx indir)</button>
      </div>

      <label class="field">
        <span>İçe aktarılacak .pfx dosyası</span>
        <input type="file" id="s-pfx-file" accept=".pfx,.p12,application/x-pkcs12">
      </label>
      <div class="btn-row">
        <button class="btn btn-sm" id="s-pfx-import">İçe aktar</button>
      </div>
      <p class="tiny muted">İçe aktarılan sertifikanın bu adresi içermesi ve özel
        anahtarın ona ait olması gerekir; ikisi de doğrulanır.</p>
      <div id="pfx-note"></div>
    </details>`;
}

function bindSettings() {
  const mailboxRef = encodeURIComponent(state.mailbox.ref);

  const notifyMail = el('s-notify-mail');
  if (notifyMail) {
    notifyMail.addEventListener('change', async () => {
      try {
        await api(`/api/v1/mailboxes/${mailboxRef}/settings`, {
          method: 'POST',
          json: { notifyPrefs: { ...state.mailbox.notifyPrefs, mail: notifyMail.checked } },
        });
        state.mailbox.notifyPrefs = { ...state.mailbox.notifyPrefs, mail: notifyMail.checked };
      } catch (err) { toast(err.message, 'error'); }
    });
  }

  for (const id of ['s-cert-issue', 's-cert-renew']) {
    const button = el(id);
    if (!button) continue;
    button.addEventListener('click', () => requestCertificate(button, id === 's-cert-renew'));
  }

  const certExport = el('s-cert-export');
  if (certExport) {
    certExport.addEventListener('click', () => {
      const panel = document.querySelector('.pfx-panel');
      if (panel) { panel.open = true; panel.scrollIntoView({ block: 'nearest' }); }
      const field = el('s-pfx-password');
      if (field) field.focus();
    });
  }

  const pfxExport = el('s-pfx-export');
  if (pfxExport) pfxExport.addEventListener('click', () => exportPfx(pfxExport));

  const pfxImport = el('s-pfx-import');
  if (pfxImport) pfxImport.addEventListener('click', () => importPfx(pfxImport));

  const pushToggle = el('s-push-toggle');
  if (pushToggle) pushToggle.addEventListener('click', togglePush);

  const pushTest = el('s-push-test');
  if (pushTest) {
    pushTest.addEventListener('click', async () => {
      try {
        const result = await api('/api/v1/push/test', { method: 'POST', json: { mailbox: state.mailbox.ref } });
        toast(result.sent ? 'Test bildirimi gönderildi' : 'Abonelik bulunamadı', result.sent ? 'ok' : 'error');
      } catch (err) { toast(err.message, 'error'); }
    });
  }

  const newPassword = el('s-new-password');
  if (newPassword) {
    newPassword.addEventListener('click', async () => {
      if (!await confirmDialog('Yeni parola üret',
        'Yeni bir parola üretilecek ve önceki parola geçersiz olacak. Bu adresi kullanan posta istemcilerini yeniden ayarlamanız gerekir.')) return;
      try {
        const result = await api(`/api/v1/mailboxes/${mailboxRef}/smtp-credentials`, {
          method: 'POST', json: { label: 'posta istemcisi' },
        });
        el('s-password-out').innerHTML = `
          <div class="reveal"><span class="label">kullanıcı adı</span>${esc(result.username)}</div>
          <div class="reveal"><span class="label">parola</span>${esc(result.password)}</div>
          <p class="hint">${esc(result.note)}</p>`;
      } catch (err) { toast(err.message, 'error'); }
    });
  }
}

/**
 * Sertifika isteği.
 *
 * Sertifika, kullanıcının KENDİ fitfak kimlik jetonuyla isteniyor; sunucu
 * kendi servis kimliğiyle sormuyor. Sunucunun kimliği bir kullanıcıyı
 * temsil etmediği için kimlik sağlayıcı onu "kullanıcı bulunamadı" diye
 * reddediyordu.
 *
 * Oturum `cert:issue` kapsamını taşımıyorsa sunucu 409 ve bir yetkilendirme
 * adresi döndürüyor. Kullanıcıyı giriş ekranına atmak yerine yalnızca eksik
 * olan izin isteniyor; dönüşte aynı oturum devam ediyor.
 */
async function requestCertificate(button, force) {
  const original = button.textContent;
  button.disabled = true;
  button.innerHTML = '<span class="spinner"></span> isteniyor…';
  const slot = el('cert-error');
  if (slot) slot.innerHTML = '';

  try {
    await api(`/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/certificate/issue`, {
      method: 'POST', json: { force, returnTo: location.pathname },
    });
    toast('S/MIME sertifikası verildi', 'ok');
    state.me = await api('/api/v1/me');
    state.mailbox = state.me.mailboxes.find((m) => m.ref === state.mailbox.ref) || state.mailbox;
    openSettings();
    return;
  } catch (err) {
    const authorizeUrl = err.detail && err.detail.authorizeUrl;
    if (authorizeUrl) {
      // Yetki onayına gitmeden önce hangi kutu için sertifika istendiğini hafızaya alıyoruz
      sessionStorage.setItem('pending_cert_issue', state.mailbox.ref);

      // HANGİ HESAPLA onaylanacağı açıkça yazılır. fitfak kimlikte birden
      // fazla hesap açık olabiliyor ve onay ekranında yanlış hesabı seçmek,
      // sertifikanın başkasına yazılmasına yol açıyordu. Sunucu artık bunu
      // reddediyor; kullanıcının en baştan doğru hesabı seçmesi için de
      // adresi burada gösteriyoruz.
      const approveAs = err.detail && err.detail.approveAs;
      renderCertNote(
        `${err.message} Sertifika alabilmek için fitfak kimlik hesabınızdan bir kez izin vermeniz gerekiyor.`
        + (approveAs ? ` Onayı <strong>${esc(approveAs)}</strong> hesabıyla verin.` : ''),
        'info',
        `<a class="btn btn-sm btn-primary" href="${esc(authorizeUrl)}">İzin ver ve dön</a>`,
      );
    } else {
      renderCertNote(err.message, 'bad', err.detail && err.detail.hint
        ? `<span class="tiny">${esc(err.detail.hint)}</span>` : '');
    }
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

/**
 * .pfx indirir.
 *
 * `api()` KULLANILMIYOR: yanıt JSON değil ikili bir dosya ve onu metne
 * çevirmek baytları bozar. İndirme, bellekteki bir Blob üzerinden yapılıyor
 * ve nesne adresi hemen serbest bırakılıyor — bırakılmazsa özel anahtar
 * içeren blob, sekme kapanana kadar bellekte kalır.
 */
async function exportPfx(button) {
  const password = (el('s-pfx-password') || {}).value || '';
  if (password.length < 8) { renderPfxNote('Dosya parolası en az 8 karakter olmalı.', 'bad'); return; }

  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'hazırlanıyor…';
  try {
    const res = await fetch(
      `/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/certificate/export`,
      {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'content-type': 'application/json', 'x-csrf-token': state.me.csrfToken },
        body: JSON.stringify({ password }),
      },
    );
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${state.mailbox.address.replace('@', '-at-')}.pfx`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    renderPfxNote('Dosya indirildi. Parolasını güvenli bir yerde saklayın — '
      + 'dosya o parola olmadan açılamaz.', 'ok');
    el('s-pfx-password').value = '';
  } catch (err) {
    renderPfxNote(err.message, 'bad');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

/** Seçilen .pfx dosyasını sunucuya gönderir. */
async function importPfx(button) {
  const input = el('s-pfx-file');
  const file = input && input.files && input.files[0];
  if (!file) { renderPfxNote('Önce bir .pfx dosyası seçin.', 'bad'); return; }

  const original = button.textContent;
  button.disabled = true;
  button.textContent = 'aktarılıyor…';
  try {
    const form = new FormData();
    form.set('file', file, file.name);
    form.set('password', (el('s-pfx-password') || {}).value || '');
    const res = await fetch(
      `/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/certificate/import`,
      {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'x-csrf-token': state.me.csrfToken },
        body: form,
      },
    );
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

    renderPfxNote(
      `Sertifika içe aktarıldı (sürüm ${data.version}${data.chainLength ? `, ${data.chainLength} ara sertifika` : ''}).`,
      'ok',
    );
    state.me = await api('/api/v1/me');
    state.mailbox = state.me.mailboxes.find((m) => m.ref === state.mailbox.ref) || state.mailbox;
    input.value = '';
    el('s-pfx-password').value = '';
  } catch (err) {
    renderPfxNote(err.message, 'bad');
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderPfxNote(message, kind) {
  const slot = el('pfx-note');
  if (!slot) return;
  slot.innerHTML = `<div class="note note-${kind}">${esc(message)}</div>`;
}

function renderCertNote(message, kind, actionsHtml) {
  const slot = el('cert-error');
  if (!slot) { toast(message, kind === 'bad' ? 'error' : 'ok'); return; }
  slot.innerHTML = `<div class="note note-${kind}">${esc(message)}
    ${actionsHtml ? `<div class="note-actions">${actionsHtml}</div>` : ''}</div>`;
}

/* ── bildirim aboneliği ──────────────────────────────────────── */

async function pushSubscriptionState() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    return { subscribed: false, reason: 'Tarayıcınız bildirimleri desteklemiyor' };
  }
  if (Notification.permission === 'denied') {
    return { subscribed: false, reason: 'Bildirim izni reddedilmiş' };
  }
  try {
    const registration = await navigator.serviceWorker.ready;
    return { subscribed: !!(await registration.pushManager.getSubscription()), reason: '' };
  } catch {
    return { subscribed: false, reason: '' };
  }
}

async function togglePush() {
  const button = el('s-push-toggle');
  button.disabled = true;
  try {
    const registration = await navigator.serviceWorker.ready;
    const existing = await registration.pushManager.getSubscription();

    if (existing) {
      await api('/api/v1/push/unsubscribe', { method: 'POST', json: { endpoint: existing.endpoint } });
      await existing.unsubscribe();
      toast('Bildirimler kapatıldı', 'ok');
    } else {
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') { toast('Bildirim izni verilmedi', 'error'); return; }
      const { publicKey } = await api('/api/v1/push/public-key');
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(publicKey),
      });
      await api('/api/v1/push/subscribe', {
        method: 'POST',
        json: { subscription: subscription.toJSON(), mailbox: state.mailbox.ref, topics: ['mail', 'security'] },
      });
      toast('Bildirimler açıldı', 'ok');
    }
    openSettings();
  } catch (err) {
    toast(err.message, 'error');
  } finally {
    button.disabled = false;
  }
}

function urlBase64ToUint8Array(base64) {
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const normalized = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(normalized);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  navigator.serviceWorker.register('/sw.js').catch(() => {});
}

/* ── gerçek zamanlı ──────────────────────────────────────────── */

function connectRealtime() {
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const socket = new WebSocket(`${protocol}//${location.host}/ws`);
  state.socket = socket;

  socket.addEventListener('open', () => {
    state.reconnectAttempt = 0;
    setConnStatus('live', 'canlı');
    if (state.lastSeq) {
      socket.send(JSON.stringify({ type: 'catchup', mailboxRef: state.mailbox.ref, sinceSeq: state.lastSeq }));
    }
  });

  socket.addEventListener('message', (event) => {
    let payload;
    try { payload = JSON.parse(event.data); } catch { return; }

    if (payload.type === 'message' && payload.mailboxRef === state.mailbox.ref) {
      onIncoming(payload.message);
    } else if (payload.type === 'catchup') {
      for (const message of payload.messages || []) onIncoming(message, { silent: true });
      if (payload.lastSeq > state.lastSeq) state.lastSeq = payload.lastSeq;
      if ((payload.messages || []).length) toast(`${payload.messages.length} yeni ileti alındı`, 'ok');
    } else if (payload.type === 'update' && payload.mailboxRef === state.mailbox.ref) {
      refreshCounts();
    }
  });

  const reconnect = () => {
    setConnStatus('down', 'bağlantı yok');
    state.reconnectAttempt++;
    const ceiling = Math.min(30_000, 1000 * 2 ** Math.min(5, state.reconnectAttempt));
    setTimeout(connectRealtime, Math.random() * ceiling);
  };
  socket.addEventListener('close', reconnect);
  socket.addEventListener('error', () => socket.close());

  const heartbeat = setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: 'ping' }));
    else clearInterval(heartbeat);
  }, 25_000);
}

function onIncoming(message, { silent = false } = {}) {
  if (message.seq > state.lastSeq) state.lastSeq = message.seq;
  if (state.messages.some((m) => m.ref === message.ref)) return;
  if (state.folder !== message.folder) { refreshCounts(); return; }

  state.messages.unshift(message);
  renderList();
  refreshCounts();
  if (!silent) {
    toast(`Yeni ileti: ${message.subject || '(konu yok)'}`, 'ok');
    document.title = 'Yeni ileti — Fitfak Posta';
    setTimeout(() => { document.title = 'Fitfak Posta'; }, 5000);
  }
}

function setConnStatus(kind, text) {
  el('conn-status').className = `conn is-${kind}`;
  el('conn-text').textContent = text;
}

/* ── kip pencereleri ─────────────────────────────────────────── */

function openModal(id) { el(id).classList.add('is-open'); }
function closeModal(id) { el(id).classList.remove('is-open'); }
function closeAllModals() {
  for (const modal of document.querySelectorAll('.modal-backdrop')) modal.classList.remove('is-open');
}

/**
 * `confirm()` yerine.
 *
 * Tarayıcının kendi penceresi sayfanın tasarımıyla ilgisiz görünüyor ve
 * bazı tarayıcılarda tekrarlandığında bastırılıyor — yani "kalıcı olarak
 * sil" onayı hiç sorulmadan geçebiliyor.
 */
function confirmDialog(title, message) {
  return new Promise((resolve) => {
    el('confirm-title').textContent = title;
    el('confirm-body').innerHTML = `<p class="muted">${esc(message)}</p>`;
    openModal('confirm-modal');

    const finish = (value) => {
      closeModal('confirm-modal');
      el('confirm-ok').removeEventListener('click', onOk);
      el('confirm-cancel').removeEventListener('click', onCancel);
      resolve(value);
    };
    const onOk = () => finish(true);
    const onCancel = () => finish(false);
    el('confirm-ok').addEventListener('click', onOk);
    el('confirm-cancel').addEventListener('click', onCancel);
  });
}

function showNote(id, message, kind) {
  const node = el(id);
  node.textContent = message;
  node.className = `note note-${kind}`;
}

/* ── olay bağlama ────────────────────────────────────────────── */

function bindEvents() {
  el('mailbox-select').addEventListener('change', async (e) => {
    state.mailbox = state.me.mailboxes.find((m) => m.ref === e.target.value);
    clearSelection();
    state.lastSeq = 0;
    renderAccessNote();
    renderQuota();
    if (state.socket && state.socket.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify({ type: 'subscribe', mailboxRefs: [state.mailbox.ref] }));
    }
    await Promise.all([loadMessages({ reset: true }), refreshCounts()]);
  });

  el('compose-btn').addEventListener('click', () => openCompose());
  el('compose-close').addEventListener('click', () => closeModal('compose-modal'));
  el('compose-cancel').addEventListener('click', () => closeModal('compose-modal'));
  el('compose-send').addEventListener('click', (e) => { e.preventDefault(); sendCompose(); });
  el('compose-form').addEventListener('submit', (e) => { e.preventDefault(); sendCompose(); });

  el('toggle-cc').addEventListener('click', () => el('cc-row').classList.toggle('hidden'));
  el('toggle-bcc').addEventListener('click', () => el('bcc-row').classList.toggle('hidden'));
  el('c-files').addEventListener('change', (e) => {
    for (const file of e.target.files) state.attachments.push(file);
    e.target.value = '';
    renderAttachChips();
  });

  el('forward-close').addEventListener('click', () => closeModal('forward-modal'));
  el('forward-cancel').addEventListener('click', () => closeModal('forward-modal'));
  el('forward-send').addEventListener('click', sendForward);

  el('settings-btn').addEventListener('click', openSettings);
  el('settings-close').addEventListener('click', () => closeModal('settings-modal'));

  for (const backdrop of document.querySelectorAll('.modal-backdrop')) {
    backdrop.addEventListener('click', (e) => {
      // Onay penceresi dışarı tıklamayla kapanmaz: "vazgeç" ile "onayla"
      // arasındaki farkı kazayla vermek istemiyoruz.
      if (e.target === backdrop && backdrop.id !== 'confirm-modal') backdrop.classList.remove('is-open');
    });
  }

  el('refresh-btn').addEventListener('click', () => { loadMessages({ reset: true }); refreshCounts(); });
  el('load-more').addEventListener('click', () => loadMessages());

  el('read-all-btn').addEventListener('click', async () => {
    try {
      const result = await api(`/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/read-all`, {
        method: 'POST', json: { folder: state.folder },
      });
      toast(`${result.changed} ileti okundu sayıldı`, 'ok');
      loadMessages({ reset: true });
      refreshCounts();
    } catch (err) { toast(err.message, 'error'); }
  });

  let searchTimer;
  el('search').addEventListener('input', (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.query = e.target.value.trim();
      loadMessages({ reset: true });
    }, 320);
  });

  for (const chip of document.querySelectorAll('.chip[data-filter]')) {
    chip.addEventListener('click', () => {
      for (const other of document.querySelectorAll('.chip[data-filter]')) other.classList.remove('is-active');
      chip.classList.add('is-active');
      state.filter = chip.dataset.filter;
      loadMessages({ reset: true });
    });
  }

  el('menu-btn').addEventListener('click', () => el('app').classList.toggle('is-menu-open'));

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeAllModals();
      el('app').classList.remove('is-menu-open');
    }
    if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) return;
    if (document.querySelector('.modal-backdrop.is-open')) return;
    if (e.key === 'c') { e.preventDefault(); openCompose(); }
    if (e.key === '/') { e.preventDefault(); el('search').focus(); }
    if (e.key === 'r') { e.preventDefault(); loadMessages({ reset: true }); }
    if (e.key === 'u' && state.current) { e.preventDefault(); clearSelection(); }
  });
}

/* ── biçimlendirme ───────────────────────────────────────────── */

function badge(kind, text) { return `<span class="badge badge-${kind}">${esc(text)}</span>`; }

function authBadge(label, result, reason) {
  const kind = result === 'pass' ? 'ok'
    : (['fail', 'permerror', 'softfail'].includes(result) ? 'bad' : 'warn');
  const title = reason ? `${label}: ${result} — ${reason}` : `${label}: ${result}`;
  return `<span class="badge badge-${kind}" title="${esc(title)}">${label} ${esc(result)}</span>`;
}

function smimeBadge(message) {
  const map = {
    'signed-valid': ['ok', 'S/MIME geçerli'],
    'signed-invalid': ['bad', 'S/MIME geçersiz'],
    'signed-untrusted': ['warn', 'S/MIME imzalayan güvenilmiyor'],
    'signed-address-mismatch': ['bad', 'S/MIME adres uyuşmuyor'],
    'signed-expired': ['warn', 'S/MIME süresi dolmuş'],
    'signed-local': ['ok', 'S/MIME imzalandı'],
    encrypted: ['info', 'şifreli'],
  };
  const [kind, label] = map[message.smimeStatus] || ['neutral', message.smimeStatus];
  const signer = message.smimeSigner && message.smimeSigner.emails
    ? ` — ${message.smimeSigner.emails.join(', ')}` : '';
  return `<span class="badge badge-${kind}" title="${esc(label + signer)}">${esc(label)}</span>`;
}

function formatAddress(a) {
  if (!a) return '—';
  if (typeof a === 'string') return a;
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function formatDate(ts) {
  const date = new Date(ts);
  const now = new Date();
  if (date.toDateString() === now.toDateString()) {
    return date.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
  }
  if (date.getFullYear() === now.getFullYear()) {
    return date.toLocaleDateString('tr-TR', { day: 'numeric', month: 'short' });
  }
  return date.toLocaleDateString('tr-TR', { day: 'numeric', month: 'short', year: '2-digit' });
}

function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n >= 1073741824) return `${(n / 1073741824).toFixed(1)} GB`;
  if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n >= 1024) return `${Math.round(n / 1024)} KB`;
  return `${n} B`;
}

function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function toast(message, kind = '') {
  const node = document.createElement('div');
  node.className = `toast${kind ? ` is-${kind}` : ''}`;
  node.textContent = message;
  el('toasts').append(node);
  setTimeout(() => {
    node.style.opacity = '0';
    setTimeout(() => node.remove(), 200);
  }, 4200);
}

boot();
