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
  cursor: null,
  lastSeq: 0,
  socket: null,
  reconnectAttempt: 0,
  attachments: [],
  loading: false,
};

const el = (id) => document.getElementById(id);
const $ = (sel, root = document) => root.querySelector(sel);

const FOLDERS = [
  { key: 'inbox', label: 'Gelen kutusu', icon: '📥' },
  { key: 'sent', label: 'Gönderilenler', icon: '📤' },
  { key: 'drafts', label: 'Taslaklar', icon: '📝' },
  { key: 'archive', label: 'Arşiv', icon: '🗄' },
  { key: 'spam', label: 'İstenmeyen', icon: '⚠' },
  { key: 'trash', label: 'Çöp kutusu', icon: '🗑' },
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
  if (res.status === 401) { showLogin(); throw new Error('Oturum gerekli'); }

  const contentType = res.headers.get('content-type') || '';
  const data = contentType.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    const message = (data && data.error) || `HTTP ${res.status}`;
    const err = new Error(message);
    err.code = data && data.code;
    err.status = res.status;
    throw err;
  }
  return data;
}

/* ── önyükleme ───────────────────────────────────────────────── */

async function boot() {
  try {
    state.me = await api('/api/v1/me');
  } catch {
    showLogin();
    return;
  }
  if (!state.me.mailboxes.length) {
    el('boot').innerHTML = `<div class="ff-card" style="text-align:center">
      <h1>Posta kutusu yok</h1>
      <p class="ff-muted">Bu kimliğe tanımlı bir posta kutusu bulunmuyor.</p>
      <a class="ff-btn" href="/cikis">Çıkış yap</a></div>`;
    return;
  }

  el('boot').classList.add('ff-hidden');
  el('app').hidden = false;
  el('account-email').textContent = state.me.email;
  el('brand-host').textContent = location.host;

  state.mailbox = state.me.mailboxes[0];
  renderMailboxPicker();
  renderFolders();
  bindEvents();
  connectRealtime();
  await Promise.all([loadMessages({ reset: true }), refreshCounts()]);
  registerServiceWorker();
}

function showLogin() {
  el('boot').classList.add('ff-hidden');
  el('app').hidden = true;
  el('login-screen').classList.remove('ff-hidden');
}

/* ── kenar çubuğu ────────────────────────────────────────────── */

function renderMailboxPicker() {
  const select = el('mailbox-select');
  select.innerHTML = state.me.mailboxes
    .map((m) => `<option value="${escapeAttr(m.ref)}">${escapeHtml(m.address)}</option>`).join('');
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
    const badge = f.key === 'inbox' || f.key === 'spam'
      ? (stat.unread ? `<span class="wm-folder-count">${stat.unread}</span>` : '')
      : (stat.total ? `<span class="wm-folder-count">${stat.total}</span>` : '');
    return `<button class="wm-folder${f.key === state.folder ? ' is-active' : ''}" data-folder="${f.key}">
      <span class="wm-folder-icon">${f.icon}</span><span>${f.label}</span>${badge}
    </button>`;
  }).join('');

  for (const button of document.querySelectorAll('.wm-folder')) {
    button.addEventListener('click', () => {
      state.folder = button.dataset.folder;
      state.selected = null;
      renderFolders();
      el('message-view').classList.add('ff-hidden');
      el('read-placeholder').classList.remove('ff-hidden');
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
    <div class="wm-quota-bar"><div class="wm-quota-fill${pct >= 90 ? ' is-full' : ''}" style="width:${pct}%"></div></div>`;
}

async function refreshCounts() {
  try {
    const counts = await api(`/api/v1/mailboxes/${encodeURIComponent(state.mailbox.ref)}/counts`);
    state.mailbox.counts = counts;
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
    // Sıra numarası kaçırılan iletileri istemek için: en yükseğini tut.
    for (const message of data.messages) {
      if (message.seq > state.lastSeq) state.lastSeq = message.seq;
    }
    renderList();
    el('list-summary').textContent = `${state.messages.length} / ${data.total} ileti`;
    el('load-more').classList.toggle('ff-hidden', !data.nextCursor);
  } catch (err) {
    toast(err.message, 'error');
    el('message-list').innerHTML = `<div class="ff-empty">Yüklenemedi: ${escapeHtml(err.message)}</div>`;
  } finally {
    state.loading = false;
  }
}

function renderList() {
  if (!state.messages.length) {
    el('message-list').innerHTML = '<div class="ff-empty">Bu klasörde ileti yok.</div>';
    return;
  }
  el('message-list').innerHTML = state.messages.map((m) => {
    const marks = [];
    if (m.hasAttachments) marks.push('<span class="ff-badge">📎 ' + m.attachmentCount + '</span>');
    if (m.flagged) marks.push('<span class="ff-badge ff-badge-accent">★</span>');
    if (m.smimeStatus === 'signed-valid') marks.push('<span class="ff-badge ff-badge-ok">🔏 imzalı</span>');
    else if (m.smimeStatus && m.smimeStatus.startsWith('signed-')) marks.push('<span class="ff-badge ff-badge-warn">🔏 şüpheli</span>');
    if (m.folder === 'spam') marks.push('<span class="ff-badge ff-badge-danger">spam</span>');

    const who = state.folder === 'sent'
      ? (m.to && m.to.length ? m.to.map((t) => t.address).join(', ') : '—')
      : (m.from.name || m.from.address || '(bilinmiyor)');

    return `<div class="wm-item${m.seen ? '' : ' is-unread'}${state.selected === m.ref ? ' is-selected' : ''}"
                 role="listitem" data-ref="${escapeAttr(m.ref)}" tabindex="0">
      <div class="wm-item-top">
        <span class="wm-item-from ff-truncate">${escapeHtml(who)}</span>
        <span class="wm-item-date">${formatDate(m.receivedAt)}</span>
      </div>
      <div class="wm-item-subject ff-truncate">${escapeHtml(m.subject || '(konu yok)')}</div>
      <div class="wm-item-preview ff-truncate">${escapeHtml(m.preview || '')}</div>
      ${marks.length ? `<div class="wm-item-marks">${marks.join('')}</div>` : ''}
    </div>`;
  }).join('');

  for (const item of document.querySelectorAll('.wm-item')) {
    const open = () => openMessage(item.dataset.ref);
    item.addEventListener('click', open);
    item.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
  }
}

function skeleton() {
  return Array.from({ length: 6 }).map(() => `<div class="wm-item">
    <div class="wm-item-top"><span class="wm-item-from ff-dim">yükleniyor…</span></div>
    <div class="wm-item-subject ff-dim">&nbsp;</div></div>`).join('');
}

/* ── ileti okuma ─────────────────────────────────────────────── */

async function openMessage(ref) {
  state.selected = ref;
  document.getElementById('app').classList.add('is-reading');
  renderList();
  el('read-placeholder').classList.add('ff-hidden');
  el('message-view').classList.remove('ff-hidden');
  el('message-view').innerHTML = '<div class="ff-empty"><span class="ff-spinner"></span></div>';

  try {
    const message = await api(`/api/v1/messages/${encodeURIComponent(ref)}`);
    renderMessage(message);
    const listed = state.messages.find((m) => m.ref === ref);
    if (listed && !listed.seen) { listed.seen = true; renderList(); refreshCounts(); }
  } catch (err) {
    el('message-view').innerHTML = `<div class="ff-empty">Açılamadı: ${escapeHtml(err.message)}</div>`;
  }
}

function renderMessage(message) {
  const auth = message.authResults || {};
  const badges = [];
  if (auth.spf) badges.push(authBadge('SPF', auth.spf.result));
  if (auth.dkim) badges.push(authBadge('DKIM', auth.dkim.overall));
  if (auth.dmarc) badges.push(authBadge('DMARC', auth.dmarc.result));
  if (message.smimeStatus && message.smimeStatus !== 'none') badges.push(smimeBadge(message));

  const hasBlocked = /data-blocked-src=/.test(message.html || '');
  const body = message.html
    ? `<div class="wm-msg-body" id="msg-html">${message.html}</div>`
    : `<div class="wm-msg-body"><pre>${escapeHtml(message.text || '(boş ileti)')}</pre></div>`;

  el('message-view').innerHTML = `
    <h1 class="wm-msg-subject">${escapeHtml(message.subject || '(konu yok)')}</h1>
    <dl class="wm-msg-meta">
      <div class="wm-msg-line"><dt>Gönderen</dt><dd>${escapeHtml(formatAddress(message.from))}</dd></div>
      <div class="wm-msg-line"><dt>Alıcı</dt><dd>${escapeHtml((message.to || []).map(formatAddress).join(', ') || '—')}</dd></div>
      ${message.cc && message.cc.length ? `<div class="wm-msg-line"><dt>Bilgi</dt><dd>${escapeHtml(message.cc.map(formatAddress).join(', '))}</dd></div>` : ''}
      <div class="wm-msg-line"><dt>Tarih</dt><dd>${escapeHtml(new Date(message.receivedAt).toLocaleString('tr-TR'))}</dd></div>
      ${badges.length ? `<div class="wm-auth-row">${badges.join('')}</div>` : ''}
    </dl>

    <div class="wm-msg-actions">
      <button class="ff-btn ff-btn-sm" data-act="reply">↩ Yanıtla</button>
      <button class="ff-btn ff-btn-sm" data-act="forward">↪ İlet</button>
      <button class="ff-btn ff-btn-sm" data-act="flag">${message.flagged ? '★ İşareti kaldır' : '☆ İşaretle'}</button>
      <button class="ff-btn ff-btn-sm" data-act="unread">◍ Okunmadı say</button>
      <button class="ff-btn ff-btn-sm" data-act="archive">🗄 Arşivle</button>
      <button class="ff-btn ff-btn-sm ff-btn-danger" data-act="delete">🗑 Sil</button>
      <a class="ff-btn ff-btn-sm ff-btn-ghost" href="/api/v1/messages/${encodeURIComponent(message.ref)}/raw" target="_blank" rel="noopener">Kaynağı gör</a>
    </div>

    ${hasBlocked ? `<div class="wm-blocked-images ff-note ff-note-warn">
      <span>Uzak görseller engellendi — bunlar iletinin açıldığını gönderene bildirebilir.</span>
      <button class="ff-btn ff-btn-sm" id="show-images">Görselleri göster</button>
    </div>` : ''}

    ${body}

    ${message.attachments && message.attachments.length ? `<div class="wm-attach-grid">
      ${message.attachments.map(renderAttachment).join('')}
    </div>` : ''}
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
      showImages.closest('.wm-blocked-images').remove();
    });
  }
  for (const preview of el('message-view').querySelectorAll('[data-preview]')) {
    preview.addEventListener('click', (e) => {
      e.preventDefault();
      const img = document.createElement('img');
      img.src = preview.href;
      img.className = 'wm-preview-img';
      preview.after(img);
      preview.remove();
    });
  }
}

function renderAttachment(att) {
  if (att.scanStatus !== 'accepted') {
    return `<div class="wm-attach is-rejected" title="${escapeAttr(att.rejectedReason || '')}">
      <span class="wm-attach-icon">🚫</span>
      <span class="wm-attach-info">
        <span class="wm-attach-name">${escapeHtml(att.fileName)}</span>
        <span class="wm-attach-size">teslim edilmedi — ${escapeHtml(att.rejectedReason || att.scanStatus)}</span>
      </span></div>`;
  }
  const isImage = /^image\//.test(att.contentType) && !/svg/.test(att.contentType);
  return `<a class="wm-attach" href="${escapeAttr(att.url)}" ${isImage ? 'data-preview="1"' : 'download'}>
    <span class="wm-attach-icon">${iconFor(att.contentType)}</span>
    <span class="wm-attach-info">
      <span class="wm-attach-name">${escapeHtml(att.fileName)}</span>
      <span class="wm-attach-size">${formatBytes(att.sizeBytes)}${isImage ? ' · önizle' : ''}</span>
    </span></a>`;
}

async function messageAction(action, message) {
  try {
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
    if (action === 'delete') {
      const permanent = state.folder === 'trash';
      if (permanent && !confirm('Bu ileti kalıcı olarak silinecek. Emin misiniz?')) return;
      await api(`/api/v1/messages/${encodeURIComponent(message.ref)}${permanent ? '?permanent=1' : ''}`, {
        method: 'DELETE',
      });
      removeFromList(message.ref);
      toast(permanent ? 'Kalıcı olarak silindi' : 'Çöp kutusuna taşındı', 'ok');
      return;
    }
    if (action === 'reply') { openCompose({ reply: message }); return; }
    if (action === 'forward') { openForward(message); }
  } catch (err) {
    toast(err.message, 'error');
  }
}

function removeFromList(ref) {
  state.messages = state.messages.filter((m) => m.ref !== ref);
  state.selected = null;
  renderList();
  el('message-view').classList.add('ff-hidden');
  el('read-placeholder').classList.remove('ff-hidden');
  document.getElementById('app').classList.remove('is-reading');
  refreshCounts();
}

/* ── oluşturma ───────────────────────────────────────────────── */

function openCompose({ reply = null } = {}) {
  state.attachments = [];
  renderAttachChips();
  el('compose-error').classList.add('ff-hidden');
  el('compose-status').textContent = '';

  const fromSelect = el('c-from');
  fromSelect.innerHTML = state.me.mailboxes
    .filter((m) => ['owner', 'delegate', 'sender'].includes(m.role))
    .map((m) => `<option value="${escapeAttr(m.address)}">${escapeHtml(m.address)}</option>`).join('');
  if (!fromSelect.options.length) {
    toast('Bu kimlikle gönderim yetkiniz yok', 'error');
    return;
  }
  fromSelect.value = state.mailbox.address;

  if (reply) {
    el('c-to').value = reply.replyTo || reply.from.address;
    el('c-subject').value = /^re:/i.test(reply.subject) ? reply.subject : `Re: ${reply.subject}`;
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
  el('c-smime').closest('label').title = smimeAvailable
    ? 'İletiyi S/MIME sertifikanızla imzalar'
    : 'Bu adres için S/MIME sertifikası yok';

  el('compose-modal').classList.remove('ff-hidden');
  el('c-to').focus();
}

function renderAttachChips() {
  const total = state.attachments.reduce((sum, f) => sum + f.size, 0);
  el('attach-summary').textContent = state.attachments.length
    ? `${state.attachments.length} ek · ${formatBytes(total)}`
    : '';
  el('attach-list').innerHTML = state.attachments.map((file, i) => {
    const tooBig = file.size > state.me.limits.maxAttachmentBytes;
    return `<div class="wm-attach-chip${tooBig ? ' is-error' : ''}">
      <span>${iconFor(file.type)}</span>
      <span class="ff-truncate" style="flex:1">${escapeHtml(file.name)}</span>
      <span class="ff-tiny ff-dim">${formatBytes(file.size)}</span>
      ${tooBig ? '<span class="ff-tiny">çok büyük</span>' : ''}
      <button type="button" class="ff-btn ff-btn-ghost ff-btn-sm" data-remove="${i}">✕</button>
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
  el('compose-error').classList.add('ff-hidden');
  el('compose-status').innerHTML = '<span class="ff-spinner"></span> gönderiliyor…';

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

    el('compose-modal').classList.add('ff-hidden');
    toast(
      `Gönderildi${result.smimeSigned ? ' · S/MIME imzalı' : ''}${result.dkimSigned ? ' · DKIM imzalı' : ''}`,
      'ok',
    );
    state.attachments = [];
    if (state.folder === 'sent') loadMessages({ reset: true });
  } catch (err) {
    el('compose-error').textContent = err.message;
    el('compose-error').className = 'ff-note ff-note-danger';
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
  el('forward-error').classList.add('ff-hidden');
  el('f-smime').disabled = !(state.mailbox.smime && state.mailbox.smime.available);
  el('forward-modal').classList.remove('ff-hidden');
  el('f-to').focus();
}

async function sendForward() {
  if (!forwardTarget) return;
  const button = el('forward-send');
  button.disabled = true;
  try {
    const result = await api(`/api/v1/messages/${encodeURIComponent(forwardTarget.ref)}/forward`, {
      method: 'POST',
      json: {
        to: el('f-to').value,
        comment: el('f-comment').value,
        smime: el('f-smime').checked,
      },
    });
    el('forward-modal').classList.add('ff-hidden');
    toast(result.hasOriginalRaw
      ? 'İletildi (özgün ileti ek olarak)'
      : 'İletildi (ham ileti yoktu, gövde yeniden kuruldu)', 'ok');
  } catch (err) {
    el('forward-error').textContent = err.message;
    el('forward-error').className = 'ff-note ff-note-danger';
  } finally {
    button.disabled = false;
  }
}

/* ── sertifika device code akışı ─────────────────────────────── */

let certPollTimer = null;

function openCertDeviceModal() {
  el('cert-device-modal').classList.remove('ff-hidden');
  el('cert-step-init').classList.remove('ff-hidden');
  el('cert-step-waiting').classList.add('ff-hidden');
  el('cert-error-note').classList.add('ff-hidden');
}

function closeCertDeviceModal() {
  el('cert-device-modal').classList.add('ff-hidden');
  if (certPollTimer) {
    clearInterval(certPollTimer);
    certPollTimer = null;
  }
}

async function startCertDeviceFlow() {
  const startBtn = el('cert-start-btn');
  startBtn.disabled = true;
  startBtn.textContent = 'Başlatılıyor…';
  
  const mailboxRef = encodeURIComponent(state.mailbox.ref);

  try {
    const startData = await api(`/api/v1/mailboxes/${mailboxRef}/certificate/device-start`, {
      method: 'POST',
    });

    el('cert-user-code').textContent = startData.userCode;
    el('cert-verify-link').href = startData.verificationUriComplete || startData.verificationUri;
    
    el('cert-step-init').classList.add('ff-hidden');
    el('cert-step-waiting').classList.remove('ff-hidden');

    const intervalMs = (startData.interval || 5) * 1000;
    const expiresAt = Date.now() + (startData.expiresIn || 600) * 1000;

    certPollTimer = setInterval(async () => {
      if (Date.now() > expiresAt) {
        clearInterval(certPollTimer);
        showCertError('Süre doldu, lütfen tekrar deneyin.');
        return;
      }

      try {
        await api(`/api/v1/mailboxes/${mailboxRef}/certificate/device-complete`, {
          method: 'POST',
          json: { deviceCode: startData.deviceCode },
        });

        clearInterval(certPollTimer);
        closeCertDeviceModal();
        toast('S/MIME sertifikanız başarıyla oluşturuldu!', 'ok');
        
        state.me = await api('/api/v1/me');
        state.mailbox = state.me.mailboxes.find((m) => m.ref === state.mailbox.ref) || state.mailbox;
        openSettings(); 
      } catch (err) {
        if (err.status !== 400 && err.status !== 429) {
          console.error(err);
        }
      }
    }, intervalMs);

  } catch (err) {
    showCertError(err.message);
    startBtn.disabled = false;
    startBtn.textContent = 'Onay Sürecini Başlat';
  }
}

function showCertError(msg) {
  const note = el('cert-error-note');
  note.textContent = msg;
  note.className = 'ff-note ff-note-danger';
  el('cert-step-init').classList.remove('ff-hidden');
  el('cert-step-waiting').classList.add('ff-hidden');
  el('cert-start-btn').disabled = false;
  el('cert-start-btn').textContent = 'Onay Sürecini Başlat';
}

/* ── ayarlar ─────────────────────────────────────────────────── */

async function openSettings() {
  el('settings-modal').classList.remove('ff-hidden');
  el('settings-body').innerHTML = '<div class="ff-empty"><span class="ff-spinner"></span></div>';

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
      <label class="ff-check"><input type="checkbox" id="s-notify-mail" ${prefs.mail !== false ? 'checked' : ''}> Yeni posta bildirimi</label>
      <label class="ff-check"><input type="checkbox" id="s-notify-security" checked disabled> Güvenlik uyarıları (kapatılamaz)</label>
      <div class="ff-row-wrap">
        <button class="ff-btn ff-btn-sm" id="s-push-toggle">${pushState.subscribed ? 'Bu cihazda kapat' : 'Bu cihazda aç'}</button>
        <button class="ff-btn ff-btn-sm" id="s-push-test" ${pushState.subscribed ? '' : 'disabled'}>Test bildirimi</button>
        <span class="ff-tiny ff-dim">${pushState.reason || ''}</span>
      </div>
    </section>

    <section>
      <h3>S/MIME sertifikası</h3>
      ${certificate.available ? `
        <dl class="wm-kv">
          <dt>Konu</dt><dd>${escapeHtml(certificate.subject || '—')}</dd>
          <dt>Veren</dt><dd>${escapeHtml(certificate.issuer || '—')}</dd>
          <dt>Seri</dt><dd class="ff-mono">${escapeHtml(certificate.serialHex || '—')}</dd>
          <dt>Geçerlilik</dt><dd>${new Date(certificate.notBefore).toLocaleDateString('tr-TR')} — ${new Date(certificate.notAfter).toLocaleDateString('tr-TR')}</dd>
          <dt>Parmak izi</dt><dd class="ff-mono ff-tiny">${escapeHtml(certificate.fingerprint || '—')}</dd>
        </dl>
        <div class="ff-row-wrap">
          <button class="ff-btn ff-btn-sm" id="s-cert-renew">Yenile</button>
          <a class="ff-btn ff-btn-sm ff-btn-ghost" download="smime.crt"
             href="data:application/x-pem-file;base64,${btoa(unescape(encodeURIComponent(certificate.certPem || '')))}">Sertifikayı indir</a>
        </div>` : `
        <p class="ff-muted ff-small">Bu adres için henüz sertifika yok.
          Sertifika olmadan giden postayı S/MIME ile imzalayamazsınız.</p>
        <button class="ff-btn ff-btn-sm ff-btn-primary" id="s-cert-issue">Sertifika iste</button>`}
    </section>

    <section>
      <h3>Posta istemcisi (Thunderbird, Apple Mail…)</h3>
      <dl class="wm-kv">
        <dt>Sunucu</dt><dd>${escapeHtml(location.hostname)}</dd>
        <dt>Gönderme</dt><dd>587 (STARTTLS) veya 465 (TLS)</dd>
        <dt>Kullanıcı adı</dt><dd>${escapeHtml(state.mailbox.address)}</dd>
      </dl>
      ${credentials.credentials.length ? `<div class="ff-tiny ff-dim">
        ${credentials.credentials.length} kayıtlı kimlik ·
        son kullanım: ${credentials.credentials[0].lastUsedAt ? new Date(credentials.credentials[0].lastUsedAt).toLocaleString('tr-TR') : 'hiç'}
      </div>` : ''}
      <button class="ff-btn ff-btn-sm" id="s-new-password">Yeni parola üret</button>
      <div id="s-password-out"></div>
    </section>

    <section>
      <h3>Hesap</h3>
      <dl class="wm-kv">
        <dt>Kimlik</dt><dd>${escapeHtml(state.me.email)}</dd>
        <dt>Erişim</dt><dd>${escapeHtml(el('mailbox-access').textContent)}</dd>
        <dt>Kullanım</dt><dd>${formatBytes(state.mailbox.usedBytes)} / ${formatBytes(state.mailbox.quotaBytes)}</dd>
      </dl>
    </section>
  `;

  bindSettings();
}

function bindSettings() {
  const mailboxRef = encodeURIComponent(state.mailbox.ref);

  const notifyMail = el('s-notify-mail');
  if (notifyMail) {
    notifyMail.addEventListener('change', async () => {
      await api(`/api/v1/mailboxes/${mailboxRef}/settings`, {
        method: 'POST',
        json: { notifyPrefs: { ...state.mailbox.notifyPrefs, mail: notifyMail.checked } },
      }).catch((err) => toast(err.message, 'error'));
      state.mailbox.notifyPrefs = { ...state.mailbox.notifyPrefs, mail: notifyMail.checked };
    });
  }

  // SADECE BIR KERE TANIMLANDI: Doğrudan cihaz kodu modalını açar
  const certIssueBtn = el('s-cert-issue');
  if (certIssueBtn) {
    certIssueBtn.addEventListener('click', () => {
      openCertDeviceModal();
    });
  }

  const certRenewBtn = el('s-cert-renew');
  if (certRenewBtn) {
    certRenewBtn.addEventListener('click', async () => {
      certRenewBtn.disabled = true;
      certRenewBtn.textContent = 'yenileniyor…';
      try {
        await api(`/api/v1/mailboxes/${mailboxRef}/certificate/issue`, {
          method: 'POST', json: { force: true },
        });
        toast('Sertifika yenilendi', 'ok');
        state.me = await api('/api/v1/me');
        state.mailbox = state.me.mailboxes.find((m) => m.ref === state.mailbox.ref) || state.mailbox;
        openSettings();
      } catch (err) {
        toast(err.message, 'error');
        certRenewBtn.disabled = false;
        certRenewBtn.textContent = 'Yenile';
      }
    });
  }

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
      if (!confirm('Yeni bir parola üretilecek ve öncekiler geçersiz olacak. Devam?')) return;
      try {
        const result = await api(`/api/v1/mailboxes/${mailboxRef}/smtp-credentials`, {
          method: 'POST', json: { label: 'posta istemcisi' },
        });
        el('s-password-out').innerHTML = `<div class="ff-note ff-note-warn" style="margin-top:8px">
          <div><strong>Kullanıcı adı:</strong> <code>${escapeHtml(result.username)}</code></div>
          <div><strong>Parola:</strong> <code>${escapeHtml(result.password)}</code></div>
          <div class="ff-tiny" style="margin-top:6px">${escapeHtml(result.note)}</div>
        </div>`;
      } catch (err) { toast(err.message, 'error'); }
    });
  }
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
    const subscription = await registration.pushManager.getSubscription();
    return { subscribed: !!subscription, reason: '' };
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
        json: {
          subscription: subscription.toJSON(),
          mailbox: state.mailbox.ref,
          topics: ['mail', 'security'],
        },
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
      socket.send(JSON.stringify({
        type: 'catchup', mailboxRef: state.mailbox.ref, sinceSeq: state.lastSeq,
      }));
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
      if ((payload.messages || []).length) {
        toast(`${payload.messages.length} yeni ileti alındı`, 'ok');
      }
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
  const node = el('conn-status');
  node.className = `wm-conn is-${kind}`;
  el('conn-text').textContent = text;
}

/* ── olay bağlama ────────────────────────────────────────────── */

function bindEvents() {
  el('mailbox-select').addEventListener('change', async (e) => {
    state.mailbox = state.me.mailboxes.find((m) => m.ref === e.target.value);
    state.selected = null;
    state.lastSeq = 0;
    renderAccessNote();
    renderQuota();
    if (state.socket && state.socket.readyState === WebSocket.OPEN) {
      state.socket.send(JSON.stringify({ type: 'subscribe', mailboxRefs: [state.mailbox.ref] }));
    }
    await Promise.all([loadMessages({ reset: true }), refreshCounts()]);
  });

  el('compose-btn').addEventListener('click', () => openCompose());
  el('compose-close').addEventListener('click', () => el('compose-modal').classList.add('ff-hidden'));
  el('compose-cancel').addEventListener('click', () => el('compose-modal').classList.add('ff-hidden'));
  el('compose-send').addEventListener('click', (e) => { e.preventDefault(); sendCompose(); });
  el('compose-form').addEventListener('submit', (e) => { e.preventDefault(); sendCompose(); });

  el('toggle-cc').addEventListener('click', () => el('cc-row').classList.toggle('ff-hidden'));
  el('toggle-bcc').addEventListener('click', () => el('bcc-row').classList.toggle('ff-hidden'));
  el('c-files').addEventListener('change', (e) => {
    for (const file of e.target.files) state.attachments.push(file);
    e.target.value = '';
    renderAttachChips();
  });

  el('forward-close').addEventListener('click', () => el('forward-modal').classList.add('ff-hidden'));
  el('forward-cancel').addEventListener('click', () => el('forward-modal').classList.add('ff-hidden'));
  el('forward-send').addEventListener('click', sendForward);

  el('settings-btn').addEventListener('click', openSettings);
  el('settings-close').addEventListener('click', () => el('settings-modal').classList.add('ff-hidden'));

  // 🟢 Cihaz Kodu modalı butonları (Ayarlar her açıldığında tekrar tekrar eklenmesin diye buraya taşındı)
  const certClose = el('cert-modal-close');
  if (certClose) certClose.addEventListener('click', closeCertDeviceModal);
  
  const certCancel = el('cert-modal-cancel');
  if (certCancel) certCancel.addEventListener('click', closeCertDeviceModal);
  
  const certStart = el('cert-start-btn');
  if (certStart) certStart.addEventListener('click', startCertDeviceFlow);

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

  for (const chip of document.querySelectorAll('.wm-chip')) {
    chip.addEventListener('click', () => {
      for (const other of document.querySelectorAll('.wm-chip')) other.classList.remove('is-active');
      chip.classList.add('is-active');
      state.filter = chip.dataset.filter;
      loadMessages({ reset: true });
    });
  }

  el('menu-btn').addEventListener('click', () => document.getElementById('app').classList.add('is-menu-open'));
  el('sidebar-close').addEventListener('click', () => document.getElementById('app').classList.remove('is-menu-open'));

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      for (const id of ['compose-modal', 'settings-modal', 'forward-modal', 'cert-device-modal']) {
        const m = el(id);
        if (m) m.classList.add('ff-hidden');
      }
      document.getElementById('app').classList.remove('is-menu-open', 'is-reading');
    }
    const inField = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (inField) return;
    if (e.key === 'c') { e.preventDefault(); openCompose(); }
    if (e.key === '/') { e.preventDefault(); el('search').focus(); }
    if (e.key === 'r') { e.preventDefault(); loadMessages({ reset: true }); }
  });
}

/* ── biçimlendirme ───────────────────────────────────────────── */

function authBadge(label, result) {
  const good = result === 'pass';
  const bad = ['fail', 'permerror', 'softfail'].includes(result);
  const cls = good ? 'ff-badge-ok' : (bad ? 'ff-badge-danger' : 'ff-badge-warn');
  return `<span class="ff-badge ${cls}" title="${label}: ${result}">${label} ${result}</span>`;
}

function smimeBadge(message) {
  const map = {
    'signed-valid': ['ff-badge-ok', '🔏 imza geçerli'],
    'signed-invalid': ['ff-badge-danger', '🔏 imza geçersiz'],
    'signed-untrusted': ['ff-badge-warn', '🔏 imzalayan güvenilmiyor'],
    'signed-address-mismatch': ['ff-badge-danger', '🔏 imza adresi uyuşmuyor'],
    'signed-expired': ['ff-badge-warn', '🔏 sertifika süresi dolmuş'],
    'signed-local': ['ff-badge-ok', '🔏 imzalandı'],
    encrypted: ['ff-badge-accent', '🔒 şifreli'],
  };
  const [cls, label] = map[message.smimeStatus] || ['ff-badge', message.smimeStatus];
  const signer = message.smimeSigner ? ` — ${message.smimeSigner.emails?.join(', ') || ''}` : '';
  return `<span class="ff-badge ${cls}" title="${escapeAttr(label + signer)}">${label}</span>`;
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

function iconFor(contentType) {
  const t = String(contentType || '');
  if (t.startsWith('image/')) return '🖼';
  if (t.startsWith('video/')) return '🎬';
  if (t.startsWith('audio/')) return '🎵';
  if (t.includes('pdf')) return '📕';
  if (t.includes('zip') || t.includes('gzip') || t.includes('rar')) return '🗜';
  if (t.includes('word') || t.includes('document')) return '📄';
  if (t.includes('sheet') || t.includes('excel')) return '📊';
  if (t.includes('rfc822')) return '✉';
  return '📎';
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}
function escapeAttr(s) { return escapeHtml(s); }

function toast(message, kind = '') {
  const node = document.createElement('div');
  node.className = `wm-toast${kind ? ` is-${kind}` : ''}`;
  node.textContent = message;
  el('toasts').append(node);
  setTimeout(() => {
    node.style.opacity = '0';
    setTimeout(() => node.remove(), 200);
  }, 4200);
}

boot();