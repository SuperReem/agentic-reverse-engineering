const $ = id => document.getElementById(id);
let result = null;
let polling = false;
let uploadedBinary = null;
let uploading = false;
let loadedBinary = null;
let functionRequest = 0;
let activeRunId = null;
const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const percent = value => `${Math.round((value || 0) * 100)}%`;
function renderAgent(name, data) {
  if (!data) return;
  $(`${name}-content`).innerHTML = `<div class="confidence-row"><span>CONFIDENCE</span><strong>${percent(data.confidence)}</strong></div>${data.proposed_name ? `<div class="suggested-name"><span>Suggested name</span><code class="function-name">ƒ ${escapeHTML(data.proposed_name)}</code></div>` : ''}<p>${escapeHTML(data.hypothesis)}</p>`;
}
function render(data) {
  result = data;
  if (data.telemetry) renderTrace(data.telemetry);
  $('results').hidden = false;
  renderAgent('static', data.static_result);
  renderAgent('dynamic', data.dynamic_result);
  const verdict = data.verdict;
  if (verdict) renderVerdict(verdict, data);
  $('export').disabled = false;
}
function renderVerdict(verdict, data) {
  const status = ['verified', 'uncertain', 'rejected'].includes(verdict.status) ? verdict.status : 'uncertain';
  const confidence = Math.max(0, Math.min(100, Math.round((verdict.confidence || 0) * 100)));
  const summary = verdict.summary;
  const tiles = summary ? [['Input', summary.inputs], ['Operation', summary.behavior], ['Output', summary.outputs]].map(([label, value]) => `<div class="verdict-tile"><dt>${label}</dt><dd>${escapeHTML(value || 'Unknown')}</dd></div>`).join('') : '';
  const list = (title, items, type) => items?.length ? `<section class="verdict-list ${type}"><h3>${title}</h3><ul>${items.map(item => `<li>${escapeHTML(item)}</li>`).join('')}</ul></section>` : '';
  $('verdict-content').innerHTML = `<div class="verdict-summary ${status}"><div class="decision-mark" aria-hidden="true">${{verified:'✓', uncertain:'?', rejected:'×'}[status]}</div><div class="decision-copy"><span class="badge ${status}">${escapeHTML(status)}</span><h3>${escapeHTML(summary?.purpose || verdict.conclusion)}</h3><code>${escapeHTML(data.target_function || 'Target function')}</code></div><div class="confidence-dial" style="--score:${confidence * 3.6}deg" role="img" aria-label="Judge confidence: ${confidence}%"><div><strong>${confidence}%</strong><span>confidence</span></div></div></div>${tiles ? `<dl class="verdict-tiles">${tiles}</dl>` : ''}<div class="verdict-lists">${list('Evidence', verdict.supporting_evidence, 'support')}${list('Contradictions', verdict.contradictions, 'conflict')}${list('Unresolved', verdict.unresolved_points, 'open')}</div>`;
}
function stages(completed = [], status = 'idle', state = {}) {
  const running = status === 'running';
  const analysesDone = completed.includes('static') && completed.includes('dynamic');
  const last = completed.at(-1);
  const experimenting = running && analysesDone && last === 'judge' && state.verdict?.needs_more_evidence;
  document.querySelectorAll('.stage').forEach(el => {
    const name = el.dataset.stage;
    const active = running && (name === 'static' || name === 'dynamic' ? !completed.includes(name) : name === 'judge' ? analysesDone && !experimenting : experimenting);
    const done = completed.includes(name) && !active;
    el.hidden = name === 'experiment' && !experimenting && !completed.includes('experiment');
    el.classList.toggle('done', done);
    el.classList.toggle('running', active);
    el.classList.toggle('failed', status === 'error' && !done);
    el.querySelector('.stage-state').textContent = done ? 'Complete' : active ? 'Running' : status === 'error' ? 'Stopped' : name === 'judge' || name === 'experiment' ? 'Waiting' : 'Ready';
  });
  $('session-state').textContent = status === 'complete' ? 'Analysis complete' : status === 'error' ? 'Analysis failed' : experimenting ? 'Running experiment' : running && analysesDone ? 'Reviewing findings' : running ? 'Running analyses in parallel' : 'Ready';
  if (running && !state.verdict) $('verdict-content').innerHTML = `<p class="muted">${analysesDone ? 'Reviewing findings…' : 'Waiting for both analyses'}</p>`;
}
function error(message) { $('error').hidden = !message; $('error').textContent = message || ''; }
async function request(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}
async function poll() {
  try {
    const data = await request('/api/status');
    if (data.result) render(data.result);
    if (data.telemetry) renderTrace(data.telemetry, data.trace); 
    stages(data.stages, data.status, data.result || {});
    if (data.status === 'running') {
      document.querySelectorAll('.stage.running').forEach(el => {
        const message = data.progress?.[el.dataset.stage];
        if (message) el.querySelector('.stage-state').textContent = message;
      });
      const seconds = Math.max(0, Math.floor(Date.now() / 1000 - (data.started_at || Date.now() / 1000)));
      $('session-state').textContent += ` · ${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    }
    if (data.status === 'running') {
      setTimeout(poll, 1200);
      return;
    }
    if (data.error) error(data.error);
  } catch (exc) { error(exc.message); $('session-state').textContent = 'Connection lost'; stages([], 'error'); }
  polling = false;
  loadHistory();
  $('run').disabled = false;
  $('saved').disabled = false;
  $('binary').disabled = false;
  $('target').disabled = false;
  $('functions').disabled = false;
  $('run').innerHTML = 'Analyze <span>↗</span>';
}
function resetFunctions() {
  functionRequest++;
  loadedBinary = null;
  $('function-note').hidden = true;
  $('target').innerHTML = '<option value="">Load functions first</option>';
  $('target').disabled = true;
  $('run').disabled = true;
  $('functions').disabled = !uploadedBinary;
  $('functions').textContent = 'Load functions ↻';
}
async function loadFunctions(preferred = '') {
  const binary = uploadedBinary;
  if (!binary || uploading) return;
  const token = ++functionRequest;
  loadedBinary = null;
  $('target').disabled = true;
  $('run').disabled = true;
  $('target').innerHTML = '<option value="">Loading…</option>';
  $('functions').disabled = true;
  $('functions').textContent = 'Loading…';
  error('');
  try {
    const data = await request('/api/functions', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({binary})});
    if (token !== functionRequest) return;
    const names = data.functions;
    const recovered = names.length && names.every(name => /^sub_[0-9a-f]+$/i.test(name));
    $('function-note').hidden = !recovered;
    $('function-note').textContent = recovered ? `${names.length} functions · names stripped, shown by address` : ''; 
    if (!names.length) {
      $('target').innerHTML = '<option value="">No function symbols found</option>';
      error('No named functions found. The binary may be stripped.');
      return;
    }
    $('target').innerHTML = names.map(name => `<option value="${escapeHTML(name)}">${escapeHTML(/^sub_[0-9a-f]+$/i.test(name) ? `Function at 0x${name.slice(4)}` : name)}</option>`).join('');
    $('target').value = names.includes(preferred) ? preferred : names.includes('main') ? 'main' : names[0];
    loadedBinary = binary;
    $('target').disabled = false;
    $('run').disabled = polling;
  } catch (exc) {
    if (token !== functionRequest) return;
    $('target').innerHTML = '<option value="">Functions unavailable</option>';
    error(exc.message);
  } finally {
    if (token === functionRequest) {
      $('functions').disabled = polling;
      $('functions').textContent = 'Load functions ↻';
    }
  }
}
$('binary').addEventListener('change', async () => {
  uploadedBinary = null;
  resetFunctions();
  const file = $('binary').files[0];
  if (!file) { $('upload-status').textContent = 'Select a binary · max 50 MB'; return; }
  if (file.size === 0 || file.size > 50 * 1024 * 1024) {
    error('Choose a nonempty binary smaller than 50 MB.');
    $('upload-status').textContent = 'Upload failed';
    return;
  }
  uploading = true;
  $('binary').disabled = true;
  $('saved').disabled = true;
  $('functions').disabled = true;
  $('upload-status').textContent = 'Uploading…';
  error('');
  try {
    const data = await request('/api/upload', {method:'POST', headers:{'Content-Type':'application/octet-stream'}, body:file});
    uploadedBinary = data.binary;
    $('upload-status').textContent = `${file.name} · ${(file.size / 1024).toFixed(0)} KB`;
    uploading = false;
    await loadFunctions();
  } catch (exc) {
    error(exc.message);
    $('upload-status').textContent = 'Upload failed';
  } finally {
    uploading = false;
    $('binary').disabled = false;
    $('saved').disabled = false;
    $('functions').disabled = !uploadedBinary;
  }
});
$('functions').addEventListener('click', () => loadFunctions($('target').value));
$('analysis-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (polling || loadedBinary !== uploadedBinary || !$('target').value) return;
  error('');
  $('run').disabled = true;
  $('saved').disabled = true;
  $('binary').disabled = true;
  $('target').disabled = true;
  $('functions').disabled = true;
  try {
    await request('/api/analyze', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({binary:uploadedBinary, binary_name:$('binary').files[0]?.name || 'binary', target:$('target').value})});
    result = null;
    activeRunId = null;
    $('trace-controls').hidden = true;
    $('trace-events').innerHTML = '';
    $('results').hidden = false;
    ['static', 'dynamic'].forEach(name => { $(`${name}-content`).innerHTML = '<p class="muted">Running…</p>'; });
    $('verdict-content').innerHTML = '<p class="muted">Waiting for both analyses</p>';
    $('export').disabled = true;
    stages([], 'running');
    polling = true;
    $('run').textContent = 'Analyzing…';
    poll();
  } catch (exc) { error(exc.message); ['run','saved','binary','target','functions'].forEach(id => $(id).disabled = false); }
});
function renderTrace(metrics, events) {
  $('trace-controls').hidden = false;
  activeRunId = metrics.run_id;
  $('trace-download').hidden = !activeRunId;
  $('trace-download').href = `/api/traces/${encodeURIComponent(activeRunId)}`;
  if (events) renderTraceEvents(events);
}
function renderTraceEvents(events) {
  $('trace-events').innerHTML = events.filter(event => event.event === 'end' || event.kind === 'guard' || event.event === 'run_end').map(event => `<li class="${event.status === 'error' ? 'trace-error' : ''}"><span>${escapeHTML(event.stage || event.kind)}</span><strong>${escapeHTML(event.name || event.reason || event.event)}</strong><span>${event.duration_ms != null ? `${(event.duration_ms / 1000).toFixed(2)}s` : ''}</span><em>${escapeHTML(event.status || '')}</em></li>`).join('');
}
async function loadTrace(runId) {
  try {
    const response = await fetch(`/api/traces/${encodeURIComponent(runId)}`);
    if (!response.ok) throw new Error('Trace unavailable');
    const content = await response.text();
    if (activeRunId === runId) renderTraceEvents(content.trim().split('\n').filter(Boolean).map(line => JSON.parse(line)));
  } catch (exc) { $('trace-events').textContent = exc.message; }
}
$('trace-toggle').addEventListener('click', () => {
  const open = $('trace-panel').hidden;
  $('trace-panel').hidden = !open;
  $('trace-toggle').setAttribute('aria-expanded', String(open));
});
async function loadHistory() {
  try {
    const data = await request('/api/history');
    $('history-list').innerHTML = data.entries.length ? data.entries.map(entry => {
      const timestamp = new Date(entry.timestamp).toLocaleString('en-GB', {timeZone:'Asia/Riyadh', day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit', hour12:false});
      return `<button class="history-entry" data-id="${escapeHTML(entry.id)}" title="${entry.timestamp_source === 'file_modified' ? 'Saved file modification time' : 'Analysis completion time'} · Riyadh"><strong>${escapeHTML(entry.binary_name)}</strong><span>${escapeHTML(entry.target)}${entry.status === 'error' ? ' · Failed' : ''}</span><time datetime="${escapeHTML(entry.timestamp)}">${escapeHTML(timestamp)} · AST</time></button>`;
    }).join('') : '<p class="history-empty">No analyses yet</p>';
  } catch (exc) { $('history-list').textContent = exc.message; }
}
$('saved').addEventListener('click', loadHistory);
$('history-list').addEventListener('click', async event => {
  const entry = event.target.closest('.history-entry');
  if (!entry || polling || uploading) return;
  error('');
  try {
    const data = await request(entry.dataset.id === 'saved' ? '/api/saved' : `/api/history/${encodeURIComponent(entry.dataset.id)}`);
    if (polling || uploading) return;
    ['static','dynamic'].forEach(name => $(`${name}-content`).innerHTML = '');
    $('verdict-content').innerHTML = '';
    $('trace-controls').hidden = !data.telemetry;
    $('trace-events').innerHTML = '';
    render(data);
    stages(data.verdict ? ['static', 'dynamic', 'judge'] : [], data.run_status === 'error' ? 'error' : 'complete');
    $('session-state').textContent = data.run_status === 'error' ? 'Failed analysis' : 'Saved analysis';
    if (data.error) error(data.error.message);
    if (data.run_id) await loadTrace(data.run_id);
    document.querySelectorAll('.history-entry').forEach(button => button.classList.toggle('selected', button === entry));
  } catch (exc) { error(exc.message); }
});
$('export').addEventListener('click', () => {
  if (!result) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], {type:'application/json'}));
  const link = document.createElement('a');
  link.href = url; link.download = 'analysis.json'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});


loadHistory();

function setHistoryCollapsed(collapsed) {
  $('app-layout').classList.toggle('history-collapsed', collapsed);
  $('history-sidebar').hidden = collapsed;
  const toggle = $('history-toggle');
  toggle.setAttribute('aria-expanded', String(!collapsed));
  toggle.setAttribute('aria-label', collapsed ? 'Expand analysis history' : 'Collapse analysis history');
  toggle.title = collapsed ? 'Expand analysis history' : 'Collapse analysis history';
  toggle.textContent = collapsed ? '›' : '‹';
  try { localStorage.setItem('history-collapsed', String(collapsed)); } catch (_) {}
}
$('history-toggle').addEventListener('click', () => {
  setHistoryCollapsed($('history-toggle').getAttribute('aria-expanded') === 'true');
});
try { setHistoryCollapsed(localStorage.getItem('history-collapsed') === 'true'); } catch (_) { setHistoryCollapsed(false); }
