/**
 * script.js — Automated Web Security Scanner
 * Handles scanning, result rendering, tab switching, and UI interactions.
 */

'use strict';

// ─────────────────────────────────────────
//  Scan entry point
// ─────────────────────────────────────────

async function startScan() {
  const rawInput = document.getElementById('url-input').value.trim();

  // Basic client-side URL normalisation
  let url = rawInput;
  if (url && !/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }

  if (!url) {
    showValidation('Please enter a URL to scan.', 'error');
    return;
  }

  // UI: lock button, show progress
  const btn = document.getElementById('scan-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span><span class="scan-btn-text">Scanning…</span>';

  clearValidation();
  showProgress(true);
  setProgressStep('ps-validate', 'active');

  // Hide old results
  document.getElementById('results-section').classList.add('hidden');

  // Animate progress steps as time passes
  const steps = ['ps-validate', 'ps-connect', 'ps-headers', 'ps-cors', 'ps-risk'];
  const delays = [0, 600, 1400, 2200, 3000];
  const timers = steps.map((id, i) =>
    setTimeout(() => {
      steps.slice(0, i).forEach(s => setProgressStep(s, 'done'));
      setProgressStep(id, 'active');
      setProgressBar((i + 1) / steps.length * 85);
    }, delays[i])
  );

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });

    timers.forEach(clearTimeout);
    steps.forEach(s => setProgressStep(s, 'done'));
    setProgressBar(100);

    const data = await res.json();

    if (!res.ok || data.error) {
      showValidation(data.error || 'An unexpected error occurred.', 'error');
      showProgress(false);
    } else {
      await sleep(400); // let progress reach 100 visually
      showProgress(false);
      renderResults(data);
    }
  } catch (err) {
    timers.forEach(clearTimeout);
    showProgress(false);
    showValidation('Network error — make sure the server is running.', 'error');
  }

  // Restore button
  btn.disabled = false;
  btn.innerHTML = '<span class="scan-btn-text">Scan Now</span><span class="scan-btn-icon">→</span>';
}

// Allow pressing Enter in the input field
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('url-input');
  if (input) {
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });
  }
});

// ─────────────────────────────────────────
//  Render results
// ─────────────────────────────────────────

function renderResults(data) {
  // Info bar
  document.getElementById('info-url').textContent  = data.final_url || data.target_url || '—';
  document.getElementById('info-time').textContent = formatTimestamp(data.timestamp);
  document.getElementById('info-conn').textContent = data.final_url
    ? (data.final_url.startsWith('https://') ? '🔒 HTTPS' : '⚠️ HTTP')
    : '—';

  const statusEl = document.getElementById('info-status');
  const sc = data.http_status;
  statusEl.textContent = sc ? `${sc} ${statusText(sc)}` : '—';
  statusEl.style.color = sc >= 200 && sc < 300 ? 'var(--status-pass)'
                       : sc >= 400 ? 'var(--sev-high)'
                       : 'var(--white-70)';

  // Security headers table
  renderHeadersTable(data.header_analysis || []);

  // CORS
  renderCorsTable(data.cors_analysis || {});

  // Findings
  const findings = data.findings || [];
  renderFindings(findings);
  document.getElementById('findings-badge').textContent = findings.length;

  // Severity summary
  const counts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach(f => { if (f.severity in counts) counts[f.severity]++; });
  document.getElementById('count-high').textContent   = counts.High;
  document.getElementById('count-medium').textContent = counts.Medium;
  document.getElementById('count-low').textContent    = counts.Low;
  document.getElementById('count-info').textContent   = counts.Informational;

  // Show results
  const section = document.getElementById('results-section');
  section.classList.remove('hidden');
  setTimeout(() => {
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 100);

  // Activate first tab
  switchTabById('tab-headers');
}

// ─────────────────────────────────────────
//  Headers table
// ─────────────────────────────────────────

function renderHeadersTable(headers) {
  const tbody = document.getElementById('headers-tbody');
  tbody.innerHTML = '';

  headers.forEach((h, idx) => {
    const tr = document.createElement('tr');
    tr.id = `hdr-row-${idx}`;
    tr.innerHTML = `
      <td><strong>${esc(h.name)}</strong></td>
      <td>${statusBadge(h.status)}</td>
      <td class="value-cell ${h.present ? '' : 'value-absent'}">
        ${h.present ? esc(h.value || '—') : 'Not present'}
      </td>
      <td>
        <button class="expand-btn" onclick="toggleDetail('hdr', ${idx})">Details ▾</button>
      </td>
    `;
    tbody.appendChild(tr);

    // Detail row (hidden by default)
    const dr = document.createElement('tr');
    dr.id = `hdr-detail-${idx}`;
    dr.className = 'detail-row hidden';
    dr.innerHTML = `<td colspan="4"><div class="detail-content">
      <dl>
        <dt>Purpose</dt><dd>${esc(h.purpose || '—')}</dd>
        <dt>Implications</dt><dd>${esc(h.implications || '—')}</dd>
        <dt>Remediation</dt><dd>${esc(h.remediation || '—')}</dd>
      </dl>
    </div></td>`;
    tbody.appendChild(dr);
  });
}

function toggleDetail(prefix, idx) {
  const row = document.getElementById(`${prefix}-detail-${idx}`);
  const btn = document.querySelector(`#${prefix}-row-${idx} .expand-btn`);
  const isHidden = row.classList.toggle('hidden');
  if (btn) btn.textContent = isHidden ? 'Details ▾' : 'Details ▴';
}

// ─────────────────────────────────────────
//  CORS table
// ─────────────────────────────────────────

function renderCorsTable(cors) {
  // Summary box
  const box = document.getElementById('cors-summary-box');
  box.textContent = cors.summary || 'No CORS data available.';

  const tbody = document.getElementById('cors-tbody');
  tbody.innerHTML = '';

  (cors.headers || []).forEach((h, idx) => {
    const tr = document.createElement('tr');
    tr.id = `cors-row-${idx}`;
    tr.innerHTML = `
      <td><strong>${esc(h.name)}</strong></td>
      <td class="value-cell ${h.value == null ? 'value-absent' : ''}">
        ${h.value != null ? esc(h.value) : 'Not present'}
      </td>
      <td>${corsStatusBadge(h.status)}</td>
      <td><button class="expand-btn" onclick="toggleDetail('cors', ${idx})">Details ▾</button></td>
    `;
    tbody.appendChild(tr);

    const dr = document.createElement('tr');
    dr.id = `cors-detail-${idx}`;
    dr.className = 'detail-row hidden';
    dr.innerHTML = `<td colspan="4"><div class="detail-content"><dl>
      <dt>Purpose</dt><dd>${esc(h.purpose || '—')}</dd>
      <dt>Observation</dt><dd>${esc(h.observation || '—')}</dd>
      <dt>Concern</dt><dd>${h.concern ? esc(h.concern) : '<em>None identified.</em>'}</dd>
      <dt>Recommendation</dt><dd>${esc(h.recommendation || '—')}</dd>
    </dl></div></td>`;
    tbody.appendChild(dr);
  });
}

// ─────────────────────────────────────────
//  Findings
// ─────────────────────────────────────────

function renderFindings(findings) {
  const list = document.getElementById('findings-list');
  list.innerHTML = '';

  if (!findings.length) {
    list.innerHTML = `<div class="cors-summary-box" style="text-align:center;padding:32px;">
      <div style="font-size:2rem;margin-bottom:8px;">✅</div>
      <strong style="color:var(--accent)">No findings generated.</strong><br>
      <span style="color:var(--white-40);font-size:0.82rem;">All checked headers passed or were not applicable.</span>
    </div>`;
    return;
  }

  findings.forEach((f, idx) => {
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.id = `finding-${idx}`;
    card.innerHTML = `
      <div class="finding-header" onclick="toggleFinding(${idx})">
        <span class="finding-sev sev-${f.severity.replace(' ', '')}">${esc(f.severity)}</span>
        <span class="finding-title">${esc(f.title)}</span>
        <span class="finding-cat">${esc(f.category)}</span>
        <span class="finding-chevron">▶</span>
      </div>
      <div class="finding-body">
        <div class="finding-grid">
          <div class="finding-field full">
            <h4>Evidence</h4>
            <div class="evidence-box">${esc(f.evidence || '—')}</div>
          </div>
          <div class="finding-field">
            <h4>Explanation</h4>
            <p>${esc(f.explanation || '—')}</p>
          </div>
          <div class="finding-field">
            <h4>Potential Impact</h4>
            <p>${esc(f.impact || '—')}</p>
          </div>
          <div class="finding-field full">
            <h4>Recommended Fix</h4>
            <div class="fix-box">${esc(f.fix || '—')}</div>
          </div>
        </div>
      </div>
    `;
    list.appendChild(card);
  });
}

function toggleFinding(idx) {
  const card = document.getElementById(`finding-${idx}`);
  card.classList.toggle('open');
}

// ─────────────────────────────────────────
//  Tab switching
// ─────────────────────────────────────────

function switchTab(btn) {
  const tabId = btn.dataset.tab;
  // Deactivate all
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  // Activate clicked
  btn.classList.add('active');
  document.getElementById(tabId).classList.add('active');
}

function switchTabById(tabId) {
  const btn = document.querySelector(`[data-tab="${tabId}"]`);
  if (btn) switchTab(btn);
}

// ─────────────────────────────────────────
//  Progress helpers
// ─────────────────────────────────────────

function showProgress(show) {
  document.getElementById('progress-area').classList.toggle('hidden', !show);
  if (show) {
    // Reset
    document.querySelectorAll('.ps').forEach(el => {
      el.classList.remove('active', 'done');
    });
    setProgressBar(0);
  }
}

function setProgressBar(pct) {
  document.getElementById('progress-bar').style.width = pct + '%';
}

function setProgressStep(id, state) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove('active', 'done');
  if (state) el.classList.add(state);
}

// ─────────────────────────────────────────
//  Validation UI
// ─────────────────────────────────────────

function showValidation(msg, type) {
  const el = document.getElementById('validation-msg');
  el.textContent = msg;
  el.className = `validation-msg ${type}`;
  el.classList.remove('hidden');
}

function clearValidation() {
  const el = document.getElementById('validation-msg');
  el.classList.add('hidden');
  el.textContent = '';
}

// ─────────────────────────────────────────
//  Badge helpers
// ─────────────────────────────────────────

function statusBadge(status) {
  const map = {
    'PASS':           ['badge-pass', 'PASS'],
    'WARNING':        ['badge-warn', 'WARNING'],
    'REVIEW':         ['badge-rev',  'REVIEW'],
    'NOT APPLICABLE': ['badge-na',   'N/A'],
  };
  const [cls, label] = map[status] || ['badge-info', status];
  return `<span class="badge ${cls}">${label}</span>`;
}

function corsStatusBadge(status) {
  const map = {
    'INFO':    ['badge-info',   'INFO'],
    'REVIEW':  ['badge-rev',    'REVIEW'],
    'WARNING': ['badge-warn',   'WARNING'],
    'NOT SET': ['badge-notset', 'NOT SET'],
  };
  const [cls, label] = map[status] || ['badge-notset', status || 'NOT SET'];
  return `<span class="badge ${cls}">${label}</span>`;
}

// ─────────────────────────────────────────
//  Utility
// ─────────────────────────────────────────

function esc(str) {
  if (str == null) return '—';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString();
  } catch { return ts; }
}

function statusText(code) {
  const codes = {
    200:'OK', 201:'Created', 204:'No Content',
    301:'Moved Permanently', 302:'Found', 304:'Not Modified',
    400:'Bad Request', 401:'Unauthorized', 403:'Forbidden',
    404:'Not Found', 405:'Method Not Allowed',
    500:'Internal Server Error', 502:'Bad Gateway', 503:'Service Unavailable',
  };
  return codes[code] || '';
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
