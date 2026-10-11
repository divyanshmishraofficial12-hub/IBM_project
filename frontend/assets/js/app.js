/**
 * app.js — PhishGuard Forensics & Citizen Cyber Shield Main Logic.
 * Handles:
 *  - 4 Scan vectors: URLs, Emails, WhatsApp/SMS Messages, UPI/QR Codes
 *  - Explainable AI (XAI) threat factor rendering
 *  - MITRE ATT&CK badge mapping
 *  - UPI Financial Trap alerts
 *  - Citizen safety action checklist & 1930 emergency reporting
 *  - SHA-256 digital evidence hashing (DFIR chain-of-custody)
 *  - 1-Click Forensic Incident Report export
 */

const LS_RECENT_KEY = 'pd_recent_scans';
const MAX_RECENT    = 6;

// ── DOM References ─────────────────────────────────────────────────────────
const tabBtns       = document.querySelectorAll('.tab-btn');
const tabPanels     = document.querySelectorAll('.tab-panel');
const urlForm       = document.getElementById('url-form');
const emailForm     = document.getElementById('email-form');
const msgForm       = document.getElementById('message-form');
const qrForm        = document.getElementById('qr-form');

const urlInput      = document.getElementById('url-input');
const emailInput    = document.getElementById('email-input');
const msgInput      = document.getElementById('message-input');
const qrInput       = document.getElementById('qr-input');

const scanSection   = document.getElementById('scan-section');
const spinnerEl     = document.getElementById('scan-spinner');
const resultSection = document.getElementById('result-section');
const recentList    = document.getElementById('recent-scans-list');
const navUser       = document.getElementById('nav-user');
const navAuthBtns   = document.getElementById('nav-auth-btns');
const navUsername   = document.getElementById('nav-username');
const logoutBtn     = document.getElementById('logout-btn');

let currentController = null;

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initNav();
  initTabs();
  initForms();
  renderRecentScans();
});

// ── Nav / Auth ─────────────────────────────────────────────────────────────
function initNav() {
  const userStr = localStorage.getItem('pd_user');
  const user    = userStr ? JSON.parse(userStr) : null;

  if (user && Api.getToken()) {
    if (navUser)      navUser.style.display    = 'flex';
    if (navAuthBtns)  navAuthBtns.style.display = 'none';
    if (navUsername)  navUsername.textContent   = user.username;
  } else {
    if (navUser)      navUser.style.display    = 'none';
    if (navAuthBtns)  navAuthBtns.style.display = 'flex';
  }

  if (logoutBtn) {
    logoutBtn.addEventListener('click', () => {
      Api.logout();
      Toast.show('Logged out successfully.', 'info');
      setTimeout(() => window.location.reload(), 800);
    });
  }
}

// ── Tabs ───────────────────────────────────────────────────────────────────
function initTabs() {
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      tabBtns.forEach(b => {
        b.classList.toggle('active', b === btn);
        b.setAttribute('aria-selected', b === btn);
      });
      tabPanels.forEach(p => {
        const isMatch = p.id === `panel-${target}`;
        p.classList.toggle('active', isMatch);
        p.style.display = isMatch ? 'block' : 'none';
      });
      hideResult();
    });
  });
}

// ── Forms ──────────────────────────────────────────────────────────────────
function initForms() {
  urlForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) { Toast.show('Please enter a URL.', 'warning'); return; }
    await runScan('url', url);
  });

  emailForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = emailInput.value.trim();
    if (!text) { Toast.show('Please paste email content.', 'warning'); return; }
    await runScan('email', text);
  });

  msgForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = msgInput.value.trim();
    if (!text) { Toast.show('Please paste SMS / WhatsApp text.', 'warning'); return; }
    await runScan('message', text);
  });

  qrForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const payload = qrInput.value.trim();
    if (!payload) { Toast.show('Please enter or scan a QR/UPI payload.', 'warning'); return; }
    await runScan('qr', payload);
  });
}

// ── Scan Flow ──────────────────────────────────────────────────────────────
async function runScan(type, value) {
  if (currentController) currentController.abort();
  currentController = new AbortController();

  setScanState('scanning');

  try {
    let result;
    if (type === 'url') {
      result = await Api.scanUrl(value, currentController.signal);
    } else if (type === 'email') {
      result = await Api.scanEmail(value, currentController.signal);
    } else if (type === 'message') {
      result = await Api.scanMessage(value, currentController.signal);
    } else if (type === 'qr') {
      result = await Api.scanQr(value, currentController.signal);
    }

    setScanState('idle');
    renderResult(result, type, value);
    saveToRecent({ type, value, verdict: result.verdict, risk_score: result.risk_score });
    renderRecentScans();

  } catch (err) {
    setScanState('idle');
    if (err.name === 'AbortError') return;
    if (err.message?.toLowerCase().includes('too many')) {
      Toast.show('Rate limit reached. Please wait a moment.', 'warning');
    } else {
      Toast.show(err.message || 'Scan failed. Check if backend is active.', 'error');
    }
  }
}

// ── UI State Machine ───────────────────────────────────────────────────────
function setScanState(state) {
  const submitBtns = document.querySelectorAll('.scan-submit-btn');

  if (state === 'scanning') {
    scanSection?.classList.remove('visible');
    resultSection?.classList.remove('visible');
    if (resultSection) resultSection.style.display = 'none';
    spinnerEl?.classList.add('active');
    if (spinnerEl) spinnerEl.style.display = 'block';
    submitBtns.forEach(b => { b.disabled = true; b.classList.add('loading'); });

    const fill = spinnerEl?.querySelector('.scan-progress-fill');
    if (fill) { fill.style.animation = 'none'; void fill.offsetWidth; fill.style.animation = ''; }

  } else {
    if (spinnerEl) {
      spinnerEl.classList.remove('active');
      spinnerEl.style.display = 'none';
    }
    submitBtns.forEach(b => { b.disabled = false; b.classList.remove('loading'); });
  }
}

function hideResult() {
  if (resultSection) {
    resultSection.classList.remove('visible');
    resultSection.style.display = 'none';
  }
}

// ── Result Rendering ───────────────────────────────────────────────────────
function renderResult(data, type, inputValue) {
  if (!resultSection) return;

  const pct = Math.round((data.risk_score || 0) * 100);
  const verdictRaw = (data.verdict || 'suspicious').toLowerCase();
  const verdict = verdictRaw.includes('phish') || verdictRaw.includes('critical') ? 'phishing'
                : (verdictRaw.includes('safe') ? 'safe' : 'suspicious');

  const verdictLabel = { safe: 'Safe', suspicious: 'Suspicious / Warning', phishing: 'High Threat / Malicious' }[verdict];
  const verdictIcon  = { safe: '✅', suspicious: '⚠️', phishing: '🚨' }[verdict];

  // Score display
  const scoreNum = resultSection.querySelector('#r-score-number');
  if (scoreNum) scoreNum.textContent = `${pct}%`;

  const scoreCont = resultSection.querySelector('#r-score-container');
  if (scoreCont) scoreCont.className = `risk-score-display ${verdict}`;

  // Verdict badge
  const badge = resultSection.querySelector('#r-verdict-badge');
  if (badge) {
    badge.className = `verdict-badge ${verdict}`;
    badge.textContent = `${verdictIcon} ${verdictLabel}`;
  }

  // Animated bar
  const bar = resultSection.querySelector('#r-risk-bar');
  if (bar) {
    bar.className = `risk-bar-fill ${verdict}`;
    requestAnimationFrame(() => { bar.style.width = `${pct}%`; });
  }

  // Target label
  const targetEl = resultSection.querySelector('#r-target');
  if (targetEl) {
    targetEl.textContent = inputValue;
  }

  // Sub-bars
  const mlScoreVal = data.ml_score != null ? `${(data.ml_score * 100).toFixed(1)}%` : 'N/A';
  _setDetail('r-ml-score', mlScoreVal);
  const mlBar = document.getElementById('r-ml-bar');
  if (mlBar) mlBar.style.width = data.ml_score != null ? `${Math.round(data.ml_score * 100)}%` : '0%';

  const heurScoreVal = data.heuristic_score != null ? `${(data.heuristic_score * 100).toFixed(1)}%` : 'N/A';
  _setDetail('r-heuristic', heurScoreVal);
  const heurBar = document.getElementById('r-heuristic-bar');
  if (heurBar) heurBar.style.width = data.heuristic_score != null ? `${Math.round(data.heuristic_score * 100)}%` : '0%';

  // Detail grid
  _setDetail('r-gsb', data.gsb_flagged ? '🚨 Flagged' : '✅ Clean');
  _setDetail('r-vt',  data.vt_positives > 0 ? `🚨 ${data.vt_positives} engines` : '✅ Clean');
  _setDetail('r-entropy', data.shannon_entropy != null ? `${data.shannon_entropy} bits` : 'N/A');
  _setDetail('r-scanned-at', new Date(data.scanned_at || Date.now()).toLocaleString());

  // Evidence Hash (Forensic Chain-of-Custody)
  const hashEl = document.getElementById('r-evidence-hash');
  if (hashEl) hashEl.textContent = data.evidence_hash || 'SHA-256 Calculated';

  // UPI Fraud Box
  const upiBox = document.getElementById('r-upi-alert-box');
  if (upiBox) {
    if (data.upi_analysis && data.upi_analysis.is_fraud_trap) {
      upiBox.style.display = 'block';
      const upiText = document.getElementById('r-upi-alert-text');
      if (upiText) {
        upiText.innerHTML = `
          <strong>${escHtml(data.upi_analysis.warning_title)}</strong><br/>
          Payee: <code>${escHtml(data.upi_analysis.payee_vpa)}</code> (${escHtml(data.upi_analysis.payee_name)})<br/>
          Amount: <strong>₹${escHtml(data.upi_analysis.amount)}</strong><br/>
          <em>${escHtml(data.upi_analysis.warning_details.join(' '))}</em>
        `;
      }
    } else {
      upiBox.style.display = 'none';
    }
  }

  // Explainable AI (XAI) Factor Cards
  const factorList = document.getElementById('r-factor-list');
  if (factorList) {
    factorList.innerHTML = '';
    const factors = data.explainable_factors || [];
    if (factors.length === 0) {
      factorList.innerHTML = '<p class="text-xs text-muted">No specific risk signals detected.</p>';
    } else {
      factors.forEach(f => {
        const card = document.createElement('div');
        card.className = `factor-card ${f.severity || 'MEDIUM'}`;
        card.innerHTML = `
          <div class="factor-header">
            <span class="factor-title">${escHtml(f.title)}</span>
            <span class="factor-badge">${escHtml(f.severity)}</span>
          </div>
          <p class="text-xs" style="color:var(--clr-text-secondary); margin:0;">${escHtml(f.description)}</p>
        `;
        factorList.appendChild(card);
      });
    }
  }

  // MITRE ATT&CK Badges
  const mitreContainer = document.getElementById('r-mitre-container');
  if (mitreContainer) {
    mitreContainer.innerHTML = '';
    const mitre = data.mitre_attack || [];
    if (mitre.length === 0) {
      mitreContainer.innerHTML = '<span class="text-xs text-muted">No standard enterprise techniques mapped.</span>';
    } else {
      mitre.forEach(m => {
        const badge = document.createElement('a');
        badge.className = 'mitre-badge';
        badge.href = m.url || '#';
        badge.target = '_blank';
        badge.rel = 'noopener noreferrer';
        badge.innerHTML = `🛡️ <strong>${escHtml(m.id)}</strong>: ${escHtml(m.name)}`;
        mitreContainer.appendChild(badge);
      });
    }
  }

  // Citizen Advice Checklist
  const adviceList = document.getElementById('r-citizen-checklist');
  if (adviceList) {
    adviceList.innerHTML = '';
    const advice = data.citizen_advice || [];
    advice.forEach(step => {
      const li = document.createElement('li');
      li.innerHTML = `<span>👉</span> <span>${escHtml(step)}</span>`;
      adviceList.appendChild(li);
    });
  }

  resultSection.style.display = 'block';
  resultSection.classList.add('visible');
  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function _setDetail(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

// ── LocalStorage Recent Scans ──────────────────────────────────────────────
function saveToRecent({ type, value, verdict, risk_score }) {
  let recent = getRecent();
  recent = recent.filter(r => r.value !== value);
  recent.unshift({ type, value, verdict, risk_score, ts: Date.now() });
  recent = recent.slice(0, MAX_RECENT);
  localStorage.setItem(LS_RECENT_KEY, JSON.stringify(recent));
}

function getRecent() {
  try {
    return JSON.parse(localStorage.getItem(LS_RECENT_KEY)) || [];
  } catch {
    return [];
  }
}

function renderRecentScans() {
  if (!recentList) return;
  const recent = getRecent();
  recentList.innerHTML = '';

  if (recent.length === 0) {
    recentList.innerHTML = '<span class="text-muted text-sm">No recent scans yet.</span>';
    return;
  }

  recent.forEach(item => {
    const chip = document.createElement('button');
    chip.className = 'recent-chip';
    chip.title = item.value;

    const label = item.type === 'url' ? item.value : `[${item.type.toUpperCase()}] ${item.value.slice(0, 30)}`;
    chip.innerHTML = `
      <span class="chip-verdict ${item.verdict}"></span>
      <span>${escHtml(label.slice(0, 35))}${label.length > 35 ? '…' : ''}</span>
    `;

    chip.addEventListener('click', () => {
      const tab = document.querySelector(`[data-tab="${item.type}"]`);
      tab?.click();
      if (item.type === 'url' && urlInput) { urlInput.value = item.value; urlInput.focus(); }
      if (item.type === 'email' && emailInput) { emailInput.value = item.value; emailInput.focus(); }
      if (item.type === 'message' && msgInput) { msgInput.value = item.value; msgInput.focus(); }
      if (item.type === 'qr' && qrInput) { qrInput.value = item.value; qrInput.focus(); }
      Toast.show('Loaded from recent scans.', 'info');
    });

    recentList.appendChild(chip);
  });
}

// ── Preset Helpers for Judges & Demos ──────────────────────────────────────
function loadPreset(type, val) {
  if (type === 'url') {
    const t = document.getElementById('tab-url'); t?.click();
    if (urlInput) { urlInput.value = val; urlInput.focus(); }
  } else if (type === 'message') {
    const t = document.getElementById('tab-message'); t?.click();
    if (msgInput) { msgInput.value = val; msgInput.focus(); }
  } else if (type === 'qr') {
    const t = document.getElementById('tab-qr'); t?.click();
    if (qrInput) { qrInput.value = val; qrInput.focus(); }
  }
  Toast.show('Preset loaded! Click Scan to evaluate.', 'info');
}
window.loadPreset = loadPreset;

// ── Export Case Report (Print / PDF) ──────────────────────────────────────
function exportCaseReport() {
  window.print();
}
window.exportCaseReport = exportCaseReport;

// ── Clipboard Helper ───────────────────────────────────────────────────────
function copyToClipboard(text, label = 'Copied!') {
  if (!text) return;
  navigator.clipboard.writeText(text)
    .then(() => Toast.show(label, 'success'))
    .catch(() => Toast.show('Copy failed — please copy manually.', 'error'));
}
window.copyToClipboard = copyToClipboard;

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
