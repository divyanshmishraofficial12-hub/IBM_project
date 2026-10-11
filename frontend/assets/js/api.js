/**
 * Environment-aware API URL resolver:
 * 1. Window global override: window.PHISHGUARD_API_URL
 * 2. User/Teacher override in localStorage: 'phishguard_api_url'
 * 3. Local development: http://127.0.0.1:5000
 * 4. Production default (Render backend): https://phishguard-backend.onrender.com
 */
function getApiBase() {
  if (typeof window !== 'undefined' && window.PHISHGUARD_API_URL) {
    return window.PHISHGUARD_API_URL.replace(/\/+$/, '');
  }
  if (typeof localStorage !== 'undefined' && localStorage.getItem('phishguard_api_url')) {
    return localStorage.getItem('phishguard_api_url').replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    if (host === 'localhost' || host === '127.0.0.1' || host === '') {
      return 'http://127.0.0.1:5000';
    }
  }
  // Production Render service default:
  return 'https://phishguard-backend.onrender.com';
}

const Api = (() => {

  // ── Auth token helpers ────────────────────────────────────────────────
  function getToken() {
    return localStorage.getItem('pd_token');
  }

  function setToken(token) {
    localStorage.setItem('pd_token', token);
  }

  function clearToken() {
    localStorage.removeItem('pd_token');
    localStorage.removeItem('pd_user');
  }

  function _headers(extra = {}) {
    const h = { 'Content-Type': 'application/json', ...extra };
    const token = getToken();
    if (token) h['Authorization'] = `Bearer ${token}`;
    return h;
  }

  // ── Generic request wrapper ───────────────────────────────────────────
  async function _request(method, path, body = null, signal = null) {
    const opts = {
      method,
      headers: _headers(),
    };
    if (body)   opts.body = JSON.stringify(body);
    if (signal) opts.signal = signal;

    const baseUrl = getApiBase();
    const res = await fetch(`${baseUrl}${path}`, opts);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const msg = Array.isArray(data.error)
        ? data.error.join(' ')
        : (data.error || `HTTP ${res.status}`);
      throw new Error(msg);
    }

    return data;
  }

  // ── Auth ──────────────────────────────────────────────────────────────
  async function register({ username, email, password }) {
    const data = await _request('POST', '/api/auth/register', { username, email, password });
    setToken(data.token);
    localStorage.setItem('pd_user', JSON.stringify(data.user));
    return data;
  }

  async function login({ username, password }) {
    const data = await _request('POST', '/api/auth/login', { username, password });
    setToken(data.token);
    localStorage.setItem('pd_user', JSON.stringify(data.user));
    return data;
  }

  function logout() {
    clearToken();
  }

  async function getMe() {
    return _request('GET', '/api/auth/me');
  }

  async function scanUrl(url, signal) {
    return _request('POST', '/api/scan/url', { url }, signal);
  }

  async function scanEmail(email_text, signal) {
    return _request('POST', '/api/scan/email', { email_text }, signal);
  }

  async function scanMessage(message_text, signal) {
    return _request('POST', '/api/scan/message', { message_text }, signal);
  }

  async function scanQr(payload, signal) {
    return _request('POST', '/api/scan/qr', { payload }, signal);
  }

  async function unshortenUrl(url, signal) {
    return _request('POST', '/api/scan/unshorten', { url }, signal);
  }

  // ── History ───────────────────────────────────────────────────────────
  async function getHistory(page = 1, perPage = 20) {
    return _request('GET', `/api/history?page=${page}&per_page=${perPage}`);
  }

  async function deleteHistory(scanId) {
    return _request('DELETE', `/api/history/${scanId}`);
  }

  async function deleteAllHistory() {
    return _request('DELETE', '/api/history');
  }

  async function getHistoryStats() {
    return _request('GET', '/api/history/stats');
  }

  // ── Health ────────────────────────────────────────────────────────────
  async function health() {
    return _request('GET', '/api/health');
  }

  // ── Environment helpers ───────────────────────────────────────────────
  function setApiBase(url) {
    if (url) {
      localStorage.setItem('phishguard_api_url', url.trim().replace(/\/+$/, ''));
    } else {
      localStorage.removeItem('phishguard_api_url');
    }
  }

  // ── Public interface ──────────────────────────────────────────────────
  return {
    getToken, setToken, clearToken,
    register, login, logout, getMe,
    scanUrl, scanEmail, scanMessage, scanQr, unshortenUrl,
    getHistory, deleteHistory, deleteAllHistory, getHistoryStats,
    health,
    getApiBase, setApiBase,
  };
})();
