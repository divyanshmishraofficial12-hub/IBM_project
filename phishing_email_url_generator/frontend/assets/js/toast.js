/**
 * toast.js — Lightweight toast notification system.
 * Usage: Toast.show("Message", "success" | "error" | "warning" | "info")
 */

const Toast = (() => {
  const ICONS = {
    success: '✅',
    error:   '❌',
    warning: '⚠️',
    info:    'ℹ️',
  };

  const DURATION = {
    success: 3000,
    error:   5000,
    warning: 4000,
    info:    3500,
  };

  let container = null;

  function _getContainer() {
    if (!container) {
      container = document.getElementById('toast-container');
      if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        document.body.appendChild(container);
      }
    }
    return container;
  }

  function _dismiss(el) {
    el.classList.add('hide');
    el.addEventListener('animationend', () => el.remove(), { once: true });
  }

  /**
   * Show a toast notification.
   * @param {string} message
   * @param {'success'|'error'|'warning'|'info'} [type='info']
   * @param {number} [duration] - Override auto-dismiss duration (ms)
   */
  function show(message, type = 'info', duration) {
    const c = _getContainer();

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
      <span class="toast-icon" aria-hidden="true">${ICONS[type] ?? 'ℹ️'}</span>
      <span class="toast-msg">${message}</span>
      <button class="toast-close" aria-label="Dismiss">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => _dismiss(toast));
    c.appendChild(toast);

    const ms = duration ?? DURATION[type] ?? 3500;
    const timer = setTimeout(() => _dismiss(toast), ms);

    // Pause auto-dismiss on hover
    toast.addEventListener('mouseenter', () => clearTimeout(timer));
    toast.addEventListener('mouseleave', () => setTimeout(() => _dismiss(toast), 1500));
  }

  return { show };
})();
