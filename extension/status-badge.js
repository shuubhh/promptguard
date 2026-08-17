/**
 * status-badge.js — PromptGuard
 *
 * Floating badge (bottom-right): "🛡️ PromptGuard Active | Safe: 12 | Flagged: 1"
 *   - Counts are persisted in chrome.storage.local under `daily_stats`,
 *     keyed by date (YYYY-MM-DD).
 *   - Clicking the badge opens a mini popup listing the last 5 audit events.
 *   - updateStatusBadge(eventType) is called by content.js after every scan.
 */
(function () {
  'use strict';

  const PG = window.__PromptGuard || {};

  let badgeEl = null;
  let popupEl = null;
  let counts = { safe: 0, flagged: 0, blocked: 0 };
  let lastEvents = [];

  function todayKey() {
    return new Date().toISOString().slice(0, 10);
  }

  // ------------------------------------------------------------------
  // Persistence
  // ------------------------------------------------------------------
  async function readDailyStats() {
    try {
      const state = await chrome.storage.local.get('daily_stats');
      const stats = (state && state.daily_stats) || {};
      const today = stats[todayKey()] || {};
      counts = {
        safe: today.safe || 0,
        flagged: today.flagged || 0,
        blocked: today.blocked || 0
      };
    } catch (err) {
      counts = { safe: 0, flagged: 0, blocked: 0 };
    }
  }

  // Counters are now maintained by the background service worker (single
  // writer — fixes the multi-tab lost-update race). This side only READS
  // daily_stats and re-renders when the worker writes it.
  async function loadRecentEvents() {
    try {
      const state = await chrome.storage.local.get('audit_log');
      lastEvents = Array.isArray(state.audit_log) ? state.audit_log.slice(-5).reverse() : [];
    } catch (err) {
      lastEvents = [];
    }
  }

  // ------------------------------------------------------------------
  // UI
  // ------------------------------------------------------------------
  function ensureBadge() {
    if (badgeEl && document.documentElement.contains(badgeEl)) return badgeEl;

    badgeEl = document.createElement('div');
    badgeEl.className = 'pg-badge';
    badgeEl.setAttribute('role', 'button');
    badgeEl.setAttribute('aria-label', 'PromptGuard status');

    const icon = document.createElement('span');
    icon.className = 'pg-badge-icon';
    icon.textContent = '🛡️';

    const text = document.createElement('span');
    text.className = 'pg-badge-text';
    text.textContent = 'PromptGuard Active';

    const stats = document.createElement('span');
    stats.className = 'pg-badge-stats';

    badgeEl.appendChild(icon);
    badgeEl.appendChild(text);
    badgeEl.appendChild(stats);

    badgeEl.addEventListener('click', (e) => {
      e.stopPropagation();
      togglePopup();
    });

    document.documentElement.appendChild(badgeEl);
    return badgeEl;
  }

  function render() {
    const el = ensureBadge();
    const statsEl = el.querySelector('.pg-badge-stats');
    if (statsEl) {
      statsEl.textContent =
        'Safe: ' + counts.safe + ' | Flagged: ' + (counts.flagged + counts.blocked);
    }
  }

  function togglePopup() {
    if (popupEl && document.documentElement.contains(popupEl)) {
      closePopup();
      return;
    }
    loadRecentEvents().then(() => {
      renderPopup();
    });
  }

  function renderPopup() {
    closePopup();
    popupEl = document.createElement('div');
    popupEl.className = 'pg-popup';

    const header = document.createElement('div');
    header.className = 'pg-popup-header';
    const title = document.createElement('span');
    title.className = 'pg-popup-title';
    title.textContent = 'Recent events';
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'pg-popup-close';
    close.textContent = '✕';
    close.addEventListener('click', closePopup);
    header.appendChild(title);
    header.appendChild(close);
    popupEl.appendChild(header);

    if (lastEvents.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'pg-popup-empty';
      empty.textContent = 'No events yet today.';
      popupEl.appendChild(empty);
    } else {
      for (const ev of lastEvents) {
        const row = document.createElement('div');
        row.className = 'pg-popup-row';
        const left = document.createElement('div');
        left.className = 'pg-popup-left';
        const when = document.createElement('div');
        when.className = 'pg-popup-when';
        when.textContent = formatTime(ev.timestamp);
        const what = document.createElement('div');
        what.className = 'pg-popup-what';
        what.textContent = String(ev.match_label || ev.match_type || 'scan');
        left.appendChild(when);
        left.appendChild(what);
        const right = document.createElement('div');
        right.className = 'pg-popup-right';
        const type = document.createElement('span');
        type.className = 'pg-popup-type pg-popup-type-' + ev.event_type;
        type.textContent = ev.event_type;
        const conf = document.createElement('span');
        conf.className = 'pg-popup-conf';
        conf.textContent = Math.round((ev.confidence || 0) * 100) + '%';
        right.appendChild(type);
        right.appendChild(conf);
        row.appendChild(left);
        row.appendChild(right);
        popupEl.appendChild(row);
      }
    }

    document.documentElement.appendChild(popupEl);

    // Close when clicking anywhere else.
    setTimeout(() => {
      document.addEventListener('click', onOutsideClick, true);
    }, 0);
  }

  function onOutsideClick(e) {
    if (popupEl && !popupEl.contains(e.target) && !(badgeEl && badgeEl.contains(e.target))) {
      closePopup();
    }
  }

  function closePopup() {
    document.removeEventListener('click', onOutsideClick, true);
    if (popupEl && popupEl.parentNode) popupEl.parentNode.removeChild(popupEl);
    popupEl = null;
  }

  function formatTime(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (err) {
      return '';
    }
  }

  // ------------------------------------------------------------------
  // Public API
  // ------------------------------------------------------------------
  // Called by content.js after every scan. The worker has already (or is
  // about to) persist the new counters — re-read and re-render. If the read
  // races ahead of the worker's write, the storage.onChanged listener below
  // catches up as soon as the write lands.
  async function updateStatusBadge(/* eventType */) {
    await readDailyStats();
    render();
  }

  async function initStatusBadge() {
    await readDailyStats();
    await loadRecentEvents();
    // Live-update from the worker's writes (this tab AND other tabs).
    try {
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;
        if (changes.daily_stats) {
          readDailyStats().then(render);
        }
        if (changes.audit_log) {
          loadRecentEvents();
        }
      });
    } catch (err) {
      /* ignore */
    }
    render();
  }

  PG.updateStatusBadge = updateStatusBadge;
  PG.initStatusBadge = initStatusBadge;
})();
