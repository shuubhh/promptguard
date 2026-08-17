/**
 * background.js — PromptGuard (MV3 service worker)
 *
 * Responsibilities:
 *   - Seed chrome.storage.local defaults on install.
 *   - Receive audit events from content scripts (PG_LOG_EVENT), persist them
 *     in `audit_log` (capped), update the toolbar badge, and — once a real
 *     backend is configured — sync events to it (silently).
 *   - Expose small helpers for the future dashboard connection
 *     (PG_IMPORT_PROJECT, PG_GET_STATE, PG_CLEAR_LOGS).
 */
'use strict';

// The event payload matches the Supabase `events` table schema from the brief.
// The real endpoint is configured at runtime via the popup
// (supabase_url + supabase_anon_key + auth_token).
const MAX_AUDIT_LOG = 500;
const MAX_PENDING_SYNC = 300;
const SYNC_RETRY_BASE_MS = 10000;

// ------------------------------------------------------------------
// Install / defaults
// ------------------------------------------------------------------
chrome.runtime.onInstalled.addListener(async () => {
  try {
    const state = await chrome.storage.local.get(null);
    const patch = {};
    if (!Array.isArray(state.projects)) patch.projects = [];
    if (!Array.isArray(state.audit_log)) patch.audit_log = [];
    if (!state.daily_stats || typeof state.daily_stats !== 'object') patch.daily_stats = {};
    if (!Array.isArray(state.pending_sync)) patch.pending_sync = [];
    if (typeof state.auth_token !== 'string') {
      patch.auth_token = '';
      patch.user_email = '';
      patch.org_id = '';
    }
    if (Object.keys(patch).length > 0) {
      await chrome.storage.local.set(patch);
    }
  } catch (err) {
    console.warn('[PromptGuard] onInstalled error', err);
  }
  // Sweep any unsynced events from the audit log (old tabs that logged
  // directly to storage before the background-sync path existed).
  reconcileAuditLog();
});

// Every time the service worker wakes, sweep the audit log for events that
// were never synced (old tabs, failed attempts) and queue them for delivery.
chrome.runtime.onStartup.addListener(() => {
  reconcileAuditLog();
});
reconcileAuditLog();

// When the popup saves/refreshes the connection (URL, keys, org_id), retry
// anything that couldn't sync before (e.g. queued while org_id was missing).
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  const keys = ['supabase_url', 'supabase_anon_key', 'auth_token', 'auth_refresh_token', 'org_id'];
  if (keys.some((k) => changes[k])) scheduleDrain(0);
});

// ------------------------------------------------------------------
// Message handling
// ------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== 'string') return false;

  if (msg.type === 'PG_LOG_EVENT') {
    logEvent(msg.event || {})
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true; // async response
  }

  if (msg.type === 'PG_GET_STATE') {
    chrome.storage.local
      .get(null)
      .then((state) => sendResponse(state))
      .catch(() => sendResponse({ error: 'storage_unavailable' }));
    return true;
  }

  if (msg.type === 'PG_CLEAR_LOGS') {
    chrome.storage.local
      .set({ audit_log: [], daily_stats: {}, pending_sync: [] })
      .then(() => {
        chrome.action.setBadgeText({ text: '' });
        sendResponse({ ok: true });
      })
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg.type === 'PG_IMPORT_PROJECT') {
    importProject(msg.project)
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: String((err && err.message) || err) }));
    return true;
  }

  return false;
});

// ------------------------------------------------------------------
// Event persistence + backend sync
// ------------------------------------------------------------------
// Every event flows through logEvent. A promise queue makes this the SINGLE
// writer for daily_stats: content scripts in multiple tabs used to do their
// own read-modify-write, which lost counts under concurrency. Serialising
// here fixes the multi-tab counter race.
let logQueue = Promise.resolve();

function logEvent(event) {
  logQueue = logQueue
    .then(() => doLogEvent(event))
    .catch((err) => {
      console.warn('[PromptGuard] logEvent error', err);
    });
  return logQueue;
}

async function doLogEvent(event) {
  const state = await chrome.storage.local.get(null);

  // 1) Audit log (capped)
  const audit = Array.isArray(state.audit_log) ? state.audit_log : [];
  audit.push(event);
  const trimmed = audit.slice(-MAX_AUDIT_LOG);

  // 2) Daily counters (single source of truth) + toolbar badge. Increment
  //    here so the badge includes THIS event, not the previous one.
  const stats = state.daily_stats && typeof state.daily_stats === 'object' ? state.daily_stats : {};
  const date = (event.timestamp || new Date().toISOString()).slice(0, 10);
  const today = stats[date] || { safe: 0, flagged: 0, blocked: 0 };
  if (event.event_type === 'silent') today.safe = (today.safe || 0) + 1;
  else if (event.event_type === 'blocked') today.blocked = (today.blocked || 0) + 1;
  else today.flagged = (today.flagged || 0) + 1;
  stats[date] = today;
  const badgeCount = (today.flagged || 0) + (today.blocked || 0);

  await chrome.storage.local.set({ audit_log: trimmed, daily_stats: stats });
  try {
    chrome.action.setBadgeText({ text: badgeCount > 0 ? String(badgeCount) : '' });
    chrome.action.setBadgeBackgroundColor({ color: '#e94560' });
  } catch (err) {
    /* action badge is cosmetic */
  }

  // 3) Sync meaningful events to the backend. Silent scans (no match, or a
  //    score below 0.50) stay local — on ChatGPT they fire on every request
  //    (telemetry, streaming, titles) and would spam the dashboard audit log.
  //    The brief's connection spec only syncs block/override/warn (+ redacted).
  //    Delivery is queued with retry + idempotent dedupe (see below) so a
  //    transient failure (expired token, network blip) can never lose an event.
  if (isSyncableEvent(event)) {
    await enqueueSync(event);
  }
}

// ------------------------------------------------------------------
// Pending-sync queue — eventually-consistent delivery to the dashboard
// ------------------------------------------------------------------
// Every syncable event goes into a persisted queue. A serialized drain
// delivers them with idempotent dedupe (an event already in the events table
// is skipped, not duplicated) and exponential backoff on failure. The queue
// lives in chrome.storage so it survives service-worker restarts.

function isSyncableEvent(event) {
  return !!(
    event &&
    event.event_type &&
    event.event_type !== 'silent' &&
    event.match_type !== 'connection_test'
  );
}

/** Deterministic identity of an event (used for dedupe + stamping). */
function eventKey(event) {
  if (!event) return '';
  return [
    event.org_id,
    event.event_type,
    event.platform,
    event.timestamp,
    event.confidence,
    event.match_preview
  ].join('|');
}

let drainTimer = null;
let drainQueue = Promise.resolve();

function scheduleDrain(delayMs) {
  if (drainTimer) return; // a drain is already scheduled
  drainTimer = setTimeout(() => {
    drainTimer = null;
    drainPendingSync();
  }, delayMs || 0);
}

async function enqueueSync(event) {
  try {
    const state = await chrome.storage.local.get('pending_sync');
    const pending = Array.isArray(state.pending_sync) ? state.pending_sync : [];
    pending.push({ event, attempts: 0, nextAttemptAt: 0 });
    await chrome.storage.local.set({ pending_sync: pending.slice(-MAX_PENDING_SYNC) });
  } catch (err) {
    /* queue is best-effort; the audit log still holds the event */
  }
  scheduleDrain(0);
}

async function drainPendingSync() {
  drainQueue = drainQueue
    .then(async () => {
      let pending = [];
      try {
        const state = await chrome.storage.local.get('pending_sync');
        pending = Array.isArray(state.pending_sync) ? state.pending_sync : [];
      } catch (err) {
        return;
      }
      if (pending.length === 0) return;

      const now = Date.now();
      const stillPending = [];
      let persisted = false;
      for (const item of pending) {
        if (!item || !isSyncableEvent(item.event)) continue; // drop junk
        if (item.nextAttemptAt && item.nextAttemptAt > now) {
          stillPending.push(item);
          continue;
        }
        const ok = await syncEventToBackend(item.event);
        if (ok) {
          persisted = true;
          await stampEventSynced(item.event);
        } else {
          item.attempts = (item.attempts || 0) + 1;
          item.nextAttemptAt = now + SYNC_RETRY_BASE_MS * Math.min(item.attempts, 6);
          stillPending.push(item);
        }
      }
      if (persisted || stillPending.length !== pending.length) {
        try {
          await chrome.storage.local.set({ pending_sync: stillPending.slice(-MAX_PENDING_SYNC) });
        } catch (err) {
          /* ignore */
        }
      }
      if (stillPending.length > 0) {
        const soonest = stillPending.reduce((m, i) => Math.min(m, i.nextAttemptAt || now), now);
        scheduleDrain(Math.max(5000, soonest - Date.now()));
      }
    })
    .catch((err) => {
      console.warn('[PromptGuard] drain error', err);
    });
  return drainQueue;
}

/**
 * Walk the audit log and queue any syncable events that were never synced.
 * Old tabs (loaded before the background-sync path) wrote events straight to
 * chrome.storage — this is how those events finally reach the dashboard.
 * Already-synced events carry a `synced_at` stamp and are skipped.
 */
async function reconcileAuditLog() {
  try {
    const state = await chrome.storage.local.get(['audit_log', 'pending_sync']);
    const audit = Array.isArray(state.audit_log) ? state.audit_log : [];
    const pending = Array.isArray(state.pending_sync) ? state.pending_sync : [];
    const pendingKeys = new Set(pending.map((p) => eventKey(p && p.event)));
    const toAdd = [];
    for (const ev of audit) {
      if (!isSyncableEvent(ev) || ev.synced_at) continue;
      const key = eventKey(ev);
      if (pendingKeys.has(key)) continue;
      toAdd.push({ event: ev, attempts: 0, nextAttemptAt: 0 });
    }
    if (toAdd.length === 0) return;
    await chrome.storage.local.set({
      pending_sync: pending.concat(toAdd).slice(-MAX_PENDING_SYNC)
    });
    console.log('[PromptGuard] reconcile: queued ' + toAdd.length + ' previously unsynced event(s)');
    scheduleDrain(0);
  } catch (err) {
    /* ignore */
  }
}

/** Mark an event in the audit log as synced so it is never re-queued. */
async function stampEventSynced(event) {
  try {
    const state = await chrome.storage.local.get('audit_log');
    const audit = Array.isArray(state.audit_log) ? state.audit_log : [];
    const key = eventKey(event);
    let changed = false;
    const next = audit.map((ev) => {
      if (!ev.synced_at && isSyncableEvent(ev) && eventKey(ev) === key) {
        changed = true;
        return Object.assign({}, ev, { synced_at: new Date().toISOString() });
      }
      return ev;
    });
    if (changed) await chrome.storage.local.set({ audit_log: next });
  } catch (err) {
    /* ignore */
  }
}

// ------------------------------------------------------------------
// Token helpers (mirrors the popup's auto-refresh so events sync even when
// the popup hasn't been opened — access-token JWTs expire after ~1 hour).
// ------------------------------------------------------------------

/** Expiry (ms) of a JWT, or null if it can't be decoded. */
function jwtExpiry(jwt) {
  if (!jwt || typeof jwt !== 'string') return null;
  try {
    const payload = JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  } catch (err) {
    return null;
  }
}

/**
 * Returns a usable access token: reuses the stored one while valid, otherwise
 * exchanges the stored refresh token for a fresh pair (rotating, so both are
 * persisted). Falls back to the stored token if there's nothing to refresh
 * with — the caller will surface the 401.
 */
async function getBackendToken(supabaseUrl, anonKey) {
  let access = '';
  let refresh = '';
  try {
    const state = await chrome.storage.local.get(['auth_token', 'auth_refresh_token']);
    access = state.auth_token || '';
    refresh = state.auth_refresh_token || '';
  } catch (err) {
    return access;
  }

  const exp = jwtExpiry(access);
  if (exp && exp > Date.now() + 30000) return access; // still valid

  if (!refresh) return access; // nothing to refresh with

  try {
    const res = await fetch(supabaseUrl + '/auth/v1/token?grant_type=refresh_token', {
      method: 'POST',
      headers: {
        apikey: anonKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ refresh_token: refresh })
    });
    if (!res.ok) {
      console.warn('[PromptGuard] token refresh failed HTTP ' + res.status);
      return access;
    }
    const data = await res.json();
    if (!data.access_token) return access;
    const next = { auth_token: data.access_token };
    if (data.refresh_token) next.auth_refresh_token = data.refresh_token;
    try {
      await chrome.storage.local.set(next);
    } catch (err) {
      /* token still works for this call even if persisting fails */
    }
    return data.access_token;
  } catch (err) {
    return access;
  }
}

async function syncEventToBackend(event) {
  let cfg = null;
  try {
    cfg = await chrome.storage.local.get(['supabase_url', 'supabase_anon_key', 'auth_token', 'org_id', 'user_email']);
  } catch (err) {
    return false;
  }
  const supabaseUrl = cfg.supabase_url || '';
  const anonKey = cfg.supabase_anon_key || '';
  let authToken = cfg.auth_token || '';
  if (!supabaseUrl || !anonKey || !authToken) return false;

  // Access tokens expire after ~1h — auto-refresh from the stored refresh
  // token so background syncs keep working between popup opens.
  authToken = await getBackendToken(supabaseUrl, anonKey);
  if (!authToken) return false;

  // Belt-and-braces: never POST with a null org_id — RLS drops those silently.
  const payload = Object.assign({}, event);
  if (!payload.org_id) payload.org_id = cfg.org_id || null;
  if (!payload.user_email) payload.user_email = cfg.user_email || '';
  if (!payload.org_id) {
    // Keep the event queued — it will deliver automatically once the popup
    // stores an org_id. Only warn once so the SW console isn't spammed.
    if (!event._warnedNoOrg) {
      event._warnedNoOrg = true;
      console.warn('[PromptGuard] event queued, waiting for org_id (connect the popup to sync)');
    }
    return false;
  }

  try {
    // Idempotency: if this exact event is already in the events table (e.g.
    // synced before the retry queue existed, or an identical re-log), skip
    // the insert — no duplicates in the dashboard.
    const existing = await findExistingEvent(supabaseUrl, anonKey, authToken, payload);
    if (existing) {
      return true;
    }

    const res = await fetch(supabaseUrl + '/rest/v1/events', {
      method: 'POST',
      headers: {
        apikey: anonKey,
        Authorization: 'Bearer ' + authToken,
        'Content-Type': 'application/json',
        Prefer: 'return=minimal'
      },
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      // Surface the failure in the service worker console for debugging.
      const text = await res.text().catch(() => '');
      console.error('[PromptGuard] event sync failed HTTP ' + res.status, text.slice(0, 300));
      return false;
    }
    return true;
  } catch (err) {
    // Event stays queued; retried with backoff.
    console.error('[PromptGuard] event sync network error', err);
    return false;
  }
}

/**
 * Returns the row if an event with the same identity fields already exists
 * in the events table (so a retry or old-tab sweep never duplicates it).
 */
async function findExistingEvent(supabaseUrl, anonKey, token, payload) {
  if (!payload.org_id || !payload.platform || !payload.event_type || !payload.timestamp) return null;
  if (payload.confidence === undefined || payload.confidence === null) return null;
  const q = [
    'select=id',
    'org_id=eq.' + encodeURIComponent(payload.org_id),
    'platform=eq.' + encodeURIComponent(payload.platform),
    'event_type=eq.' + encodeURIComponent(payload.event_type),
    'timestamp=eq.' + encodeURIComponent(payload.timestamp),
    'confidence=eq.' + encodeURIComponent(payload.confidence)
  ];
  if (payload.match_preview) q.push('match_preview=eq.' + encodeURIComponent(payload.match_preview));
  try {
    const res = await fetch(supabaseUrl + '/rest/v1/events?' + q.join('&'), {
      headers: { apikey: anonKey, Authorization: 'Bearer ' + token }
    });
    if (!res.ok) return null;
    const rows = await res.json();
    return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
  } catch (err) {
    return null;
  }
}

// ------------------------------------------------------------------
// Project import (used later by the dashboard connection)
// ------------------------------------------------------------------
async function importProject(project) {
  if (!project || !project.fingerprint) throw new Error('invalid project payload');
  const state = await chrome.storage.local.get('projects');
  const projects = Array.isArray(state.projects) ? state.projects : [];
  projects.push({
    id: project.id || 'project-' + Date.now().toString(36),
    name: project.name || 'Unnamed project',
    fingerprint: project.fingerprint,
    policy: project.policy || {}
  });
  await chrome.storage.local.set({ projects });
}
