/**
 * popup.js — PromptGuard extension popup
 *
 * Connects the extension to the dashboard backend (Supabase REST):
 *   1. User pastes Supabase URL + anon key + API key (their user JWT from
 *      Dashboard → Settings → Extension API key), and optionally the
 *      long-lived refresh token from the same page.
 *   2. "Save & Fetch Projects" stores the connection and pulls the org's
 *      projects (id, name, fingerprint) into chrome.storage.local.
 *   3. The scanner-engine live-reloads on chrome.storage changes, so new
 *      fingerprints are active immediately.
 *
 * TOKEN LIFECYCLE (why the refresh token matters):
 *   Supabase access-token JWTs expire after ~1 hour ("JWT expired" / 401).
 *   The refresh token stays valid long-term and is single-use (rotating):
 *   each exchange returns a NEW access token AND a NEW refresh token. The
 *   extension stores both after every exchange, so it stays connected
 *   indefinitely — re-paste only after clearing extension storage or signing
 *   out of the dashboard (which invalidates the refresh token server-side).
 */
'use strict';

const $ = (id) => document.getElementById(id);

async function loadStateIntoForm() {
  try {
    const state = await chrome.storage.local.get([
      'supabase_url',
      'supabase_anon_key',
      'auth_token',
      'auth_refresh_token',
      'projects',
      'daily_stats'
    ]);
    $('supabaseUrl').value = state.supabase_url || '';
    $('anonKey').value = state.supabase_anon_key || '';
    $('apiKey').value = state.auth_token || '';
    $('refreshToken').value = state.auth_refresh_token || '';

    const projects = Array.isArray(state.projects) ? state.projects : [];
    $('statProjects').textContent = projects.length > 0 ? String(projects.length) : '—';

    const today = todayKey();
    const stats = (state.daily_stats && state.daily_stats[today]) || {};
    $('statSafe').textContent = String(stats.safe || 0);
    $('statFlagged').textContent = String(stats.flagged || 0);
    $('statBlocked').textContent = String(stats.blocked || 0);
  } catch (err) {
    /* ignore */
  }
}

function todayKey() {
  return new Date().toISOString().slice(0, 10);
}

function setStatus(text, isError) {
  const el = $('saveStatus');
  el.textContent = text;
  el.className = 'pg-save-status' + (isError ? ' error' : '');
}

function setJoinStatus(text, isError) {
  const el = $('joinStatus');
  el.textContent = text;
  el.className = 'pg-save-status' + (isError ? ' error' : '');
}

function setOrgStatus(text, isError) {
  const el = $('orgStatus');
  el.textContent = text;
  el.className = 'pg-save-status' + (isError ? ' error' : '');
}

// ------------------------------------------------------------------
// v2: org join (device-token flow — no manual Supabase credentials)
// ------------------------------------------------------------------
function setOrgUi(device) {
  const joined = !!device && !!device.token;
  $('orgJoined').hidden = !joined;
  $('orgJoinForm').hidden = joined;
  if (joined) {
    $('orgNameLabel').textContent = device.org_name || 'Connected org';
    $('orgEmailLabel').textContent = device.user_email || '';
  }
}

async function loadOrgState() {
  try {
    const res = await chrome.runtime.sendMessage({ type: 'PG_GET_DEVICE_STATE' });
    setOrgUi(res && res.device);
  } catch (err) {
    /* background not ready */
  }
}

async function joinOrg() {
  const code = $('orgCode').value.trim().toUpperCase();
  const email = $('orgEmail').value.trim();
  if (code.length < 6) {
    setJoinStatus('Enter the org code from your admin', true);
    return;
  }
  setJoinStatus('Joining…', false);
  try {
    const res = await chrome.runtime.sendMessage({
      type: 'PG_JOIN_ORG',
      code: code,
      device_name: /Edg\//.test(navigator.userAgent) ? 'Edge' : /Firefox\//.test(navigator.userAgent) ? 'Firefox' : 'Chrome',
      user_email: email
    });
    if (!res || !res.ok) {
      setJoinStatus(res && res.error ? res.error : 'Join failed', true);
      return;
    }
    setJoinStatus('Joined ' + (res.org_name || '') + ' — projects loaded', false);
    await loadOrgState();
    loadStateIntoForm(); // refresh project/stats counts
  } catch (err) {
    setJoinStatus('Error: ' + (err && err.message ? err.message : err), true);
  }
}

async function syncNow() {
  setOrgStatus('Syncing…', false);
  try {
    const res = await chrome.runtime.sendMessage({ type: 'PG_SYNC_NOW' });
    if (!res || !res.ok) {
      setOrgStatus(res && res.error ? res.error : 'Sync failed', true);
      return;
    }
    setOrgStatus('Synced — ' + res.projects + ' project(s)', false);
    loadStateIntoForm();
  } catch (err) {
    setOrgStatus('Error: ' + (err && err.message ? err.message : err), true);
  }
}

async function disconnect() {
  try {
    await chrome.runtime.sendMessage({ type: 'PG_DISCONNECT_DEVICE' });
    setOrgUi(null);
    loadStateIntoForm();
  } catch (err) {
    /* ignore */
  }
}

// ------------------------------------------------------------------
// v2: on-device AI (Gemini Nano) — enable / disable with download progress
// ------------------------------------------------------------------
let aiAvailability = 'unavailable';

function setAIStatus(text, isError) {
  const el = $('aiStatus');
  el.textContent = text;
  el.className = 'pg-ai-status' + (isError ? ' error' : '');
}

function updateAIProgress(ratio) {
  const pct = Math.max(0, Math.min(100, Math.round((ratio || 0) * 100)));
  $('aiProgressBar').style.width = pct + '%';
  $('aiProgressLabel').textContent =
    pct < 100
      ? 'Downloading Gemini Nano — ' + pct + '% (one-time, Chrome-managed)'
      : 'Download complete — finishing up…';
}

async function loadAIState() {
  let enabled = false;
  let flags = {};
  try {
    const state = await chrome.storage.local.get(['ai_enabled', 'feature_flags']);
    enabled = state.ai_enabled === true;
    flags = state.feature_flags && typeof state.feature_flags === 'object' ? state.feature_flags : {};
  } catch (err) {
    /* ignore */
  }

  // Org admin can force on/off via the organisation's feature flags.
  if (flags.ai === 'off') {
    $('aiEnableBtn').hidden = true;
    $('aiDisableBtn').hidden = true;
    setAIStatus('Disabled by your org admin (feature flag)', true);
    return;
  }
  if (flags.ai === 'on') {
    enabled = true;
  }

  // Availability check runs in the popup document (an extension page, where
  // the Prompt API exists) — the same context that will host the download.
  if (PG.ai) {
    try {
      aiAvailability = await PG.ai.checkAvailability();
    } catch (err) {
      aiAvailability = 'unavailable';
    }
  } else {
    aiAvailability = 'unavailable';
  }
  renderAIUi(enabled);
}

function renderAIUi(enabled) {
  $('aiEnableBtn').hidden = enabled;
  $('aiDisableBtn').hidden = !enabled;
  if (enabled) {
    setAIStatus('Active — Gemini Nano adjudicates ambiguous prompts, fully on-device');
    return;
  }
  if (aiAvailability === 'available') {
    setAIStatus('Gemini Nano is downloaded — ready to enable.');
  } else if (aiAvailability === 'downloading' || aiAvailability === 'downloadable') {
    setAIStatus('Available to download (~1–2 GB, one-time, managed by Chrome).');
  } else {
    setAIStatus(
      'Not available on this device. Needs Chrome 138+ on Windows 10/11, macOS 13+, Linux or Chromebook Plus, with 16 GB+ RAM (or 4 GB+ VRAM) and 22 GB free storage.',
      true
    );
  }
}

async function enableAI() {
  if (!PG.ai) {
    setAIStatus('AI engine failed to load — reload the extension', true);
    return;
  }
  const btn = $('aiEnableBtn');
  btn.disabled = true;
  $('aiProgressWrap').hidden = false;
  updateAIProgress(0);
  setAIStatus('Preparing Gemini Nano…');
  try {
    // create() runs synchronously inside this click handler — the fresh user
    // activation the Prompt API requires for the first (download) session.
    // The monitor callback reports download progress; when the model is
    // already downloaded, create() resolves immediately.
    const session = await PG.ai.createSession({
      monitor(m) {
        m.addEventListener('downloadprogress', (e) => {
          // Per the docs e.loaded is a 0..1 ratio; guard for total-based too.
          const ratio = e.total ? e.loaded / e.total : e.loaded;
          updateAIProgress(ratio);
        });
      }
    });
    if (!session) throw new Error('session create failed');
    try {
      if (session.destroy) session.destroy();
    } catch (err) {
      /* ignore */
    }
    await chrome.storage.local.set({ ai_enabled: true });
    $('aiProgressWrap').hidden = true;
    aiAvailability = 'available';
    renderAIUi(true);
    setAIStatus('Enabled — Gemini Nano is now active on AI platforms');
  } catch (err) {
    $('aiProgressWrap').hidden = true;
    aiAvailability = await PG.ai.checkAvailability().catch(() => 'unavailable');
    renderAIUi(false);
    setAIStatus('Could not start the download: ' + String((err && err.message) || err), true);
  } finally {
    btn.disabled = false;
  }
}

async function disableAI() {
  try {
    await chrome.storage.local.set({ ai_enabled: false });
  } catch (err) {
    /* ignore */
  }
  renderAIUi(false);
  setAIStatus('Disabled — regex + fingerprint detection still active');
}

// ------------------------------------------------------------------
// Token helpers
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
 * Returns a valid access token for REST calls:
 *   - reuse the stored access token while it's still valid (30s margin),
 *   - otherwise exchange the stored refresh token for a fresh pair
 *     (GoTrue grant_type=refresh_token — single-use, so the rotated pair is
 *     persisted), 
 *   - otherwise fall back to the stored token (the caller will surface the
 *     401 so the user can re-paste).
 */
async function getAccessToken(supabaseUrl, anonKey) {
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
    if (!res.ok) return access;
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

async function saveAndFetchProjects() {
  const supabaseUrl = $('supabaseUrl').value.trim().replace(/\/+$/, '');
  const anonKey = $('anonKey').value.trim();
  const apiKey = $('apiKey').value.trim();
  const refreshToken = $('refreshToken').value.trim();

  if (!supabaseUrl || !anonKey || (!apiKey && !refreshToken)) {
    setStatus('Supabase URL, anon key, and API key (or refresh token) are required', true);
    return;
  }
  if (!/^https:\/\//.test(supabaseUrl)) {
    setStatus('Supabase URL must start with https://', true);
    return;
  }

  setStatus('Fetching projects…', false);

  try {
    // Persist the raw pasted credentials first, then let getAccessToken()
    // refresh/rotate as needed before we use the token.
    await chrome.storage.local.set({
      supabase_url: supabaseUrl,
      supabase_anon_key: anonKey,
      auth_token: apiKey,
      auth_refresh_token: refreshToken
    });

    const token = await getAccessToken(supabaseUrl, anonKey);
    if (!token) {
      setStatus('No usable API key — paste your JWT or a refresh token', true);
      return;
    }

    // Pull the projects the user's org can see (RLS applies server-side).
    const res = await fetch(supabaseUrl + '/rest/v1/projects?select=id,name,fingerprint,org_id', {
      headers: {
        apikey: anonKey,
        Authorization: 'Bearer ' + token
      }
    });
    if (res.status === 401 || res.status === 403) {
      setStatus('Auth failed — API key expired? Re-copy it from Dashboard → Settings', true);
      return;
    }
    if (!res.ok) {
      setStatus('Request failed (' + res.status + ')', true);
      return;
    }
    const rows = await res.json();
    const projects = Array.isArray(rows)
      ? rows
          .filter((r) => r && r.fingerprint)
          .map((r) => ({ id: r.id, name: r.name || 'Unnamed project', fingerprint: r.fingerprint }))
      : [];

    // org_id must be stored even when there are zero projects — otherwise the
    // extension POSTs events with org_id=null and Supabase RLS drops them all.
    let orgId = rows && rows.length > 0 ? rows[0].org_id : null;
    if (!orgId) {
      try {
        const pRes = await fetch(supabaseUrl + '/rest/v1/user_profiles?select=org_id&limit=1', {
          headers: {
            apikey: anonKey,
            Authorization: 'Bearer ' + token
          }
        });
        if (pRes.ok) {
          const profiles = await pRes.json();
          if (Array.isArray(profiles) && profiles.length > 0) {
            orgId = profiles[0].org_id || null;
          }
        }
      } catch (err) {
        /* org_id stays null; events will be logged locally only */
      }
    }

    await chrome.storage.local.set({
      org_id: orgId,
      user_email: decodeEmailFromJwt(token),
      projects: projects
    });

    $('statProjects').textContent = String(projects.length);
    if (projects.length === 0) {
      setStatus('Saved — 0 projects loaded. Create a project in the dashboard to enable fingerprint scanning.', false);
    } else {
      setStatus('Saved — ' + projects.length + ' project(s) loaded', false);
    }
  } catch (err) {
    setStatus('Network error: ' + (err && err.message ? err.message : err), true);
  }
}

function decodeEmailFromJwt(jwt) {
  try {
    const payload = jwt.split('.')[1];
    const json = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return json.email || '';
  } catch (err) {
    return '';
  }
}

/**
 * POSTs a synthetic event straight to the Supabase events table and shows the
 * raw HTTP result — instant diagnosis of the connection/RLS/auth pipeline.
 * Uses a fresh access token (auto-refreshed from the stored refresh token)
 * and then deletes its probe row so the audit log stays clean.
 */
async function testConnection() {
  const supabaseUrl = $('supabaseUrl').value.trim().replace(/\/+$/, '');
  const anonKey = $('anonKey').value.trim();
  if (!supabaseUrl || !anonKey) {
    setStatus('Fill in Supabase URL and anon key first', true);
    return;
  }
  setStatus('Sending test event…', false);
  try {
    const token = await getAccessToken(supabaseUrl, anonKey);
    if (!token) {
      setStatus('No usable API key — click Save & Fetch Projects first', true);
      return;
    }
    const state = await chrome.storage.local.get(['org_id', 'user_email']);
    const orgId = state.org_id || null;
    if (!orgId) {
      setStatus('No org linked yet — click Save & Fetch Projects first', true);
      return;
    }
    const res = await fetch(supabaseUrl + '/rest/v1/events', {
      method: 'POST',
      headers: {
        apikey: anonKey,
        Authorization: 'Bearer ' + token,
        'Content-Type': 'application/json',
        // return=representation gives us the inserted row so we can clean it
        // up right away — the test must not linger in the audit log.
        Prefer: 'return=representation'
      },
      body: JSON.stringify({
        org_id: orgId,
        user_email: state.user_email || 'test@promptguard.local',
        event_type: 'silent',
        confidence: 0,
        match_type: 'connection_test',
        match_label: 'Connection Test',
        match_preview: 'Popup connection test',
        platform: 'popup',
        timestamp: new Date().toISOString()
      })
    });
    const text = await res.text().catch(() => '');
    if (!res.ok) {
      setStatus('FAILED HTTP ' + res.status + ' — ' + text.slice(0, 140), true);
      return;
    }
    // Best-effort cleanup: delete the probe row we just inserted (allowed by
    // the RLS delete policy on connection_test rows). If the policy isn't
    // applied yet, the dashboard hides test rows by default anyway.
    let cleaned = false;
    try {
      const rows = JSON.parse(text);
      const id = Array.isArray(rows) && rows[0] ? rows[0].id : null;
      if (id) {
        const del = await fetch(supabaseUrl + '/rest/v1/events?id=eq.' + id, {
          method: 'DELETE',
          headers: {
            apikey: anonKey,
            Authorization: 'Bearer ' + token
          }
        });
        cleaned = del.ok;
      }
    } catch (err) {
      /* cleanup is best-effort */
    }
    setStatus(
      cleaned
        ? 'Test event sent (HTTP ' + res.status + ') & cleaned up — pipeline OK'
        : 'Test event sent (HTTP ' + res.status + ') — row hidden from Events page',
      false
    );
  } catch (err) {
    setStatus('Network error: ' + (err && err.message ? err.message : err), true);
  }
}

async function clearLogs() {
  try {
    await chrome.runtime.sendMessage({ type: 'PG_CLEAR_LOGS' });
    $('statSafe').textContent = '0';
    $('statFlagged').textContent = '0';
    $('statBlocked').textContent = '0';
  } catch (err) {
    /* ignore */
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadStateIntoForm();
  loadOrgState();
  loadAIState();
  $('saveBtn').addEventListener('click', saveAndFetchProjects);
  $('testBtn').addEventListener('click', testConnection);
  $('clearLogsBtn').addEventListener('click', clearLogs);
  $('joinBtn').addEventListener('click', joinOrg);
  $('syncNowBtn').addEventListener('click', syncNow);
  $('disconnectBtn').addEventListener('click', disconnect);
  $('aiEnableBtn').addEventListener('click', enableAI);
  $('aiDisableBtn').addEventListener('click', disableAI);
});
