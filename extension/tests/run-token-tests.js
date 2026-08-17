/**
 * run-token-tests.js — end-to-end test of the extension's JWT auto-refresh.
 *
 * Loads the REAL popup.js in a Node vm sandbox (stubbing only chrome.storage
 * and document), signs up a throwaway user against the REAL Supabase backend
 * (dashboard/.env), then proves:
 *   1. getAccessToken() reuses a still-valid access token (no refresh call).
 *   2. getAccessToken() with an EXPIRED access token exchanges the stored
 *      refresh token for a fresh pair and persists the rotation.
 *   3. The freshly rotated access token actually works against the REST API.
 *   4. With no refresh token stored, it degrades gracefully (returns the
 *      stored token instead of throwing).
 *
 * Requires: dashboard/.env with real VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY,
 * and email confirmation disabled on the project (autoconfirm).
 *
 * Usage: node extension/tests/run-token-tests.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

// ---------------------------------------------------------------- config
function loadEnv(file) {
  const out = {};
  const text = fs.readFileSync(file, 'utf8');
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}

const envFile = path.join(__dirname, '..', '..', 'dashboard', '.env');
const env = loadEnv(envFile);
const SUPABASE_URL = (env.VITE_SUPABASE_URL || '').replace(/\/+$/, '');
const ANON_KEY = env.VITE_SUPABASE_ANON_KEY || '';
if (!/^https:\/\//.test(SUPABASE_URL) || !ANON_KEY) {
  console.error('SKIP: dashboard/.env missing VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY');
  process.exit(2);
}

// ------------------------------------------------------------- helpers
let failures = 0;
function check(name, cond, extra) {
  const ok = !!cond;
  console.log((ok ? '  PASS ' : '  FAIL ') + name + (ok ? '' : ' — ' + (extra || '')));
  if (!ok) failures++;
}

function craftExpiredJwt(jwt) {
  // Rebuild the payload with exp in the past. Signature is left untouched —
  // the client never verifies it; it only decodes exp (exactly how the
  // "JWT expired" state manifests in production).
  const parts = jwt.split('.');
  const payload = JSON.parse(
    Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()
  );
  payload.exp = Math.floor(Date.now() / 1000) - 60;
  const newPayload = Buffer.from(JSON.stringify(payload))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return parts[0] + '.' + newPayload + '.' + parts[2];
}

function decodeJwtPayload(jwt) {
  return JSON.parse(Buffer.from(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
}

// Sandbox the REAL popup.js. Top-level `const` stays in script scope, so we
// append an export line to grab the functions.
function loadPopup(storageData) {
  const context = {
    console,
    fetch: global.fetch,
    // Real Chrome exposes atob on window; the vm sandbox needs it injected.
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    document: { addEventListener() {} },
    chrome: {
      storage: {
        local: {
          async get(keys) {
            if (Array.isArray(keys)) {
              const out = {};
              for (const k of keys) out[k] = storageData[k];
              return out;
            }
            if (typeof keys === 'string') return { [keys]: storageData[keys] };
            return { ...storageData };
          },
          async set(obj) {
            Object.assign(storageData, obj);
          }
        }
      }
    }
  };
  vm.createContext(context);
  const src =
    fs.readFileSync(path.join(__dirname, '..', 'popup.js'), 'utf8') +
    '\n;globalThis.__pg = { getAccessToken, jwtExpiry, saveAndFetchProjects, testConnection };';
  vm.runInContext(src, context);
  return context.__pg;
}

// ------------------------------------------------------------- the test
async function signup() {
  const email = 'pg.token.' + Date.now() + '.' + Math.floor(Math.random() * 1e6) + '@gmail.com';
  const res = await fetch(SUPABASE_URL + '/auth/v1/signup', {
    method: 'POST',
    headers: { apikey: ANON_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'PromptGuard!Test1' })
  });
  if (!res.ok) throw new Error('signup failed HTTP ' + res.status + ' ' + (await res.text()).slice(0, 200));
  const data = await res.json();
  if (!data.access_token || !data.refresh_token) {
    throw new Error('signup returned no session — email confirmation may still be ON. Body: ' + JSON.stringify(data).slice(0, 200));
  }
  return { email, accessToken: data.access_token, refreshToken: data.refresh_token };
}

(async () => {
  console.log('Signing up a throwaway user against ' + SUPABASE_URL + ' …');
  const { email, accessToken, refreshToken } = await signup();
  console.log('  session obtained for ' + email);

  console.log('\nTest 1 — still-valid token is reused, no refresh call:');
  {
    const storage = { auth_token: accessToken, auth_refresh_token: refreshToken };
    const { getAccessToken } = loadPopup(storage);
    const got = await getAccessToken(SUPABASE_URL, ANON_KEY);
    check('returns the stored token unchanged', got === accessToken);
    check('refresh token untouched (no rotation)', storage.auth_refresh_token === refreshToken);
  }

  console.log('\nTest 2 — EXPIRED token triggers refresh + rotation:');
  {
    const expired = craftExpiredJwt(accessToken);
    const storage = { auth_token: expired, auth_refresh_token: refreshToken };
    const { getAccessToken } = loadPopup(storage);
    const got = await getAccessToken(SUPABASE_URL, ANON_KEY);
    check('returned token differs from the expired one', got && got !== expired, 'got same token');
    check('persisted auth_token is the fresh one', storage.auth_token === got);
    check('refresh token rotated to a new value', storage.auth_refresh_token && storage.auth_refresh_token !== refreshToken, 'not rotated');
    check('fresh token has a future exp', decodeJwtPayload(got).exp * 1000 > Date.now());
  }

  console.log('\nTest 3 — rotated access token works against the REST API:');
  {
    const expired = craftExpiredJwt(accessToken);
    const storage = { auth_token: expired, auth_refresh_token: refreshToken };
    const { getAccessToken } = loadPopup(storage);
    const fresh = await getAccessToken(SUPABASE_URL, ANON_KEY);
    const res = await fetch(SUPABASE_URL + '/rest/v1/user_profiles?select=org_id&limit=1', {
      headers: { apikey: ANON_KEY, Authorization: 'Bearer ' + fresh }
    });
    check('user_profiles returns HTTP 200 with fresh token', res.ok, 'HTTP ' + res.status);
  }

  console.log('\nTest 4 — no refresh token stored → graceful fallback:');
  {
    const expired = craftExpiredJwt(accessToken);
    const storage = { auth_token: expired, auth_refresh_token: '' };
    const { getAccessToken } = loadPopup(storage);
    const got = await getAccessToken(SUPABASE_URL, ANON_KEY);
    check('returns stored token without throwing', got === expired);
  }

  console.log('\n' + (failures === 0 ? 'ALL TOKEN TESTS PASSED' : failures + ' TOKEN TEST(S) FAILED'));
  process.exit(failures === 0 ? 0 : 1);
})().catch((err) => {
  console.error('FATAL:', err.message);
  process.exit(1);
});
