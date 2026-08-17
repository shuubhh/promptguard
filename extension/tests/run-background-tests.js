/**
 * run-background-tests.js — headless tests for background.js's pending-sync
 * queue: retry/backoff, idempotent dedupe, audit-log reconciliation (heals
 * old tabs), and org_id waiting.
 *
 * Loads the REAL background.js in a Node vm sandbox with a stubbed chrome
 * API and a controllable fetch. No real network, no side effects.
 *
 * Usage: node extension/tests/run-background-tests.js
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

let failures = 0;
function check(name, cond, extra) {
  const ok = !!cond;
  console.log((ok ? '  PASS ' : '  FAIL ') + name + (ok ? '' : ' — ' + (extra || '')));
  if (!ok) failures++;
}

// ------------------------------------------------------------------ sandbox
function loadBackground({ fetchImpl }) {
  const storageData = {
    projects: [],
    audit_log: [],
    daily_stats: {},
    pending_sync: [],
    supabase_url: 'https://proj.supabase.co',
    supabase_anon_key: 'anon',
    auth_token: 'tok',
    org_id: 'org-1',
    user_email: 'dev@company.com'
  };
  const listeners = {};

  const chrome = {
    runtime: {
      onInstalled: { addListener: (f) => (listeners.installed = f) },
      onStartup: { addListener: (f) => (listeners.startup = f) },
      onMessage: { addListener: (f) => (listeners.message = f) }
    },
    storage: {
      local: {
        async get(keys) {
          if (keys === null) return { ...storageData };
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
      },
      onChanged: { addListener: (f) => (listeners.changed = f) }
    },
    action: {
      setBadgeText: () => {},
      setBadgeBackgroundColor: () => {}
    }
  };

  const calls = { posts: 0, gets: 0 };

  const context = {
    console,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
    setTimeout: () => 1, // never auto-fire; tests drive drains manually
    clearTimeout: () => {},
    chrome,
    fetch: async (url, opts) => {
      const u = String(url);
      if (u.includes('/rest/v1/events?') && (!opts || opts.method === undefined)) {
        calls.gets++;
        const existing = fetchImpl.existing ? fetchImpl.existing() : [];
        return { ok: true, status: 200, json: async () => existing };
      }
      if (u.includes('/rest/v1/events')) {
        calls.posts++;
        if (fetchImpl.failPosts) {
          return { ok: false, status: 500, text: async () => 'boom' };
        }
        return { ok: true, status: 201, text: async () => '' };
      }
      if (u.includes('/auth/v1/token')) {
        return { ok: false, status: 400, text: async () => '' };
      }
      return { ok: true, status: 200, json: async () => [] };
    }
  };
  vm.createContext(context);
  const src =
    fs.readFileSync(path.join(__dirname, '..', 'background.js'), 'utf8') +
    '\n;globalThis.__bg = { eventKey, isSyncableEvent, enqueueSync, drainPendingSync, reconcileAuditLog, syncEventToBackend };';
  vm.runInContext(src, context);
  return { bg: context.__bg, storage: storageData, calls, listeners };
}

const EVENT = {
  timestamp: '2026-08-17T10:00:00.000Z',
  org_id: 'org-1',
  user_email: 'dev@company.com',
  event_type: 'override',
  confidence: 0.99,
  regex_score: 0.99,
  match_type: 'aws_access_key',
  match_label: 'AWS Access Key',
  match_preview: 'AKIAIOSFODNN7EXAMPLE',
  platform: 'chatgpt',
  url: 'https://chatgpt.com/backend-api/conversation'
};

function makeEvent(overrides) {
  return Object.assign({}, EVENT, overrides || {});
}

(async () => {
  console.log('Test 1 — isSyncableEvent / eventKey:');
  {
    const { bg } = loadBackground({ fetchImpl: {} });
    check('silent is NOT syncable', !bg.isSyncableEvent(makeEvent({ event_type: 'silent' })));
    check('connection_test is NOT syncable', !bg.isSyncableEvent(makeEvent({ match_type: 'connection_test' })));
    check('override IS syncable', bg.isSyncableEvent(makeEvent({})));
    check('blocked IS syncable', bg.isSyncableEvent(makeEvent({ event_type: 'blocked' })));
    check('warned IS syncable', bg.isSyncableEvent(makeEvent({ event_type: 'warned' })));
    const a = bg.eventKey(makeEvent({}));
    const b = bg.eventKey(makeEvent({}));
    const c = bg.eventKey(makeEvent({ timestamp: '2026-08-17T11:00:00.000Z' }));
    check('eventKey deterministic for identical events', a === b);
    check('eventKey differs for different events', a !== c);
  }

  console.log('\nTest 2 — enqueue + drain delivers and stamps:');
  {
    const { bg, storage, calls } = loadBackground({ fetchImpl: {} });
    const ev = makeEvent({});
    storage.audit_log.push(ev); // mirror doLogEvent: persist THEN enqueue
    await bg.enqueueSync(ev);
    await bg.drainPendingSync();
    check('pending_sync drained', storage.pending_sync.length === 0);
    check('one POST to events table', calls.posts === 1, 'posts=' + calls.posts);
    const stamped = storage.audit_log.filter((e) => e.synced_at).length;
    check('audit log entry stamped synced_at', stamped === 1, 'stamped=' + stamped);
  }

  console.log('\nTest 3 — dedupe: already-existing event is NOT re-posted:');
  {
    const { bg, storage, calls } = loadBackground({
      fetchImpl: { existing: () => [{ id: 'already-there' }] }
    });
    const ev = makeEvent({});
    storage.audit_log.push(ev);
    await bg.enqueueSync(ev);
    await bg.drainPendingSync();
    check('no POST when event already exists', calls.posts === 0, 'posts=' + calls.posts);
    check('still drained + stamped', storage.pending_sync.length === 0 && storage.audit_log.some((e) => e.synced_at));
  }

  console.log('\nTest 4 — failed sync retries with backoff, then succeeds:');
  {
    const fetchImpl = { failPosts: true };
    const { bg, storage, calls } = loadBackground({ fetchImpl });
    const ev = makeEvent({});
    storage.audit_log.push(ev);
    await bg.enqueueSync(ev);
    await bg.drainPendingSync();
    check('first attempt failed → stays queued', storage.pending_sync.length === 1, 'len=' + storage.pending_sync.length);
    check('attempt count incremented', storage.pending_sync[0].attempts === 1);
    check('backoff scheduled in the future', storage.pending_sync[0].nextAttemptAt > Date.now());
    check('not stamped yet', !storage.audit_log.some((e) => e.synced_at));

    // Simulate time passing: clear the backoff and let the backend recover.
    storage.pending_sync[0].nextAttemptAt = 0;
    fetchImpl.failPosts = false;
    await bg.drainPendingSync();
    check('second attempt succeeds → queue drained', storage.pending_sync.length === 0);
    check('two POSTs total', calls.posts === 2, 'posts=' + calls.posts);
    check('stamped after success', storage.audit_log.some((e) => e.synced_at));
  }

  console.log('\nTest 5 — reconcile sweeps old-tab events from the audit log:');
  {
    const unsynced = makeEvent({ timestamp: '2026-08-17T09:00:00.000Z' });
    const already = makeEvent({ timestamp: '2026-08-17T08:00:00.000Z', synced_at: '2026-08-17T08:05:00.000Z' });
    const silent = makeEvent({ event_type: 'silent', timestamp: '2026-08-17T09:30:00.000Z' });
    const { bg, storage, calls } = loadBackground({ fetchImpl: {} });
    storage.audit_log = [unsynced, already, silent];
    await bg.reconcileAuditLog();
    check('only the unsynced syncable event is queued', storage.pending_sync.length === 1, 'len=' + storage.pending_sync.length);
    await bg.drainPendingSync();
    check('old-tab event POSTed exactly once', calls.posts === 1, 'posts=' + calls.posts);
    check('silent event never synced', !storage.audit_log.find((e) => e.event_type === 'silent').synced_at);
  }

  console.log('\nTest 6 — no org_id yet → event waits, does not drop:');
  {
    const { bg, storage, calls } = loadBackground({ fetchImpl: {} });
    storage.org_id = null;
    const ev = makeEvent({ org_id: null });
    storage.audit_log.push(ev);
    await bg.enqueueSync(ev);
    await bg.drainPendingSync();
    check('still queued (no POST without org_id)', storage.pending_sync.length === 1, 'len=' + storage.pending_sync.length);
    check('zero POSTs', calls.posts === 0);
    // Popup connects → storage change fires a drain → syncs.
    storage.org_id = 'org-1';
    storage.pending_sync[0].nextAttemptAt = 0; // clear backoff
    await bg.drainPendingSync();
    check('delivered once org_id arrives', storage.pending_sync.length === 0 && calls.posts === 1);
  }

  console.log('\n' + (failures === 0 ? 'ALL BACKGROUND TESTS PASSED' : failures + ' BACKGROUND TEST(S) FAILED'));
  process.exit(failures === 0 ? 0 : 1);
})().catch((err) => {
  console.error('FATAL:', err);
  process.exit(1);
});
