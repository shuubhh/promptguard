/**
 * run-interceptor-tests.js — behavioral tests for page-interceptor.js.
 *
 * Loads the MAIN-world fetch/XHR wrapper into a stubbed environment and
 * verifies that ONLY user-prompt payloads are scanned — telemetry/auth/short
 * bodies pass through untouched (this is what caused the Aadhaar false
 * positives on ChatGPT background requests).
 *
 * Run with Node:
 *   node extension/tests/run-interceptor-tests.js
 */
'use strict';

const assert = require('assert');
const path = require('path');
const { createRequire } = require('module');

// ------------------------------------------------------------------
// Environment stubs (mirrors a page running on chatgpt.com)
// ------------------------------------------------------------------
const listeners = {};
let scanEventCount = 0;
let scanBodies = [];
const originalCalls = [];

const originalFetchStub = async function (url, opts) {
  originalCalls.push({ url, opts });
  return { ok: true, status: 200 };
};

global.window = {
  __PROMPTGUARD_INTERCEPTOR__: undefined,
  location: { hostname: 'chatgpt.com', href: 'https://chatgpt.com/' },
  fetch: originalFetchStub,
  addEventListener: (type, fn) => {
    (listeners[type] = listeners[type] || []).push(fn);
  },
  removeEventListener: () => {},
  dispatchEvent: (ev) => {
    if (ev && ev.type === 'promptguard:scan') {
      scanEventCount += 1;
      scanBodies.push(ev.detail ? ev.detail.body : null);
      // Simulate the isolated-world scanner answering "allow".
      const d = ev.detail || {};
      setTimeout(() => {
        const resp = new global.CustomEvent('promptguard:decision', {
          detail: { requestId: d.requestId, decision: 'allow' }
        });
        for (const fn of listeners['promptguard:decision'] || [].slice()) fn(resp);
      }, 0);
    }
    for (const fn of (listeners[ev.type] || []).slice()) fn(ev);
  },
  CustomEvent: global.CustomEvent
};

// Recording stub: the interceptor captures this as its "originalSend", so
// anything the wrapper ultimately sends lands here (allowing us to assert
// that the request went through with the same body).
const sentBodies = [];
global.XMLHttpRequest = function () {
  this.__pgUrl = '';
  this.__pgMethod = 'POST';
};
XMLHttpRequest.prototype.open = function () {};
XMLHttpRequest.prototype.send = function (body) {
  sentBodies.push(body);
};

// ------------------------------------------------------------------
// Load the interceptor (wraps window.fetch + XHR)
// ------------------------------------------------------------------
const req = createRequire(__filename);
req('../page-interceptor.js');

assert(typeof window.fetch === 'function' && window.fetch !== originalFetchStub, 'fetch not wrapped');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log('  ✓ ' + name);
  } catch (err) {
    failed += 1;
    console.log('  ✗ ' + name);
    console.log('    ' + (err && err.message ? err.message : err));
  }
}

function reset() {
  scanEventCount = 0;
  scanBodies = [];
  originalCalls.length = 0;
}

const CONVERSATION_BODY = JSON.stringify({
  model: 'gpt-4o',
  conversation_id: '6a808afc-1a98-83ee-b7dd-4a97091023cd',
  messages: [
    {
      author: { role: 'user' },
      content: { content_type: 'text', parts: ['Refactor the login flow'] }
    }
  ],
  stream: true
});

const TELEMETRY_BODY = JSON.stringify({
  event: 'page_view',
  source: 'web',
  id: '699999988079',
  client_timestamp: 1786809270000
});

const AUTH_BODY = JSON.stringify({
  access_token: 'eyJhbGciOiJIUzI1NiJ9.abc',
  session: { refresh_token: 'xyz' }
});

(async function main() {
  console.log('PromptGuard interceptor tests\n');

  // ---------- fetch: which bodies get scanned ----------
  await test('Conversation payload IS scanned', async () => {
    reset();
    const options = { method: 'POST', body: CONVERSATION_BODY };
    await window.fetch('https://chatgpt.com/backend-api/conversation', options);
    assert.strictEqual(scanEventCount, 1, 'scan event dispatched');
    assert.strictEqual(scanBodies[0], CONVERSATION_BODY, 'scanned body matches');
    assert.strictEqual(originalCalls.length, 1, 'original fetch called');
    assert.strictEqual(originalCalls[0].opts, options, 'same options object passed through (no mutation)');
  });

  await test('Telemetry payload (numeric ID) is NOT scanned', async () => {
    reset();
    const options = { method: 'POST', body: TELEMETRY_BODY };
    await window.fetch('https://chatgpt.com/backend-api/register_event', options);
    assert.strictEqual(scanEventCount, 0, 'no scan event');
    assert.strictEqual(originalCalls.length, 1, 'original fetch called immediately');
    assert.strictEqual(originalCalls[0].opts, options, 'same options object');
  });

  await test('Auth/token payload is NOT scanned', async () => {
    reset();
    const options = { method: 'POST', body: AUTH_BODY };
    await window.fetch('https://chatgpt.com/backend-api/session', options);
    assert.strictEqual(scanEventCount, 0, 'no scan event');
  });

  await test('Short/empty body is NOT scanned', async () => {
    reset();
    await window.fetch('https://chatgpt.com/backend-api/ping', { method: 'POST', body: '{}' });
    assert.strictEqual(scanEventCount, 0, 'no scan event');
  });

  await test('Non-string body (FormData/stream) passes through untouched', async () => {
    reset();
    const fd = { __formData: true };
    await window.fetch('https://chatgpt.com/backend-api/upload', { method: 'POST', body: fd });
    assert.strictEqual(scanEventCount, 0, 'no scan event');
    assert.strictEqual(originalCalls.length, 1, 'original fetch called');
  });

  await test('GET request (no body) is NOT scanned', async () => {
    reset();
    await window.fetch('https://chatgpt.com/backend-api/settings');
    assert.strictEqual(scanEventCount, 0, 'no scan event');
  });

  await test('Claude-style payload (role:user) IS scanned', async () => {
    reset();
    const body = JSON.stringify({
      type: 'message',
      message: { role: 'user', content: 'Explain nostro accounts' }
    });
    await window.fetch('https://claude.ai/api/chat', { method: 'POST', body });
    assert.strictEqual(scanEventCount, 1, 'scan event dispatched');
  });

  await test('Gemini-style payload (parts array) IS scanned', async () => {
    reset();
    const body = JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: 'Summarize this ledger' }] }]
    });
    await window.fetch('https://gemini.google.com/_/BardChatUi/data', { method: 'POST', body });
    assert.strictEqual(scanEventCount, 1, 'scan event dispatched');
  });

  // ---------- XHR ----------
  await test('XHR with conversation payload IS scanned', async () => {
    reset();
    sentBodies.length = 0;
    const xhr = new XMLHttpRequest();
    xhr.__pgUrl = 'https://chatgpt.com/backend-api/conversation';
    xhr.__pgMethod = 'POST';
    xhr.send(CONVERSATION_BODY);
    await sleep(10);
    assert.strictEqual(scanEventCount, 1, 'scan event dispatched');
    assert.strictEqual(sentBodies.length, 1, 'request allowed through');
    assert.strictEqual(sentBodies[0], CONVERSATION_BODY, 'same body sent');
  });

  await test('XHR with telemetry body is NOT scanned', async () => {
    reset();
    sentBodies.length = 0;
    const xhr = new XMLHttpRequest();
    xhr.__pgUrl = 'https://chatgpt.com/backend-api/register_event';
    xhr.__pgMethod = 'POST';
    xhr.send(TELEMETRY_BODY);
    await sleep(10);
    assert.strictEqual(scanEventCount, 0, 'no scan event');
    assert.strictEqual(sentBodies.length, 1, 'sent immediately');
    assert.strictEqual(sentBodies[0], TELEMETRY_BODY, 'same body sent');
  });

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('Harness crashed:', err);
  process.exit(2);
});
