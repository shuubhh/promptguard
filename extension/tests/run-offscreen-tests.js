/**
 * run-offscreen-tests.js — regression tests for the offscreen document.
 *
 * THE BUG THIS GUARDS AGAINST (v0.1.4, found live in the user's browser):
 * offscreen.js referenced the bare identifier `PG`, but ai-engine.js attaches
 * to `window.__PromptGuard` inside an IIFE and never declares a global PG —
 * so EVERY PG_AI_INFER message crashed with "ReferenceError: PG is not
 * defined" before Nano was ever consulted. Node tests passed because their
 * harnesses predefine PG. This file loads offscreen.js EXACTLY like the
 * offscreen document does (ai-engine.js then offscreen.js, nothing else
 * predefined) and exercises the real chrome.runtime.onMessage handlers.
 *
 * Run with Node (no npm needed):
 *   node extension/tests/run-offscreen-tests.js
 */
'use strict';

const assert = require('assert');
const { createRequire } = require('module');

// ------------------------------------------------------------------
// Browser-ish environment: NOTHING predefined except what the two
// scripts genuinely get in the offscreen document.
// ------------------------------------------------------------------
const listeners = [];
global.chrome = {
  runtime: {
    onMessage: {
      addListener(fn) {
        listeners.push(fn);
      }
    }
  }
};

// Minimal DOM shim: window with an event system for DOMContentLoaded.
const domListeners = {};
global.window = {
  __PromptGuard: {}, // the ONLY thing ai-engine.js may assume
  addEventListener(type, fn) {
    (domListeners[type] = domListeners[type] || []).push(fn);
  },
  removeEventListener(type, fn) {
    const arr = domListeners[type];
    if (arr) {
      const i = arr.indexOf(fn);
      if (i !== -1) arr.splice(i, 1);
    }
  },
  dispatchEvent() {
    return true;
  }
};
global.document = {
  readyState: 'loading',
  addEventListener(type, fn) {
    (domListeners['document:' + type] = domListeners['document:' + type] || []).push(fn);
  },
  removeEventListener(type, fn) {
    const arr = domListeners['document:' + type];
    if (arr) {
      const i = arr.indexOf(fn);
      if (i !== -1) arr.splice(i, 1);
    }
  }
};

// ------------------------------------------------------------------
// Load the real extension scripts in offscreen.html order.
// createRequire executes the file in this Node context (shared globals).
// ------------------------------------------------------------------
const req = createRequire(__filename);
req('../ai-engine.js');
req('../offscreen.js');

// ------------------------------------------------------------------
// Fake LanguageModel injected AFTER load (like the real offscreen doc,
// where the model is a browser global, not something scripts install).
// ------------------------------------------------------------------
let fakeVerdict = { label: 'SENSITIVE', reason: 'watch-list terms' };
const fakeLM = {
  async availability() {
    return 'available';
  },
  async params() {
    return { defaultTopK: 3, defaultTemperature: 1 };
  },
  async create() {
    return {
      async prompt() {
        return JSON.stringify(fakeVerdict);
      },
      destroy() {}
    };
  }
};
global.LanguageModel = fakeLM;

const PG = global.window.__PromptGuard;
assert(PG && PG.ai, 'ai-engine.js did not attach PG.ai to window.__PromptGuard');

// ------------------------------------------------------------------
// Harness: dispatch a message through the REAL registered listener.
// ------------------------------------------------------------------
async function handleMessage(msg) {
  let response;
  const sendResponse = (r) => {
    response = r;
  };
  for (const fn of listeners) {
    const wantsAsync = fn(msg, {}, sendResponse);
    if (wantsAsync === true) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    if (response !== undefined) return response;
  }
  return undefined;
}

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

(async function main() {
  console.log('PromptGuard offscreen-document tests\n');

  await test('offscreen.js loads without a ReferenceError (the v0.1.4 bug)', async () => {
    // Loading already happened at module scope; reaching here proves the
    // bare-PG reference did not throw during script evaluation.
    assert.ok(listeners.length >= 1, 'message listener registered');
  });

  await test('PG_AI_INFER → real classify verdict (was: PG is not defined)', async () => {
    const res = await handleMessage({ type: 'PG_AI_INFER', text: 'nostro vostro ledger' });
    assert.ok(res && res.ok === true, 'classify succeeded, got: ' + JSON.stringify(res));
    assert.strictEqual(res.label, 'SENSITIVE');
  });

  await test('PG_AI_INFER with context → watch-list reaches the model prompt', async () => {
    let seen = null;
    fakeLM.create = async () => ({
      async prompt(text) {
        seen = String(text);
        return JSON.stringify(fakeVerdict);
      },
      destroy() {}
    });
    await handleMessage({
      type: 'PG_AI_INFER',
      text: 'walk me through it',
      context: { project: 'Fakebank', domain_vocabulary: ['nostro', 'settlement'] }
    });
    assert.ok(seen && seen.includes('CONFIDENTIAL WATCH-LIST'), 'watch-list in prompt');
    assert.ok(seen.includes('nostro'), 'term present');
    fakeLM.create = async () => ({
      async prompt() {
        return JSON.stringify(fakeVerdict);
      },
      destroy() {}
    });
  });

  await test('PG_AI_AVAILABILITY → responds with availability', async () => {
    const res = await handleMessage({ type: 'PG_AI_AVAILABILITY' });
    assert.ok(res && res.availability === 'available', 'got: ' + JSON.stringify(res));
  });

  await test('unknown message type → returns false (not handled)', async () => {
    const res = await handleMessage({ type: 'SOMETHING_ELSE' });
    assert.strictEqual(res, undefined, 'no response for unhandled types');
  });

  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('Harness crashed:', err);
  process.exit(2);
});
