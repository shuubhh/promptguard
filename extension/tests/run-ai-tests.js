/**
 * run-ai-tests.js — headless tests for ai-engine.js (the modern Prompt API
 * wrapper: global LanguageModel, JSON-Schema structured output, graceful
 * degradation, verdict cache).
 *
 * Loads ai-engine.js into a Node context with a fake global LanguageModel
 * (injected — the same hook the offscreen document uses for the real one).
 *
 * Run with Node (no npm needed):
 *   node extension/tests/run-ai-tests.js
 */
'use strict';

const assert = require('assert');
const path = require('path');
const { createRequire } = require('module');

// ------------------------------------------------------------------
// Fake LanguageModel (records every call; behavior switched per test)
// ------------------------------------------------------------------
let fakeAvailability = 'available'; // 'available' | 'downloading' | 'unavailable'
let fakePromptResponse = '{"label":"SENSITIVE","reason":"contains client package"}';
let fakePromptMode = 'normal'; // 'normal' | 'hang' | 'reject'
let fakeCreateThrows = false;

const calls = {
  availability: [],
  params: 0,
  create: [],
  prompt: 0,
  promptOpts: [],
  destroy: 0
};

function resetCalls() {
  calls.availability.length = 0;
  calls.params = 0;
  calls.create.length = 0;
  calls.prompt = 0;
  calls.promptOpts.length = 0;
  calls.destroy = 0;
}

const fakeLanguageModel = {
  async availability(opts) {
    calls.availability.push(opts);
    return fakeAvailability;
  },
  async params() {
    calls.params += 1;
    return { defaultTopK: 3, maxTopK: 128, defaultTemperature: 1, maxTemperature: 2 };
  },
  async create(opts) {
    calls.create.push(opts);
    if (fakeCreateThrows) throw new Error('create failed (NotSupportedError)');
    return {
      async prompt(text, opts) {
        calls.prompt += 1;
        calls.promptOpts.push(opts);
        if (fakePromptMode === 'hang') {
          return new Promise((resolve, reject) => {
            if (opts && opts.signal) {
              opts.signal.addEventListener('abort', () => {
                const err = new Error('aborted');
                err.name = 'AbortError';
                reject(err);
              });
            }
          });
        }
        if (fakePromptMode === 'reject') throw new Error('prompt boom');
        return fakePromptResponse;
      },
      destroy() {
        calls.destroy += 1;
      }
    };
  }
};

global.LanguageModel = fakeLanguageModel;
// The engine attaches to window.__PromptGuard like the other extension files.
global.window = { __PromptGuard: {} };

// ------------------------------------------------------------------
// Load ai-engine.js
// ------------------------------------------------------------------
const req = createRequire(__filename);
req('../ai-engine.js');

const PG = global.window.__PromptGuard;
assert(PG && PG.ai, 'ai-engine did not expose PG.ai');

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

(async function main() {
  console.log('PromptGuard ai-engine tests\n');

  // ---------- 1. Availability ----------
  await test('availability=available → "available"', async () => {
    resetCalls();
    fakeAvailability = 'available';
    assert.strictEqual(await PG.ai.checkAvailability(), 'available');
    assert.strictEqual(calls.availability.length, 1, 'availability called once');
  });

  await test('availability passes the SAME expectedInputs/Outputs as create (docs: critical)', async () => {
    resetCalls();
    fakeAvailability = 'downloading';
    await PG.ai.checkAvailability();
    assert.deepStrictEqual(calls.availability[0], {
      expectedInputs: PG.ai.EXPECTED_INPUTS,
      expectedOutputs: PG.ai.EXPECTED_OUTPUTS
    });
  });

  await test('availability=unavailable → "unavailable"', async () => {
    resetCalls();
    fakeAvailability = 'unavailable';
    assert.strictEqual(await PG.ai.checkAvailability(), 'unavailable');
  });

  // ---------- 2. Classification ----------
  await test('classify SENSITIVE → score 0.75, JSON-schema constraint passed', async () => {
    resetCalls();
    fakePromptResponse = '{"label":"SENSITIVE","reason":"client package in text"}';
    const r = await PG.ai.classify('import com.hdfcbank.wealth.portfolio.Helper;');
    assert.strictEqual(r.ok, true, 'ok');
    assert.strictEqual(r.label, 'SENSITIVE', 'label');
    assert.strictEqual(r.score, 0.75, 'SENSITIVE mapped to 0.75');
    // The prompt call must carry the JSON-Schema responseConstraint.
    assert.ok(calls.create[0].expectedInputs, 'create called with expectedInputs');
    const schema = PG.ai.SCHEMA;
    assert.strictEqual(schema.properties.label.enum[0], 'SENSITIVE', 'schema enum');
    const promptOpts = calls.promptOpts[0];
    assert.strictEqual(promptOpts.responseConstraint, schema, 'responseConstraint passed to prompt()');
    assert.ok(promptOpts.signal, 'abort signal passed to prompt()');
    assert.strictEqual(calls.destroy, 1, 'session destroyed after classification');
  });

  await test('classify tolerates a fenced JSON response', async () => {
    resetCalls();
    fakePromptResponse = '```json\n{"label":"SAFE","reason":"generic question"}\n```';
    const r = await PG.ai.classify('How do I sort a list?');
    assert.strictEqual(r.ok, true, 'ok');
    assert.strictEqual(r.label, 'SAFE', 'label');
    assert.strictEqual(r.score, 0.1, 'SAFE mapped to 0.1');
  });

  await test('classify POSSIBLY_SENSITIVE → 0.55', async () => {
    resetCalls();
    fakePromptResponse = '{"label":"POSSIBLY_SENSITIVE","reason":"banking jargon"}';
    const r = await PG.ai.classify('The nostro ledger entry needs review');
    assert.strictEqual(r.label, 'POSSIBLY_SENSITIVE', 'label');
    assert.strictEqual(r.score, 0.55, 'score');
  });

  await test('classify unknown label → ok with score 0 (never throws)', async () => {
    resetCalls();
    fakePromptResponse = '{"label":"MAYBE","reason":"odd"}';
    const r = await PG.ai.classify('something odd');
    assert.strictEqual(r.ok, true, 'ok');
    assert.strictEqual(r.label, 'MAYBE', 'label');
    assert.strictEqual(r.score, 0, 'unmapped label scores 0');
  });

  await test('classify unparseable response → ok:false ai-bad-response', async () => {
    resetCalls();
    fakePromptResponse = 'I am sorry, I cannot do that.';
    const r = await PG.ai.classify('whatever');
    assert.strictEqual(r.ok, false, 'not ok');
    assert.strictEqual(r.error, 'ai-bad-response', 'error code');
  });

  await test('classify prompt rejection → ok:false, session still destroyed', async () => {
    resetCalls();
    fakePromptMode = 'reject';
    const r = await PG.ai.classify('hello');
    assert.strictEqual(r.ok, false, 'not ok');
    assert.ok(String(r.error).includes('boom'), 'error surfaced');
    assert.strictEqual(calls.destroy, 1, 'session destroyed in finally');
    fakePromptMode = 'normal';
  });

  await test('classify timeout → ok:false ai-timeout (AbortController fires)', async () => {
    resetCalls();
    fakePromptMode = 'hang';
    const r = await PG.ai.classify('will never answer', { timeoutMs: 50 });
    assert.strictEqual(r.ok, false, 'not ok');
    assert.strictEqual(r.error, 'ai-timeout', 'error code');
    assert.strictEqual(calls.destroy, 1, 'session destroyed');
    fakePromptMode = 'normal';
  });

  // ---------- 3. Verdict cache ----------
  await test('identical text within TTL → model NOT re-run (LRU cache)', async () => {
    resetCalls();
    fakePromptResponse = '{"label":"SENSITIVE","reason":"x"}';
    await PG.ai.classify('Cache me: the portfolio service');
    await PG.ai.classify('Cache me: the portfolio service');
    assert.strictEqual(calls.prompt, 1, 'prompt called exactly once');
    assert.strictEqual(calls.create.length, 1, 'session created once');
  });

  await test('different text → model re-run', async () => {
    resetCalls();
    await PG.ai.classify('first distinct text');
    await PG.ai.classify('second distinct text');
    assert.strictEqual(calls.prompt, 2, 'prompt called twice');
  });

  // ---------- 4. Session creation ----------
  await test('createSession with temperature/topK → params() read, both set together', async () => {
    resetCalls();
    const session = await PG.ai.createSession({ temperature: 0, topK: 1 });
    assert.ok(session, 'session returned');
    assert.strictEqual(calls.params, 1, 'params() called for extension defaults');
    const opts = calls.create[0];
    assert.strictEqual(opts.temperature, 0, 'temperature passed');
    assert.strictEqual(opts.topK, 1, 'topK passed');
  });

  await test('createSession without temperature/topK → neither set', async () => {
    resetCalls();
    await PG.ai.createSession({});
    const opts = calls.create[0];
    assert.strictEqual(opts.temperature, undefined, 'no temperature');
    assert.strictEqual(opts.topK, undefined, 'no topK');
    assert.strictEqual(calls.params, 0, 'params() not called');
  });

  await test('createSession monitors download progress events', async () => {
    resetCalls();
    const seen = [];
    const session = await PG.ai.createSession({
      monitor(m) {
        m.addEventListener('downloadprogress', (e) => seen.push(e));
      }
    });
    assert.ok(session, 'session returned');
    const monitorFn = calls.create[0].monitor;
    assert.strictEqual(typeof monitorFn, 'function', 'monitor passed to create()');
    // Simulate the browser invoking the monitor callback.
    const fakeMonitor = {
      listeners: {},
      addEventListener(type, fn) {
        this.listeners[type] = fn;
      }
    };
    monitorFn(fakeMonitor);
    fakeMonitor.listeners.downloadprogress({ loaded: 0.5, total: undefined });
    assert.strictEqual(seen.length, 1, 'downloadprogress delivered to popup handler');
    assert.strictEqual(seen[0].loaded, 0.5, 'progress event carries loaded');
  });

  await test('createSession failure → returns null (never throws)', async () => {
    resetCalls();
    fakeCreateThrows = true;
    const session = await PG.ai.createSession({});
    assert.strictEqual(session, null, 'null on failure');
    fakeCreateThrows = false;
  });

  // ---------- 5. Graceful degradation ----------
  await test('no LanguageModel at all → availability unavailable + classify ok:false', async () => {
    delete global.LanguageModel;
    assert.strictEqual(await PG.ai.checkAvailability(), 'unavailable');
    const r = await PG.ai.classify('anything');
    assert.strictEqual(r.ok, false, 'not ok');
    assert.strictEqual(r.error, 'ai-unavailable', 'error code');
    global.LanguageModel = fakeLanguageModel;
  });

  // ---------- Summary ----------
  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('Harness crashed:', err);
  process.exit(2);
});
