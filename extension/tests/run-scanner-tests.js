/**
 * run-scanner-tests.js — headless tests for the PromptGuard scanner engine.
 *
 * Loads patterns.js + scanner-engine.js into a stubbed window/chrome
 * environment and verifies: secret patterns, fingerprint scoring, confidence
 * thresholds, multi-project matching, redaction, and the Gemini Nano
 * tie-breaker (mapping, formula, timeout fallback, skip-above-0.6).
 *
 * Run with Node (no npm needed):
 *   node extension/tests/run-scanner-tests.js
 */
'use strict';

const assert = require('assert');
const path = require('path');
const { createRequire } = require('module');

// ------------------------------------------------------------------
// Test fixtures (two client projects, per the storage schema)
// ------------------------------------------------------------------
const HDFC_PROJECT = {
  id: 'hdfc-1',
  name: 'HDFC Wealth Platform',
  fingerprint: {
    packages: ['com.hdfcbank.wealth.portfolio', 'com.hdfcbank.retail.core'],
    class_names: ['CustomerWealthPortfolioService', 'TransactionLedgerReconciliation'],
    domain_vocabulary: ['ledger', 'portfolio', 'nostro', 'vostro', 'reconciliation'],
    internal_urls: ['https://api.hdfcbank-internal.corp/v2/portfolio'],
    internal_ips: ['192.168.10.45'],
    secrets_found: []
  },
  policy: { warn_threshold: 0.7, block_threshold: 0.9 }
};

const APOLLO_PROJECT = {
  id: 'apollo-1',
  name: 'Apollo EMR System',
  fingerprint: {
    packages: ['com.apolloemr.patient.core', 'com.apolloemr.billing'],
    class_names: ['PatientVitalsMonitor', 'BillingInvoiceGenerator'],
    domain_vocabulary: ['patient', 'vitals', 'invoice'],
    internal_urls: ['https://emr.apollo-internal.corp/api'],
    internal_ips: ['10.10.5.22'],
    secrets_found: []
  },
  policy: { warn_threshold: 0.6, block_threshold: 0.85 }
};

// Which projects the stub storage returns (switched per test group).
let testProjects = [HDFC_PROJECT, APOLLO_PROJECT];

// ------------------------------------------------------------------
// Environment stubs
// ------------------------------------------------------------------
let aiRequestCount = 0;
let aiRespondWith = 'unavailable'; // 'unavailable' | 'SENSITIVE' | 'POSSIBLY_SENSITIVE' | 'SAFE'
let aiEnabled = true; // storage ai_enabled toggle

global.window = {
  __PromptGuard: {},
  location: { hostname: 'chatgpt.com', href: 'https://chatgpt.com/' },
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => true,
  CustomEvent: global.CustomEvent
};

global.chrome = {
  storage: {
    local: {
      // Returns the same object regardless of requested keys, so ai_enabled
      // and feature_flags are always present (isAIEnabled reads them).
      get: async () => ({ projects: testProjects, ai_enabled: aiEnabled, feature_flags: {} })
    }
  },
  runtime: {
    getURL: (p) => 'chrome-extension://test/' + p,
    // The AI now runs in the offscreen document, reached via the background
    // service worker. Stub the whole round trip here.
    sendMessage: async (msg) => {
      if (msg && msg.type === 'PG_AI_REQUEST') {
        aiRequestCount += 1;
        if (aiRespondWith === 'unavailable') return { ok: false, error: 'ai-unavailable' };
        return { ok: true, label: aiRespondWith };
      }
      return {};
    }
  }
};

global.fetch = async () => {
  throw new Error('unexpected fetch call (dev fingerprint fallback should not be used)');
};

// ------------------------------------------------------------------
// Load the extension files
// ------------------------------------------------------------------
const req = createRequire(__filename);
req('../patterns.js');
req('../scanner-engine.js');

const PG = window.__PromptGuard;
assert(PG && typeof PG.scanContent === 'function', 'scanner-engine did not expose scanContent');

// ------------------------------------------------------------------
// Test runner
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

function expectLevel(level, expected, name) {
  assert.strictEqual(level, expected, name + ': expected "' + expected + '", got "' + level + '"');
}

(async function main() {
  console.log('PromptGuard scanner tests\n');

  // ---------- 1. Secret patterns + thresholds ----------
  await test('AWS key (AKIA…) → 0.99 critical, global match', async () => {
    const r = await PG.scanContent('Deploy config: AKIAIOSFODNN7EXAMPLE region us-east-1');
    expectLevel(r.level, 'critical', 'level');
    assert.strictEqual(r.confidence, 0.99, 'confidence');
    assert.strictEqual(r.hasSecret, true, 'hasSecret');
    assert.strictEqual(r.matches[0].key, 'aws_access_key', 'match key');
  });

  await test('AWS secret key → 0.99 critical', async () => {
    const r = await PG.scanContent('const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";');
    expectLevel(r.level, 'critical', 'level');
    assert.ok(r.matches.some((m) => m.key === 'aws_secret_key'), 'aws_secret_key match');
  });

  await test('SendGrid API key → 0.99 critical', async () => {
    const r = await PG.scanContent('SENDGRID_API = "SG.aaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"');
    expectLevel(r.level, 'critical', 'level');
    assert.ok(r.matches.some((m) => m.key === 'sendgrid_key'), 'sendgrid_key match');
  });

  await test('Twilio SID → 0.99 critical', async () => {
    const r = await PG.scanContent('TWILIO_SID = "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"');
    expectLevel(r.level, 'critical', 'level');
    assert.ok(r.matches.some((m) => m.key === 'twilio_sid'), 'twilio_sid match');
  });

  await test('Hardcoded high-entropy password → 0.99 critical', async () => {
    const r = await PG.scanContent("DB_PASSWORD='Xk9#mP2$vLqRz8!'");
    expectLevel(r.level, 'critical', 'level');
    assert.ok(r.matches.some((m) => m.key === 'generic_password'), 'generic_password match');
  });

  await test('Low-entropy password (password="demo") → silent, no match', async () => {
    const r = await PG.scanContent('password="demo"');
    expectLevel(r.level, 'silent', 'level');
    assert.ok(!r.matches.some((m) => m.key === 'generic_password'), 'no generic_password match');
  });

  await test('Exact package match → 0.95 critical, names the project', async () => {
    const r = await PG.scanContent('import com.hdfcbank.wealth.portfolio.Helper;');
    expectLevel(r.level, 'critical', 'level');
    assert.ok(r.confidence >= 0.95, 'confidence >= 0.95');
    assert.strictEqual(r.topProject.name, 'HDFC Wealth Platform', 'topProject name');
    assert.ok(r.matches.some((m) => m.key === 'package_name'), 'package match present');
  });

  await test('Exact class name match → 0.85 modal', async () => {
    const r = await PG.scanContent('Refactor CustomerWealthPortfolioService to use the new API');
    expectLevel(r.level, 'modal', 'level');
    assert.strictEqual(r.confidence, 0.85, 'confidence');
    assert.strictEqual(r.topProject.name, 'HDFC Wealth Platform', 'topProject');
  });

  await test('3 vocabulary terms → 0.45 silent (regex only)', async () => {
    const r = await PG.scanContent('The ledger shows the portfolio with nostro balances');
    expectLevel(r.level, 'silent', 'level');
    assert.strictEqual(r.confidence, 0.45, 'confidence');
  });

  await test('Internal IP pattern (10.0.0.5) → 0.70 modal', async () => {
    const r = await PG.scanContent('Point the job at the server 10.0.0.5 please');
    expectLevel(r.level, 'modal', 'level');
    assert.strictEqual(r.confidence, 0.7, 'confidence');
    assert.strictEqual(r.matches[0].key, 'internal_ip', 'match key');
  });

  await test('Generic code → silent, no matches', async () => {
    const r = await PG.scanContent('for (let i = 0; i < items.length; i++) { console.log(items[i]); }');
    expectLevel(r.level, 'silent', 'level');
    assert.strictEqual(r.matches.length, 0, 'no matches');
    assert.strictEqual(r.confidence, 0, 'confidence');
  });

  // ---------- 2. Multi-project scanning ----------
  await test('Multi-project: both fingerprints matched, both named', async () => {
    const text = 'com.hdfcbank.wealth.portfolio and com.apolloemr.patient.core both need review';
    const r = await PG.scanContent(text);
    const names = r.matchedProjects.map((p) => p.name).sort();
    assert.deepStrictEqual(names, ['Apollo EMR System', 'HDFC Wealth Platform'], 'matched projects');
    expectLevel(r.level, 'critical', 'level');
  });

  await test('Multi-project: only Apollo matched → names Apollo', async () => {
    const r = await PG.scanContent('Bug in com.apolloemr.billing.PaymentFlow');
    assert.strictEqual(r.topProject.name, 'Apollo EMR System', 'topProject');
    assert.strictEqual(r.matchedProjects.length, 1, 'one matched project');
  });

  // ---------- 3. Redaction ----------
  await test('Redact: secret + fingerprint strings replaced, original gone', async () => {
    const text = 'Key AKIAIOSFODNN7EXAMPLE in com.hdfcbank.wealth.portfolio';
    const r = await PG.scanContent(text);
    const redacted = PG.redactText(text, r);
    assert.ok(!redacted.includes('AKIAIOSFODNN7EXAMPLE'), 'AWS key redacted');
    assert.ok(!redacted.includes('com.hdfcbank.wealth.portfolio'), 'package redacted');
    assert.ok(redacted.includes('[REDACTED:aws_access_key]'), 'aws tag present');
    assert.ok(redacted.includes('[REDACTED:package_name]'), 'package tag present');
  });

  // ---------- 4. Gemini Nano tie-breaker ----------
  aiRespondWith = 'SENSITIVE';
  await test('AI SENSITIVE on fuzzy 0.45 → final 0.57 soft', async () => {
    aiRequestCount = 0;
    // Distinct text per test: the 2s scan cache would otherwise reuse the
    // first result for identical strings.
    const r = await PG.scanContent('Check the ledger and nostro before updating the portfolio');
    assert.strictEqual(r.aiUsed, true, 'aiUsed');
    assert.strictEqual(r.aiLabel, 'SENSITIVE', 'aiLabel');
    assert.strictEqual(r.aiScore, 0.75, 'aiScore mapping SENSITIVE=0.75');
    assert.strictEqual(r.confidence, 0.57, '0.45*0.6 + 0.75*0.4 = 0.57');
    expectLevel(r.level, 'soft', 'level');
    assert.ok(aiRequestCount >= 1, 'AI was invoked');
  });

  aiRespondWith = 'SAFE';
  await test('AI SAFE on fuzzy 0.45 → final 0.31 silent (false-positive avoided)', async () => {
    const r = await PG.scanContent('Our portfolio ledger mentions the nostro account');
    assert.strictEqual(r.aiLabel, 'SAFE', 'aiLabel');
    assert.strictEqual(r.aiScore, 0.1, 'aiScore mapping SAFE=0.1');
    assert.strictEqual(r.confidence, 0.31, '0.45*0.6 + 0.1*0.4 = 0.31');
    expectLevel(r.level, 'silent', 'level');
  });

  aiRespondWith = 'POSSIBLY_SENSITIVE';
  await test('AI POSSIBLY_SENSITIVE → 0.55 mapped, final 0.49 silent', async () => {
    const r = await PG.scanContent('The nostro ledger entry fits the portfolio view');
    assert.strictEqual(r.aiScore, 0.55, 'aiScore mapping POSSIBLY_SENSITIVE=0.55');
    assert.strictEqual(r.confidence, 0.49, '0.45*0.6 + 0.55*0.4 = 0.49');
    expectLevel(r.level, 'silent', 'level');
  });

  aiRespondWith = 'unavailable';
  await test('AI unavailable → silent fallback to regex score (0.45)', async () => {
    const r = await PG.scanContent('The portfolio ledger for nostro should sync');
    assert.strictEqual(r.aiUsed, false, 'aiUsed false');
    assert.strictEqual(r.aiScore, 0, 'aiScore 0');
    assert.strictEqual(r.confidence, 0.45, 'falls back to regex score');
    expectLevel(r.level, 'silent', 'level');
  });

  await test('AI skipped when regex > 0.6 (class name 0.85) — no AI request', async () => {
    aiRequestCount = 0;
    const r = await PG.scanContent('Refactor CustomerWealthPortfolioService');
    assert.strictEqual(r.aiUsed, false, 'aiUsed false');
    assert.strictEqual(aiRequestCount, 0, 'no AI request dispatched');
    assert.strictEqual(r.confidence, 0.85, 'pure regex score');
  });

  await test('AI skipped when regex < 0.3 — no AI request', async () => {
    aiRequestCount = 0;
    const r = await PG.scanContent('Just a normal question about sorting algorithms');
    assert.strictEqual(r.confidence, 0, 'no matches');
    assert.strictEqual(aiRequestCount, 0, 'no AI request dispatched');
  });

  // ---------- 4b. Layer 0 context patterns (log signatures, no fingerprint) ----------
  await test('Java stack trace → 0.55, AI adjudicates → soft when Nano says SENSITIVE', async () => {
    aiRespondWith = 'SENSITIVE';
    const r = await PG.scanContent(
      'Getting this error when processing:\n' +
      'at com.fakebank.wealth.PortfolioService.reconcile(PortfolioService.java:142)\n' +
      'at com.fakebank.wealth.PortfolioService.run(JobRunner.java:88)  — any ideas?'
    );
    assert.strictEqual(r.contextCount, 2, 'two stack frames matched');
    assert.ok(r.matches.some((m) => m.key === 'java_stacktrace'), 'java_stacktrace match');
    assert.strictEqual(r.regexScore, 0.55, 'regex score from context only');
    assert.strictEqual(r.aiUsed, true, 'log signature triggered AI');
    assert.strictEqual(r.confidence, 0.63, '0.55*0.6 + 0.75*0.4 = 0.63');
    expectLevel(r.level, 'soft', 'level');
  });

  await test('Stack trace + Nano SAFE → 0.37 silent (no false alarm)', async () => {
    aiRespondWith = 'SAFE';
    const r = await PG.scanContent(
      'Debugging my homework:\n' +
      'at com.example.demo.HelloWorld.main(HelloWorld.java:12)\n' +
      'Can someone explain the stack trace?'
    );
    assert.strictEqual(r.aiUsed, true, 'AI ran');
    assert.strictEqual(r.confidence, 0.37, '0.55*0.6 + 0.1*0.4 = 0.37');
    expectLevel(r.level, 'silent', 'level');
  });

  await test('Timestamped ERROR log line → 0.50, AI unavailable → falls back', async () => {
    aiRespondWith = 'unavailable';
    const r = await PG.scanContent(
      '2026-08-18 09:14:22,731 ERROR PaymentProcessor Failed to settle batch 88213'
    );
    assert.ok(r.matches.some((m) => m.key === 'log_error_line'), 'log_error_line match');
    assert.strictEqual(r.confidence, 0.5, 'falls back to regex score');
    expectLevel(r.level, 'soft', 'level');
  });

  await test('Internal hostname (.corp) → 0.75 modal without any fingerprint', async () => {
    const r = await PG.scanContent('The deployment hit https://api.corpbank-internal.corp/v2/settle and timed out');
    assert.ok(r.matches.some((m) => m.key === 'internal_url'), 'internal_url match');
    assert.strictEqual(r.confidence, 0.75, '0.75 from context pattern');
    expectLevel(r.level, 'modal', 'level');
  });

  await test('Customer identifier in a ticket excerpt → 0.50 fuzzy zone, AI consulted', async () => {
    aiRespondWith = 'POSSIBLY_SENSITIVE';
    aiRequestCount = 0;
    const r = await PG.scanContent(
      'Support ticket: customer_id: 4829103 reported a failed payout, account number in the notes'
    );
    assert.ok(r.matches.some((m) => m.key === 'customer_identifier'), 'customer_identifier match');
    assert.strictEqual(r.aiUsed, true, 'AI consulted');
    assert.ok(aiRequestCount >= 1, 'AI request dispatched');
  });

  // ---------- 4c. AI gating ----------
  await test('ai_enabled=false → AI never runs, regex-only result', async () => {
    aiEnabled = false;
    aiRequestCount = 0;
    aiRespondWith = 'SENSITIVE';
    // Distinct text: the 2s scan cache would otherwise reuse an earlier result.
    const r = await PG.scanContent('The nostro ledger for the portfolio should sync');
    assert.strictEqual(r.aiUsed, false, 'aiUsed false');
    assert.strictEqual(aiRequestCount, 0, 'no AI request');
    assert.strictEqual(r.confidence, 0.45, 'pure regex score');
    aiEnabled = true;
  });

  await test('org feature_flags.ai=off forces AI off even when enabled', async () => {
    // isAIEnabled reads feature_flags from storage; flip via a scoped override
    // by temporarily changing the stub return.
    const origGet = global.chrome.storage.local.get;
    global.chrome.storage.local.get = async () => ({
      projects: testProjects,
      ai_enabled: true,
      feature_flags: { ai: 'off' }
    });
    aiRequestCount = 0;
    const r = await PG.scanContent('The nostro ledger needs the portfolio view');
    assert.strictEqual(r.aiUsed, false, 'AI forced off');
    assert.strictEqual(aiRequestCount, 0, 'no AI request');
    global.chrome.storage.local.get = origGet;
  });

  await test('org feature_flags.ai=on forces AI on even when disabled', async () => {
    const origGet = global.chrome.storage.local.get;
    global.chrome.storage.local.get = async () => ({
      projects: testProjects,
      ai_enabled: false,
      feature_flags: { ai: 'on' }
    });
    aiRespondWith = 'SAFE';
    aiRequestCount = 0;
    const r = await PG.scanContent('Check the nostro ledger before updating the portfolio');
    assert.strictEqual(r.aiUsed, true, 'AI forced on');
    assert.ok(aiRequestCount >= 1, 'AI request dispatched');
    global.chrome.storage.local.get = origGet;
    aiRespondWith = 'unavailable';
  });

  // ---------- 5. Project loading ----------
  await test('loadProjects returns both configured projects', async () => {
    const projects = await PG.loadProjects();
    assert.strictEqual(projects.length, 2, 'two projects');
    assert.deepStrictEqual(
      projects.map((p) => p.name).sort(),
      ['Apollo EMR System', 'HDFC Wealth Platform']
    );
  });

  // ---------- Summary ----------
  console.log('\n' + passed + ' passed, ' + failed + ' failed');
  process.exit(failed === 0 ? 0 : 1);
})().catch((err) => {
  console.error('Harness crashed:', err);
  process.exit(2);
});
