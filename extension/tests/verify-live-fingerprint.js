/**
 * verify-live-fingerprint.js — end-to-end proof that a real scanned
 * fingerprint (produced by the Python scanner) drives the real extension
 * scanner engine correctly.
 *
 * Loads patterns.js + scanner-engine.js (the actual extension code), injects
 * the fingerprint the Python scanner produced for THIS repo, and runs
 * scanContent() against sample prompts:
 *   - a package name from the fingerprint
 *   - a class name from the fingerprint
 *   - a secret (AWS key — flagged by global patterns)
 *   - an internal IP from the fingerprint
 *   - safe text (should stay silent)
 *
 * Run with:  node extension/tests/verify-live-fingerprint.js
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

// ------------------------------------------------------------------
// Generate the REAL fingerprint by scanning THIS repo with the Python
// scanner (the same Component 1 code the dashboard uploads).
// ------------------------------------------------------------------
const repoRoot = path.join(__dirname, '..', '..');
const tmpFp = path.join(os.tmpdir(), 'pg-live-fingerprint-' + Date.now() + '.json');
const py = process.env.PY || 'py';
// `research/` holds downloaded third-party competitor bundles (gitignored dev
// scratch) — scanning it would fingerprint minified vendor code, so exclude it
// from the self-scan.
execFileSync(
  py,
  ['scanner/promptguard_scanner.py', '.', '--name', 'promptguard', '--output', tmpFp, '--exclude', 'research'],
  { cwd: repoRoot, stdio: ['ignore', 'ignore', 'pipe'] }
);
const fpRaw = fs.readFileSync(tmpFp, 'utf8');
fs.unlinkSync(tmpFp);
const fp = JSON.parse(fpRaw);

const PROJECT = {
  id: 'live-pg-repo',
  name: 'promptguard (self-scan)',
  fingerprint: fp,
  policy: { warn_threshold: 0.7, block_threshold: 0.9 }
};

// ------------------------------------------------------------------
// Environment stubs (same shape as run-scanner-tests.js)
// ------------------------------------------------------------------
let aiRespondWith = 'unavailable'; // 'unavailable' | 'SENSITIVE' | 'POSSIBLY_SENSITIVE' | 'SAFE'

global.window = {
  __PromptGuard: {},
  location: { hostname: 'chatgpt.com', href: 'https://chatgpt.com/' },
  addEventListener: () => {},
  removeEventListener: () => {},
  dispatchEvent: () => true
};

global.chrome = {
  runtime: {
    id: 'test',
    getURL: (p) => 'file:///extension/' + p,
    // AI now runs in the offscreen document via the background worker.
    sendMessage: async (msg) => {
      if (msg && msg.type === 'PG_AI_REQUEST') {
        if (aiRespondWith === 'unavailable') return { ok: false, error: 'ai-unavailable' };
        return { ok: true, label: aiRespondWith };
      }
      return {};
    }
  },
  storage: {
    local: {
      get: async (keys) => {
        const want = Array.isArray(keys) ? keys : [keys];
        const out = {};
        if (want.includes('projects')) out.projects = [PROJECT];
        if (want.includes('ai_enabled')) out.ai_enabled = true;
        return out;
      },
      set: async () => {}
    }
  }
};

// ------------------------------------------------------------------
// Load the REAL extension modules
// ------------------------------------------------------------------
const extDir = path.join(__dirname, '..');
require(path.join(extDir, 'patterns.js'));
require(path.join(extDir, 'scanner-engine.js'));

const PG = global.window.__PromptGuard;

// ------------------------------------------------------------------
// Run the checks
// ------------------------------------------------------------------
(async () => {
  const results = [];
  const samples = [
    {
      name: 'class name (modal, 0.85)',
      text: 'Can you explain what CustomerWealthPortfolioService does?',
      expectLevel: 'modal'
    },
    {
      name: 'class name ScanResult (real repo class, modal)',
      text: 'I need help debugging the ScanResult class',
      expectLevel: 'modal'
    },
    {
      name: 'internal IP (critical — global pattern + fingerprint both match)',
      text: 'The staging server is at 192.168.10.45',
      expectLevel: 'critical'
    },
    {
      name: 'internal URL (critical — two fingerprint URLs overlap)',
      text: 'Point the client to https://api.hdfcbank-internal.corp/v2/portfolio',
      expectLevel: 'critical'
    },
    {
      name: 'AWS secret (critical, global pattern)',
      text: 'Here is the deployment config: AKIAIOSFODNN7EXAMPLE',
      expectLevel: 'critical'
    },
    {
      name: 'vocabulary only (silent, capped 0.45)',
      text: 'The extension dashboard event message needs a state path',
      expectLevel: 'silent'
    },
    {
      name: 'generic safe text (silent)',
      text: 'How do I center a div with flexbox?',
      expectLevel: 'silent'
    }
  ];

  // The Gemini Nano path itself is covered by run-scanner-tests.js (controlled
  // fixtures) and run-ai-tests.js (mocked LanguageModel). The AI here stays
  // 'unavailable' so this check is deterministic against the live fingerprint.

  for (const s of samples) {
    const r = await PG.scanContent(s.text);
    const ok = r.level === s.expectLevel;
    results.push({ ok, ...s, got: r.level, conf: r.confidence, matches: r.matches });
  }

  let pass = 0;
  for (const r of results) {
    const mark = r.ok ? '✓' : '✗';
    if (r.ok) pass += 1;
    console.log(
      `${mark} ${r.name}\n` +
      `    expected ${r.expectLevel}, got ${r.got} (conf ${r.conf})\n` +
      `    matches: ${(r.matches || []).map((m) => m.label + ' @ ' + (m.matchedText || '').slice(0, 40)).join(' | ') || '(none)'}`
    );
  }
  console.log(`\n${pass}/${results.length} checks passed`);
  process.exit(pass === results.length ? 0 : 1);
})();
