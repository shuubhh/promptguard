/**
 * e2e-nano-chrome.js — drives a REAL Chrome (CDP, port 9222) through the
 * whole PromptGuard loop. Not a unit test: it needs the automation Chrome
 * started with the extension loaded, e.g.
 *
 *   chrome.exe --user-data-dir=%TEMP%\pg-e2e --remote-debugging-port=9222 \
 *     --no-first-run --load-extension=<repo>\extension about:blank
 *
 * Then:  node extension/tests/e2e-nano-chrome.js
 *
 * What it proves (the things Node harnesses cannot):
 *   1. popup.html wires ai-engine.js without ReferenceError (the PG bug)
 *   2. LanguageModel.availability() from inside the popup page
 *   3. the popup join flow works against the REAL join code (CLI arg)
 *   4. the device + org land in chrome.storage and config loads projects
 *   5. scanContent (real engine, in-browser) matches the fakebank fingerprint
 *   6. the MAIN-world interceptor injects on chatgpt.com and hooks fetch
 *
 * Optional env: PG_E2E_ORG_ID (to re-point a generated join code at a
 * specific org instead of creating a new one).
 */
'use strict';

const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

const WS_PATH = path.join(__dirname, '..', '..', 'dashboard', 'node_modules', 'ws');
const WebSocket = require(WS_PATH);

const CDP_HTTP = process.env.PG_E2E_CDP || 'http://localhost:9223';
const EXT_DIR = path.resolve(__dirname, '..');
let extId = null;

// ---------------------------------------------------------------- CDP core
let ws = null;
let msgId = 0;
const pending = new Map();

function send(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++msgId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify(sessionId ? { sessionId, id, method, params } : { id, method, params }));
    setTimeout(() => {
      if (pending.has(id)) {
        pending.delete(id);
        reject(new Error('CDP timeout: ' + method));
      }
    }, 20000);
  });
}

const contextsBySession = new Map(); // sessionId -> [executionContext]

function onMessage(raw) {
  const msg = JSON.parse(raw);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(msg.error.message || JSON.stringify(msg.error)));
    else resolve(msg.result);
    return;
  }
  if (msg.method === 'Runtime.executionContextCreated' && msg.params && msg.params.context) {
    const list = contextsBySession.get(msg.sessionId) || [];
    list.push(msg.params.context);
    contextsBySession.set(msg.sessionId, list);
  }
}

/** Find the extension's ISOLATED world on a tab (where chrome.* + our engine live). */
async function isolatedContextId(sessionId, extId) {
  contextsBySession.set(sessionId, []);
  await send('Runtime.enable', {}, sessionId);
  for (let i = 0; i < 20; i++) {
    const list = contextsBySession.get(sessionId) || [];
    const hit = list.find(c => c.origin === 'chrome-extension://' + extId && !c.auxData ||
      (c.origin === 'chrome-extension://' + extId));
    if (hit) return hit.id;
    await sleep(300);
  }
  const list = contextsBySession.get(sessionId) || [];
  throw new Error('isolated world not found; contexts seen: ' + JSON.stringify(list.map(c => c.origin)));
}

function connect() {
  return new Promise((resolve, reject) => {
    fs.readFile(path.join(__dirname, '..', '..', '.pg-e2e-wsurl'), 'utf8', (err, data) => {
      const url = (!err && data.trim()) || null;
      if (!url) return reject(new Error('no ws url file'));
      ws = new WebSocket(url);
      ws.on('open', resolve);
      ws.on('message', onMessage);
      ws.on('error', reject);
    });
  });
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/** Create a page target; returns its sessionId. */
async function newPage(url) {
  const { targetId } = await send('Target.createTarget', { url: url || 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  return { targetId, sessionId };
}

/** Evaluate an expression in a target (by sessionId), optionally in a world. */
async function evalIn(sessionId, expression, awaitPromise = true, contextId = undefined) {
  const res = await send('Runtime.evaluate', {
    expression,
    awaitPromise,
    returnByValue: true,
    ...(contextId ? { contextId } : {}),
  }, sessionId);
  if (res.exceptionDetails) {
    const d = res.exceptionDetails;
    throw new Error('eval failed: ' + (d.exception && d.exception.description || d.text));
  }
  return res.result && res.result.value;
}

// ------------------------------------------------------------- extensions
/**
 * Resolve the extension ID: arg 2 if given (command-line-loaded extensions
 * don't list their pages in /json until opened); else scan targets.
 */
async function findExtensionId(argId) {
  if (argId) return { id: argId };
  const { targetInfos } = await send('Target.getTargets', {});
  for (const t of targetInfos) {
    if (t.url && t.url.startsWith('chrome-extension://')) {
      return { id: t.url.split('/')[2] };
    }
  }
  throw new Error('PromptGuard extension not found among targets');
}

// ------------------------------------------------------------------ tests
let pass = 0, fail = 0;
function check(name, ok, detail) {
  if (ok) { pass++; console.log('  ok   ' + name); }
  else { fail++; console.log('  FAIL ' + name + (detail ? '  — ' + detail : '')); }
}

async function main() {
  const joinCode = process.argv[2];
  const argExtId = process.argv[3];
  if (!joinCode) {
    console.error('usage: node e2e-nano-chrome.js <JOIN_CODE> [EXTENSION_ID]');
    process.exit(1);
  }

  // 0. locate the browser ws url
  const http = await fetch(CDP_HTTP + '/json/version').then(r => r.json());
  fs.writeFileSync(path.join(__dirname, '..', '..', '.pg-e2e-wsurl'), http.webSocketDebuggerUrl);
  await connect();

  // 1. resolve the extension + open its popup page as a real target
  const ext = await findExtensionId(argExtId);
  extId = ext.id;
  console.log('extension id:', extId);
  const popupPage = await newPage('chrome-extension://' + extId + '/popup.html');
  const pop = popupPage.sessionId;
  await sleep(1500); // let popup.js init run

  // 2. no ReferenceError on load (the v0.1.2 bug class)
  const bootErrors = await evalIn(pop, `window.__pgBootErrors || []`);
  check('popup loaded without boot errors', bootErrors.length === 0, JSON.stringify(bootErrors));

  // 3. ai-engine reachable in the popup (PG defined)
  const hasPG = await evalIn(pop, `!!(window.__PromptGuard && window.__PromptGuard.ai)`);
  check('ai-engine loaded in popup (PG binding)', hasPG);

  // 4. real availability answer
  const avail = await evalIn(pop, `window.__PromptGuard.ai.checkAvailability().then(a => a)`);
  console.log('  availability:', avail);
  check('availability() returned a known state', ['available', 'downloading', 'downloadable', 'unavailable', 'unknown'].includes(avail));

  // 5. THE JOIN — drive the real popup flow with the real code
  await evalIn(pop, `
    (async () => {
      document.getElementById('orgCode').value = ${JSON.stringify(joinCode)};
      document.getElementById('orgEmail').value = 'e2e@promptguard.test';
      document.getElementById('joinBtn').click();
    })()
  `, false);
  await sleep(4000);
  const joinState = await evalIn(pop, `
    (async () => {
      const st = document.getElementById('joinStatus');
      const orgUi = await chrome.storage.local.get(['device_token', 'org_id', 'device_org', 'user_email', 'projects']);
      return { status: st ? st.textContent : null, storage: orgUi };
    })()
  `);
  check('join flow succeeded', /Joined/i.test(joinState.status || ''), joinState.status);
  check('device_token in storage', !!joinState.storage.device_token);
  check('device_org stored', !!(joinState.storage.device_org && joinState.storage.device_org.name), JSON.stringify(joinState.storage.device_org));

  // 6. config loaded projects — read what sync actually stored.
  await evalIn(pop, `chrome.runtime.sendMessage({ type: 'PG_SYNC_NOW' })`, false);
  await sleep(2500);
  const projects = await evalIn(pop, `chrome.storage.local.get('projects').then(s => s.projects || [])`);
  check('org-config loaded at least 1 project', projects.length >= 1, 'projects=' + projects.length);

  // 7. real engine, real browser — evaluate INSIDE the extension's isolated
  //    world on the chatgpt.com tab: the genuine content-script context with
  //    chrome.storage, the loaded org projects, and the live PG engine.
  const tab = await newPage('https://chatgpt.com/');
  await sleep(9000); // allow content scripts to inject
  const ctxId = await isolatedContextId(tab.sessionId, extId);
  console.log('isolated world context:', ctxId);

  const engineThere = await evalIn(tab.sessionId, `!!(window.__PromptGuard && window.__PromptGuard.scanContent)`, true, ctxId);
  check('content-script engine live in isolated world', engineThere === true);

  const scanRes = await evalIn(tab.sessionId,
    `window.__PromptGuard.scanContent('Refactor CustomerWealthPortfolioService to use the new API')`, true, ctxId);
  check('in-browser scanContent catches the class name', scanRes && scanRes.confidence >= 0.8,
    JSON.stringify({ c: scanRes && scanRes.confidence, p: projects.length }));

  const scanSecret = await evalIn(tab.sessionId,
    `window.__PromptGuard.scanContent('Here is my config: AKIAIOSFODNN7EXAMPLE')`, true, ctxId);
  check('in-browser scanContent catches the AWS key', scanSecret && scanSecret.confidence >= 0.95,
    JSON.stringify({ c: scanSecret && scanSecret.confidence }));

  // 8. injection on chatgpt.com: MAIN-world interceptor flag (CDP evaluates
  //    in the MAIN world — the isolated-world engine above shares the DOM).
  const injected = await evalIn(tab.sessionId, `
    ({ main: window.__PROMPTGUARD_INTERCEPTOR__ === true,
       badge: !!document.querySelector('.pg-badge'),
       fetchHooked: (function(){ try { return String(window.fetch).includes('native code') === false; } catch (e) { return false; } })() })
  `);
  check('MAIN-world interceptor injected on chatgpt.com', injected.main === true, JSON.stringify(injected));
  check('fetch/XHR hooked on chatgpt.com', injected.fetchHooked === true);
  check('status badge present on chatgpt.com', injected.badge === true, JSON.stringify(injected));

  console.log('\\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
}

main().catch(err => { console.error('E2E ERROR:', err.message); process.exit(2); });
