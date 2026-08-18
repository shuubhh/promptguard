# PROMPTGUARD — V2 HANDBOOK (Handoff / Recovery Document)

> If a session loses context, paste this entire file as the starting prompt.
> It contains: product, current state, locked decisions, research findings,
> the v2/v3 plan, and operating rules. Approved-work starts ONLY on user approval.

---

## 0. TL;DR

PromptGuard is a B2B SaaS DLP tool for Indian IT-services companies (50–500
employees) that prevents engineers from leaking client code, credentials, logs
and business data into AI chatbots (ChatGPT, Claude, Gemini, DeepSeek, Copilot,
Perplexity). Three components, all built and working (v1 complete):

1. `scanner/` — Python CLI that fingerprints a client codebase into
   `fingerprint.json` (or scans a git URL directly, incl. private repos with a token).
2. `extension/` — Chrome MV3 extension that intercepts network requests on AI
   sites (MAIN-world fetch/XHR hook), scans content against fingerprints +
   secret patterns + (optionally) Chrome's on-device Gemini Nano, and blocks /
   warns / redacts before data leaves the browser.
3. `dashboard/` — React + Vite + Supabase (no custom backend). Org auth,
   projects, audit log, team, settings, plan scaffolding.

The v2 direction (user-approved in principle): org-level auto-config +
accountability enforcement (no Google Workspace / Intune dependency), Web Store
listing, Stripe billing + plan gating, hosted private-repo scan API, then a
Nano-first context-aware detection engine (WASM embeddings later), with
fingerprints demoted to an enhancement layer over an always-on detection core.

---

## 1. Product

- **Problem:** engineers paste proprietary client code, credentials, internal
  URLs, and log excerpts into public AI tools → contractual violation, penalty
  clauses, ISO27001/SOC2 risk for the services firm.
- **Differentiator vs competitors (Nightfall, LayerX, Purview):**
  - *Source-aware DLP* — fingerprints of the actual client codebase (packages,
    classes, internal URLs/IPs, vocab). No competitor does this.
  - *On-device detection* — content never leaves the machine (Nano is local);
    competitors (Nightfall) send content to their cloud for classification.
  - *Network-layer interception* — hooks fetch/XHR before the request leaves the
    page; competitors rely on paste/DOM-level hooks.
  - *Zero-setup core* — from day one the extension protects via generic patterns
    + context classification, without requiring a repo scan.
- **Pricing (from the brief, to be revisited):** Free (1 project/5 users),
  Starter ₹2,999/mo (3 projects/25 users), Growth ₹7,999/mo (10/100),
  Enterprise ₹19,999/mo (unlimited — flagged as too cheap vs 3× Growth).

---

## 2. Current state of the repo

- Repo: `https://github.com/shuubhh/promptguard.git` (origin = `main`, pushed).
- Git: 7 commits, clean working tree. Commit style: `feat:` / `fix:` / `test:`
  prefixes, message + body. **NEVER add a `Co-Authored-By: Codebuff` footer —
  the user explicitly removed codebuff-team from all history and future commits.**
- `research/` is gitignored (third-party extension artifacts — do not commit).

### Components and key files

```
scanner/
  promptguard_scanner.py   # CLI: local path or git URL; --token for private
  spec.json                # SHARED single source of truth: secret regexes,
                           # domain terms, package roots, generic names, stopwords
                           # (loaded by BOTH the Python and JS scanners)
  tests/run-scanner-tests.py        # 66 checks
extension/
  manifest.json            # MV3; MAIN-world page-interceptor
  page-interceptor.js      # MAIN world: hooks window.fetch + XMLHttpRequest
  patterns.js              # secret regex registry + scanSecrets() (entropy-gated)
  scanner-engine.js        # multi-project fingerprint scoring + Nano tie-breaker
  warning-modal.js         # soft banner / modal / critical modal (3s lockout)
  status-badge.js          # floating badge, daily counts, last-5 events
  content.js               # orchestration: scan -> thresholds -> UI -> audit log
  background.js            # service worker: audit log, sync queue, badge
  popup.html / popup.js    # connection settings (Supabase URL/anon/refresh token)
  fingerprint.json         # dev fallback (fakebank fixture)
  tests/run-scanner-tests.js        # 21 checks
  tests/run-interceptor-tests.js    # 10 checks
  tests/run-token-tests.js          # 8 checks (needs real dashboard/.env)
  tests/run-background-tests.js     # 18 checks
  tests/verify-live-fingerprint.js  # 7/7: real scanner output -> real engine
dashboard/
  src/pages/              # Login, Home, Events (audit), Projects, Team, Settings
  src/lib/repoScanner.js  # browser-side GitHub/GitLab scan (public repos)
  scripts/run-repo-scanner-tests.mjs  # 47 checks
  supabase/schema.sql + migrations/   # organisations, projects, user_profiles,
                                      # events, invites + RLS org isolation
  .env                    # VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY (real)
```

### Verified working (all green)

- 66 Python scanner tests; 47 JS scanner tests; 21 + 10 + 8 + 18 extension tests.
- `verify-live-fingerprint.js` proves the real fingerprint drives the real engine
  (class name → modal 0.85, secret → critical 0.99, vocab → silent 0.45).
- Dashboard repo-URL scan was live-tested end-to-end against this repo.
- Known bug fixed: Python scanner summary crashed on Windows consoles (⚠ emoji,
  cp1252) — fixed with ASCII-safe output.

---

## 3. How it works today

```
scanner/spec.json ──► scanner ──► fingerprint.json ──► Dashboard (Supabase)
        ▲                                          │ "Save & Fetch Projects"
        │ (shared by JS scanner too)               ▼
                                           chrome.storage.local (projects)
                                           │ every intercepted request
                                           ▼
                              page-interceptor.js (MAIN world)
                                           │ promptguard:scan event
                                           ▼
                              scanner-engine.js ──► UI decision ──► audit log ──► events table
```

- **Confidence ladder:** <0.50 silent · 0.50–0.70 soft warn · 0.70–0.90 modal ·
  >0.90 critical modal (3s lockout + checkbox). Scores: package +0.95, class
  +0.85, secret +0.99, internal URL +0.75, IP +0.70, vocab +0.15/term (cap
  +0.45), cap 0.99.
- **Interception:** MAIN-world fetch/XHR hook (Chrome 111+); Stream/FormData
  bodies never scanned; blocked fetch → HTTP 499.
- **Nano tie-breaker (current):** only in the 0.3–0.6 gray zone, 2.5s timeout,
  `Final = Regex*0.6 + AI*0.4`.

---

## 4. PIVOTED DETECTION MODEL (agreed — fingerprints demoted to enhancement)

Rationale (user's insight): most employees never touch a client codebase —
they paste log excerpts, tickets, configs, API responses. And SAST/gitleaks in
CI means committed secrets are increasingly rare. So the core is always-on
detection of sensitive runtime data; fingerprints are a bonus exact-match layer.

| Layer | Always on? | Catches | Needs repo scan? |
|---|---|---|---|
| **0 — Generic patterns** | ✅ | Secrets, PII (Aadhaar/PAN/phone/email), internal hosts/IPs, credentials, **log signatures** (stack trace + internal host + customer id) | No |
| **1 — Context classifier (Nano)** | ✅ | Log excerpts, ticket text, config dumps, customer data, internal architecture detail — sensitive *by nature*, zero prior knowledge | No |
| **2 — Fingerprint match** | only if scanned | Exact client packages/classes/URLs | Yes |

Phase B = **Nano only first** (user decision). WASM embeddings tested later,
after the build is done.

---

## 5. LOCKED DECISIONS (with rationale)

1. **Assume ≥16 GB RAM on target machines.** Matches Chrome's own documented
   CPU floor for Nano (16GB + 4 cores). (User decision.)
2. **No model downloads to user PCs by OUR extension.** Chrome's Nano model is
   Chrome-managed (one-time, `chrome://components`, invisible as an install) —
   that is acceptable. WASM LLM downloads (1–3 GB) are dropped entirely. Only
   optional WASM piece: a ~22 MB embedding model bundled INSIDE the extension
   package (part of the install, zero separate download) — Phase B decision,
   defer.
3. **AI backends = exactly two:** Nano (default, on-device) and cloud Gemini
   API (org opt-in only, paid-tier lever, payload minimized + never persisted,
   secrets already blocked by the deterministic layer before any cloud call).
4. **Enforcement must NOT depend on Google Workspace / Chrome Enterprise /
   Microsoft Intune.** Ladder:
   - Layer 1 (default): org auto-config via sign-in link + server-pushed policy +
     heartbeat/tamper detection (bypass = visible to admin) + audit accountability.
   - Layer 2 (upgrade): self-hosted CRX + Windows registry
     `ExtensionInstallForcelist` (local admin only; macOS needs MDM/profile —
     Windows is the primary path; Indian IT devs are overwhelmingly Windows).
   - Layer 3 (v3): desktop agent via nativeMessaging (Nightfall's pattern).
5. **Stripe for billing:** use Supabase's official Stripe Sync Engine (one-click,
   Dec 2025) + webhooks/edge functions for the rest. Plumbing solved; pricing is
   the real decision.
6. **No custom backend in v2:** Supabase (auth, DB, RLS, REST) + Vercel
   (dashboard) + Supabase Realtime (policy/flag/fingerprint push to extensions).
7. **Keep the deterministic engine deterministic:** rules decide blocks; AI only
   adjudicates gray zones / adds context. Audit trail must be reproducible.
8. **Manifest hygiene:** minimal permissions (AI-platform host perms only, never
   "all URLs"), airtight privacy disclosures — AI extensions are under heavy
   Web Store scrutiny after the Jan 2026 malicious-extension scandal (~900k
   users compromised). Nightfall ships `http://*/*` + `https://*/*` — do NOT
   copy that; it's our review risk.
9. **No Codebuff commit footer. Ever.** (History was force-pushed clean.)
10. **`scanner/spec.json` is the single source of truth** for all pattern data;
    edit the spec, not the code, when patterns change.

---

## 6. RESEARCH FINDINGS (facts to build on)

### 6a. Chrome built-in AI (verified from developer.chrome.com, May 2026)

- **Prompt API for Chrome Extensions is STABLE since Chrome 138.** Web Prompt
  API at intent-to-ship (Chrome 148). Embedding API still **origin trial** —
  don't build on it.
- **API surface:** global `LanguageModel` (not `window.ai.languageModel`):
  `LanguageModel.availability()`, `LanguageModel.create({temperature, topK,
  signal, initialPrompts, expectedInputs, expectedOutputs, monitor})`,
  `LanguageModel.params()` (extensions only). Session: `prompt(text, {signal,
  responseConstraint})` — JSON-Schema structured output is the right tool for a
  SENSITIVE/POSSIBLY_SAFE/SAFE enum; also `promptStreaming()`, `clone()`,
  `destroy()`, `append()`, `contextUsage/contextWindow`, `contextoverflow`.
  Typings: `@types/dom-chromium-ai`.
- **Hardware:** Win10/11, macOS 13+, Linux, Chromebook Plus · GPU >4GB VRAM OR
  CPU 16GB RAM + 4 cores · 22GB free storage (model smaller; auto-removed if
  storage < 10GB). No data sent to Google when using the model.
- **Gotchas (build-critical):**
  1. NOT available in Web Workers → run inference in an **offscreen document**.
  2. `availability()` must be called with the SAME options as `prompt()`.
  3. First `create()` triggers the model download — needs **user activation**;
     surface `monitor` downloadprogress in the popup. Size at
     `chrome://on-device-internals`.
  4. Remove expired origin-trial permission `aiLanguageModelOriginTrial` from manifest.
  5. `temperature`/`topK` honored only for extensions/origin trial — fine (we're an extension).
  6. Chrome-only (CEF/forks can't use it) → WASM fallback remains for
     cross-browser, but deferred (Nano-first).
- **New (2026):** Prompt API now multimodal (image/audio input, text output);
  languages en/ja/es/de/fr.

### 6b. Nightfall teardown (from actual CRX v8.16.0, shipped today, 80k users)

- **Stack:** React popup, webextension-polyfill, minified bundles WITH sourcemaps
  shipped. Chrome Web Store AND Firefox.
- **Interception is DOM-level, NOT network-level:** MAIN-world
  `inject-event-listener.js` monkey-patches `addEventListener` into a WeakMap
  registry (sees/detaches React handlers); ClipboardMonitor hooks
  copy/cut/paste on every page; a paste-gate with a server-backed permission
  flag does `preventDefault()+stopPropagation()` and even blocks Ctrl+V on Edge
  Copilot domains. They do NOT hook fetch/XHR for AI apps.
- **Detection is CLOUD-based:** content scripts capture → background → POST to
  `extension.nightfall.ai` → ML verdict. Content leaves the device (their
  privacy policy declares PII + website content collection).
- **Per-platform "AccountType" scripts** extract the user's platform email:
  ChatGPT via `client-bootstrap` script JSON; Claude via MAIN-world
  `postMessage` bridge (`__nf_claude_email`) with a DOM-click fallback that
  opens the user-menu; Perplexity via `pplx-next-auth-session` localStorage.
- **Org control:** remote feature flags (`ENABLE_CLIPBOARD_MONITOR`,
  `ENABLE_UPLOAD_MONITORING`, `ENABLE_WEB_SOCKET_CONNECTION`, `ENABLE_TAB_MONITOR`),
  diagnostics logging (`SEND_ERROR_LOG`), tab tracking (`PING_TAB_TRACKING`),
  browser-brand detection (Chrome/Edge/Arc/Brave via userAgentData).
- **Permissions:** `http://*/*` + `https://*/*`, `webRequest`, `identity` OAuth
  (Google, gmail.modify), `cookies`, `downloads`, `alarms`, `nativeMessaging`
  (desktop agent bridge), `all_frames` + `match_about_blank`, iframe traversal
  with MutationObserver for dynamic iframes.

**What to STEAL (all approved for our roadmap):**
1. Paste-gate UX (allow-this-paste / edit) instead of only hard-block.
2. Remote feature flags / kill-switch — via **Supabase Realtime** (also replaces
   manual "Save & Fetch Projects" with live policy+fingerprint push).
3. `all_frames` + iframe traversal on AI sites (check our manifest — likely gap).
4. Platform-email attribution in audit events.
5. Browser-brand + diagnostics fields in events.

**What to KEEP (our moats):** on-device detection (they send content to cloud),
network-layer interception (they don't hook fetch), source-aware fingerprints.

### 6c. Competitors / market

- **Nightfall:** ~$12–15/user/mo (SMB modular); Microsoft Purview ~$12–51/user/mo;
  Chrome Enterprise Premium (Google's own DLP) $6/user/mo — generic patterns,
  NOT source-aware → our wedge holds.
- **ManageEngine Endpoint DLP Plus (Zoho, India):** $795/yr per 100 endpoints
  (~$0.66/endpoint/mo). Endpoint agent, data discovery/classification, USB
  control. NOT AI-chat-focused: their own forum (Apr 2023) has users *requesting*
  GenAI paste-blocking as a missing feature. Low-to-moderate threat; validates
  our India pricing band.
- **LayerX (Akamai):** enterprise browser extension; graduated enforcement
  (monitor-only → warn+justify → redact → block); shadow-AI discovery; agentic
  browsers (Atlas, Comet, Dia). Steal: monitor-only mode, shadow-AI discovery,
  justification prompts.
- **2026 landscape (new opportunities):**
  - **Agentic AI is the #1 emerging threat** (48% of pros expect agents to be
    primary targets; prompt injection, memory poisoning). ChatGPT Atlas /
    Perplexity Comet are new agentic browsers — a future coverage surface.
  - **WebMCP** (Web Model Context Protocol): W3C standard, origin trial in
    Chrome 149 (June 2026) — sites expose structured tools to AI agents. Watch;
    relevant when we add agentic coverage (Phase C).
  - Prompt-injection defense and "man-in-the-prompt" are adjacent markets
    (LayerX disclosed it). Consider as a v3 feature axis.

### 6d. Deployment facts

- Web Store public listing is viable for DLP extensions (Nightfall precedent),
  but broad-permission extensions face rising review scrutiny → keep manifest
  minimal (decision 8).
- Chrome Enterprise Core (free) force-install works via
  `ExtensionInstallForcelist`; Microsoft Purview's own docs confirm
  policy-based deployment is the real DLP channel — but our Ladder avoids
  requiring it (decision 4).

---

## 6e. A1 DELIVERED (org auto-config + accountability) — build state

Implemented, deployed, and E2E-verified against the real Supabase project:

- **Schema:** `dashboard/supabase/migrations/004_org_management.sql` (APPLIED):
  `extension_devices` (token_hash, last_seen_at, revoked_at),
  `extension_join_codes` (code_hash, expires_at, used_at), org columns
  `warn_threshold / block_threshold / monitor_only / feature_flags`,
  `events.device_id / device_name`, RLS member policies.
- **Edge functions (DEPLOYED, verify_jwt=false, auth inside):**
  `supabase/functions/{join-org, org-config, heartbeat, log-event, org-admin}`
  + shared `_shared/device.ts`. Device tokens hashed at rest; codes
  single-use, 1h expiry; events sanitized server-side (30-char previews,
  event_type/match_type allowlists).
- **Extension:** `config.js` (baked anon key — public by design); popup
  "Protect this browser" join flow (code + optional email, Sync now,
  Disconnect); background: 1-min heartbeat + 3-min config-poll alarms,
  device-token event sync via `log-event` (legacy JWT path preserved),
  auto-disconnect on 401 (revocation); content: org-policy threshold
  override + monitor-only mode (log-only, silent events sync when flagged).
- **Dashboard:** Settings → "Protect my browser": generate code (copy),
  connected-device table (Active / Protection off / Revoked + Revoke),
  org policy editor (thresholds + monitor-only).
- **Verified live:** 14/14 `dashboard/scripts/test-v2-functions.py`;
  dashboard UI loop (generate code → join → config → heartbeat → event →
  device list → revoke) exercised end-to-end via the preview with a real
  JWT; audit event landed device-attributed.
- **Design note:** Realtime push was replaced by a 3-min config poll —
  Realtime requires Supabase JWTs which conflict with the device-token auth
  model; polling is simpler and robust. Revisit Realtime only if live push
  becomes a product requirement.

## 7. V2 PLAN — PHASE A (sellable loop). Order matters.

**A1. Org auto-config + accountability (FOUNDATION — build first).**
- "Protect me" org sign-in link: user clicks, signs in with company email,
  extension auto-configures from server (no manual Supabase URL/anon/refresh
  paste). Reuse existing org/user_profiles RLS model.
- Server-pushed policy: per-org thresholds (warn/block), feature flags.
- Supabase Realtime: live push of policy + fingerprints + flags to extensions
  (replaces manual fetch; Nightfall-style kill-switch).
- Heartbeat + tamper detection: heartbeat events from extension; admin sees
  "protection off — user, date" when heartbeats stop.
- Audit events gain: platform email, browser brand, diagnostics fields.

**A2. Self-hosted CRX + Windows force-install runbook (enforcement upgrade).**
- Pipeline to build/sign/host the CRX on our server; runbook for client IT:
  Windows registry `ExtensionInstallForcelist` (local admin). Note macOS needs
  MDM/profile — Windows primary.

**A3. Hosted scan API (private repos).**
- Supabase edge function that clones + scans private GitHub/GitLab repos
  server-side with a token (dashboard browser scan is public-only today).
  Completes the paid workflow.

**A4. Web Store listing + Stripe billing + plan gating.**
- Stripe via Supabase Sync Engine + webhooks; enforce brief's Free/Starter/
  Growth/Enterprise limits (max_projects/max_users already in schema).
- REVISIT Enterprise flat ₹19,999 — priced below 3× Growth, likely too low.
- Web Store submission: minimal permissions, privacy policy, single-purpose
  framing. Prepare now (review takes time).

**A5. Extension hardening (from teardown, can ship anytime):**
- `all_frames` + iframe traversal on AI sites.
- Paste-gate UX (allow/edit on paste-detected-sensitive).
- Platform-email attribution + browser-brand in events.

---

## 8. V3 PLAN — PHASE B + C

**B1. `rules.json` (YARA-INSPIRED, not YARA itself).**
- Declarative rules: AND/OR/near/count conditions, per-rule severity + message;
  replaces the fixed additive scoring in scanner-engine.js. spec.json is the
  embryo — evolve it. Admin-editable later. Deterministic layer upgrade.

**B2. Nano context engine (Phase B = NANO ONLY FIRST; WASM later).**
- Backends: Nano (default) + cloud Gemini (org opt-in). No WASM LLM.
- Intent classification via `LanguageModel` + JSON-Schema responseConstraint
  (SENSITIVE/POSSIBLY_SENSITIVE/SAFE enum) → maps to confidence.
- Fuzzy/paraphrase detection via Nano prompting (feed fingerprint terms, ask
  "does this reference any?") — zero extra model. Embeddings (bundled ~22MB
  WASM) only if/when needed after the build.
- Composer pre-scan (debounced, verdict cached before Send — never block UX on
  AI latency).
- Offscreen document for inference (Prompt API not in Workers).
- Model-download UX in popup (monitor downloadprogress; user activation).
- Dual-engine audit: deterministic + AI scores + rationale logged per event.

**C. Later:** desktop agent (nativeMessaging), shadow-AI discovery, per-client
project segmentation, compliance reports, agentic-browser coverage (Atlas/
Comet/WebMCP watch), prompt-injection defense.

---

## 9. THINGS TO KEEP THE SAME

- Network-layer interception (MAIN-world fetch/XHR hook) — the core mechanism.
- Fingerprint engine + `spec.json` single source of truth (Python + JS).
- Confidence ladder + per-rule thresholds from the brief.
- Supabase + RLS org isolation; no custom backend in v2.
- On-device privacy posture ("content stays local"; only 30-char previews in
  audit logs; secrets never stored, only hashed).
- Multi-project extension storage model (chrome.storage.local).
- Test culture: every change runs the relevant suites; live-verification script.

---

## 10. VERIFICATION / TEST COMMANDS (Windows, Git Bash)

```bash
py scanner/tests/run-scanner-tests.py                        # 66
node extension/tests/run-scanner-tests.js                    # 21
node extension/tests/run-interceptor-tests.js                # 10
node extension/tests/run-background-tests.js                 # 18
node extension/tests/run-token-tests.js                      # 8 (needs dashboard/.env)
node extension/tests/verify-live-fingerprint.js              # 7/7 live pipeline
cd dashboard && node scripts/run-repo-scanner-tests.mjs      # 47
cd dashboard && npm run build                                # prod build
```

Dev server: `cd dashboard && npm run dev` (port 5173; check listeners first).
Extension: `chrome://extensions` → Load unpacked → `extension/`; refresh icon +
reload AI tab after each change. Chrome flags for Nano:
`chrome://flags/#optimization-guide-on-device-model` +
`#prompt-api-for-gemini-nano`, then download model at `chrome://components`.

---

## 11. OPEN QUESTIONS / DECISIONS PENDING

1. Enterprise tier price (₹19,999 flat vs 3× Growth) — user decision.
2. Cloud-offload mode as a paid-tier feature — likely yes, confirm.
3. Whether Phase B bundles the ~22MB embedding model — defer to after build.
4. Web Store listing timing — prepare early, submit after A1–A2.
5. Agentic-browser coverage priority (v3 vs later).
6. Monitor-only mode as default onboarding state (LayerX pattern) — likely yes.

---

## 12. OPERATING NOTES

- **Commits:** prefix style (`feat:`/`fix:`/`test:`), NEVER the Codebuff
  footer. Push to `origin/main` only with explicit user request.
- **Research artifacts** live in `research/` (gitignored) — never commit
  third-party code.
- **Windows environment:** `py` (not python3), Git Bash POSIX syntax, Node
  available in `dashboard/`.
- **Supabase:** real project ("PromptGuard UI Test Org") with creds in
  `dashboard/.env`; schema + migrations in `dashboard/supabase/`.
- Freebuff restarts kill background processes — restart dev servers/watchers
  as needed; files are never touched.
- The user is the sole author of the repo. Keep it that way.
