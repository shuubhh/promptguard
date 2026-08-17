# PromptGuard — Chrome Extension (Component 2)

Vanilla JavaScript, Manifest V3, zero build step, zero external CDN dependencies.

## How interception works (read this first)

AI platforms (ChatGPT, Claude, DeepSeek…) use ContentEditable divs with React
synthetic events, so `e.preventDefault()` on paste events does **not** reliably
stop text insertion. PromptGuard therefore intercepts at the **network layer**,
hooking `fetch` and `XMLHttpRequest` **before** the request leaves the page.

A critical Chrome detail: content scripts run in an *isolated world* — overriding
`window.fetch` there does **not** affect the page's own JavaScript. So the
extension is split across two worlds that communicate over DOM `CustomEvent`s:

| File                | World      | Role                                                              |
| ------------------- | ---------- | ----------------------------------------------------------------- |
| `page-interceptor.js` | MAIN     | Hooks the page's real `fetch` / `XHR` (requires Chrome 111+ via `"world": "MAIN"`) and bridges to the scanner |
| `patterns.js`       | ISOLATED   | Hardcoded secret regex registry + `scanSecrets()`                 |
| `scanner-engine.js` | ISOLATED   | Multi-project fingerprint scoring + Gemini Nano AI tie-breaker    |
| `warning-modal.js`  | ISOLATED   | Soft banner, modal, critical modal (3s lockout + checkbox)        |
| `status-badge.js`   | ISOLATED   | Floating badge with daily counts + last-5-events popup            |
| `content.js`        | ISOLATED   | Orchestrates scanning → thresholds → UI → audit logging           |
| `background.js`     | Service worker | Persists audit log, sets toolbar badge, syncs to backend (stub) |

Flow: `page-interceptor.js` wraps fetch/XHR → dispatches `promptguard:scan` →
`content.js` runs `scanContent()` → returns `allow | cancel | redact` via
`promptguard:decision` → interceptor either passes the request through
(optionally with a redacted body), returns HTTP 499, or aborts the XHR.

## Confidence ladder (from the brief)

- `< 0.50` → **silent** — logged only, nothing shown
- `0.50–0.70` → **soft warning** — subtle dismissible banner, request proceeds
- `0.70–0.90` → **modal warning** — requires user action
- `> 0.90` → **critical modal** — red-tinted, "Send Anyway" disabled 3s +
  confirmation checkbox

Scoring: package +0.95 · class +0.85 · secret +0.99 · internal URL +0.75 ·
internal IP +0.70 · vocabulary +0.15/term (max +0.45) · cap 0.99.

## Chrome Built-in AI (Gemini Nano)

Only used as a tie-breaker. When the regex score is in `[0.3, 0.6]`, the AI runs
with a **2.5s `Promise.race` timeout** and the exact system prompt from the
brief. `Final = Regex*0.6 + AI*0.4` with `SENSITIVE=0.75`,
`POSSIBLY_SENSITIVE=0.55`, `SAFE=0.1`. Regex scores `> 0.6` skip the AI entirely
to save CPU. If the AI is unavailable or times out, the extension **silently**
falls back to the regex score — the user never sees an error.

To enable Gemini Nano (Chrome 126+): `chrome://flags/#optimization-guide-on-device-model`
→ *Enabled BypassPerfRequirement*, then `chrome://flags/#prompt-api-for-gemini-nano`
→ *Enabled*, restart Chrome, and download the model at `chrome://components` →
"Optimization Guide On Device Model".

## File structure

```
extension/
├── manifest.json
├── background.js
├── content.js
├── page-interceptor.js      (MAIN world — see above)
├── scanner-engine.js
├── warning-modal.js
├── status-badge.js
├── patterns.js
├── styles/
│   └── modal.css
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   ├── icon128.png
│   └── generate-icons.py     (regenerate placeholders: py icons/generate-icons.py)
├── fingerprint.json          (dev fallback — fakebank data)
└── README.md
```

---

## Testing guide (Chrome)

### a) Load the unpacked extension

1. Open `chrome://extensions` in Chrome (must be Chrome 111+ for the
   MAIN-world interceptor; 126+ for Gemini Nano).
2. Toggle **Developer mode** ON (top-right).
3. Click **Load unpacked** and select the **`extension/`** folder
   (the folder containing `manifest.json` — not the project root).
4. Open any supported AI site (e.g. `https://chatgpt.com`), open DevTools
   (**F12** → Console) and confirm the log line:
   `[PromptGuard] initialized on chatgpt.com`.
5. A floating badge should appear bottom-right:
   `🛡️ PromptGuard Active | Safe: 0 | Flagged: 0`.

> After editing any extension file: click the **refresh icon** on the
> PromptGuard card in `chrome://extensions`, then reload the AI tab.

### b) Inject a fake fingerprint for testing

`chrome.storage` is not exposed in a normal page's DevTools console, so use the
**service worker console**:

1. On `chrome://extensions`, click the **"service worker"** link on the
   PromptGuard card (opens the extension's own DevTools).
2. Paste this into the service worker console and press Enter:

```js
await chrome.storage.local.set({
  projects: [
    {
      id: 'test-hdfc',
      name: 'HDFC Wealth Platform (test)',
      fingerprint: {
        version: '1.0',
        project: 'HDFC Wealth Platform',
        scanned_at: new Date().toISOString(),
        packages: ['com.hdfcbank.wealth.portfolio', 'com.hdfcbank.retail.core', 'com.hdfcbank.internal'],
        class_names: ['CustomerWealthPortfolioService', 'TransactionLedgerReconciliation', 'PortfolioReconciliationReport', 'TransactionLedgerExport'],
        domain_vocabulary: ['ledger', 'nostro', 'vostro', 'portfolio', 'reconciliation', 'swift', 'clearing', 'settlement', 'collateral', 'wealth', 'premium', 'tier', 'iban'],
        internal_urls: ['https://api.hdfcbank-internal.corp/v2/portfolio'],
        internal_ips: ['192.168.10.45', '10.10.5.22'],
        secrets_found: []
      },
      policy: { warn_threshold: 0.7, block_threshold: 0.9 }
    }
  ]
});
```

3. Back on the AI site tab, reload the page. The extension now scans against
   **both** the injected project and the bundled dev fingerprint.

> To reset: run `await chrome.storage.local.remove('projects')` in the same
> console, then reload the tab. (With no projects in storage, the bundled
> `fingerprint.json` is used automatically.)

### c) Trigger the critical modal with a fake AWS key

1. On `https://chatgpt.com` (logged in), type (or paste) this into the
   composer:

   ```
   Here is my config for the deployment:
   AKIAIOSFODNN7EXAMPLE
   ```

2. Click **Send**.
3. Expect the **critical** modal:
   - Red-tinted overlay, title *"Sensitive Content Detected"*,
   - Subtitle *"AWS Access Key found in your prompt"*,
   - CRITICAL badge, the matched text preview `AKIAIOSFODNN7EXAMPLE`,
   - **Send Anyway** is greyed out for 3 seconds with a countdown and requires
     ticking *"I confirm this is not sensitive client data"*.
4. Click **Cancel & Edit** → the request is blocked (the network call never
   fires; fetch would have returned HTTP 499).
5. Send again, wait out the 3s, tick the checkbox, click **Send Anyway** →
   request goes through, logged as `override`, and the badge's Flagged count
   increments. Click the badge to see the event in the popup.

### d) Multi-project test (brief fix D)

1. Re-inject the snippet from (b) (project "HDFC Wealth Platform (test)").
2. In the ChatGPT composer, type:

   ```
   Refactor the CustomerWealthPortfolioService using com.hdfcbank.wealth.portfolio
   ```

3. Send → expect a **critical** modal that says
   *"Matched in project: HDFC Wealth Platform (test)"* (class name +0.85 and
   package +0.95 → capped at 0.99).

### e) Soft warning test (0.50–0.70)

The regex-only floor for a soft warning comes from the AI tie-breaker on
vocabulary-heavy text (vocab alone caps at 0.45). With Gemini Nano enabled,
type:

```
nostro vostro ledger portfolio reconciliation settlement clearing
```

Send → a small amber banner appears (*"Possible sensitive content detected —
57% confidence (HDFC Wealth Platform (test)). Sending anyway."*) and the
message is sent without blocking.

### f) Audit log

Open the service worker console (see b) and run:

```js
await chrome.storage.local.get(['audit_log', 'daily_stats'])
```

Each entry contains `event_type` (silent / warned / override / redacted /
blocked), confidence, match type + 30-char preview, project name, and platform.

## Automated tests

Headless tests. Needs Node 18+:

```bash
node extension/tests/run-scanner-tests.js        # scanner engine: 16 tests
node extension/tests/run-interceptor-tests.js    # fetch/XHR interception: 10 tests
node extension/tests/run-token-tests.js          # JWT auto-refresh vs real Supabase: 8 tests
node extension/tests/run-background-tests.js     # sync queue/retry/dedupe/reconcile: 18 tests
```

`run-background-tests.js` covers the pending-sync queue: events survive transient
failures (backoff + retry), already-synced events are never duplicated (dedupe
check before insert), and old tabs that logged directly to `chrome.storage` are
swept into the queue on service-worker wake (`reconcileAuditLog`), so their
events finally reach the dashboard without a tab reload.

`run-token-tests.js` needs a real `dashboard/.env` (Supabase URL + anon key, with
email confirmation disabled) — it signs up a throwaway user and proves the
popup's `getAccessToken()` reuses a valid JWT, auto-refreshes an expired one
(rotating the refresh token), and falls back gracefully when no refresh token is
stored.

## Connecting to the dashboard (popup)

1. Dashboard → **Settings** → copy the **Supabase URL**, the **anon key**
   (from Supabase Project Settings → API), and the **Refresh token** (new,
   recommended).
2. In the extension popup, paste all three (the API-key JWT field is optional
   when a refresh token is present) → **Save & Fetch Projects**.

Why the refresh token: Supabase access-token JWTs expire after ~1 hour, which
surfaces as `PGRST303 JWT expired` in the popup. The refresh token is long-lived
and single-use (rotating): every exchange stores a fresh pair, so the extension
stays connected indefinitely — in the popup **and** in the background worker,
which now auto-refreshes before syncing events. Re-copy it only after clearing
extension storage or signing out of the dashboard (both invalidate it
server-side). Note that the refresh token is shared with your dashboard session:
if either side rotates it, the other may need a re-login/re-copy.

## Notes

- **OpenAI migrated ChatGPT to `chatgpt.com`.** The manifest covers both
  `chatgpt.com` and the legacy `chat.openai.com` so the extension keeps
  working regardless of which domain you land on.


- **Backend sync is a stub.** `background.js` posts events to
  `https://your-backend-url.com/api/events` only after you replace
  `BACKEND_BASE` and set an `auth_token` in storage. Until then it silently
  persists everything locally.
- **XHR blocking** aborts the request and synthesizes a 499 response so callers
  don't hang; `fetch` blocking returns `new Response(null, { status: 499 })`.
- **Stream/FormData bodies are never scanned** (brief fix A) — file uploads and
  image generation pass through untouched.
