# PromptGuard — End-to-End Test Plan (Nano build, v0.1.2+)

Whole-project acceptance test: scanner → dashboard → org join → extension →
Gemini Nano → audit trail. Run top to bottom; ~10 minutes.

## Prep (2 min)

1. `chrome://extensions` → PromptGuard **v0.1.2+**, refreshed; no duplicate cards.
2. Popup: org joined (org name + email visible), AI section says
   **"Enabled — Gemini Nano is now active on AI platforms"**.
3. Dashboard open on the **Events** page (so you can watch events land live).
4. A project with a fingerprint loaded in the org (Dashboard → Projects →
   scan/refresh). Test texts below use the fakebank fixture names
   (`CustomerWealthPortfolioService`, `com.hdfcbank.wealth.portfolio`).

## A. Deterministic layers (Nano must NOT change these)

| # | Paste into ChatGPT → Send | Expected | Event on dashboard |
|---|---|---|---|
| A1 | `Here is my config: AKIAIOSFODNN7EXAMPLE` | Critical modal (red, 3s lockout + confirm checkbox). Cancel & Edit → nothing sent | `BLOCKED`, ~99%, **no AI label**, match `secret` |
| A2 | `Refactor CustomerWealthPortfolioService to use the new API` | Critical modal naming the project | `BLOCKED`/`override`, ~85%+, **no AI label** (regex > 0.6) |
| A3 | `How do I reverse a string in JavaScript?` | Nothing happens at all | `silent`, ~0%, no AI |

## B. Nano-adjudicated paths (the new engine)

> In the fuzzy zone [30–60%] and for pasted logs, Nano runs and
> `Final = Regex×0.6 + AI×0.4`. BOTH outcomes below are PASS — what you're
> verifying is that **Nano actually ran**, which the dashboard proves via the
> `AI: <label>` + `% regex` fields on the event.

| # | Paste into ChatGPT → Send | Expected | Event on dashboard |
|---|---|---|---|
| B1 | `nostro vostro ledger portfolio reconciliation settlement clearing` | Soft amber banner (Nano SENSITIVE → 57%) **or** silent (Nano SAFE → 31%) | `warned`/`silent`, `AI: SENSITIVE` or `AI: SAFE`, `45% regex` |
| B2 | `Exception in thread "main" java.lang.NullPointerException` ⏎ `    at com.hdfcbank.wealth.PortfolioService.reconcile(PortfolioService.java:142)` | Soft warning or silent (Nano's call) | event shows `AI:` label + `log_signature` match |
| B3 | `2026-09-14 10:00:00 INFO UserService login ok for user 42` (harmless log line) | Silent pass — no false alarm | `silent`, `AI: SAFE` expected |

## C. Multi-platform spot-check

Repeat B1 on `claude.ai` (and optionally Gemini/DeepSeek) — same behavior.

## D. Org/accountability loop

1. Dashboard → Settings → Protect my browser: your device shows **ACTIVE**
   (heartbeat < 1 min old).
2. Events page: events from A/B carry the device name.
3. Popup counters (Safe/Flagged/Blocked today) incremented.

## Failure signatures (what to report)

- **No `AI:` label on B-row events** → Nano didn't run: check the service
  worker console (`chrome://extensions` → PromptGuard → *Inspect service
  worker*) for offscreen-document errors and report them.
- **Popup error text in the AI status line** → send a screenshot (the error
  trap names the exact failure).
- **No event on the dashboard** → check popup → Sync now, then the service
  worker console for `log-event` failures.

## Regression sweep (headless, before any release)

```bash
node extension/tests/run-ai-tests.js             # 19
node extension/tests/run-scanner-tests.js        # 29
node extension/tests/run-interceptor-tests.js    # 10
node extension/tests/run-background-tests.js
node extension/tests/verify-live-fingerprint.js  # 7/7
py scanner/tests/run-scanner-tests.py            # 66
cd dashboard && node scripts/run-repo-scanner-tests.mjs  # 47
cd dashboard && npm run build
```
