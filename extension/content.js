/**
 * content.js — PromptGuard (isolated world)
 *
 * Orchestrates the whole pipeline for every intercepted request:
 *   1. Receives "promptguard:scan" CustomEvents from page-interceptor.js
 *      (the MAIN-world fetch/XHR hook).
 *   2. Runs scanContent() (scanner-engine.js) which scans the body against
 *      every loaded project fingerprint + global secret patterns, and
 *      optionally cross-checks with Chrome Built-in AI (Gemini Nano).
 *   3. Applies the confidence ladder and shows the right UI:
 *        < 0.50  silent           (log only)
 *        0.50–0.70 soft warning   (subtle banner, request proceeds)
 *        0.70–0.90 modal warning  (requires user action)
 *        > 0.90   critical modal  (red, 3s lockout + checkbox)
 *   4. Answers the MAIN world with 'allow' | 'cancel' | 'redact' (+ body).
 *   5. Logs every event to the background service worker.
 */
(function () {
  'use strict';

  const PG = window.__PromptGuard || {};

  console.log('[PromptGuard] initialized on', location.hostname);

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------
  // Serializes scan+decision handling so two requests never show two modals
  // at the same time.
  let serialQueue = Promise.resolve();
  // Org/identity info from the dashboard connection (popup), used in audit
  // events so the Supabase `events` table gets org_id + user_email.
  let orgIdentity = { org_id: null, user_email: '' };
  // Reuses the last decision for an identical body within 5s — prevents
  // double modals when the same prompt is sent via fetch AND XHR, or when a
  // blocked request is automatically retried by the platform.
  const decisionCache = new Map(); // body -> { ts, decision }

  // ------------------------------------------------------------------
  // Platform detection
  // ------------------------------------------------------------------
  function detectPlatform() {
    const h = location.hostname;
    if (h.includes('chatgpt.com') || h.includes('chat.openai.com')) return 'chatgpt';
    if (h.includes('claude.ai')) return 'claude';
    if (h.includes('gemini.google.com')) return 'gemini';
    if (h.includes('chat.deepseek.com')) return 'deepseek';
    if (h.includes('copilot.microsoft.com')) return 'copilot';
    if (h.includes('perplexity.ai')) return 'perplexity';
    return 'unknown';
  }

  // ------------------------------------------------------------------
  // Audit logging
  // ------------------------------------------------------------------
  async function logEvent(eventType, result, url) {
    // Always use the latest identity from storage — never a stale value from
    // before the popup was connected.
    if (!orgIdentity.org_id) {
      try {
        const idState = await chrome.storage.local.get(['org_id', 'user_email']);
        orgIdentity = {
          org_id: idState.org_id || null,
          user_email: idState.user_email || ''
        };
      } catch (err) {
        /* keep existing */
      }
    }
    const top = result.matches && result.matches.length ? result.matches[0] : null;
    const event = {
      timestamp: new Date().toISOString(),
      org_id: orgIdentity.org_id,
      user_email: orgIdentity.user_email || '',
      event_type: eventType, // silent | warned | override | redacted | blocked
      confidence: result.confidence,
      regex_score: result.regexScore,
      ai_used: result.aiUsed,
      ai_label: result.aiLabel || null,
      match_type: top ? top.key : 'none',
      match_label: top ? top.label : 'none',
      match_preview: top ? String(top.matchedText).slice(0, 30) : '',
      project_id: result.topProject ? result.topProject.id : null,
      project_name: result.topProject
        ? result.topProject.name
        : result.matchedProjects.length > 1
          ? 'Multiple projects'
          : 'Global',
      matched_projects: result.matchedProjects.map((p) => p.name),
      platform: detectPlatform(),
      url: url || ''
    };
    try {
      chrome.runtime.sendMessage({ type: 'PG_LOG_EVENT', event: event }).catch(() => {});
    } catch (err) {
      /* background not ready yet — event still counted locally by the badge */
    }
  }

  // ------------------------------------------------------------------
  // Scan request handling (called from the MAIN world bridge)
  // ------------------------------------------------------------------
  function handleScanRequest(detail) {
    const { requestId, body, url } = detail || {};
    const sendDecision = (decision, redactedBody) => {
      try {
        window.dispatchEvent(
          new CustomEvent('promptguard:decision', {
            detail: {
              requestId: requestId,
              decision: decision,
              redactedBody: redactedBody || undefined
            }
          })
        );
      } catch (err) {
        /* ignore */
      }
    };

    return (async () => {
      try {
        // Reuse the previous decision for an identical body (dedupe).
        const cached = decisionCache.get(body);
        if (cached && Date.now() - cached.ts < 5000) {
          if (cached.decision === 'redact' && cached.redactedBody) {
            sendDecision('redact', cached.redactedBody);
          } else {
            sendDecision(cached.decision);
          }
          return;
        }

        const result = await PG.scanContent(body);
        const action = await decideAction(result, url);

        let redactedBody;
        if (action === 'redact') {
          redactedBody = PG.redactText(body, result);
        }
        decisionCache.set(body, { ts: Date.now(), decision: action, redactedBody: redactedBody || null });
        if (decisionCache.size > 100) decisionCache.clear();

        sendDecision(action, redactedBody);
      } catch (err) {
        // Never break the page: on any scanning error, let the request through.
        console.warn('[PromptGuard] scan error, allowing request', err);
        sendDecision('allow');
      }
    })();
  }

  /**
   * Apply the confidence ladder and drive the UI. Returns:
   *   'allow'  — request proceeds (silent / soft / user chose Send Anyway)
   *   'cancel' — request blocked
   *   'redact' — request proceeds with a redacted body
   */
  async function decideAction(result, url) {
    switch (result.level) {
      case 'silent':
        logEvent('silent', result, url);
        PG.updateStatusBadge('silent');
        return 'allow';

      case 'soft':
        logEvent('warned', result, url);
        PG.updateStatusBadge('warned');
        if (PG.showSoftWarning) PG.showSoftWarning(result);
        return 'allow';

      default: {
        // modal (0.70–0.90) or critical (>0.90)
        const choice = await PG.showWarningModal(result);
        if (choice === 'cancel') {
          logEvent('blocked', result, url);
          PG.updateStatusBadge('blocked');
          return 'cancel';
        }
        if (choice === 'redact') {
          logEvent('redacted', result, url);
          PG.updateStatusBadge('redacted');
          return 'redact';
        }
        logEvent('override', result, url);
        PG.updateStatusBadge('override');
        return 'allow';
      }
    }
  }

  // ------------------------------------------------------------------
  // Bridge listeners (registered synchronously so the MAIN world can
  // start scanning immediately)
  // ------------------------------------------------------------------
  window.addEventListener('promptguard:scan', (e) => {
    const detail = (e && e.detail) || {};
    serialQueue = serialQueue.then(() => handleScanRequest(detail)).catch(() => {});
  });

  // Tell the MAIN-world interceptor we are listening (it falls back to
  // allow-through for the first ~1.5s if we haven't).
  try {
    window.dispatchEvent(new CustomEvent('promptguard:ready'));
  } catch (err) {
    /* ignore */
  }

  // ------------------------------------------------------------------
  // Init (async, non-blocking)
  // ------------------------------------------------------------------
  (async function init() {
    try {
      if (PG.initStatusBadge) await PG.initStatusBadge();
      await PG.loadProjects();
      try {
        const idState = await chrome.storage.local.get(['org_id', 'user_email']);
        orgIdentity = {
          org_id: idState.org_id || null,
          user_email: idState.user_email || ''
        };
      } catch (err) {
        /* ignore */
      }
      // Live-refresh fingerprints + identity when the popup/dashboard syncs,
      // so no tab reload is needed after connecting.
      chrome.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;
        if (changes.projects) {
          PG.loadProjects(true);
        }
        if (changes.org_id && changes.org_id.newValue) {
          orgIdentity.org_id = changes.org_id.newValue;
        }
        if (changes.user_email && typeof changes.user_email.newValue === 'string') {
          orgIdentity.user_email = changes.user_email.newValue;
        }
      });
    } catch (err) {
      console.warn('[PromptGuard] init error', err);
    }
  })();
})();
