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
  // Org-level policy pushed to the extension (v2): thresholds + monitor-only.
  let orgPolicy = null;
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
  // Maps a pattern key to the bucket stored in the Supabase events table.
  // The log-event edge function allowlists: package_name, class_name, secret,
  // internal_url, internal_ip, vocabulary, rules, ai_context, log_signature.
  let auditTypeByKey = null;
  function getAuditTypeByKey() {
    if (auditTypeByKey) return auditTypeByKey;
    const map = {};
    for (const p of PG.SECRET_PATTERNS || []) map[p.key] = p.auditType || 'secret';
    for (const p of PG.CONTEXT_PATTERNS || []) map[p.key] = p.auditType || 'log_signature';
    auditTypeByKey = map;
    return map;
  }

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
    // Bucket the top match into the events-table allowlist ('secret' for AWS
    // keys etc., 'log_signature' for stack traces, ...). When the AI alone
    // flagged the text with no deterministic match, record 'ai_context'.
    const bucketMap = getAuditTypeByKey();
    const matchType =
      top && top.key
        ? bucketMap[top.key] || top.key
        : result.aiUsed
          ? 'ai_context'
          : 'none';
    const event = {
      timestamp: new Date().toISOString(),
      org_id: orgIdentity.org_id,
      user_email: orgIdentity.user_email || '',
      event_type: eventType, // silent | warned | override | redacted | blocked
      confidence: result.confidence,
      regex_score: result.regexScore,
      ai_used: result.aiUsed,
      ai_label: result.aiLabel || null,
      ai_model: result.aiUsed ? result.aiModel || 'gemini-nano' : null,
      match_type: matchType,
      match_label: top ? top.label : 'none',
      match_preview: top ? String(top.matchedText).slice(0, 30) : '',
      monitor_only: result.monitor_only === true ? true : null,
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

        const result = applyOrgPolicy(await PG.scanContent(body));

        // Monitor-only orgs: observe and log everything, but never intervene.
        if (result.monitor_only === true) {
          const eventType =
            result.level === 'critical' ? 'blocked' :
            result.level === 'modal' || result.level === 'soft' ? 'warned' : 'silent';
          logEvent(eventType, Object.assign({}, result, { monitor_only: true }), url);
          PG.updateStatusBadge('silent');
          sendDecision('allow');
          return;
        }

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

  /**
   * Apply the org's pushed policy on top of the scanner-engine result:
   * warn_threshold shifts where the modal starts, block_threshold where it
   * becomes critical, and monitor_only forces observation-only behaviour.
   * With defaults (0.7 / 0.9 / false) this is identical to the brief ladder.
   */
  function applyOrgPolicy(result) {
    if (!orgPolicy || typeof orgPolicy !== 'object' || typeof result !== 'object') return result;
    const warn = typeof orgPolicy.warn_threshold === 'number' ? orgPolicy.warn_threshold : 0.7;
    const block = typeof orgPolicy.block_threshold === 'number' ? orgPolicy.block_threshold : 0.9;
    const c = result.confidence || 0;
    let level = 'silent';
    if (c >= 0.5 && c < warn) level = 'soft';
    else if (c >= warn && c < block) level = 'modal';
    else if (c >= block) level = 'critical';
    return Object.assign({}, result, {
      level: level,
      monitor_only: orgPolicy.monitor_only === true ? true : (result.monitor_only === true)
    });
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
        const idState = await chrome.storage.local.get(['org_id', 'user_email', 'org_policy']);
        orgIdentity = {
          org_id: idState.org_id || null,
          user_email: idState.user_email || ''
        };
        orgPolicy = idState.org_policy || null;
      } catch (err) {
        /* ignore */
      }
      // Live-refresh fingerprints + identity + policy when the popup/background
      // syncs, so no tab reload is needed after connecting.
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
        if (changes.org_policy && typeof changes.org_policy.newValue === 'object') {
          orgPolicy = changes.org_policy.newValue;
        }
      });
    } catch (err) {
      console.warn('[PromptGuard] init error', err);
    }
  })();
})();
