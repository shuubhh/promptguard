/**
 * page-interceptor.js — PromptGuard (runs in the PAGE / MAIN world)
 *
 * WHY THIS FILE EXISTS (important):
 * Content scripts run in an "isolated world" — overriding window.fetch or
 * XMLHttpRequest.prototype there does NOT affect the page's own JavaScript.
 * AI platforms (ChatGPT, Claude, DeepSeek…) use ContentEditable divs and
 * React synthetic events, so paste-event blocking is unreliable. The only
 * reliable interception point is the network layer, and to hook the page's
 * real fetch/XHR we must run in the MAIN world (declared as
 * "world": "MAIN" in manifest.json — requires Chrome 111+).
 *
 * This script therefore:
 *   1. Wraps window.fetch and XMLHttpRequest in the MAIN world.
 *   2. Bridges scan requests to the isolated-world scanner engine via
 *      CustomEvents ("promptguard:scan" / "promptguard:decision").
 *   3. Also bridges the Chrome Built-in AI (Gemini Nano) call
 *      ("promptguard:ai-request" / "promptguard:ai-response"), because
 *      window.ai is only guaranteed to exist in the page world.
 *
 * Technical rules honoured (brief "critical fixes"):
 *   - Only string bodies are scanned. ReadableStream / FormData bodies are
 *     never touched — uploads and image generation pass through untouched.
 *   - The original options object is passed through unmodified unless the
 *     user chooses "Redact"; only then is options.body replaced.
 */
(() => {
  'use strict';

  if (window.__PROMPTGUARD_INTERCEPTOR__) return;
  window.__PROMPTGUARD_INTERCEPTOR__ = true;

  const SCAN_EVENT = 'promptguard:scan';
  const DECISION_EVENT = 'promptguard:decision';
  const READY_EVENT = 'promptguard:ready';
  const AI_REQUEST_EVENT = 'promptguard:ai-request';
  const AI_RESPONSE_EVENT = 'promptguard:ai-response';
  const AI_TIMEOUT_MS = 2500;      // 2.5s cap on session.prompt()
  const NOT_READY_TIMEOUT_MS = 1500;

  let ready = false;
  let counter = 0;
  const pending = new Map(); // requestId -> { resolve, timer }

  // ------------------------------------------------------------------
  // Event bridge
  // ------------------------------------------------------------------
  window.addEventListener(READY_EVENT, () => {
    ready = true;
  }, true);

  window.addEventListener(DECISION_EVENT, (e) => {
    const d = (e && e.detail) || {};
    if (!d.requestId) return;
    const entry = pending.get(d.requestId);
    if (!entry) return;
    pending.delete(d.requestId);
    if (entry.timer) clearTimeout(entry.timer);
    entry.resolve(d);
  }, true);

  function askScanner(body, url, method) {
    return new Promise((resolve) => {
      const requestId =
        'pg' + ++counter + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);
      let timer = null;
      // Before the isolated-world listener is registered (a tiny race at
      // document_start), never let a request hang: fall back to allowing it.
      if (!ready) {
        timer = setTimeout(() => {
          pending.delete(requestId);
          resolve({ decision: 'allow', reason: 'scanner-not-ready' });
        }, NOT_READY_TIMEOUT_MS);
      }
      pending.set(requestId, { resolve, timer });
      try {
        window.dispatchEvent(
          new CustomEvent(SCAN_EVENT, {
            detail: { requestId, body, url, method }
          })
        );
      } catch (err) {
        pending.delete(requestId);
        if (timer) clearTimeout(timer);
        resolve({ decision: 'allow', reason: 'dispatch-error' });
      }
    });
  }

  // ------------------------------------------------------------------
  // Which requests are candidates for scanning?
  // ------------------------------------------------------------------
  function shouldScanUrl(url) {
    if (!url) return false;
    try {
      const target = new URL(url, window.location.href);
      const host = target.hostname;
      // Same-origin API calls (most AI platforms send prompts to their own backend).
      if (target.origin === window.location.origin) return true;
      // Cross-origin API hosts used by the supported platforms.
      const known =
        /(^|\.)(chatgpt\.com|chat\.openai\.com|openai\.com|claude\.ai|anthropic\.com|gemini\.google\.com|googleapis\.com|deepseek\.com|copilot\.microsoft\.com|perplexity\.ai)$/i;
      return known.test(host);
    } catch (err) {
      return false;
    }
  }

  // Heuristic to skip auth/session/telemetry payloads that are never user
  // prompt content. AI platforms fire MANY same-origin requests while you
  // merely have a page open (telemetry, register_event, session refreshes),
  // and those bodies routinely contain numeric IDs that false-positive the
  // Aadhaar/PAN patterns. Only payloads that carry an actual user message
  // structure are scanned:
  //   - ChatGPT / DeepSeek / OpenAI:    {"messages":[{...}]}
  //   - ChatGPT current + Gemini:       {"contents":[{..."parts":[...]}]}
  //   - Claude:                         {"role":"user","content":"..."}
  //   - Microsoft Copilot:             {"conversation_history":[...]}
  function isLikelyPromptBody(body) {
    if (!body || typeof body !== 'string') return false;
    const trimmed = body.trim();
    if (trimmed.length < 30) return false;
    if (/"(token|access_token|refresh_token|jwt|session|apikey|api_key|authorization|secret)"\s*:/i.test(trimmed)) {
      return false;
    }
    return (
      /"messages"\s*:\s*\[/i.test(trimmed) ||
      /"parts"\s*:\s*\[/i.test(trimmed) ||
      /"role"\s*:\s*"user"/i.test(trimmed) ||
      /"conversation_history"\s*:/i.test(trimmed)
    );
  }

  // ------------------------------------------------------------------
  // fetch interception
  // ------------------------------------------------------------------
  const originalFetch = window.fetch;

  window.fetch = async function (input, init) {
    let url = '';
    if (typeof input === 'string') url = input;
    else if (input && typeof input === 'object') url = input.url || '';

    const options = init && typeof init === 'object' ? init : {};

    let intercepted = false;
    let decision = null;

    // CRITICAL FIX (brief A): only scan plain string bodies. Never try to
    // read ReadableStream / FormData bodies — that breaks uploads and image
    // generation. Non-string bodies pass through completely untouched.
    if (typeof options.body === 'string' && shouldScanUrl(url) && isLikelyPromptBody(options.body)) {
      intercepted = true;
      decision = await askScanner(options.body, url, (init && init.method) || (input && input.method) || 'POST');
    }

    if (intercepted && decision && decision.decision === 'cancel') {
      return new Response(null, { status: 499, statusText: 'Blocked by PromptGuard' });
    }

    // CRITICAL FIX (brief A): if the user chose "Redact", replace the string
    // body and assign it back onto the same options object. Otherwise the
    // options object is passed through exactly as the page built it.
    if (intercepted && decision && decision.decision === 'redact' && typeof decision.redactedBody === 'string') {
      options.body = decision.redactedBody;
    }

    return originalFetch.call(this, input, options);
  };

  // ------------------------------------------------------------------
  // XMLHttpRequest interception
  // ------------------------------------------------------------------
  const XHR = XMLHttpRequest.prototype;
  const originalOpen = XHR.open;
  const originalSend = XHR.send;

  XHR.open = function (method, url) {
    try {
      this.__pgUrl = typeof url === 'string' ? url : '';
      this.__pgMethod = typeof method === 'string' ? method.toUpperCase() : 'GET';
    } catch (err) {
      /* ignore */
    }
    return originalOpen.apply(this, arguments);
  };

  XHR.send = function (body) {
    const xhr = this;
    let url = '';
    let method = 'POST';
    try {
      url = xhr.__pgUrl || '';
      method = xhr.__pgMethod || 'POST';
    } catch (err) {
      /* ignore */
    }

    if (typeof body === 'string' && shouldScanUrl(url) && isLikelyPromptBody(body)) {
      askScanner(body, url, method).then((decision) => {
        if (!decision) {
          originalSend.call(xhr, body);
          return;
        }
        if (decision.decision === 'cancel') {
          synthesizeBlockedResponse(xhr);
        } else if (decision.decision === 'redact' && typeof decision.redactedBody === 'string') {
          originalSend.call(xhr, decision.redactedBody);
        } else {
          originalSend.call(xhr, body);
        }
      });
      return; // request is deferred until the scan decision arrives
    }

    return originalSend.call(xhr, body);
  };

  /**
   * Best-effort "blocked" response for XHR: shadow the read-only status
   * properties with 499, abort the real request, and fire completion events
   * so callers don't hang forever. Anything that fails here still results in
   * the request being aborted — never sent.
   */
  function synthesizeBlockedResponse(xhr) {
    try {
      Object.defineProperty(xhr, 'status', { configurable: true, get: () => 499 });
      Object.defineProperty(xhr, 'statusText', { configurable: true, get: () => 'Blocked by PromptGuard' });
      Object.defineProperty(xhr, 'readyState', { configurable: true, get: () => 4 });
      Object.defineProperty(xhr, 'responseText', {
        configurable: true,
        get: () => '{"error":"Blocked by PromptGuard","status":499}'
      });
      Object.defineProperty(xhr, 'response', {
        configurable: true,
        get: () => '{"error":"Blocked by PromptGuard","status":499}'
      });
    } catch (err) {
      /* ignore */
    }
    try {
      xhr.abort();
    } catch (err) {
      /* ignore */
    }
    try {
      xhr.dispatchEvent(new Event('readystatechange'));
      xhr.dispatchEvent(new Event('load'));
      xhr.dispatchEvent(new Event('loadend'));
    } catch (err) {
      /* ignore */
    }
  }

  // ------------------------------------------------------------------
  // Chrome Built-in AI (Gemini Nano) — executed in the MAIN world
  // ------------------------------------------------------------------
  window.addEventListener(AI_REQUEST_EVENT, async (e) => {
    const d = (e && e.detail) || {};
    const respond = (detail) => {
      try {
        window.dispatchEvent(
          new CustomEvent(AI_RESPONSE_EVENT, {
            detail: Object.assign({ requestId: d.requestId }, detail)
          })
        );
      } catch (err) {
        /* ignore */
      }
    };
    try {
      const label = await classifyWithBuiltInAI(d.text || '', d.systemPrompt || '');
      if (label) respond({ ok: true, label });
      else respond({ ok: false, error: 'ai-unavailable' });
    } catch (err) {
      respond({ ok: false, error: String((err && err.message) || err) });
    }
  }, true);

  /**
   * Runs the classification with the strict system prompt and a 2.5s
   * Promise.race timeout. Returns the raw label ("SENSITIVE" |
   * "POSSIBLY_SENSITIVE" | "SAFE") or null when the AI is unavailable or
   * times out. Never throws to the caller.
   */
  async function classifyWithBuiltInAI(text, systemPrompt) {
    // Graceful availability check (brief, fix B).
    if (typeof window.ai === 'undefined' || !window.ai.languageModel) return null;
    let caps = null;
    try {
      caps = await window.ai.languageModel.capabilities();
    } catch (err) {
      caps = window.ai.languageModel.capabilities || null;
    }
    if (!caps || caps.available === 'no' || caps.available === undefined) return null;

    const session = await window.ai.languageModel.create({
      systemPrompt: systemPrompt || undefined
    });
    try {
      const prompt =
        'Classify this text. Reply ONLY with JSON: {"label": "SENSITIVE|POSSIBLE|SAFE", "reason": "short reason"}\n\nText:\n' +
        String(text).slice(0, 4000);
      const raw = await Promise.race([
        Promise.resolve(session.prompt(prompt)),
        new Promise((_, reject) => setTimeout(() => reject(new Error('ai-timeout')), AI_TIMEOUT_MS))
      ]);
      return parseLabel(raw);
    } finally {
      try {
        if (session.destroy) session.destroy();
      } catch (err) {
        /* ignore */
      }
    }
  }

  function parseLabel(raw) {
    if (!raw) return null;
    let s = String(raw).trim();
    const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fence) s = fence[1].trim();
    const brace = s.indexOf('{');
    const endBrace = s.lastIndexOf('}');
    if (brace !== -1 && endBrace > brace) {
      try {
        const parsed = JSON.parse(s.slice(brace, endBrace + 1));
        if (parsed && parsed.label) return String(parsed.label).toUpperCase();
      } catch (err) {
        /* fall through to regex extraction */
      }
    }
    const m = s.match(/"label"\s*:\s*"([^"]+)"/i);
    if (m) return m[1].toUpperCase();
    return null;
  }
})();
