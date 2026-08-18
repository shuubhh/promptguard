/**
 * ai-engine.js — PromptGuard
 *
 * Thin, defensive wrapper around the modern Prompt API for Chrome Extensions
 * (the global `LanguageModel` object — stable in extensions since Chrome 138).
 *
 * WHY THIS FILE EXISTS (important — the API changed):
 *   - The old `window.ai.languageModel` API is deprecated. The current surface
 *     is a GLOBAL `LanguageModel`: LanguageModel.availability(),
 *     LanguageModel.create(), LanguageModel.params().
 *   - The Prompt API is NOT available in Web Workers, and NOT available on
 *     arbitrary web pages (content scripts). It only exists in document
 *     contexts that are extension pages — which is why inference runs in an
 *     OFFSCREEN DOCUMENT (offscreen.html), and the popup hosts the initial
 *     model download (which requires a user gesture).
 *   - Per the official docs, availability() MUST be passed the same
 *     expectedInputs/expectedOutputs as create() — "this is critical".
 *
 * This file is loaded by three contexts and must stay world-agnostic:
 *   - offscreen.html  — real inference (chrome.runtime messaging)
 *   - popup.html      — availability check + user-gesture model download
 *   - Node tests      — a fake LanguageModel is injected
 *
 * Graceful degradation contract: every function returns a safe value or
 * { ok: false } on ANY failure. Nothing here ever throws to the caller.
 */
(function () {
  'use strict';

  const PG = (window.__PromptGuard = window.__PromptGuard || {});

  // ------------------------------------------------------------------
  // Model access
  // ------------------------------------------------------------------
  let injectedLM = null;

  function getLanguageModel() {
    if (injectedLM) return injectedLM;
    if (typeof LanguageModel !== 'undefined' && LanguageModel) return LanguageModel;
    return null;
  }

  /** Test hook: inject a fake LanguageModel (never used in production). */
  function setLanguageModelForTest(lm) {
    injectedLM = lm;
  }

  // ------------------------------------------------------------------
  // Constants
  // ------------------------------------------------------------------
  const AI_TIMEOUT_MS = 3000; // hard cap on a single session.prompt()
  // The same modalities/languages must be passed to availability(), create()
  // and (indirectly) prompt() — the docs call this critical.
  const EXPECTED_INPUTS = [{ type: 'text', languages: ['en'] }];
  const EXPECTED_OUTPUTS = [{ type: 'text', languages: ['en'] }];

  const CLASSIFY_SYSTEM_PROMPT =
    'You are a data-security classifier for a DLP tool. Analyze the user text below. ' +
    'It is a prompt a developer is about to send to an AI chatbot. ' +
    'Decide if it contains sensitive information that should not leave the company: ' +
    'proprietary business logic, client-specific identifiers (package names, class names, ' +
    'internal hostnames, customer/account IDs), credentials, internal IPs, ' +
    'or pasted logs/stack traces from production systems with internal detail. ' +
    'Generic programming questions, public open-source code, and natural language are SAFE. ' +
    'Reply ONLY with a JSON object matching the schema.';

  const CLASSIFY_SCHEMA = {
    type: 'object',
    properties: {
      label: { type: 'string', enum: ['SENSITIVE', 'POSSIBLY_SENSITIVE', 'SAFE'] },
      reason: { type: 'string' }
    },
    required: ['label', 'reason'],
    additionalProperties: false
  };

  const AI_LABEL_SCORES = {
    SENSITIVE: 0.75,
    POSSIBLY_SENSITIVE: 0.55,
    POSSIBLE: 0.55, // tolerate the model printing the short spelling
    SAFE: 0.1
  };

  // LRU cache of classification verdicts. Repeated identical prompts
  // (auto-retries, fetch+XHR double-fire) must never re-run the model.
  const CACHE_MAX = 100;
  const CACHE_TTL_MS = 60000;
  const verdictCache = new Map(); // textHash -> { ts, value }

  // ------------------------------------------------------------------
  // Availability
  // ------------------------------------------------------------------
  /**
   * Returns 'available' | 'downloading' | 'unavailable'.
   * Mirrors LanguageModel.availability() with the SAME options used in
   * create() (per the docs, mixing options is unsupported).
   */
  async function checkAvailability() {
    const LM = getLanguageModel();
    if (!LM || typeof LM.availability !== 'function') return 'unavailable';
    try {
      const status = await LM.availability({
        expectedInputs: EXPECTED_INPUTS,
        expectedOutputs: EXPECTED_OUTPUTS
      });
      return status === 'unavailable' ? 'unavailable' : status;
    } catch (err) {
      return 'unavailable';
    }
  }

  // ------------------------------------------------------------------
  // Session creation
  // ------------------------------------------------------------------
  /**
   * Creates a session with the shared expectedInputs/expectedOutputs.
   * opts:
   *   monitor   — download-progress callback for the first (user-gesture)
   *               create in the popup: monitor(m) { m.addEventListener(
   *               'downloadprogress', e => ...) }
   *   temperature / topK — extensions-only; must be set together or not at all
   *   signal    — AbortSignal to destroy the session
   * Returns the session or null (never throws).
   */
  async function createSession(opts) {
    const LM = getLanguageModel();
    if (!LM || typeof LM.create !== 'function') return null;
    const options = {
      expectedInputs: EXPECTED_INPUTS,
      expectedOutputs: EXPECTED_OUTPUTS
    };
    if (opts && (opts.temperature !== undefined || opts.topK !== undefined)) {
      let params = null;
      try {
        if (typeof LM.params === 'function') params = await LM.params();
      } catch (err) {
        /* defaults below */
      }
      options.temperature =
        opts.temperature !== undefined
          ? opts.temperature
          : params && typeof params.defaultTemperature === 'number'
            ? params.defaultTemperature
            : 1;
      options.topK =
        opts.topK !== undefined
          ? opts.topK
          : params && typeof params.defaultTopK === 'number'
            ? params.defaultTopK
            : 3;
    }
    if (opts && typeof opts.monitor === 'function') options.monitor = opts.monitor;
    if (opts && opts.signal) options.signal = opts.signal;
    try {
      return await LM.create(options);
    } catch (err) {
      return null;
    }
  }

  // ------------------------------------------------------------------
  // Classification
  // ------------------------------------------------------------------
  /**
   * Classify `text` as SENSITIVE / POSSIBLY_SENSITIVE / SAFE using JSON-Schema
   * structured output (responseConstraint). Returns:
   *   { ok: true, label, reason, score, raw }
   *   { ok: false, error }
   * Never throws. `score` maps the label to the brief's confidence scale.
   */
  async function classify(text, opts) {
    const input = String(text || '').slice(0, 4000);
    const key = hashKey(input);
    const hit = verdictCache.get(key);
    if (hit && Date.now() - hit.ts < CACHE_TTL_MS) return hit.value;

    // Deterministic sampling for reproducible verdicts (the audit trail needs
    // the same text to produce the same label). temperature/topK are an
    // extensions-only feature; createSession keeps them paired as required.
    const session = await createSession(Object.assign({ temperature: 0, topK: 1 }, opts || {}));
    if (!session) return { ok: false, error: 'ai-unavailable' };

    try {
      const controller = new AbortController();
      const timeoutMs = (opts && opts.timeoutMs) || AI_TIMEOUT_MS;
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      let raw = null;
      try {
        raw = await session.prompt(
          CLASSIFY_SYSTEM_PROMPT +
            '\n\nUser text to classify:\n' +
            input +
            '\n\nRespond with the JSON object only.',
          { signal: controller.signal, responseConstraint: CLASSIFY_SCHEMA }
        );
      } catch (err) {
        const name = (err && err.name) || '';
        return {
          ok: false,
          error: name === 'AbortError' ? 'ai-timeout' : String((err && err.message) || err || 'ai-prompt-failed')
        };
      } finally {
        clearTimeout(timer);
      }

      const verdict = parseVerdict(raw);
      if (!verdict) return { ok: false, error: 'ai-bad-response' };

      const score =
        typeof AI_LABEL_SCORES[verdict.label] === 'number' ? AI_LABEL_SCORES[verdict.label] : 0;
      const value = {
        ok: true,
        label: verdict.label,
        reason: String(verdict.reason || '').slice(0, 200),
        score: score,
        raw: String(raw || '').slice(0, 500)
      };
      verdictCache.set(key, { ts: Date.now(), value });
      if (verdictCache.size > CACHE_MAX) verdictCache.clear();
      return value;
    } finally {
      try {
        if (session.destroy) session.destroy();
      } catch (err) {
        /* ignore */
      }
    }
  }

  /**
   * Parse the model's JSON response. With responseConstraint the model should
   * return valid JSON, but we defensively strip fences and extract the label
   * by regex when JSON.parse fails (models are not always perfect).
   */
  function parseVerdict(raw) {
    if (!raw) return null;
    let s = String(raw).trim();
    const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if (fence) s = fence[1].trim();
    const brace = s.indexOf('{');
    const endBrace = s.lastIndexOf('}');
    if (brace !== -1 && endBrace > brace) {
      try {
        const parsed = JSON.parse(s.slice(brace, endBrace + 1));
        if (parsed && parsed.label) {
          return { label: String(parsed.label).toUpperCase(), reason: parsed.reason || '' };
        }
      } catch (err) {
        /* fall through to regex extraction */
      }
    }
    const labelMatch = s.match(/"label"\s*:\s*"([^"]+)"/i);
    if (labelMatch) return { label: labelMatch[1].toUpperCase(), reason: '' };
    const bare = s.match(/\b(SENSITIVE|POSSIBLY_SENSITIVE|POSSIBLE|SAFE)\b/i);
    if (bare) return { label: bare[1].toUpperCase(), reason: '' };
    return null;
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  /** djb2 hash — a compact, deterministic key for the verdict cache. */
  function hashKey(text) {
    let h = 5381;
    for (let i = 0; i < text.length; i++) {
      h = ((h << 5) + h + text.charCodeAt(i)) | 0;
    }
    return 't' + (h >>> 0).toString(36);
  }

  PG.ai = {
    checkAvailability: checkAvailability,
    createSession: createSession,
    classify: classify,
    getLanguageModel: getLanguageModel,
    LABEL_SCORES: AI_LABEL_SCORES,
    SYSTEM_PROMPT: CLASSIFY_SYSTEM_PROMPT,
    SCHEMA: CLASSIFY_SCHEMA,
    EXPECTED_INPUTS: EXPECTED_INPUTS,
    EXPECTED_OUTPUTS: EXPECTED_OUTPUTS
  };
  PG.__aiSetLanguageModelForTest = setLanguageModelForTest;
})();
