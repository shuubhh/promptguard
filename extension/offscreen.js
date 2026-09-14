/**
 * offscreen.js — PromptGuard (offscreen document)
 *
 * Receives inference requests from the background service worker (which in
 * turn receives them from content scripts — content cannot host the Prompt
 * API, and only chrome.runtime is available here).
 *
 * Handled messages:
 *   PG_AI_INFER          { text, context? }  -> classification verdict
 *   PG_AI_AVAILABILITY   {}                  -> 'available' | 'downloading' | 'unavailable'
 *
 * Every response is { ok: false, error } on failure — inference must never
 * break the page that requested a scan.
 *
 * NOTE ON THE PG BINDING (this exact reference crashed once): ai-engine.js
 * attaches to `window.__PromptGuard` INSIDE an IIFE and never declares a
 * global `PG`. Every context that uses the bare name must bind it itself
 * (same pattern as content.js / popup.js). The 2026-09 v0.1.4 regression —
 * every PG_AI_INFER dying with "ReferenceError: PG is not defined", which
 * made Gemini Nano silently never run — is guarded against below.
 */
'use strict';

const PG = (window.__PromptGuard = window.__PromptGuard || {});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== 'string') return false;

  if (msg.type === 'PG_AI_INFER') {
    if (!PG.ai || typeof PG.ai.classify !== 'function') {
      // ai-engine.js failed to load or loaded after us — never leave the
      // caller hanging: respond with the standard failure shape.
      sendResponse({ ok: false, error: 'ai-engine-not-loaded' });
      return false;
    }
    PG.ai
      .classify(String(msg.text || ''), { context: msg.context })
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: String((err && err.message) || err) }));
    return true; // async response
  }

  if (msg.type === 'PG_AI_AVAILABILITY') {
    if (!PG.ai || typeof PG.ai.checkAvailability !== 'function') {
      sendResponse({ availability: 'unavailable' });
      return false;
    }
    PG.ai
      .checkAvailability()
      .then((availability) => sendResponse({ availability: availability }))
      .catch(() => sendResponse({ availability: 'unavailable' }));
    return true;
  }

  return false;
});
