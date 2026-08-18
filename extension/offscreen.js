/**
 * offscreen.js — PromptGuard (offscreen document)
 *
 * Receives inference requests from the background service worker (which in
 * turn receives them from content scripts — content cannot host the Prompt
 * API, and only chrome.runtime is available here).
 *
 * Handled messages:
 *   PG_AI_INFER          { text }            -> classification verdict
 *   PG_AI_AVAILABILITY   {}                  -> 'available' | 'downloading' | 'unavailable'
 *
 * Every response is { ok: false, error } on failure — inference must never
 * break the page that requested a scan.
 */
'use strict';

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== 'string') return false;

  if (msg.type === 'PG_AI_INFER') {
    PG.ai
      .classify(String(msg.text || ''), {})
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: String((err && err.message) || err) }));
    return true; // async response
  }

  if (msg.type === 'PG_AI_AVAILABILITY') {
    PG.ai
      .checkAvailability()
      .then((availability) => sendResponse({ availability: availability }))
      .catch(() => sendResponse({ availability: 'unavailable' }));
    return true;
  }

  return false;
});
