/**
 * warning-modal.js — PromptGuard
 *
 * Warning UI:
 *   - showSoftWarning(result)  — subtle, easy-dismiss banner (0.50–0.70)
 *   - showWarningModal(result) — blocking modal (0.70–0.90) and critical
 *                                red-tinted modal (>0.90) with a 3-second
 *                                "Send Anyway" lockout + confirmation checkbox.
 *
 * showWarningModal resolves to one of:
 *   'cancel' — the request is blocked (fetch returns 499 / XHR is aborted)
 *   'redact' — the caller replaces the body with the redacted version
 *   'send'   — allow the request through (logged as an override)
 */
(function () {
  'use strict';

  const PG = window.__PromptGuard || {};

  let softBannerEl = null;

  // ------------------------------------------------------------------
  // Soft warning (0.50 – 0.70): subtle banner, request still goes through.
  // ------------------------------------------------------------------
  function showSoftWarning(result) {
    if (softBannerEl && document.documentElement.contains(softBannerEl)) return;

    const banner = document.createElement('div');
    banner.className = 'pg-soft-banner';

    const icon = document.createElement('span');
    icon.className = 'pg-soft-icon';
    icon.textContent = '🛡️';

    const msg = document.createElement('span');
    msg.className = 'pg-soft-msg';
    const projectName =
      result.topProject && result.topProject.name ? ' (' + result.topProject.name + ')' : '';
    msg.textContent =
      'Possible sensitive content detected — ' +
      Math.round(result.confidence * 100) +
      '% confidence' +
      projectName +
      '. Sending anyway.';

    const dismiss = document.createElement('button');
    dismiss.className = 'pg-soft-dismiss';
    dismiss.type = 'button';
    dismiss.textContent = 'Dismiss';
    dismiss.addEventListener('click', () => {
      if (banner.parentNode) banner.parentNode.removeChild(banner);
    });

    banner.appendChild(icon);
    banner.appendChild(msg);
    banner.appendChild(dismiss);
    document.documentElement.appendChild(banner);
    softBannerEl = banner;

    // Auto-dismiss after 12s — it is intentionally non-intrusive.
    setTimeout(() => {
      if (banner.parentNode) banner.parentNode.removeChild(banner);
    }, 12000);
  }

  // ------------------------------------------------------------------
  // Modal warning (>= 0.70) — resolves to 'cancel' | 'redact' | 'send'
  // ------------------------------------------------------------------
  function showWarningModal(result) {
    return new Promise((resolve) => {
      const critical = result.level === 'critical';
      const topMatch = result.matches && result.matches.length ? result.matches[0] : null;

      // Remove any pre-existing overlay first (defensive).
      const existing = document.querySelector('.pg-overlay');
      if (existing && existing.parentNode) existing.parentNode.removeChild(existing);

      const overlay = document.createElement('div');
      overlay.className = 'pg-overlay' + (critical ? ' pg-critical' : '');

      const card = document.createElement('div');
      card.className = 'pg-modal';

      const shield = document.createElement('div');
      shield.className = 'pg-shield';
      shield.textContent = '🛡️';

      const title = document.createElement('h2');
      title.className = 'pg-title';
      title.textContent = 'Sensitive Content Detected';

      const subtitle = document.createElement('p');
      subtitle.className = 'pg-subtitle';
      subtitle.textContent = subtitleText(result, topMatch);

      const projectLine = document.createElement('p');
      projectLine.className = 'pg-project-line';
      projectLine.textContent = projectLineText(result);

      const severity = document.createElement('span');
      severity.className =
        'pg-severity pg-severity-' + (critical ? 'critical' : severityClass(topMatch ? topMatch.severity : 'high'));
      severity.textContent = critical ? 'CRITICAL' : topMatch ? String(topMatch.severity).toUpperCase() : 'HIGH';

      const previewBox = document.createElement('div');
      previewBox.className = 'pg-preview';
      const previewLabel = document.createElement('div');
      previewLabel.className = 'pg-preview-label';
      previewLabel.textContent = 'Matched text (truncated to 60 chars):';
      const previewCode = document.createElement('code');
      previewCode.className = 'pg-preview-code';
      previewCode.textContent = truncate((topMatch && topMatch.matchedText) || '', 60);
      previewBox.appendChild(previewLabel);
      previewBox.appendChild(previewCode);

      const aiNote = document.createElement('div');
      aiNote.className = 'pg-ai-note';
      if (result.aiUsed && result.aiLabel) {
        aiNote.textContent =
          'AI cross-check (' + result.aiLabel + ') — final confidence ' +
          Math.round(result.confidence * 100) + '%';
      } else {
        aiNote.textContent = 'Final confidence ' + Math.round(result.confidence * 100) + '%';
      }

      card.appendChild(shield);
      card.appendChild(title);
      card.appendChild(subtitle);
      card.appendChild(projectLine);
      card.appendChild(severity);
      card.appendChild(previewBox);
      card.appendChild(aiNote);

      // --- Critical-only confirmation checkbox ---
      let checkbox = null;
      if (critical) {
        const row = document.createElement('label');
        row.className = 'pg-checkbox-row';
        checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.className = 'pg-checkbox';
        const span = document.createElement('span');
        span.textContent = 'I confirm this is not sensitive client data';
        row.appendChild(checkbox);
        row.appendChild(span);
        card.appendChild(row);
      }

      // --- Actions ---
      const actions = document.createElement('div');
      actions.className = 'pg-actions';

      const cancelBtn = document.createElement('button');
      cancelBtn.type = 'button';
      cancelBtn.className = 'pg-btn pg-btn-red';
      cancelBtn.textContent = 'Cancel & Edit';
      cancelBtn.addEventListener('click', () => {
        cleanup();
        resolve('cancel');
      });

      const redactBtn = document.createElement('button');
      redactBtn.type = 'button';
      redactBtn.className = 'pg-btn pg-btn-ghost';
      redactBtn.textContent = 'Redact Sensitive Parts';
      redactBtn.addEventListener('click', () => {
        cleanup();
        resolve('redact');
      });

      const sendBtn = document.createElement('button');
      sendBtn.type = 'button';
      sendBtn.className = 'pg-btn pg-btn-grey';
      sendBtn.textContent = 'Send Anyway';
      sendBtn.addEventListener('click', () => {
        cleanup();
        resolve('send');
      });

      actions.appendChild(cancelBtn);
      actions.appendChild(redactBtn);
      actions.appendChild(sendBtn);
      card.appendChild(actions);
      overlay.appendChild(card);
      document.documentElement.appendChild(overlay);

      // --- Critical lockout: "Send Anyway" disabled for 3 seconds ---
      let tick = null;
      if (critical) {
        sendBtn.disabled = true;
        sendBtn.textContent = 'Send Anyway (3s)';
        if (checkbox) checkbox.disabled = true;
        let remaining = 3;
        tick = setInterval(() => {
          remaining -= 1;
          if (remaining <= 0) {
            clearInterval(tick);
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send Anyway';
            if (checkbox) checkbox.disabled = false;
          } else {
            sendBtn.textContent = 'Send Anyway (' + remaining + 's)';
          }
        }, 1000);
      }

      if (checkbox) {
        checkbox.addEventListener('change', () => {
          sendBtn.disabled = !checkbox.checked;
        });
      }

      // Non-critical: clicking the backdrop = cancel. Critical requires an
      // explicit button choice.
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay && !critical) {
          cleanup();
          resolve('cancel');
        }
      });

      // Escape cancels (non-critical only).
      const onKey = (e) => {
        if (e.key === 'Escape' && !critical) {
          e.preventDefault();
          cleanup();
          resolve('cancel');
        }
      };
      document.addEventListener('keydown', onKey, true);

      function cleanup() {
        clearInterval(tick);
        document.removeEventListener('keydown', onKey, true);
        if (overlay.parentNode) overlay.parentNode.removeChild(overlay);
      }

      try {
        cancelBtn.focus();
      } catch (err) {
        /* ignore */
      }
    });
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  function subtitleText(result, topMatch) {
    if (topMatch) {
      if (topMatch.projectName === 'Global security patterns' || !topMatch.projectId) {
        return topMatch.label + ' found in your prompt';
      }
      return topMatch.label + ' detected in your prompt';
    }
    return 'Sensitive content detected in your prompt';
  }

  function projectLineText(result) {
    const names = (result.matchedProjects || [])
      .map((p) => p.name)
      .filter(Boolean);
    if (result.hasSecret && names.length === 0) {
      return 'Matched by global security patterns (all projects)';
    }
    if (names.length === 1) {
      return 'Matched in project: ' + names[0];
    }
    if (names.length > 1) {
      return 'Matched in projects: ' + names.join(', ');
    }
    if (result.hasSecret) {
      return 'Matched by global security patterns (all projects)';
    }
    return '';
  }

  function severityClass(sev) {
    if (sev === 'critical') return 'critical';
    if (sev === 'medium') return 'medium';
    return 'high';
  }

  function truncate(s, max) {
    const str = String(s == null ? '' : s);
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  PG.showSoftWarning = showSoftWarning;
  PG.showWarningModal = showWarningModal;
})();
