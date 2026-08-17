/**
 * scanner-engine.js — PromptGuard
 *
 * Fingerprint matching + confidence scoring + Chrome Built-in AI (Gemini Nano).
 *
 * Scoring (per the project brief):
 *   exact package match            +0.95
 *   exact class name match         +0.85
 *   hardcoded secret pattern       +0.99 (per pattern; 0.70 for internal IPs)
 *   internal URL match             +0.75
 *   internal IP match              +0.70
 *   domain vocabulary term         +0.15 per term (max 0.45 total)
 *   final confidence capped at 0.99
 *
 * Built-in AI (Gemini Nano) is used only as a tie-breaker: it runs only when
 * the regex-only confidence is in [0.3, 0.6]. When it runs:
 *   Final_Confidence = (Regex_Score * 0.6) + (AI_Mapped_Score * 0.4)
 * with AI labels mapped SENSITIVE=0.75, POSSIBLY_SENSITIVE=0.55, SAFE=0.1.
 * If the AI is unavailable or does not answer within 2.5s, we silently fall
 * back to the regex score. The AI itself is executed in the MAIN world (where
 * window.ai actually exists) through the promptguard:ai-request/ai-response
 * CustomEvent bridge — see page-interceptor.js.
 */
(function () {
  'use strict';

  const PG = window.__PromptGuard || {};

  // ------------------------------------------------------------------
  // Constants (match the brief exactly)
  // ------------------------------------------------------------------
  const AI_SYSTEM_PROMPT =
    'You are a code-security classifier. Analyze if the input contains specific hardcoded internal domain names (e.g., `com.clientname`), explicit credentials, internal IPs, or unique internal project codenames. Ignore generic programming syntax (loops, imports, standard libraries). If it contains explicit unique identifiers for a specific company, output SENSITIVE. If it contains financial/banking jargon but no explicit names, output POSSIBLY_SENSITIVE. If it is generic public code or natural language, output SAFE. Reply ONLY in JSON format: {"label": "SENSITIVE|POSSIBLE|SAFE", "reason": "short reason"}.';

  const AI_LABEL_SCORES = {
    SENSITIVE: 0.75,
    POSSIBLY_SENSITIVE: 0.55,
    // the system prompt occasionally prints "POSSIBLE" — accept both spellings
    POSSIBLE: 0.55,
    SAFE: 0.1
  };

  const AI_TIMEOUT_MS = 2500;          // 2.5s hard cap on session.prompt()
  const AI_FUZZY_MIN = 0.3;            // run AI only when regex score is in…
  const AI_FUZZY_MAX = 0.6;            // …this fuzzy zone; > 0.6 skip AI entirely
  const MAX_CONFIDENCE = 0.99;
  const MAX_VOCAB_SCORE = 0.45;
  const VOCAB_PER_TERM = 0.15;
  const SCAN_CACHE_TTL_MS = 2000;
  const SCAN_CACHE_MAX = 200;

  const SCORE_BY_TYPE = {
    package_name: 0.95,
    class_name: 0.85,
    internal_url: 0.75,
    internal_ip: 0.7,
    domain_vocabulary: 0.15
  };

  // ------------------------------------------------------------------
  // State
  // ------------------------------------------------------------------
  let cachedProjects = null;
  const scanCache = new Map(); // text -> { ts, result }

  // ------------------------------------------------------------------
  // Project loading (multi-project from chrome.storage.local)
  // ------------------------------------------------------------------
  async function loadProjects(force) {
    if (cachedProjects && !force) return cachedProjects;
    try {
      const state = await chrome.storage.local.get('projects');
      const stored = Array.isArray(state.projects) ? state.projects : [];
      const projects = stored
        .filter((p) => p && p.fingerprint)
        .map((p) => ({
          id: p.id || 'project-' + (p.name || 'unknown'),
          name: p.name || 'Unnamed project',
          fingerprint: normalizeFingerprint(p.fingerprint),
          policy: p.policy || {}
        }));

      // Development fallback: if no projects are configured in storage yet,
      // use the bundled fingerprint.json so the extension is testable
      // out of the box.
      if (projects.length === 0) {
        const dev = await loadDevFingerprint();
        if (dev) projects.push(dev);
      }
      cachedProjects = projects;
    } catch (err) {
      console.warn('[PromptGuard] failed to load projects', err);
      cachedProjects = cachedProjects || [];
    }
    return cachedProjects;
  }

  async function loadDevFingerprint() {
    try {
      const res = await fetch(chrome.runtime.getURL('fingerprint.json'));
      if (!res.ok) return null;
      const raw = await res.json();
      return {
        id: 'dev-fingerprint',
        name: 'Dev Fingerprint (fakebank)',
        fingerprint: normalizeFingerprint(raw),
        policy: {}
      };
    } catch (err) {
      return null;
    }
  }

  function normalizeFingerprint(raw) {
    if (!raw || typeof raw !== 'object') {
      return {
        packages: [],
        class_names: [],
        domain_vocabulary: [],
        internal_urls: [],
        internal_ips: [],
        secrets_found: []
      };
    }
    return {
      packages: Array.isArray(raw.packages) ? raw.packages : [],
      class_names: Array.isArray(raw.class_names) ? raw.class_names : [],
      domain_vocabulary: Array.isArray(raw.domain_vocabulary) ? raw.domain_vocabulary : [],
      internal_urls: Array.isArray(raw.internal_urls) ? raw.internal_urls : [],
      internal_ips: Array.isArray(raw.internal_ips) ? raw.internal_ips : [],
      secrets_found: Array.isArray(raw.secrets_found) ? raw.secrets_found : []
    };
  }

  // ------------------------------------------------------------------
  // Per-project fingerprint scanning
  // ------------------------------------------------------------------
  function scanProjectFingerprint(text, fingerprint, project) {
    const matches = [];
    let score = 0;

    for (const pkg of fingerprint.packages) {
      if (pkg && text.includes(pkg)) {
        score += SCORE_BY_TYPE.package_name;
        matches.push(
          makeMatch('package_name', 'Client package name', 'high', pkg, SCORE_BY_TYPE.package_name, project)
        );
      }
    }

    for (const cn of fingerprint.class_names) {
      if (cn && text.includes(cn)) {
        score += SCORE_BY_TYPE.class_name;
        matches.push(
          makeMatch('class_name', 'Client class name', 'high', cn, SCORE_BY_TYPE.class_name, project)
        );
      }
    }

    for (const u of fingerprint.internal_urls) {
      if (u && text.includes(u)) {
        score += SCORE_BY_TYPE.internal_url;
        matches.push(
          makeMatch('internal_url', 'Internal URL', 'high', u, SCORE_BY_TYPE.internal_url, project)
        );
      }
    }

    for (const ip of fingerprint.internal_ips) {
      if (ip && text.includes(ip)) {
        score += SCORE_BY_TYPE.internal_ip;
        matches.push(
          makeMatch('internal_ip', 'Internal IP', 'medium', ip, SCORE_BY_TYPE.internal_ip, project)
        );
      }
    }

    // Domain vocabulary: case-insensitive, word-boundary, +0.15 per term
    // capped at +0.45 total.
    let vocabScore = 0;
    const vocabMatched = [];
    for (const term of fingerprint.domain_vocabulary) {
      if (!term) continue;
      const re = new RegExp('\\b' + escapeRegExp(term) + '\\b', 'gi');
      re.lastIndex = 0;
      if (re.test(text)) {
        vocabMatched.push(term);
        vocabScore += VOCAB_PER_TERM;
      }
    }
    if (vocabMatched.length > 0) {
      const vocabTotal = Math.min(MAX_VOCAB_SCORE, vocabScore);
      score += vocabTotal;
      matches.push(
        makeMatch(
          'domain_vocabulary',
          'Domain vocabulary terms',
          'low',
          vocabMatched.slice(0, 8).join(', ').slice(0, 60),
          vocabTotal,
          project
        )
      );
    }

    return {
      project,
      score: Math.min(MAX_CONFIDENCE, score),
      matches
    };
  }

  function makeMatch(key, label, severity, matchedText, confidence, project) {
    return {
      key,
      label,
      severity,
      matchedText,
      confidence,
      projectId: project ? project.id : null,
      projectName: project ? project.name : null
    };
  }

  // ------------------------------------------------------------------
  // Main scan entry point
  // ------------------------------------------------------------------
  async function scanContent(text) {
    if (!text || typeof text !== 'string' || text.trim().length < 5) {
      return buildResult(0, 0, [], null, [], false, null, 0, false);
    }

    const cacheHit = scanCache.get(text);
    if (cacheHit && Date.now() - cacheHit.ts < SCAN_CACHE_TTL_MS) {
      return cacheHit.result;
    }

    const projects = await loadProjects();

    // 1) Global hardcoded secrets — scanned regardless of fingerprints.
    const secretMatches = PG.scanSecrets ? PG.scanSecrets(text) : [];

    // 2) Scan the text against EVERY loaded project fingerprint at once.
    const projectResults = [];
    for (const project of projects) {
      projectResults.push(scanProjectFingerprint(text, project.fingerprint, project));
    }

    const projectScore = projectResults.reduce((max, pr) => Math.max(max, pr.score), 0);
    let secretScore = 0;
    for (const m of secretMatches) secretScore += m.confidence;
    const regexScore = Math.min(MAX_CONFIDENCE, projectScore + secretScore);

    // 3) Built-in AI (Gemini Nano) — only in the fuzzy zone [0.3, 0.6].
    //    regex > 0.6  -> skip AI entirely to save CPU.
    //    regex < 0.3  -> clearly safe, skip AI.
    let aiUsed = false;
    let aiLabel = null;
    let aiScore = 0;
    let finalConfidence = regexScore;

    if (regexScore >= AI_FUZZY_MIN && regexScore <= AI_FUZZY_MAX) {
      const ai = await runAIClassifier(text);
      if (ai && ai.available) {
        aiUsed = true;
        aiLabel = ai.label;
        aiScore = ai.score;
        finalConfidence = regexScore * 0.6 + aiScore * 0.4;
      }
      // AI unavailable / timed out -> silently fall back to regex score.
    }

    finalConfidence = Math.min(MAX_CONFIDENCE, finalConfidence);

    // 4) Collect + dedupe all matches across projects and global patterns.
    const allMatches = [];
    const seen = new Set();
    for (const pr of projectResults) {
      for (const m of pr.matches) {
        const id = m.key + '|' + m.matchedText;
        if (!seen.has(id)) {
          seen.add(id);
          allMatches.push(m);
        }
      }
    }
    for (const m of secretMatches) {
      const id = m.key + '|' + m.matchedText;
      if (!seen.has(id)) {
        seen.add(id);
        allMatches.push(m);
      }
    }
    allMatches.sort((a, b) => b.confidence - a.confidence);

    // The top project = the project whose fingerprint contributed the most.
    let topProject = null;
    let topScore = 0;
    for (const pr of projectResults) {
      if (pr.score > topScore) {
        topScore = pr.score;
        topProject = pr.project;
      }
    }
    const matchedProjects = projectResults.filter((pr) => pr.score > 0).map((pr) => pr.project);

    const result = buildResult(
      finalConfidence,
      regexScore,
      allMatches,
      topProject,
      matchedProjects,
      aiUsed,
      aiLabel,
      aiScore,
      secretMatches.length > 0
    );

    scanCache.set(text, { ts: Date.now(), result });
    if (scanCache.size > SCAN_CACHE_MAX) scanCache.clear();
    return result;
  }

  function buildResult(confidence, regexScore, matches, topProject, matchedProjects, aiUsed, aiLabel, aiScore, hasSecret) {
    return {
      confidence: round2(confidence),
      regexScore: round2(regexScore),
      aiUsed: !!aiUsed,
      aiLabel: aiLabel || null,
      aiScore: aiScore || 0,
      level: levelFor(confidence),
      matches: matches || [],
      topProject: topProject || null,
      matchedProjects: matchedProjects || [],
      hasSecret: !!hasSecret
    };
  }

  /**
   * Thresholds (brief, section C):
   *   < 0.50            silent (log only)
   *   0.50 – 0.70       soft warning (subtle, easy dismiss)
   *   0.70 – 0.90       modal warning (requires user action)
   *   > 0.90            critical modal (red, 3s lockout + checkbox)
   */
  function levelFor(confidence) {
    if (confidence < 0.5) return 'silent';
    if (confidence < 0.7) return 'soft';
    if (confidence <= 0.9) return 'modal';
    return 'critical';
  }

  // ------------------------------------------------------------------
  // Redaction (used when the user chooses "Redact Sensitive Parts")
  // ------------------------------------------------------------------
  function redactText(text, result) {
    let out = text;

    // Fingerprint string matches first (longest first to avoid partial overlap).
    const fpMatches = (result.matches || []).filter(
      (m) => m.projectId && m.key !== 'domain_vocabulary'
    );
    fpMatches.sort((a, b) => b.matchedText.length - a.matchedText.length);
    for (const m of fpMatches) {
      if (!m.matchedText) continue;
      out = out.split(m.matchedText).join('[REDACTED:' + m.key + ']');
    }

    // Hardcoded secret patterns (regex based — replaces every occurrence).
    for (const p of PG.SECRET_PATTERNS || []) {
      out = out.replace(p.regex, '[REDACTED:' + p.key + ']');
    }

    return out;
  }

  // ------------------------------------------------------------------
  // Chrome Built-in AI (Gemini Nano) — bridged to the MAIN world
  // ------------------------------------------------------------------
  function runAIClassifier(text) {
    return new Promise((resolve) => {
      let settled = false;
      const finish = (value) => {
        if (!settled) {
          settled = true;
          resolve(value);
        }
      };

      const requestId = 'pgai_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 10);

      // Belt-and-suspenders timeout: the MAIN world enforces 2.5s on
      // session.prompt(); this gives it a little extra room to report back.
      const timer = setTimeout(() => {
        window.removeEventListener('promptguard:ai-response', onResponse);
        finish({ available: false });
      }, AI_TIMEOUT_MS + 1000);

      const onResponse = (e) => {
        const d = (e && e.detail) || {};
        if (d.requestId !== requestId) return;
        window.removeEventListener('promptguard:ai-response', onResponse);
        clearTimeout(timer);
        if (d.ok && d.label) {
          const score = AI_LABEL_SCORES[d.label];
          if (typeof score === 'number') {
            finish({ available: true, label: d.label, score });
          } else {
            finish({ available: true, label: d.label, score: 0 });
          }
        } else {
          finish({ available: false });
        }
      };

      window.addEventListener('promptguard:ai-response', onResponse);
      try {
        window.dispatchEvent(
          new CustomEvent('promptguard:ai-request', {
            detail: { requestId, text: text.slice(0, 4000), systemPrompt: AI_SYSTEM_PROMPT }
          })
        );
      } catch (err) {
        clearTimeout(timer);
        window.removeEventListener('promptguard:ai-response', onResponse);
        finish({ available: false });
      }
    });
  }

  // ------------------------------------------------------------------
  // Helpers
  // ------------------------------------------------------------------
  function round2(n) {
    return Math.round(n * 100) / 100;
  }

  function escapeRegExp(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  PG.loadProjects = loadProjects;
  PG.scanContent = scanContent;
  PG.redactText = redactText;
  PG.getProjects = () => (cachedProjects ? cachedProjects.slice() : []);
})();
