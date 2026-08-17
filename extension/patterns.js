/**
 * patterns.js — PromptGuard
 *
 * Hardcoded secret / credential regex patterns. These are scanned on EVERY
 * intercepted request, regardless of which project fingerprints are loaded.
 *
 * Each entry:
 *   key        — machine id used as match_type in the audit log
 *   label      — human readable name shown in the warning modal
 *   severity   — critical | high | medium
 *   confidence — score contributed when this pattern matches
 *   regex      — global regex used to find every occurrence
 */
(function () {
  'use strict';

  const PG = (window.__PromptGuard = window.__PromptGuard || {});

  const SECRET_PATTERNS = [
    {
      key: 'aws_access_key',
      label: 'AWS Access Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bAKIA[0-9A-Z]{16}\b/g
    },
    {
      key: 'aws_secret_key',
      label: 'AWS Secret Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /aws.{0,20}secret.{0,20}['"][0-9a-zA-Z/+]{40}['"]/gi
    },
    {
      key: 'github_token',
      label: 'GitHub Personal Access Token',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bghp_[a-zA-Z0-9]{36}\b/g
    },
    {
      key: 'github_oauth',
      label: 'GitHub OAuth Token',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bgho_[a-zA-Z0-9]{36}\b/g
    },
    {
      key: 'gitlab_token',
      label: 'GitLab Personal Access Token',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bglpat-[a-zA-Z0-9\-]{20}\b/g
    },
    {
      key: 'stripe_secret_key',
      label: 'Stripe Secret Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bsk_live_[a-zA-Z0-9]{24,}\b/g
    },
    {
      key: 'stripe_publishable',
      label: 'Stripe Publishable Key',
      severity: 'high',
      confidence: 0.99,
      regex: /\bpk_live_[a-zA-Z0-9]{24,}\b/g
    },
    {
      key: 'twilio_sid',
      label: 'Twilio Account SID',
      severity: 'high',
      confidence: 0.99,
      regex: /\bAC[a-f0-9]{32}\b/g
    },
    {
      key: 'sendgrid_key',
      label: 'SendGrid API Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b/g
    },
    {
      key: 'brevo_smtp_key',
      label: 'Brevo SMTP Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bxsmtpsib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b/g
    },
    {
      key: 'db_connection_string',
      label: 'Database Connection String',
      severity: 'critical',
      confidence: 0.99,
      regex: /(?:mongodb|postgresql|postgres|mysql|redis|mssql|sqlserver):\/\/[^\s]{10,}/g
    },
    {
      key: 'private_key',
      label: 'Private Key (PEM/PGP/SSH)',
      severity: 'critical',
      confidence: 0.99,
      regex: /-----BEGIN (?:RSA |EC |PGP |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----/g
    },
    {
      key: 'jwt_token',
      label: 'JWT Token',
      severity: 'high',
      confidence: 0.99,
      regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\./g
    },
    {
      key: 'aadhaar_number',
      label: 'Aadhaar Number',
      severity: 'high',
      confidence: 0.99,
      regex: /\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b/g,
      // Real Aadhaar numbers end in a Verhoeff checksum digit; this kills
      // false positives from random 12-digit IDs in telemetry payloads.
      validate: (match) => verhoeffValid(String(match).replace(/\s/g, ''))
    },
    {
      key: 'pan_number',
      label: 'PAN Number',
      severity: 'medium',
      confidence: 0.99,
      regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g
    },
    {
      key: 'generic_password',
      label: 'Hardcoded Password',
      severity: 'high',
      confidence: 0.99,
      regex: /(?:password|passwd|pwd|secret|api_key|apikey|auth_token)\s*[=:]\s*['"][^'"]{8,}['"]/gi,
      // Skip low-entropy values like password="demo" that are clearly not
      // real credentials (same gate as the Python scanner).
      validate: (match) => {
        const vm = String(match).match(/[=:]\s*['"]([^'"]+)['"]/);
        const value = vm ? vm[1] : match;
        return shannonEntropy(value) >= 3.5;
      }
    },
    {
      key: 'internal_ip',
      label: 'Internal IP Address',
      severity: 'medium',
      confidence: 0.7,
      regex: /\b(10\.|172\.1[6-9]\.|192\.168\.)\d+\.\d+\b/g
    },
    // --- Additional high-precision patterns (production hardening) ---
    {
      key: 'anthropic_api_key',
      label: 'Anthropic API Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bsk-ant-[a-zA-Z0-9_-]{20,}\b/g
    },
    {
      key: 'openai_api_key',
      label: 'OpenAI API Key',
      severity: 'critical',
      confidence: 0.99,
      regex: /\bsk-(?:proj|svcacct)-[a-zA-Z0-9_-]{20,}\b/g
    },
    {
      key: 'slack_token',
      label: 'Slack Token',
      severity: 'high',
      confidence: 0.99,
      regex: /\bxox[baprs]-[a-zA-Z0-9-]{10,}\b/g
    },
    {
      key: 'google_api_key',
      label: 'Google API Key',
      severity: 'high',
      confidence: 0.99,
      regex: /\bAIza[0-9A-Za-z_-]{35}\b/g
    }
  ];

  /** Shannon entropy — used to reject low-entropy password-assignment hits. */
  function shannonEntropy(text) {
    if (!text) return 0;
    const counts = {};
    for (const ch of text) counts[ch] = (counts[ch] || 0) + 1;
    const len = text.length;
    let entropy = 0;
    for (const k of Object.keys(counts)) {
      const p = counts[k] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Find every occurrence of every secret pattern in `text`.
   * Returns an array of normalized match objects:
   *   { key, label, severity, confidence, matchedText, start, end, projectId, projectName }
   */
  function scanSecrets(text) {
    const found = [];
    for (const p of SECRET_PATTERNS) {
      p.regex.lastIndex = 0;
      let m;
      while ((m = p.regex.exec(text)) !== null) {
        // Skip matches that fail a pattern-level validator (e.g. the Verhoeff
        // checksum on Aadhaar numbers).
        if (p.validate && !p.validate(m[0])) {
          if (m[0].length === 0) p.regex.lastIndex += 1;
          continue;
        }
        found.push({
          key: p.key,
          label: p.label,
          severity: p.severity,
          confidence: p.confidence,
          matchedText: m[0],
          start: m.index,
          end: m.index + m[0].length,
          projectId: null,
          projectName: 'Global security patterns'
        });
        if (m[0].length === 0) {
          p.regex.lastIndex += 1;
        }
      }
    }
    return found;
  }

  // ------------------------------------------------------------------
  // Verhoeff checksum (used by India's Aadhaar numbers)
  // ------------------------------------------------------------------
  const VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
  ];
  const VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
  ];

  function verhoeffValid(numStr) {
    if (!/^[0-9]+$/.test(numStr)) return false;
    let c = 0;
    const n = numStr.length;
    for (let i = 0; i < n; i++) {
      const digit = numStr.charCodeAt(n - 1 - i) - 48;
      c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
    }
    return c === 0;
  }

  PG.SECRET_PATTERNS = SECRET_PATTERNS;
  PG.scanSecrets = scanSecrets;
})();
