/**
 * repoScanner.js — PromptGuard dashboard
 *
 * Browser-side port of scanner/promptguard_scanner.py. Fetches a git
 * repository's file tree + raw files over the provider REST API (GitHub /
 * GitLab), runs the same extraction logic, and returns a fingerprint object
 * identical in shape to the Python scanner's output.
 *
 * Pattern data (secret patterns, domain terms, generic names, package roots,
 * stopwords) is loaded from ../../scanner/spec.json — the SAME file the Python
 * scanner reads, so the two implementations can never drift. Edit the spec,
 * not this file, when patterns change.
 *
 * Used by the Projects page's "scan from a repository" flow:
 *   import { scanRepoUrl } from '../lib/repoScanner';
 *   const fingerprint = await scanRepoUrl('https://github.com/org/repo', {
 *     onProgress: (msg) => setStatus(msg)
 *   });
 */

import spec from '../../../scanner/spec.json' with { type: 'json' };

// ---------------------------------------------------------------------------
// Constants (mirror the Python scanner)
// ---------------------------------------------------------------------------

const LANG_BY_EXT = {
  '.java': 'java',
  '.kt': 'kotlin', '.kts': 'kotlin',
  '.cs': 'csharp',
  '.py': 'python',
  '.go': 'go',
  '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript',
  '.rb': 'ruby',
  '.php': 'php',
  '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp', '.h': 'cpp', '.c': 'c',
  '.swift': 'swift',
  '.scala': 'scala',
  '.sql': 'sql'
};

const CONFIG_EXTS = new Set(['.properties', '.yml', '.yaml', '.toml', '.ini', '.conf', '.env', '.xml', '.json']);

const EXCLUDE_DIRS = new Set([
  '.git', '.hg', '.svn', '.idea', '.vscode', '.gradle', '.mvn', '.settings',
  'node_modules', 'dist', 'build', 'target', 'out', 'bin', 'obj',
  '.next', '.nuxt', '.venv', 'venv', 'env', '__pycache__',
  'coverage', '.cache', '.pytest_cache', '.mypy_cache', 'Pods', 'DerivedData',
  'vendor', 'third_party', 'libs', 'lib', 'deps', '.terraform'
]);

const EXCLUDE_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
  'Pipfile.lock', 'go.sum', 'Cargo.lock', 'composer.lock', 'Gemfile.lock',
  'gradle.lockfile', 'deno.lock', 'bun.lockb'
]);

const GENERIC_CLASS_NAMES = new Set(spec.generic_class_names);
const THIRD_PARTY_ROOTS = spec.third_party_package_roots;
const BUSINESS_DOMAIN_TERMS = new Set(spec.business_domain_terms);
const VOCAB_STOP = new Set([...spec.stopwords, ...spec.prog_keywords]);

const INTERNAL_TLDS = [
  '.corp', '.internal', '.local', '.lan', '.int', '.home', '.office',
  '.srv', '.test', '.example', '.localhost', '.localdomain', '.prv'
];

const MAX_FILES = 300; // sanity cap so a giant repo can't hang the browser
const MAX_SECRETS = 200;

// Verhoeff tables (Aadhaar checksum) — mirrors extension/patterns.js
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

// ---------------------------------------------------------------------------
// URL parsing + provider fetchers
// ---------------------------------------------------------------------------

/**
 * Parse a repo URL into { provider, owner, repo, branch }.
 * Supports GitHub and GitLab web URLs.
 */
export function parseRepoUrl(rawUrl) {
  const url = String(rawUrl || '').trim();
  if (!url) throw new Error('Enter a repository URL');

  let parsed;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new Error('That does not look like a valid URL');
  }

  const host = parsed.hostname.toLowerCase();
  const path = parsed.pathname.replace(/\/+$/, '').replace(/\.git$/, '');

  if (host === 'github.com' || host.endsWith('.github.com')) {
    const parts = path.split('/').filter(Boolean);
    if (parts.length < 2) throw new Error('GitHub URL should look like https://github.com/owner/repo');
    return {
      provider: 'github',
      owner: parts[0],
      repo: parts[1],
      branch: parsed.searchParams.get('ref') || undefined
    };
  }

  if (host === 'gitlab.com' || host.endsWith('.gitlab.com')) {
    const parts = path.split('/').filter(Boolean);
    if (parts.length < 2) throw new Error('GitLab URL should look like https://gitlab.com/group/repo');
    return {
      provider: 'gitlab',
      // GitLab groups can be nested: group/subgroup/repo
      projectPath: parts.join('/'),
      repo: parts[parts.length - 1],
      branch: parsed.searchParams.get('ref') || undefined
    };
  }

  throw new Error('Only GitHub and GitLab URLs are supported');
}

/**
 * Fetch the default branch for a repo.
 */
async function getDefaultBranch(meta) {
  try {
    const api = meta.provider === 'github'
      ? `https://api.github.com/repos/${meta.owner}/${meta.repo}`
      : `https://gitlab.com/api/v4/projects/${encodeURIComponent(meta.projectPath)}`;
    const res = await fetch(api, { headers: { Accept: 'application/vnd.github+json' } });
    if (!res.ok) {
      throw new Error(`Repo not found (HTTP ${res.status}) — is it public?`);
    }
    const data = await res.json();
    return data.default_branch || 'main';
  } catch (err) {
    if (err && err.message && err.message.startsWith('Repo not found')) throw err;
    // Fall back to main/master guesses without the API call.
    return undefined;
  }
}

/**
 * List files in the repo. Returns [{ path }] filtered to scannable files.
 */
async function listFiles(meta) {
  if (meta.provider === 'github') {
    const branch = meta.branch || (await getDefaultBranch(meta));
    const res = await fetch(
      `https://api.github.com/repos/${meta.owner}/${meta.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      { headers: { Accept: 'application/vnd.github+json' } }
    );
    if (!res.ok) throw new Error(`Failed to list repo files (HTTP ${res.status})`);
    const data = await res.json();
    if (!data.tree) throw new Error('Unexpected GitHub API response');
    return data.tree
      .filter((entry) => entry.type === 'blob')
      .map((entry) => ({ path: entry.path }));
  }

  // GitLab
  const branch = meta.branch || (await getDefaultBranch(meta));
  const projectId = encodeURIComponent(meta.projectPath);
  const files = [];
  let page = 1;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const res = await fetch(
      `https://gitlab.com/api/v4/projects/${projectId}/repository/tree?recursive=true&per_page=100&page=${page}`,
      { headers: { Accept: 'application/json' } }
    );
    if (!res.ok) throw new Error(`Failed to list repo files (HTTP ${res.status})`);
    const batch = await res.json();
    if (!Array.isArray(batch) || batch.length === 0) break;
    batch.forEach((entry) => {
      if (entry.type === 'blob') files.push({ path: entry.path });
    });
    if (batch.length < 100) break;
    page += 1;
  }
  return files;
}

/**
 * Fetch one file's text content.
 */
async function fetchFile(meta, path) {
  if (meta.provider === 'github') {
    const branch = meta.branch || (await getDefaultBranch(meta));
    const res = await fetch(
      `https://raw.githubusercontent.com/${meta.owner}/${meta.repo}/${encodeURIComponent(branch)}/${path.split('/').map(encodeURIComponent).join('/')}`
    );
    if (!res.ok) return null;
    return res.text();
  }

  // GitLab raw endpoint
  const branch = meta.branch || (await getDefaultBranch(meta));
  const projectId = encodeURIComponent(meta.projectPath);
  const res = await fetch(
    `https://gitlab.com/api/v4/projects/${projectId}/repository/files/${encodeURIComponent(path)}/raw?ref=${encodeURIComponent(branch)}`
  );
  if (!res.ok) return null;
  return res.text();
}

// ---------------------------------------------------------------------------
// Extraction (mirror the Python scanner)
// ---------------------------------------------------------------------------

function isPrivateIp(ip) {
  const parts = ip.split('.').map((x) => parseInt(x, 10));
  if (parts.length !== 4 || parts.some((x) => Number.isNaN(x) || x < 0 || x > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function isInternalHost(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return false;
  if (h === 'localhost') return true;
  if (isPrivateIp(h)) return true;
  if (!h.includes('.')) return true;
  return INTERNAL_TLDS.some((tld) => h.endsWith(tld));
}

function isInternalUrl(url) {
  try {
    return isInternalHost(new URL(url).hostname);
  } catch (err) {
    return false;
  }
}

function verhoeffValid(numStr) {
  if (!numStr || !/^[0-9]+$/.test(numStr)) return false;
  let c = 0;
  const n = numStr.length;
  for (let i = 0; i < n; i++) {
    const digit = numStr.charCodeAt(n - 1 - i) - 48;
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]];
  }
  return c === 0;
}

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

async function valueHash(value) {
  // SHA-256 via WebCrypto (available in browsers and Node 15+)
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  const hex = Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 16);
}

const PACKAGE_DECL_RES = [
  /^\s*package\s+([A-Za-z_][\w.]*)\s*;?/gm,   // Java / Kotlin
  /^\s*namespace\s+([A-Za-z_][\w.]*)/gm       // C#
];

const CLASS_DECL_RES = {
  java: /\b(?:class|interface|enum|record|annotation)\s+([A-Z][A-Za-z0-9_]*)\b/g,
  kotlin: /\b(?:class|interface|enum class|data class|sealed class|object)\s+([A-Z][A-Za-z0-9_]*)\b/g,
  csharp: /\b(?:class|interface|struct|enum|record)\s+([A-Z][A-Za-z0-9_]*)\b/g,
  python: /^\s*class\s+([A-Z][A-Za-z0-9_]*)/gm,
  go: /\btype\s+([A-Z][A-Za-z0-9_]*)\s+(?:struct|interface)\b/g,
  typescript: /\b(?:class|interface|enum|type)\s+([A-Z][A-Za-z0-9_]*)\b/g,
  javascript: /\bclass\s+([A-Z][A-Za-z0-9_]*)\b/g,
  cpp: /\bclass\s+([A-Z][A-Za-z0-9_]*)\b/g,
  c: /\bstruct\s+([A-Z][A-Za-z0-9_]*)\b/g,
  swift: /\b(?:class|struct|enum|protocol|actor)\s+([A-Z][A-Za-z0-9_]*)\b/g,
  scala: /\b(?:class|trait|object|case class)\s+([A-Z][A-Za-z0-9_]*)\b/g,
  php: /\bclass\s+([A-Z][A-Za-z0-9_]*)\b/g,
  ruby: /\bclass\s+([A-Z][A-Za-z0-9_]*)\b/g
};

function isThirdParty(pkg) {
  if (!pkg) return true;
  if (!pkg.includes('.') && ['com', 'org', 'net', 'io', 'dev', 'app'].includes(pkg)) return true;
  const lower = pkg.toLowerCase() + '.';
  return THIRD_PARTY_ROOTS.some((root) => lower.startsWith(root));
}

function tokenizeIdentifiers(text) {
  const words = new Set();
  const identRe = /[A-Za-z_][A-Za-z0-9_]{2,}/g;
  let m;
  while ((m = identRe.exec(text)) !== null) {
    const ident = m[0];
    for (const part of ident.split(/[_\-\s]+/)) {
      const tokens = part.match(/[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+/g) || [];
      for (const token of tokens) {
        const w = token.toLowerCase();
        if (w.length >= 3 && !/^[0-9]+$/.test(w) && !VOCAB_STOP.has(w)) words.add(w);
      }
    }
  }
  return words;
}

function stripTrailingPunct(s) {
  return String(s).replace(/[.,;:)\]}"']+$/, '');
}

// ---------------------------------------------------------------------------
// Main scan
// ---------------------------------------------------------------------------

/**
 * Scan an in-memory file map: { path: content }.
 * Returns the same fingerprint shape as the Python scanner.
 */
export async function scanFiles(fileMap, { project = 'repo', vocabLimit = 30, minFiles = 2, onProgress } = {}) {
  const packages = new Set();
  const classNames = new Set();
  const vocabCounts = {}; // word -> { count, files:Set }
  const internalUrls = new Set();
  const internalIps = new Set();
  const secrets = [];
  const languages = new Set();
  const seenSecretKeys = new Set();
  let filesScanned = 0;
  let totalLines = 0;

  const paths = Object.keys(fileMap).sort();
  for (const path of paths) {
    const parts = path.split('/');
    if (parts.some((p) => EXCLUDE_DIRS.has(p))) continue;
    const fname = parts[parts.length - 1];
    if (fname.startsWith('.') || EXCLUDE_FILES.has(fname)) continue;

    const dotIdx = fname.lastIndexOf('.');
    const ext = dotIdx === -1 ? '' : fname.slice(dotIdx).toLowerCase();
    const lang = LANG_BY_EXT[ext];
    const isSource = !!lang;
    const isConfig = CONFIG_EXTS.has(ext);
    if (!isSource && !isConfig) continue;

    const text = String(fileMap[path] || '');
    if (!text) continue;
    if (text.includes('\u0000')) continue;

    filesScanned += 1;
    totalLines += (text.match(/\n/g) || []).length + 1;
    if (lang) languages.add(lang);

    // URLs & IPs
    const urlRe = /https?:\/\/[^\s"'<>)\]]+/gi;
    let um;
    while ((um = urlRe.exec(text)) !== null) {
      const url = stripTrailingPunct(um[0]);
      if (isInternalUrl(url)) internalUrls.add(url);
    }
    const ipRe = /\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g;
    let im;
    while ((im = ipRe.exec(text)) !== null) {
      const ip = im[0];
      if (isPrivateIp(ip)) internalIps.add(ip);
    }

    // Secrets
    for (const entry of spec.secret_patterns) {
      // spec.json patterns are written for Python's regex engine, which uses
      // the inline (?i) flag; JS uses the /i flag instead.
      let pattern = entry.pattern;
      let flags = 'g';
      if (pattern.startsWith('(?i)')) {
        pattern = pattern.slice(4);
        flags = 'gi';
      }
      const re = new RegExp(pattern, flags);
      let sm;
      while ((sm = re.exec(text)) !== null) {
        const matched = sm[0];
        if (entry.validator === 'verhoeff' && !verhoeffValid(matched.replace(/\s/g, ''))) continue;
        if (entry.validator === 'entropy') {
          const vm = matched.match(/[=:]\s*['"]([^'"]+)['"]/);
          const value = vm ? vm[1] : matched;
          if (shannonEntropy(value) < 3.5) continue;
        }
        const hash = await valueHash(matched);
        const dedupeKey = entry.key + '|' + hash;
        if (seenSecretKeys.has(dedupeKey)) continue;
        seenSecretKeys.add(dedupeKey);
        secrets.push({
          key: entry.key,
          label: entry.label,
          severity: entry.severity,
          file: path,
          line: (text.slice(0, sm.index).match(/\n/g) || []).length + 1,
          value_hash: hash,
          preview: matched.length > 6 ? matched.slice(0, 6) + '...' : matched
        });
        if (secrets.length >= MAX_SECRETS) break;
      }
      if (secrets.length >= MAX_SECRETS) break;
    }
    if (secrets.length >= MAX_SECRETS) break;

    if (!isSource) continue;

    // Packages
    if (lang === 'java' || lang === 'kotlin' || lang === 'csharp') {
      for (const re of PACKAGE_DECL_RES) {
        let pm;
        while ((pm = re.exec(text)) !== null) {
          const pkg = pm[1];
          if (!isThirdParty(pkg)) packages.add(pkg);
        }
      }
    } else if (lang === 'python') {
      const pyRe = /^\s*(?:from|import)\s+([A-Za-z_][\w.]*)/gm;
      let pm;
      while ((pm = pyRe.exec(text)) !== null) {
        const dotted = pm[1];
        const segments = dotted.split('.');
        for (let i = segments.length; i >= 1; i--) {
          const candidate = segments.slice(0, i).join('.');
          const rel = candidate.split('.').join('/');
          if (fileMap[rel + '/__init__.py'] !== undefined || fileMap[rel + '.py'] !== undefined) {
            packages.add(candidate);
            break;
          }
        }
      }
    }

    // Classes
    const classRe = CLASS_DECL_RES[lang];
    if (classRe) {
      classRe.lastIndex = 0;
      let cm;
      while ((cm = classRe.exec(text)) !== null) {
        const name = cm[1];
        if (!GENERIC_CLASS_NAMES.has(name)) classNames.add(name);
      }
    }

    // Vocabulary
    for (const w of tokenizeIdentifiers(text)) {
      const entry = vocabCounts[w] || (vocabCounts[w] = { count: 0, files: new Set() });
      entry.count += 1;
      entry.files.add(path);
    }
    const textLower = text.toLowerCase();
    for (const term of BUSINESS_DOMAIN_TERMS) {
      if (new RegExp('\\b' + term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b').test(textLower)) {
        const entry = vocabCounts[term] || (vocabCounts[term] = { count: 0, files: new Set() });
        entry.count += 1;
        entry.files.add(path);
      }
    }

    if (onProgress && filesScanned % 25 === 0) {
      onProgress(`Scanned ${filesScanned} files…`);
    }
  }

  // Go module
  if (fileMap['go.mod']) {
    const gm = fileMap['go.mod'].match(/^\s*module\s+([^\s]+)/m);
    if (gm && !isThirdParty(gm[1])) packages.add(gm[1]);
  }

  // Rank vocabulary
  const ranked = [];
  for (const word of Object.keys(vocabCounts)) {
    const entry = vocabCounts[word];
    if (entry.files.size >= minFiles) ranked.push([entry.files.size, entry.count, word]);
  }
  ranked.sort((a, b) => (b[0] - a[0]) || (b[1] - a[1]));
  const vocab = ranked.slice(0, vocabLimit).map((x) => x[2]);

  const sortUnique = (s) => Array.from(s).sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));

  return {
    version: '1.0',
    project,
    scanned_at: new Date().toISOString(),
    packages: sortUnique(packages),
    class_names: sortUnique(classNames),
    domain_vocabulary: vocab,
    internal_urls: sortUnique(internalUrls),
    internal_ips: sortUnique(internalIps),
    secrets_found: secrets,
    stats: {
      files_scanned: filesScanned,
      languages_detected: Array.from(languages).sort(),
      total_lines: totalLines
    }
  };
}

/**
 * Scan a repository from its web URL. Returns the fingerprint object.
 *
 * @param {string} url  e.g. https://github.com/org/repo or https://gitlab.com/group/repo
 * @param {object} opts { onProgress, project, vocabLimit, minFiles }
 */
export async function scanRepoUrl(url, { onProgress, project, vocabLimit, minFiles } = {}) {
  const meta = parseRepoUrl(url);

  if (onProgress) onProgress(`Fetching file list from ${meta.provider}…`);
  const files = await listFiles(meta);

  // Resolve the branch once — every raw-file fetch reuses it instead of
  // hitting the provider API per file.
  const branch = meta.branch || (await getDefaultBranch(meta)) || 'main';
  meta.branch = branch;

  const fileMap = {};
  let scanned = 0;
  for (const f of files) {
    if (scanned >= MAX_FILES) break;
    if (onProgress && scanned % 25 === 0) onProgress(`Downloading files (${scanned}/${Math.min(files.length, MAX_FILES)})…`);
    // eslint-disable-next-line no-await-in-loop
    const content = await fetchFile(meta, f.path);
    if (content !== null) fileMap[f.path] = content;
    scanned += 1;
  }
  if (scanned === 0) throw new Error('No readable source files found in the repository');

  const defaultName = project || meta.repo || meta.owner || 'repo';
  if (onProgress) onProgress('Scanning for packages, classes, secrets…');
  return scanFiles(fileMap, { project: defaultName, vocabLimit, minFiles, onProgress });
}
