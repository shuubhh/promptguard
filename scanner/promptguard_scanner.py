#!/usr/bin/env python3
"""
promptguard_scanner.py — PromptGuard Component 1 (Python scanner)

Scans a client codebase and produces the fingerprint.json that powers
PromptGuard's DLP scanning in the Chrome extension:

    packages           — first-party package/namespace names (Java, Kotlin, C#,
                         Python, Go) the extension scores +0.95 on
    class_names        — distinctive class/interface/enum/record names (+0.85)
    domain_vocabulary  — jargon-heavy identifier tokens extracted from the code,
                         ranked by frequency (+0.15/term, capped +0.45)
    internal_urls      — URLs pointing at internal hosts (+0.75)
    internal_ips       — private-range IP literals (+0.70)
    secrets_found      — hardcoded credentials detected in the code (informational;
                         shown as a warning badge in the dashboard)

The output file is uploaded in the dashboard (Projects -> Add Project ->
upload fingerprint.json), then synced to the extension which scans every
intercepted prompt against it.

Pure Python 3 standard library — zero dependencies.

Usage:
    python promptguard_scanner.py <path> \
        [--name "HDFC Wealth Platform"] [--output fingerprint.json]
    python promptguard_scanner.py <path> --stdout

Options:
    --name NAME       Project name (default: the scanned folder's name)
    --output PATH     Write fingerprint.json to PATH (default ./fingerprint.json)
    --stdout          Print the fingerprint JSON to stdout instead of a file
    --vocab-limit N   Max domain-vocabulary terms (default 30)
    --min-files N     A vocab term must appear in at least N files (default 2)
    --exclude DIR     Extra directory name to skip (repeatable)

Example:
    python promptguard_scanner.py ~/work/hdfc-wealth --name "HDFC Wealth Platform"
"""

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FINGERPRINT_VERSION = "1.0"

# Source-file language detection by extension.
LANG_BY_EXT = {
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp",
    ".py": "python",
    ".go": "go",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".rb": "ruby",
    ".php": "php",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".h": "cpp", ".c": "c",
    ".swift": "swift",
    ".scala": "scala",
    ".sql": "sql",
}

# Config-ish files are scanned for URLs / IPs / secrets but never for
# packages, classes or vocabulary.
CONFIG_EXTS = {".properties", ".yml", ".yaml", ".toml", ".ini", ".conf", ".env", ".xml", ".json"}

# Directories that are never scanned (build output, vendored code, VCS).
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".vscode", ".gradle", ".mvn", ".settings",
    "node_modules", "dist", "build", "target", "out", "bin", "obj",
    ".next", ".nuxt", ".venv", "venv", "env", "__pycache__",
    "coverage", ".cache", ".pytest_cache", ".mypy_cache", "Pods", "DerivedData",
    "vendor", "third_party", "libs", "lib", "deps", ".terraform", "Pods",
}

# Files that are never scanned.
DEFAULT_EXCLUDE_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "go.sum", "Cargo.lock", "composer.lock", "Gemfile.lock",
    "gradle.lockfile", "deno.lock", "bun.lockb",
}

# Generic class names that carry no fingerprint value (a compound name like
# CustomerWealthPortfolioService is kept; the bare word "Service" is not).
GENERIC_CLASS_NAMES = {
    "App", "Main", "Application", "ApplicationTests", "Test", "Tests", "Testing",
    "Base", "BaseTest", "AbstractTest", "Config", "Configuration", "Constants",
    "Utils", "Util", "Helper", "Helpers", "Controller", "RestController",
    "Service", "ServiceImpl", "Manager", "ManagerImpl", "Handler", "Repository",
    "RepositoryImpl", "Mapper", "Dao", "Dto", "Entity", "Model", "Models",
    "Client", "Server", "Factory", "Builder", "Listener", "Adapter", "Exception",
    "Error", "Response", "Request", "Result", "Results", "Key", "Keys", "Value",
    "Values", "Component", "Resource", "Resources", "Properties", "Enums",
    "Enum", "Interface", "Impl", "ServiceTest", "ControllerTest", "RepositoryTest",
    "RestControllerAdvice", "ControllerAdvice", "SecurityConfig", "WebConfig",
}

# Well-known third-party / standard-library package roots that are never
# reported as client packages.
THIRD_PARTY_PACKAGE_ROOTS = (
    "java.", "javax.", "jakarta.", "jdk.",
    "org.apache.", "org.springframework.", "org.springframework.",
    "org.hibernate.", "org.junit", "org.mockito", "org.slf4j", "org.json",
    "org.w3c.", "org.xml.", "org.yaml.", "org.gradle", "org.glassfish",
    "org.jboss", "org.jetbrains", "org.elasticsearch", "org.postgresql",
    "org.neo4j", "org.mongodb", "org.thymeleaf", "org.mybatis", "org.assertj",
    "org.awaitility", "org.projectlombok", "org.reactivestreams", "org.aspectj",
    "org.camunda", "org.flowable", "org.quartz", "org.openqa", "org.joda",
    "org.testng", "org.checkerframework", "org.dom4j", "org.dom4j",
    "com.google.", "com.fasterxml.", "com.sun.", "com.ibm.", "com.microsoft.",
    "com.amazon.", "com.oracle.", "com.github.", "com.squareup.", "com.zaxxer",
    "com.mysql.", "com.mongodb.", "com.couchbase.", "com.rabbitmq.", "com.redis.",
    "android.", "kotlin.", "io.reactivex", "io.netty", "io.grpc", "io.swagger",
    "io.undertow", "io.micrometer", "io.micronaut", "io.quarkus", "io.vertx",
    "net.sf.", "redis.", "ch.qos.logback", "org.wildfly", "org.kie", "org.drools",
    "org.keycloak", "org.owasp", "org.bouncycastle", "org.xerial",
)

# Business domain terms that signal sensitive/proprietary content. Curated so
# the vocabulary catches domain jargon that appears in comments/prose/config
# rather than only in code identifiers (a prompt mentioning "nostro" or
# "hipaa" is a strong DLP signal even in natural language).
BUSINESS_DOMAIN_TERMS = {
    # Finance / Banking
    "ledger", "nostro", "vostro", "remittance", "swift", "iban", "clearing",
    "settlement", "reconciliation", "portfolio", "wealth", "premium", "tier",
    "yield", "collateral", "mortgage", "underwriting", "actuarial",
    # Healthcare
    "hl7", "dicom", "icd10", "npi", "formulary", "ehr", "emr", "hipaa",
    "patient", "diagnosis", "prescription", "clinical", "pharmacy",
    "insurance", "claim",
    # Logistics
    "awb", "consignee", "shipper", "incoterm", "waybill", "manifest",
    "customs", "tariff", "freight",
    # General enterprise
    "proprietary", "confidential", "internal", "restricted",
}

# Common English words + programming keywords excluded from domain vocabulary.
STOPWORDS = set(
    """a an and are as at be been being but by can could did do does doing done down
    for from had has have having he her here hers him his how i i'd i'll i'm i've if
    in into is it its itself just me more most my myself no nor not now of off on once
    only or other our ours ourselves out over own same she should so some such than
    that the their theirs them themselves then there these they this those through
    to too under until up very we were what when where which while who whom why will
    with you your yours yourself yourselves about above after again against all any
    both each few etc even ever every far few get got i.e. ie inc into let like made
    may might much must near never new next none often old once one onto out over own
    per put quite rather really right said same say says see seen seem seems several
    shall should since still such sure take than too try two under until upon us use
    used using very via want way well were what when where whether which while who
    whom whose why will with within without would yes yet you your
    """.split()
)

PROG_KEYWORDS = set(
    """if else elif for while do switch case break continue return def class import
    from as try except finally raise with pass lambda yield global nonlocal assert
    del not in is and or new public private protected static final void int long
    double float boolean byte short char string bool true false null none self this
    super base var let const function async await of typeof instanceof extends
    implements interface enum struct union type record module export default require
    package namespace using select insert update delete where join order group by
    limit offset set values into create table alter drop index primary foreign key
    reference references cascade begin commit rollback transaction trigger function
    procedure view database schema user role grant revoke explain analyze vacuum
    explain select from where and or not null default unique check constraint
    auto_increment serial bigint integer varchar char text date time timestamp
    datetime interval year month day hour minute second current_date current_time
    current_timestamp now localtime localtimestamp coalesce nullif cast convert
    substring trim length upper lower concat sum avg min max count distinct
    inner left right full outer cross natural join on using group having order
    asc desc limit offset fetch first next row rows only window partition over
    rank dense_rank row_number lag lead first_value last_value nth_value cume_dist
    percent_rank ntile cube rollup grouping sets materialized view temp temporary
    unlogged sequence owned by rename alter column add drop constraint truncate
    reload flush privileges lock unlock tables show describe explain kill use quit
    exit begin end declare cursor open fetch close deallocate prepare execute
    execute immediate call return value language plpgsql sql procedural stable
    volatile immutable strict security definer invoker search_path set local
    """.split()
)

VOCAB_STOP = STOPWORDS | PROG_KEYWORDS

# ---------------------------------------------------------------------------
# Secret patterns — the extension's patterns (extension/patterns.js) plus a
# broader set inspired by truffleHog / gitleaks. The scanner is a *repo audit*:
# secrets_found is informational (dashboard badge), so wider coverage is fine —
# the extension keeps its own conservative runtime list.
# ---------------------------------------------------------------------------

# entry: (key, label, severity, regex, validator|None)
SECRET_PATTERNS = [
    ("aws_access_key", "AWS Access Key", "critical", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret_key", "AWS Secret Key", "critical", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("github_token", "GitHub Personal Access Token", "critical", r"\bghp_[a-zA-Z0-9]{36}\b"),
    ("github_oauth", "GitHub OAuth Token", "critical", r"\bgho_[a-zA-Z0-9]{36}\b"),
    ("gitlab_token", "GitLab Personal Access Token", "critical", r"\bglpat-[a-zA-Z0-9\-]{20}\b"),
    ("stripe_secret_key", "Stripe Secret Key", "critical", r"\bsk_live_[a-zA-Z0-9]{24,}\b"),
    ("stripe_publishable", "Stripe Publishable Key", "high", r"\bpk_live_[a-zA-Z0-9]{24,}\b"),
    ("twilio_sid", "Twilio Account SID", "high", r"\bAC[a-f0-9]{32}\b"),
    ("sendgrid_key", "SendGrid API Key", "critical", r"\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b"),
    ("brevo_smtp_key", "Brevo SMTP Key", "critical", r"\bxsmtpsib-[a-f0-9]{64}-[a-zA-Z0-9]{16}\b"),
    ("db_connection_string", "Database Connection String", "critical", r"(?:mongodb|postgresql|postgres|mysql|redis|mssql|sqlserver)://[^\s\"']{10,}"),
    ("private_key", "Private Key (PEM/PGP/SSH)", "critical", r"-----BEGIN (?:RSA |EC |PGP |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----"),
    ("jwt_token", "JWT Token", "high", r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\."),
    ("aadhaar_number", "Aadhaar Number", "high", r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", "verhoeff"),
    ("pan_number", "PAN Number", "medium", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    ("generic_password", "Hardcoded Password", "high", r"(?i)(?:password|passwd|pwd|secret|api_key|apikey|auth_token)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "entropy"),
    ("anthropic_api_key", "Anthropic API Key", "critical", r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b"),
    ("openai_api_key", "OpenAI API Key", "critical", r"\bsk-(?:proj|svcacct)-[a-zA-Z0-9_-]{20,}\b"),
    ("slack_token", "Slack Token", "high", r"\bxox[baprs]-[a-zA-Z0-9-]{10,}\b"),
    ("google_api_key", "Google API Key", "high", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("indian_phone", "Indian Phone Number", "low", r"(?<!\d)(?:\+91|0)?[6-9]\d{9}(?!\d)"),
]

# Verhoeff checksum tables (Aadhaar) — mirrors extension/patterns.js.
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(num_str):
    """True if the 12-digit number passes Aadhaar's Verhoeff checksum."""
    if not num_str or not num_str.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(num_str)):
        digit = ord(ch) - 48
        c = VERHOEFF_D[c][VERHOEFF_P[i % 8][digit]]
    return c == 0


URL_RE = re.compile(r"https?://[^\s\"'<>\]\)]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

INTERNAL_TLDS = (
    ".corp", ".internal", ".local", ".lan", ".int", ".home", ".office",
    ".srv", ".test", ".example", ".localhost", ".localdomain", ".prv",
)


def is_private_ip(ip):
    try:
        a, b, c, d = (int(x) for x in ip.split("."))
    except ValueError:
        return False
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    if a == 169 and b == 254:
        return True
    if a == 100 and 64 <= b <= 127:
        return True
    return False


def is_internal_host(host):
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    if host == "localhost":
        return True
    if is_private_ip(host):
        return True
    if "." not in host:  # single-label host like http://api-server/
        return True
    for tld in INTERNAL_TLDS:
        if host.endswith(tld):
            return True
    return False


def is_internal_url(url):
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return is_internal_host(parsed.hostname)


# ---------------------------------------------------------------------------
# Source extraction
# ---------------------------------------------------------------------------

PACKAGE_DECL_RES = [
    # Java:  package com.fakebank.wealth.portfolio;
    # Kotlin: package com.fakebank.wealth.portfolio
    re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)\s*;?", re.MULTILINE),
    # C#:    namespace Foo.Bar.Baz
    re.compile(r"^\s*namespace\s+([A-Za-z_][\w.]*)", re.MULTILINE),
]

CLASS_DECL_RES = {
    "java": re.compile(r"\b(?:class|interface|enum|record|annotation)\s+([A-Z][A-Za-z0-9_]*)\b"),
    "kotlin": re.compile(r"\b(?:class|interface|enum class|data class|sealed class|object)\s+([A-Z][A-Za-z0-9_]*)\b"),
    "csharp": re.compile(r"\b(?:class|interface|struct|enum|record)\s+([A-Z][A-Za-z0-9_]*)\b"),
    "python": re.compile(r"^\s*class\s+([A-Z][A-Za-z0-9_]*)", re.MULTILINE),
    "go": re.compile(r"\btype\s+([A-Z][A-Za-z0-9_]*)\s+(?:struct|interface)\b"),
    "typescript": re.compile(r"\b(?:class|interface|enum|type)\s+([A-Z][A-Za-z0-9_]*)\b"),
    "javascript": re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]*)\b"),
    "cpp": re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]*)\b"),
    "c": re.compile(r"\bstruct\s+([A-Z][A-Za-z0-9_]*)\b"),
    "swift": re.compile(r"\b(?:class|struct|enum|protocol|actor)\s+([A-Z][A-Za-z0-9_]*)\b"),
    "scala": re.compile(r"\b(?:class|trait|object|case class)\s+([A-Z][A-Za-z0-9_]*)\b"),
    "php": re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]*)\b"),
    "ruby": re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]*)\b"),
}

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
CAMEL_SPLIT_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")

INTERNAL_IP_RANGES = ((10, None), (172, (16, 31)), (192, (168,)), (127, None), (169, (254,)), (100, (64, 127)))


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class ScanResult:
    def __init__(self):
        self.packages = set()
        self.class_names = set()
        self.vocab_counts = {}   # word -> {"count": int, "files": set}
        self.internal_urls = set()
        self.internal_ips = set()
        self.secrets = []        # list of dicts
        self.languages = set()
        self.files_scanned = 0
        self.total_lines = 0
        self._seen_secret_keys = set()


def _read_text(path):
    """Read a file as text, skipping obvious binaries."""
    try:
        with open(path, "rb") as f:
            head = f.read(8192)
        if b"\x00" in head:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _strip_trailing_punct(s):
    return s.rstrip(".,;:)]}\"'")


def shannon_entropy(text):
    """Shannon entropy of a string (high entropy -> likely a secret)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _value_hash(value):
    """SHA-256 prefix — lets findings be de-duplicated without storing the
    actual secret value anywhere."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _scan_secrets(text, rel_path, result):
    for entry in SECRET_PATTERNS:
        key, label, severity, pattern = entry[0], entry[1], entry[2], entry[3]
        validate = entry[4] if len(entry) > 4 else None
        regex = re.compile(pattern)
        for m in regex.finditer(text):
            matched = m.group(0)

            if validate == "verhoeff" and not verhoeff_valid(re.sub(r"\s", "", matched)):
                continue

            # Password-assignment pattern: only report values that look
            # high-entropy (a real secret), skip things like password="demo".
            if validate == "entropy":
                value_match = re.search(r"[=:]\s*['\"]([^'\"]+)['\"]", matched)
                value = value_match.group(1) if value_match else matched
                if shannon_entropy(value) < 3.5:
                    continue

            dedupe_key = key + "|" + _value_hash(matched)
            if dedupe_key in result._seen_secret_keys:
                continue
            result._seen_secret_keys.add(dedupe_key)
            result.secrets.append({
                "key": key,
                "label": label,
                "severity": severity,
                "file": rel_path,
                "line": text[: m.start()].count("\n") + 1,
                # Never store the full value — hash + first 6 chars for context.
                "value_hash": _value_hash(matched),
                "preview": matched[:6] + "..." if len(matched) > 6 else matched,
            })
            if len(result.secrets) >= 200:
                return


def _tokenize_identifiers(text):
    """Split camelCase/snake_case identifiers into lowercased words."""
    words = set()
    for ident in IDENT_RE.findall(text):
        for part in re.split(r"[_\-\s]+", ident):
            for token in CAMEL_SPLIT_RE.findall(part):
                w = token.lower()
                if len(w) >= 3 and not w.isdigit() and w not in VOCAB_STOP:
                    words.add(w)
    return words


def _extract_python_packages(content, root):
    """Derive first-party Python packages from import statements that resolve
    to real directories under the repo."""
    found = set()
    for m in re.finditer(r"^\s*(?:from|import)\s+([A-Za-z_][\w.]*)", content, re.MULTILINE):
        dotted = m.group(1)
        segments = dotted.split(".")
        # Try progressively shorter prefixes until one maps to a real dir.
        for i in range(len(segments), 0, -1):
            candidate = ".".join(segments[:i])
            rel = candidate.replace(".", os.sep)
            if os.path.isdir(os.path.join(root, rel)):
                found.add(candidate)
                break
            # Also accept a file module (e.g. import foo.bar where bar.py)
            if os.path.isfile(os.path.join(root, rel + ".py")):
                found.add(candidate)
                break
    return found


def _is_third_party(pkg):
    if not pkg:
        return True
    if "." not in pkg and pkg in {"com", "org", "net", "io", "dev", "app"}:
        return True
    lower = pkg.lower() + "."
    for root in THIRD_PARTY_PACKAGE_ROOTS:
        if lower.startswith(root):
            return True
    return False


def scan_repo(root, exclude_dirs=None, vocab_limit=30, min_files=2, extra_exclude=None):
    """Walk `root` and build a fingerprint. Returns a dict ready for JSON."""
    root = os.path.abspath(root)
    exclude = set(DEFAULT_EXCLUDE_DIRS)
    exclude.update(extra_exclude or [])
    result = ScanResult()

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in exclude and not d.startswith(".")
        ]

        for fname in sorted(filenames):
            if fname in DEFAULT_EXCLUDE_FILES:
                continue
            if fname.startswith("."):
                continue
            fpath = os.path.join(dirpath, fname)
            rel = os.path.relpath(fpath, root).replace(os.sep, "/")
            ext = os.path.splitext(fname)[1].lower()

            is_source = ext in LANG_BY_EXT
            is_config = ext in CONFIG_EXTS
            if not is_source and not is_config:
                continue

            text = _read_text(fpath)
            if text is None:
                continue

            result.files_scanned += 1
            result.total_lines += text.count("\n") + 1
            lang = LANG_BY_EXT.get(ext)
            if lang:
                result.languages.add(lang)

            # --- URLs & IPs (any text file) ---
            for m in URL_RE.finditer(text):
                url = _strip_trailing_punct(m.group(0))
                if is_internal_url(url):
                    result.internal_urls.add(url)
            for m in IP_RE.finditer(text):
                ip = m.group(0)
                if is_private_ip(ip):
                    result.internal_ips.add(ip)

            # --- Secrets (any text file) ---
            _scan_secrets(text, rel, result)

            if not is_source:
                continue

            # --- Packages ---
            if lang in ("java", "kotlin", "csharp"):
                for regex in PACKAGE_DECL_RES:
                    for m in regex.finditer(text):
                        pkg = m.group(1)
                        if not _is_third_party(pkg):
                            result.packages.add(pkg)
            elif lang == "python":
                result.packages.update(_extract_python_packages(text, root))
            elif lang == "go":
                # Go package namespaces come from the module path in go.mod;
                # handled below when we read go.mod files.
                pass

            # --- Class names ---
            class_re = CLASS_DECL_RES.get(lang)
            if class_re:
                for m in class_re.finditer(text):
                    name = m.group(1)
                    if name not in GENERIC_CLASS_NAMES:
                        result.class_names.add(name)

            # --- Vocabulary: words seen across >= min_files files ---
            words = _tokenize_identifiers(text)
            for w in words:
                entry = result.vocab_counts.setdefault(w, {"count": 0, "files": set()})
                entry["count"] += 1
                entry["files"].add(rel)

            # --- Curated business-domain terms (comments, prose, config) ---
            # These are high-signal: a single mention anywhere in the repo is
            # enough to keep them in the vocabulary.
            text_lower = text.lower()
            for term in BUSINESS_DOMAIN_TERMS:
                if re.search(r"\b" + re.escape(term) + r"\b", text_lower):
                    entry = result.vocab_counts.setdefault(term, {"count": 0, "files": set()})
                    entry["count"] += 1
                    entry["files"].add(rel)

    # --- Go module path (top-level packages) ---
    go_mod = os.path.join(root, "go.mod")
    if os.path.isfile(go_mod):
        text = _read_text(go_mod)
        if text:
            m = re.search(r"^\s*module\s+([^\s]+)", text, re.MULTILINE)
            if m:
                module = m.group(1).strip()
                if module and not _is_third_party(module):
                    result.packages.add(module)

    # --- Rank vocabulary ---
    ranked = []
    for word, entry in result.vocab_counts.items():
        if len(entry["files"]) >= min_files:
            ranked.append((len(entry["files"]), entry["count"], word))
    ranked.sort(reverse=True)
    vocab = [word for _, _, word in ranked[:vocab_limit]]

    # --- Dedupe + sort everything for deterministic output ---
    def sort_unique(s):
        return sorted(s, key=lambda x: x.lower())

    stats = {
        "files_scanned": result.files_scanned,
        "languages_detected": sorted(result.languages),
        "total_lines": result.total_lines,
    }

    return {
        "version": FINGERPRINT_VERSION,
        "project": os.path.basename(root),
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "packages": sort_unique(result.packages),
        "class_names": sort_unique(result.class_names),
        "domain_vocabulary": vocab,
        "internal_urls": sort_unique(result.internal_urls),
        "internal_ips": sort_unique(result.internal_ips),
        "secrets_found": result.secrets,
        "stats": stats,
    }


def _is_git_url(value):
    return value.startswith("http://") or value.startswith("https://") or value.startswith("git@")


def _inject_token(repo_url, token):
    """Build an authenticated clone URL for private repos."""
    if not token:
        return repo_url
    parsed = urlparse(repo_url)
    host = (parsed.hostname or "").lower()
    if "gitlab" in host:
        auth = "oauth2:" + token
    elif "bitbucket" in host:
        auth = "x-token-auth:" + token
    else:
        auth = token
    netloc = auth + "@" + (parsed.netloc.rsplit("@", 1)[-1])
    new = parsed._replace(netloc=netloc).geturl()
    if not new.endswith(".git"):
        new += ".git"
    return new


def _clone_to_temp(repo_url, token):
    tmp = tempfile.mkdtemp(prefix="pg-scan-")
    url = _inject_token(repo_url, token)
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", url, tmp],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        shutil.rmtree(tmp, ignore_errors=True)
        print("ERROR: git is not installed or not on PATH", file=sys.stderr)
        sys.exit(2)
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        print("ERROR: failed to clone repository:\n%s" % result.stderr.strip(), file=sys.stderr)
        sys.exit(2)
    return tmp


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="promptguard_scanner.py",
        description="Scan a client codebase and emit the fingerprint.json used by PromptGuard.",
    )
    parser.add_argument("path", help="Path to the codebase, or a git URL (https:// or git@) to clone")
    parser.add_argument("--token", help="Auth token for cloning a private git repository")
    parser.add_argument("--name", help="Project name (default: the scanned folder's name)")
    parser.add_argument("--output", "-o", default="fingerprint.json", help="Output path (default ./fingerprint.json)")
    parser.add_argument("--stdout", action="store_true", help="Print JSON to stdout instead of writing a file")
    parser.add_argument("--vocab-limit", type=int, default=30, help="Max domain-vocabulary terms (default 30)")
    parser.add_argument("--min-files", type=int, default=2, help="A vocab term must appear in >= N files (default 2)")
    parser.add_argument("--exclude", action="append", default=[], help="Extra directory name to skip (repeatable)")

    args = parser.parse_args(argv)

    tmp_clone = None
    if _is_git_url(args.path):
        print("Cloning %s ..." % args.path)
        tmp_clone = _clone_to_temp(args.path, args.token)
        scan_path = tmp_clone
    else:
        if not os.path.isdir(args.path):
            print("ERROR: not a directory: %s" % args.path, file=sys.stderr)
            return 2
        scan_path = args.path

    try:
        fingerprint = scan_repo(
            scan_path,
            vocab_limit=args.vocab_limit,
            min_files=args.min_files,
            extra_exclude=args.exclude,
        )
        if tmp_clone:
            # The clone is a single commit checkout; use the requested name
            # (or the URL's repo slug) rather than the temp dir name.
            if not args.name:
                slug = args.path.rstrip("/").split("/")[-1].replace(".git", "")
                fingerprint["project"] = slug
    finally:
        if tmp_clone:
            shutil.rmtree(tmp_clone, ignore_errors=True)

    if args.name:
        fingerprint["project"] = args.name

    if args.stdout:
        print(json.dumps(fingerprint, indent=2, ensure_ascii=False))
        return 0

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(fingerprint, f, indent=2, ensure_ascii=False)
        f.write("\n")

    s = fingerprint["stats"]
    print("PromptGuard scanner — %s" % fingerprint["project"])
    print("  files scanned : %d" % s["files_scanned"])
    print("  languages     : %s" % ", ".join(s["languages_detected"]) or "(none)")
    print("  packages      : %d" % len(fingerprint["packages"]))
    print("  class names   : %d" % len(fingerprint["class_names"]))
    print("  vocabulary    : %d terms" % len(fingerprint["domain_vocabulary"]))
    print("  internal urls : %d" % len(fingerprint["internal_urls"]))
    print("  internal ips  : %d" % len(fingerprint["internal_ips"]))
    if fingerprint["secrets_found"]:
        print("  ⚠ secrets found: %d (review before uploading!)" % len(fingerprint["secrets_found"]))
        for sec in fingerprint["secrets_found"][:10]:
            print("    - %s (%s) in %s" % (sec["label"], sec["severity"], sec["file"]))
    else:
        print("  secrets       : 0")
    print("Wrote %s" % args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
