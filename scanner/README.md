# PromptGuard — Python Scanner (Component 1)

Scans a client codebase and emits the `fingerprint.json` that powers
PromptGuard's DLP scanning. Pure Python 3 standard library — no dependencies.

## Pipeline

```
client repo ──► promptguard_scanner.py ──► fingerprint.json
                                              │
            dashboard: Projects → Add Project → upload fingerprint.json
                                              │
            extension: popup → Save & Fetch Projects (fingerprints sync
            to chrome.storage.local; every intercepted prompt is scanned
            against all of them)
```

## Usage

Scan a local folder:

```bash
python scanner/promptguard_scanner.py <path> \
    --name "HDFC Wealth Platform" \
    --output fingerprint.json
```

Scan a git repository (clones it, scans, cleans up):

```bash
python scanner/promptguard_scanner.py https://gitlab.com/org/repo.git \
    --token <personal-access-token> \
    --name "Apollo EMR"
```

Print to stdout instead of writing a file:

```bash
python scanner/promptguard_scanner.py <path> --name "Apollo EMR" --stdout
```

### Options

| Flag            | Default           | Purpose                                        |
| --------------- | ----------------- | ---------------------------------------------- |
| `--token TOKEN` | —                 | Auth token for cloning a **private** git repo (GitLab `oauth2:`, Bitbucket `x-token-auth:`) |
| `--name NAME`   | folder / repo slug| Project name stored in the fingerprint         |
| `--output PATH` | `fingerprint.json`| Where to write the fingerprint                 |
| `--stdout`      | —                 | Print JSON instead of writing a file           |
| `--vocab-limit` | 30                | Max domain-vocabulary terms                    |
| `--min-files`   | 2                 | A vocab term must appear in ≥ N files          |
| `--exclude DIR` | (built-in list)   | Extra directory name to skip (repeatable)      |

## What it extracts

| Field                | Source                                                                  |
| -------------------- | ----------------------------------------------------------------------- |
| `packages`           | Java/Kotlin `package`, C# `namespace`, Go `module` (go.mod), Python imports that resolve to real dirs |
| `class_names`        | `class` / `interface` / `enum` / `record` / `struct` / `trait` declarations (generic names filtered) |
| `domain_vocabulary`  | camelCase/snake_case identifier tokens ranked by file-frequency **plus** curated business-domain terms (finance/healthcare/logistics) found anywhere in the code — comments, prose and config included |
| `internal_urls`      | URLs whose host is `.corp/.internal/.local/.lan/…`, a single-label host, `localhost`, or a private IP |
| `internal_ips`       | Private-range IP literals (10.x, 172.16–31.x, 192.168.x, 127.x, 169.254.x, 100.64–127.x) |
| `secrets_found`      | The extension's patterns (`patterns.js`) plus a broader truffleHog/gitleaks-style set: AWS access+secret keys, GitHub (PAT/OAuth), GitLab, Stripe, Twilio, SendGrid, Brevo, DB connection strings, PEM/PGP/SSH private keys, JWTs, Aadhaar (Verhoeff-validated), PAN, hardcoded passwords (entropy-gated), OpenAI/Anthropic/Slack/Google keys, Indian phone numbers |

Third-party package roots (`com.google.*`, `org.springframework.*`, …),
generic class names (`Service`, `Config`, `Utils`, …), and build/vendored
directories (`node_modules`, `dist`, `build`, `target`, `.git`, …) are
automatically excluded.

## Privacy

`secrets_found` never stores a secret value. Each finding carries:

- `value_hash` — first 16 hex chars of the SHA-256 of the value (for dedupe)
- `preview` — first 6 characters + `...` (e.g. `AKIAIO...`) for context
- `file` + `line` — where the secret lives, so you can go fix it

The dashboard shows a red "N secrets" badge on projects whose fingerprint
contains entries, and the scan summary prints a warning so you can review
before uploading.

## Tests

```bash
python scanner/tests/run-scanner-tests.py
```

66 checks: Verhoeff/IP/host/entropy/hash/token-helper units, plus a full
integration pass over a synthetic multi-language repo (Java + Python + C# +
Go) verifying packages, classes, vocabulary (identifier + curated terms),
internal URLs/IPs, secret detection (incl. the entropy gate and value
hashing), and that build output is ignored.
