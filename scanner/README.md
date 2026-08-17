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

```bash
python scanner/promptguard_scanner.py <path> \
    --name "HDFC Wealth Platform" \
    --output fingerprint.json
```

Or print to stdout (for piping):

```bash
python scanner/promptguard_scanner.py <path> --name "Apollo EMR" --stdout
```

### Options

| Flag            | Default           | Purpose                                        |
| --------------- | ----------------- | ---------------------------------------------- |
| `--name NAME`   | folder name       | Project name stored in the fingerprint         |
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
| `domain_vocabulary`  | camelCase/snake_case identifier tokens, ranked by file-frequency (stopwords & keywords excluded) |
| `internal_urls`      | URLs whose host is `.corp/.internal/.local/.lan/…`, a single-label host, `localhost`, or a private IP |
| `internal_ips`       | Private-range IP literals (10.x, 172.16–31.x, 192.168.x, 127.x, 169.254.x, 100.64–127.x) |
| `secrets_found`      | The same hardcoded-credential patterns as the extension (`patterns.js`): AWS/GitHub/GitLab/Stripe/OpenAI/Anthropic keys, DB connection strings, PEM private keys, JWTs, Aadhaar (Verhoeff-validated), PAN, Slack, Google API keys |

Third-party package roots (`com.google.*`, `org.springframework.*`, …),
generic class names (`Service`, `Config`, `Utils`, …), and build/vendored
directories (`node_modules`, `dist`, `build`, `target`, `.git`, …) are
automatically excluded.

## Privacy

`secrets_found` stores only a **30-character preview** of each match and the
relative file path — never the full secret value — consistent with how the
rest of PromptGuard handles matches. The dashboard shows a red "N secrets"
badge on projects whose fingerprint contains entries, and the scan summary
prints a warning so you can review before uploading.

## Tests

```bash
python scanner/tests/run-scanner-tests.py
```

45 checks: Verhoeff/IP/host helpers, plus a full integration pass over a
synthetic multi-language repo (Java + Python + C# + Go) verifying packages,
classes, vocabulary, internal URLs/IPs, secret detection, and that build
output is ignored.
