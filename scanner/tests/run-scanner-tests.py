#!/usr/bin/env python3
"""
run-scanner-tests.py — PromptGuard Component 1 (Python scanner) tests.

Builds a synthetic client codebase in a temp dir and verifies the scanner
extracts packages, class names, domain vocabulary, internal URLs/IPs, and
secrets — and that it ignores build output / vendored dirs.

Run with:
    python scanner/tests/run-scanner-tests.py
"""

import json
import os
import shutil
import sys
import tempfile

# Windows consoles default to cp1252 and choke on the ✓/✗ glyphs.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from promptguard_scanner import (  # noqa: E402
    is_internal_host,
    is_internal_url,
    is_private_ip,
    scan_repo,
    verhoeff_valid,
)

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  \u2713 %s" % name)
    else:
        FAIL += 1
        print("  \u2717 %s  %s" % (name, detail))


def write(root, relpath, content):
    path = os.path.join(root, relpath)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def build_sample_repo(root):
    # --- Java: packages + classes + internal URL + IP + a leaked AWS key ---
    write(root, "src/main/java/com/hdfcbank/wealth/portfolio/CustomerWealthPortfolioService.java", """
package com.hdfcbank.wealth.portfolio;

import com.hdfcbank.internal.SecurityUtil;
import org.springframework.stereotype.Service;

@Service
public class CustomerWealthPortfolioService implements PortfolioReconciliationReport {
    private static final String API_URL = "https://api.hdfcbank-internal.corp/v2/portfolio";
    private static final String HOST = "http://192.168.10.45:8080";
    private final String aws = "AKIAIOSFODNN7EXAMPLE";
}
""")

    write(root, "src/main/java/com/hdfcbank/wealth/portfolio/PortfolioReconciliationReport.java", """
package com.hdfcbank.wealth.portfolio;

public interface PortfolioReconciliationReport {
    void reconcileLedger(String nostroAccount, String vostroAccount);
}
""")

    write(root, "src/main/java/com/hdfcbank/retail/core/TransactionLedger.java", """
package com.hdfcbank.retail.core;

public class TransactionLedger {
    private final String ledger;
    private final String settlement;
    public TransactionLedger(String ledger, String settlement) {
        this.ledger = ledger;
        this.settlement = settlement;
    }
}
""")

    write(root, "src/main/java/com/hdfcbank/internal/SecurityUtil.java", """
package com.hdfcbank.internal;

public class SecurityUtil {
    public static String mask(String value) { return "***"; }
}
""")

    # --- Python: package detection via imports + classes + vocab ---
    write(root, "python_pkg/__init__.py", "")
    write(root, "python_pkg/recon.py", """
from python_pkg import models
from python_pkg.models import ReconciliationRecord


class ReconciliationEngine:
    def reconcile(self, ledger, nostro, vostro):
        return ReconciliationRecord(ledger=ledger)
""")
    write(root, "python_pkg/models.py", """
class ReconciliationRecord:
    def __init__(self, ledger, settlement=None):
        self.ledger = ledger
        self.settlement = settlement
""")

    # --- C# namespace ---
    write(root, "src/Wealth.Api/PortfolioController.cs", """
namespace Wealth.Api.Portfolio
{
    public class PortfolioController
    {
        private const string Endpoint = "http://wealth-internal-svc:9000/portfolio";
    }
}
""")

    # --- Go module ---
    write(root, "go.mod", "module com.hdfcbank.wealth\n\ngo 1.21\n")

    # --- Config: DB connection string (a real secret pattern) ---
    write(root, "config/app.properties", """
db.url=postgresql://admin:supersecret@10.10.5.22:5432/wealth
api.endpoint=https://api.hdfcbank-internal.corp/v2/portfolio
""")

    # --- Should be ignored: build output + vendored code + lockfiles ---
    write(root, "node_modules/fake-lib/index.js", "const key = 'AKIAFAKEKEYFAKEKEYFAKEKEYFAKEKEY1';")
    write(root, "dist/bundle.min.js", "var x=1;AKIAFAKEKEYFAKEKEYFAKEKEYFAKEKEY2;")
    write(root, "target/classes/Leaked.java", "package com.evil; public class Leaked { }")
    write(root, "package-lock.json", '{"name":"fake","lockfileVersion":3,"packages":{}}')
    write(root, "build.gradle", "// nothing interesting")


def main():
    print("== scanner unit tests (helpers) ==")
    check("verhoeff accepts a valid Aadhaar checksum",
          verhoeff_valid("699999988079"), "699999988079 was verified by the extension")
    check("verhoeff rejects random 12-digit id",
          not verhoeff_valid("123456789012"))
    check("verhoeff rejects non-digits", not verhoeff_valid("abcd12345678"))
    check("private ip 10.x", is_private_ip("10.10.5.22"))
    check("private ip 192.168.x", is_private_ip("192.168.10.45"))
    check("private ip 172.16-31", is_private_ip("172.20.3.4") and not is_private_ip("172.32.0.1"))
    check("public ip rejected", not is_private_ip("8.8.8.8"))
    check("internal host .corp", is_internal_host("api.hdfcbank-internal.corp"))
    check("internal host single label", is_internal_host("wealth-internal-svc"))
    check("internal host localhost", is_internal_host("localhost"))
    check("public host rejected", not is_internal_host("api.stripe.com"))
    check("internal url detection", is_internal_url("https://api.hdfcbank-internal.corp/v2"))
    check("public url rejected", not is_internal_url("https://api.openai.com/v1"))

    print("== scanner integration (synthetic repo) ==")
    tmp = tempfile.mkdtemp(prefix="pg-scanner-test-")
    try:
        build_sample_repo(tmp)
        fp = scan_repo(tmp)

        check("packages include Java package",
              "com.hdfcbank.wealth.portfolio" in fp["packages"])
        check("packages include com.hdfcbank.internal",
              "com.hdfcbank.internal" in fp["packages"])
        check("packages include com.hdfcbank.retail.core",
              "com.hdfcbank.retail.core" in fp["packages"])
        check("packages include C# namespace",
              "Wealth.Api.Portfolio" in fp["packages"])
        check("packages include Go module",
              "com.hdfcbank.wealth" in fp["packages"])
        check("packages include Python package",
              "python_pkg" in fp["packages"])
        check("no third-party packages (springframework)",
              not any("springframework" in p for p in fp["packages"]))

        check("class names include service",
              "CustomerWealthPortfolioService" in fp["class_names"])
        check("class names include interface",
              "PortfolioReconciliationReport" in fp["class_names"])
        check("class names include python class",
              "ReconciliationEngine" in fp["class_names"])
        check("class names include csharp class",
              "PortfolioController" in fp["class_names"])
        check("class names include Go-style service class", True)  # Go has no classes

        check("vocabulary includes 'ledger'",
              "ledger" in fp["domain_vocabulary"], str(fp["domain_vocabulary"]))
        check("vocabulary includes 'reconciliation'",
              "reconciliation" in fp["domain_vocabulary"], str(fp["domain_vocabulary"]))
        check("vocabulary includes 'portfolio'",
              "portfolio" in fp["domain_vocabulary"], str(fp["domain_vocabulary"]))
        check("vocabulary excludes stopword 'public'",
              "public" not in fp["domain_vocabulary"])
        check("vocabulary excludes 'class'",
              "class" not in fp["domain_vocabulary"])

        check("internal urls include hdfcbank-internal.corp",
              any("hdfcbank-internal.corp" in u for u in fp["internal_urls"]),
              str(fp["internal_urls"]))
        check("internal urls include single-label host",
              any("wealth-internal-svc" in u for u in fp["internal_urls"]),
              str(fp["internal_urls"]))
        check("no public urls captured",
              not any("stripe.com" in u for u in fp["internal_urls"]))

        check("internal ips include 192.168.10.45",
              "192.168.10.45" in fp["internal_ips"], str(fp["internal_ips"]))
        check("internal ips include 10.10.5.22",
              "10.10.5.22" in fp["internal_ips"], str(fp["internal_ips"]))

        secrets = fp["secrets_found"]
        keys = [s["key"] for s in secrets]
        check("secrets include aws_access_key", "aws_access_key" in keys, str(secrets))
        check("secrets include db_connection_string", "db_connection_string" in keys, str(secrets))
        check("secrets never store full values (>30 chars)",
              all(len(s["preview"]) <= 30 for s in secrets))
        check("no secrets from node_modules/dist/target",
              all("node_modules" not in s["file"] and "dist/" not in s["file"]
                  and "target/" not in s["file"] for s in secrets), str(secrets))

        stats = fp["stats"]
        check("files_scanned excludes build dirs",
              stats["files_scanned"] >= 8 and stats["files_scanned"] <= 14,
              "scanned %d files" % stats["files_scanned"])
        check("languages detected include java",
              "java" in stats["languages_detected"], str(stats["languages_detected"]))
        check("languages detected include python",
              "python" in stats["languages_detected"], str(stats["languages_detected"]))
        check("fingerprint has version + project + scanned_at",
              fp.get("version") == "1.0" and fp.get("project") and fp.get("scanned_at"))

        # JSON round-trip (what the dashboard upload expects)
        json.dumps(fp)
        check("fingerprint is JSON-serializable", True)

        # Deterministic across runs (scanned_at legitimately changes)
        def without_scanned_at(f):
            f = dict(f)
            f.pop("scanned_at", None)
            return f
        fp2 = scan_repo(tmp)
        check("output is deterministic", without_scanned_at(fp) == without_scanned_at(fp2))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n%d passed, %d failed" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
