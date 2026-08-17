#!/usr/bin/env node
/**
 * run-repo-scanner-tests.mjs — headless tests for the dashboard's JS scanner
 * (dashboard/src/lib/repoScanner.js).
 *
 * Covers: URL parsing, the extraction logic (packages / classes / vocab /
 * URLs / IPs / secrets), the entropy gate, Verhoeff validation, value
 * hashing, and exclusion of build/vendored dirs — mirroring the Python
 * scanner's test suite so the two implementations stay in parity.
 *
 * Run with:  node dashboard/scripts/run-repo-scanner-tests.mjs
 */

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { parseRepoUrl, scanFiles } = await import('../src/lib/repoScanner.js');

let pass = 0;
let fail = 0;

function check(name, cond, detail = '') {
  if (cond) {
    pass += 1;
    console.log('  \u2713 ' + name);
  } else {
    fail += 1;
    console.log('  \u2717 ' + name + '  ' + detail);
  }
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------
console.log('== URL parsing ==');
let m = parseRepoUrl('https://github.com/shuubhh/promptguard');
check('github https', m.provider === 'github' && m.owner === 'shuubhh' && m.repo === 'promptguard', JSON.stringify(m));
m = parseRepoUrl('https://github.com/shuubhh/promptguard.git');
check('github with .git', m.repo === 'promptguard', JSON.stringify(m));
m = parseRepoUrl('https://gitlab.com/group/sub/repo');
check('gitlab nested group', m.provider === 'gitlab' && m.projectPath === 'group/sub/repo' && m.repo === 'repo', JSON.stringify(m));
m = parseRepoUrl('https://github.com/a/b?ref=dev');
check('github with ref param', m.branch === 'dev', JSON.stringify(m));
let threw = false;
try { parseRepoUrl('https://bitbucket.org/a/b'); } catch (e) { threw = true; }
check('bitbucket rejected', threw);
threw = false;
try { parseRepoUrl('not a url'); } catch (e) { threw = true; }
check('garbage rejected', threw);
threw = false;
try { parseRepoUrl('https://github.com/onlyowner'); } catch (e) { threw = true; }
check('missing repo rejected', threw);

// ---------------------------------------------------------------------------
// scanFiles — synthetic repo mirroring the Python test fixtures
// ---------------------------------------------------------------------------
console.log('== scanFiles (synthetic repo) ==');

const files = {
  'src/main/java/com/hdfcbank/wealth/portfolio/CustomerWealthPortfolioService.java': `
package com.hdfcbank.wealth.portfolio;

import com.hdfcbank.internal.SecurityUtil;
import org.springframework.stereotype.Service;

@Service
public class CustomerWealthPortfolioService implements PortfolioReconciliationReport {
    private static final String API_URL = "https://api.hdfcbank-internal.corp/v2/portfolio";
    private static final String HOST = "http://192.168.10.45:8080";
    private final String aws = "AKIAIOSFODNN7EXAMPLE";
}
`,
  'src/main/java/com/hdfcbank/wealth/portfolio/PortfolioReconciliationReport.java': `
package com.hdfcbank.wealth.portfolio;

public interface PortfolioReconciliationReport {
    void reconcileLedger(String nostroAccount, String vostroAccount);
}
`,
  'src/main/java/com/hdfcbank/retail/core/TransactionLedger.java': `
package com.hdfcbank.retail.core;

public class TransactionLedger {
    private final String ledger;
    private final String settlement;
    public TransactionLedger(String ledger, String settlement) {
        this.ledger = ledger;
        this.settlement = settlement;
    }
}
`,
  'src/main/java/com/hdfcbank/internal/SecurityUtil.java': `
package com.hdfcbank.internal;

public class SecurityUtil {
    public static String mask(String value) { return "***"; }
}
`,
  'python_pkg/__init__.py': '',
  'python_pkg/recon.py': `
from python_pkg import models
from python_pkg.models import ReconciliationRecord


class ReconciliationEngine:
    def reconcile(self, ledger, nostro, vostro):
        return ReconciliationRecord(ledger=ledger)
`,
  'python_pkg/models.py': `
class ReconciliationRecord:
    def __init__(self, ledger, settlement=None):
        self.ledger = ledger
        self.settlement = settlement
`,
  'src/Wealth.Api/PortfolioController.cs': `
namespace Wealth.Api.Portfolio
{
    public class PortfolioController
    {
        private const string Endpoint = "http://wealth-internal-svc:9000/portfolio";
    }
}
`,
  'go.mod': 'module com.hdfcbank.wealth\n\ngo 1.21\n',
  'config/app.properties': `
db.url=postgresql://admin:supersecret@10.10.5.22:5432/wealth
api.endpoint=https://api.hdfcbank-internal.corp/v2/portfolio
`,
  'config/creds.env': `
DB_PASSWORD='Xk9#mP2$vLqRz8!'
DEBUG_PASSWORD='demo'
`,
  'src/infra/AwsClient.java': `
package com.hdfcbank.infra;
public class AwsClient {
    private static final String AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    private static final String SENDGRID = "SG.aaaaaaaaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    private static final String TWILIO = "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
}
`,
  // Should be ignored
  'node_modules/fake-lib/index.js': "const key = 'AKIAFAKEKEYFAKEKEYFAKEKEYFAKEKEY1';",
  'dist/bundle.min.js': 'var x=1;AKIAFAKEKEYFAKEKEYFAKEKEYFAKEKEY2;',
  'target/classes/Leaked.java': 'package com.evil; public class Leaked { }',
  'package-lock.json': '{"name":"fake","lockfileVersion":3,"packages":{}}',
  'build.gradle': '// nothing interesting'
};

const fp = await scanFiles(files, { project: 'TestRepo' });

check('packages include Java package', fp.packages.includes('com.hdfcbank.wealth.portfolio'), JSON.stringify(fp.packages));
check('packages include com.hdfcbank.internal', fp.packages.includes('com.hdfcbank.internal'), JSON.stringify(fp.packages));
check('packages include com.hdfcbank.retail.core', fp.packages.includes('com.hdfcbank.retail.core'), JSON.stringify(fp.packages));
check('packages include C# namespace', fp.packages.includes('Wealth.Api.Portfolio'), JSON.stringify(fp.packages));
check('packages include Go module', fp.packages.includes('com.hdfcbank.wealth'), JSON.stringify(fp.packages));
check('packages include Python package', fp.packages.includes('python_pkg'), JSON.stringify(fp.packages));
check('no third-party packages', !fp.packages.some((p) => p.includes('springframework')), JSON.stringify(fp.packages));

check('class names include service', fp.class_names.includes('CustomerWealthPortfolioService'), JSON.stringify(fp.class_names));
check('class names include interface', fp.class_names.includes('PortfolioReconciliationReport'), JSON.stringify(fp.class_names));
check('class names include python class', fp.class_names.includes('ReconciliationEngine'), JSON.stringify(fp.class_names));
check('class names include csharp class', fp.class_names.includes('PortfolioController'), JSON.stringify(fp.class_names));

check('vocabulary includes ledger', fp.domain_vocabulary.includes('ledger'), JSON.stringify(fp.domain_vocabulary));
check('vocabulary includes reconciliation', fp.domain_vocabulary.includes('reconciliation'), JSON.stringify(fp.domain_vocabulary));
check('vocabulary includes portfolio', fp.domain_vocabulary.includes('portfolio'), JSON.stringify(fp.domain_vocabulary));
check('vocabulary includes curated nostro', fp.domain_vocabulary.includes('nostro'), JSON.stringify(fp.domain_vocabulary));
check('vocabulary excludes stopword public', !fp.domain_vocabulary.includes('public'), JSON.stringify(fp.domain_vocabulary));
check('vocabulary excludes class', !fp.domain_vocabulary.includes('class'), JSON.stringify(fp.domain_vocabulary));

check('internal urls include hdfcbank-internal.corp', fp.internal_urls.some((u) => u.includes('hdfcbank-internal.corp')), JSON.stringify(fp.internal_urls));
check('internal urls include single-label host', fp.internal_urls.some((u) => u.includes('wealth-internal-svc')), JSON.stringify(fp.internal_urls));
check('no public urls captured', !fp.internal_urls.some((u) => u.includes('stripe.com')), JSON.stringify(fp.internal_urls));

check('internal ips include 192.168.10.45', fp.internal_ips.includes('192.168.10.45'), JSON.stringify(fp.internal_ips));
check('internal ips include 10.10.5.22', fp.internal_ips.includes('10.10.5.22'), JSON.stringify(fp.internal_ips));

const keys = fp.secrets_found.map((s) => s.key);
check('secrets include aws_access_key', keys.includes('aws_access_key'), JSON.stringify(keys));
check('secrets include db_connection_string', keys.includes('db_connection_string'), JSON.stringify(keys));
check('secrets include aws_secret_key', keys.includes('aws_secret_key'), JSON.stringify(keys));
check('secrets include sendgrid_key', keys.includes('sendgrid_key'), JSON.stringify(keys));
check('secrets include twilio_sid', keys.includes('twilio_sid'), JSON.stringify(keys));
check('secrets include generic_password', keys.includes('generic_password'), JSON.stringify(keys));
check('secrets exclude low-entropy password', !fp.secrets_found.some((s) => s.key === 'generic_password' && s.preview.includes('demo')), JSON.stringify(fp.secrets_found));
check('every secret has value_hash', fp.secrets_found.every((s) => s.value_hash && s.value_hash.length === 16));
check('every secret has line number', fp.secrets_found.every((s) => typeof s.line === 'number' && s.line > 0));
check('secrets previews <= 9 chars', fp.secrets_found.every((s) => s.preview.length <= 9), JSON.stringify(fp.secrets_found.map((s) => s.preview)));
check('no secrets from build/vendored dirs', fp.secrets_found.every((s) => !s.file.includes('node_modules') && !s.file.includes('dist/') && !s.file.includes('target/')), JSON.stringify(fp.secrets_found.map((s) => s.file)));

check('files_scanned excludes build dirs', fp.stats.files_scanned >= 8 && fp.stats.files_scanned <= 14, String(fp.stats.files_scanned));
check('languages include java', fp.stats.languages_detected.includes('java'), JSON.stringify(fp.stats.languages_detected));
check('languages include python', fp.stats.languages_detected.includes('python'), JSON.stringify(fp.stats.languages_detected));
check('fingerprint shape complete', fp.version === '1.0' && fp.project === 'TestRepo' && !!fp.scanned_at);

// Determinism (excluding scanned_at)
const fp2 = await scanFiles(files, { project: 'TestRepo' });
const { scanned_at, ...rest1 } = fp;
const { scanned_at: _sa2, ...rest2 } = fp2;
check('output is deterministic', JSON.stringify(rest1) === JSON.stringify(rest2));

// ---------------------------------------------------------------------------
// Secret validator edge cases
// ---------------------------------------------------------------------------
console.log('== secret validator edge cases ==');
const aadhaarFiles = {
  'config/aadhaar-valid.properties': 'aadhaar=699999988079',
  'config/aadhaar-random.properties': 'random=123456789012'
};
const aadhaarFp = await scanFiles(aadhaarFiles);
check('valid Verhoeff Aadhaar flagged', aadhaarFp.secrets_found.some((s) => s.key === 'aadhaar_number' && s.preview.includes('699999')), JSON.stringify(aadhaarFp.secrets_found));
check('random 12-digit not flagged', !aadhaarFp.secrets_found.some((s) => s.key === 'aadhaar_number' && s.preview.includes('123456')), JSON.stringify(aadhaarFp.secrets_found));

// ---------------------------------------------------------------------------
// Verhoeff + entropy helpers
// ---------------------------------------------------------------------------
console.log('== helpers ==');
// (verhoeffValid and shannonEntropy aren't exported; verified via scanFiles above)

console.log('\n%d passed, %d failed', pass, fail);
process.exit(fail === 0 ? 0 : 1);
