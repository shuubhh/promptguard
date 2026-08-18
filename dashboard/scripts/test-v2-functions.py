"""
E2E test for the v2 edge functions (org auto-config + accountability backend).

Exercises the exact loop the extension will run:
  join-org (code) -> device token -> org-config / heartbeat / log-event
  and verifies the audit event landed with device attribution.

Requires: SUPABASE_ACCESS_TOKEN (sbp_...) in env, and dashboard/.env
(VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY). Creates clearly-named test
data ("V2 Device Test Org") you can delete in the Table Editor.

Usage:
  SUPABASE_ACCESS_TOKEN=sbp_... py dashboard/scripts/test-v2-functions.py
"""

import hashlib
import json
import os
import random
import re
import string
import sys
import urllib.error
import urllib.request

PROJECT_REF = None  # resolved from .env
MGMT = "https://api.supabase.com/v1"
UA = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0",
    "Content-Type": "application/json",
}
TOKEN = os.environ.get("SUPABASE_ACCESS_TOKEN", "")


def read_env():
    env = {}
    with open(os.path.join(os.path.dirname(__file__), "..", ".env"), encoding="utf-8") as f:
        for line in f:
            m = re.match(r"([A-Z_]+)=(.*)", line.strip())
            if m:
                env[m.group(1)] = m.group(2)
    return env


def mgmt(sql):
    req = urllib.request.Request(
        f"{MGMT}/projects/{PROJECT_REF}/database/query",
        data=json.dumps({"query": sql}).encode(),
        headers={**UA, "Authorization": f"Bearer {TOKEN}"},
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())


def fn(name, body, token=None, method="POST"):
    headers = {**UA, "apikey": ANON}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if method == "POST" else None
    req = urllib.request.Request(
        f"{BASE}/functions/v1/{name}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def gen_code():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(random.choice(alphabet) for _ in range(8))


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


PASS = 0
FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {detail}")


if __name__ == "__main__":
    if not TOKEN:
        print("SUPABASE_ACCESS_TOKEN env var required"); sys.exit(1)
    env = read_env()
    url = env.get("VITE_SUPABASE_URL", "")
    ANON = env.get("VITE_SUPABASE_ANON_KEY", "")
    m = re.search(r"https://([^.]+)\.supabase\.co", url)
    if not m:
        print("could not resolve project ref from .env"); sys.exit(1)
    PROJECT_REF = m.group(1)
    BASE = f"https://{PROJECT_REF}.supabase.co"

    print(f"project: {PROJECT_REF}")

    # 1. Fresh test org
    org = mgmt(
        "insert into organisations (name, plan, max_projects, max_users) "
        "values ('V2 Device Test Org', 'free', 1, 5) returning id, name"
    )[0]
    org_id = org["id"]
    print(f"test org: {org['name']} ({org_id[:8]}...)")

    # 2. Insert a join code directly (as an admin would via org-admin)
    code = gen_code()
    mgmt(
        "insert into extension_join_codes (org_id, created_by, code_hash, expires_at) "
        f"values ('{org_id}', 'test-admin@example.com', '{sha256_hex(code)}', now() + interval '1 hour')"
    )
    print(f"join code: {code}")

    # 3. join-org
    st, r = fn("join-org", {"code": code, "device_name": "E2E test device", "user_email": "dev@example.com"})
    check("join-org returns 201", st == 201, f"got {st}: {r}")
    check("join-org returns device_token", bool(r.get("device_token")))
    device_token = r.get("device_token", "")
    check("join-org returns org_id", r.get("org_id") == org_id, str(r.get("org_id")))

    # 4. code is single-use
    st, r = fn("join-org", {"code": code, "device_name": "second device"})
    check("code rejected after use", st == 409, f"got {st}: {r}")

    # 5. org-config
    st, r = fn("org-config", {}, device_token, method="GET")
    check("org-config 200", st == 200, f"got {st}: {r}")
    check("org-config policy defaults", r.get("policy", {}).get("warn_threshold") == 0.7, str(r.get("policy")))
    check("org-config projects list", isinstance(r.get("projects"), list))

    # 6. heartbeat
    st, r = fn("heartbeat", {}, device_token)
    check("heartbeat 200", st == 200 and r.get("ok") is True, f"got {st}: {r}")

    # 7. log-event
    st, r = fn("log-event", {
        "event_type": "silent",
        "confidence": 0.35,
        "match_type": "vocabulary",
        "match_preview": "ledger reconciliation test",
        "platform": "chatgpt",
    }, device_token)
    check("log-event 201", st == 201, f"got {st}: {r}")

    # 8. verify the row landed with device attribution
    rows = mgmt(
        "select event_type, confidence, match_preview, user_email, device_id, device_name "
        f"from events where org_id = '{org_id}' order by timestamp desc limit 1"
    )
    check("event row persisted", len(rows) == 1, str(rows))
    if rows:
        row = rows[0]
        check("event has device_id", bool(row.get("device_id")))
        check("event user_email from device", row.get("user_email") == "dev@example.com", str(row.get("user_email")))

    # 9. bad device token rejected
    st, r = fn("heartbeat", {}, "bogus-token")
    check("bad device token -> 401", st == 401, f"got {st}: {r}")

    # 10. invalid event rejected
    st, r = fn("log-event", {"event_type": "nonsense", "confidence": 0.5}, device_token)
    check("invalid event_type -> 400", st == 400, f"got {st}: {r}")

    print(f"\n{PASS} passed, {FAIL} failed")
    print(f"test org id for cleanup: {org_id}")
    sys.exit(1 if FAIL else 0)
