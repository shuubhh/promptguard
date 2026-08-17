#!/usr/bin/env python3
"""
e2e-check.py — PromptGuard Supabase end-to-end verification.

Checks, in order:
  1. All five tables exist and are reachable (anon key).
  2. The my_org_id() RPC function exists.
  3. Full API-level E2E (requires email confirmation to be OFF, or the signup
     to return a session):
       signup a throwaway user  ->  create organisation  ->  attach profile
       ->  create a project with a fakebank fingerprint  ->  insert an event
       with the EXACT payload shape the extension sends  ->  read it back.

Creates clearly-named TEST data ("PromptGuard E2E ...") you can delete later.

Run with:
    python dashboard/scripts/e2e-check.py
"""
import datetime
import json
import sys
import urllib.error
import urllib.request

ENV_FILE = "dashboard/.env"


def read_env():
    vals = {}
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("VITE_"):
                k, _, v = line.partition("=")
                vals[k] = v.strip().strip('"').strip("'")
    return vals


def req(url, path, method="GET", body=None, token=None, extra_headers=None):
    headers = {"apikey": KEY, "Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=25) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def main():
    env = read_env()
    url = env.get("VITE_SUPABASE_URL", "").rstrip("/")
    global KEY
    KEY = env.get("VITE_SUPABASE_ANON_KEY", "")
    if not url or not KEY:
        print("FAIL: missing VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY in .env")
        return 1

    ok = True

    print("== 1. Tables (anon key) ==")
    for t in ["organisations", "projects", "events", "user_profiles", "invites"]:
        code, body = req(url, "/rest/v1/%s?select=id&limit=1" % t)
        good = code == 200
        ok = ok and good
        print("  %s %-15s HTTP %s" % ("OK " if good else "ERR", t, code))
        if not good and isinstance(body, dict):
            print("      ", body.get("message") or body.get("code"))

    print("== 2. RPC my_org_id ==")
    code, body = req(url, "/rest/v1/rpc/my_org_id", "POST", {})
    if code == 200:
        print("  OK function exists (anon call -> %r as expected)" % body)
    else:
        ok = False
        print("  ERR HTTP %s %s" % (code, body))

    print("== 3. API E2E (signup -> org -> project -> event) ==")
    stamp = datetime.datetime.now().strftime("%H%M%S")
    email = "pg.e2e.%s@gmail.com" % stamp
    password = "PromptGuard-E2E-2026!"
    code, body = req(url, "/auth/v1/signup", "POST", {"email": email, "password": password})
    if code not in (200, 201):
        print("  ERR signup HTTP %s: %s" % (code, body))
        print("\nIf it says email confirmation is required, disable it in")
        print("Supabase -> Authentication -> Providers -> Email -> Confirm email, or")
        print("confirm the signup email, then re-run.")
        return 1

    # GoTrue returns the session at the TOP level of the signup response
    # ({access_token, refresh_token, user...}); supabase-js wraps it under
    # `session`. Accept both shapes.
    user = body.get("user") or {}
    session = body.get("session") or {}
    token = session.get("access_token") or body.get("access_token")
    uid = user.get("id") or body.get("id")
    print("  signup ok for %s (uid %s)" % (email, uid))
    if not token:
        print("  no session returned — email confirmation may still be ON.")
        print("  Check Authentication -> Providers -> Email -> Confirm email, then re-run.")
        return 1

    # -- organisation (atomic RPC: creates org + attaches profile as owner) --
    code, body = req(url, "/rest/v1/rpc/create_organisation_with_owner", "POST", {"org_name": "PromptGuard E2E Test Org"}, token)
    if code not in (200, 201) or not isinstance(body, dict) or not body.get("id"):
        ok = False
        print("  ERR create organisation HTTP %s: %s" % (code, body))
        return 1
    org_id = body["id"]
    print("  organisation created (owner attached): %s" % org_id)

    # -- project with fingerprint --
    repr_hdr = {"Prefer": "return=representation"}
    fingerprint = {
        "version": "1.0",
        "project": "E2E FakeBank",
        "packages": ["com.e2e.fakebank.wealth", "com.e2e.fakebank.retail"],
        "class_names": ["E2eWealthService", "E2eLedgerRecon"],
        "domain_vocabulary": ["ledger", "nostro", "portfolio"],
        "internal_urls": ["https://api.e2e-internal.corp/v2"],
        "internal_ips": ["192.168.9.9"],
        "secrets_found": [],
    }
    code, body = req(url, "/rest/v1/projects", "POST", {"org_id": org_id, "name": "E2E FakeBank", "fingerprint": fingerprint}, token, repr_hdr)
    if code not in (200, 201) or not isinstance(body, list) or not body:
        ok = False
        print("  ERR create project HTTP %s: %s" % (code, body))
        return 1
    project_id = body[0]["id"]
    print("  project created: %s" % project_id)

    # -- event exactly as the extension sends it --
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    event = {
        "timestamp": now,
        "org_id": org_id,
        "project_id": project_id,
        "user_email": email,
        "event_type": "blocked",
        "confidence": 0.99,
        "regex_score": 0.99,
        "ai_used": False,
        "ai_label": None,
        "match_type": "aws_access_key",
        "match_label": "AWS Access Key",
        "match_preview": "AKIAIOSFODNN7EXAMPLE",
        "project_name": "E2E FakeBank",
        "matched_projects": ["E2E FakeBank"],
        "platform": "chatgpt",
        "url": "https://chatgpt.com/",
    }
    code, body = req(url, "/rest/v1/events", "POST", event, token, repr_hdr)
    if code not in (200, 201):
        ok = False
        print("  ERR insert event HTTP %s: %s" % (code, body))
        if isinstance(body, dict) and "code" in body:
            print("\n  This is usually a column mismatch between the extension payload")
            print("  and the events table. If you see PGRST204, run the migration:")
            print("  dashboard/supabase/migrations/001_add_event_columns.sql")
        return 1
    print("  event inserted (HTTP %s)" % code)

    # -- read back --
    code, body = req(url, "/rest/v1/events?select=*&order=timestamp.desc&limit=3", token=token)
    if code == 200 and body:
        ev = body[0]
        print("  read-back ok: %s | %s | %s | conf %s" % (
            ev.get("event_type"), ev.get("match_type"), ev.get("platform"), ev.get("confidence")))
    else:
        ok = False
        print("  ERR read events HTTP %s: %s" % (code, body))

    print("\nTest data created (delete from Supabase when done):")
    print("  user: %s" % email)
    print("  org:  PromptGuard E2E Test Org (%s)" % org_id)
    print("  project: E2E FakeBank (%s)" % project_id)
    print("\n%s" % ("ALL CHECKS PASSED" if ok else "SOME CHECKS FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
