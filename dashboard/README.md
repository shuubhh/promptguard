# PromptGuard — Web Dashboard (Component 3)

React + Vite + TailwindCSS (v4) + Supabase. No custom backend for v1 — Supabase
handles auth, database and the REST API the extension talks to.

## Prerequisites

- Node.js 18+ (not currently installed on this machine — install from
  https://nodejs.org first)
- A Supabase project (free tier is fine): https://supabase.com/dashboard

## 1. Supabase setup

1. Create a Supabase project.
2. Open **SQL Editor** and run the whole file `supabase/schema.sql`.
   This creates `organisations`, `projects`, `user_profiles`, `events` and
   `invites`, the auth-signup trigger, and all Row Level Security policies
   (org isolation).
3. **If you already ran an older copy of `schema.sql`**, also run the
   migrations in order:
   - `supabase/migrations/001_add_event_columns.sql` (extension payload columns)
   - `supabase/migrations/002_org_creation_rpc.sql` (atomic org-creation RPC,
     required for first-login onboarding — without it, creating an org fails
     with an RLS 42501 error)
   - `supabase/migrations/003_allow_event_cleanup.sql` (RLS policy so the
     popup's "Test Connection" can delete its probe row; without it test rows
     remain but are hidden on the Events page by default)
3. Go to **Project Settings → API** and copy the **Project URL** and the
   **anon/public key**.

## 2. Run locally

```bash
cd dashboard
cp .env.example .env        # then paste your Supabase URL + anon key
npm install
npm run dev                 # http://localhost:5173
```

Build for production: `npm run build` (output in `dist/`).

## 3. Deploy to Vercel

1. Push this `dashboard/` folder to a Git repo.
2. Import it in Vercel (framework preset: Vite).
3. Add the environment variables `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY`.
4. Deploy. Login/Signup works immediately.

## 4. Connect the extension

1. In the dashboard: **Settings → Extension API key**.
2. In the browser extension popup (🛡️ toolbar icon): paste the Supabase URL,
   the anon key, and the API key, then **Save & Fetch Projects**.
3. The extension now pulls the org's project fingerprints and POSTs every
   blocked/override/warned/silent event to `POST /rest/v1/events` with the
   user's JWT — events appear in the dashboard in near real time.

## Pages

| Route      | Purpose                                                        |
| ---------- | -------------------------------------------------------------- |
| `/login`   | Email + password auth; org name prompt on first signup         |
| `/`        | Stats, 7-day flagged-vs-allowed chart, recent events, alert banner |
| `/events`  | Full audit log: filters (date/project/user/type), expandable rows, CSV export |
| `/projects`| Fingerprint upload (from the Python scanner), deploy invite link |
| `/team`    | Member list + invites                                          |
| `/settings`| Org name, plan usage, extension download, extension API key    |

## Verification script

`python scripts/e2e-check.py` (after filling `.env`) checks the five tables,
the `my_org_id()` RPC, and runs an API-level end-to-end test: signup →
organisation → project → event insert with the extension's exact payload →
read-back. Requires email confirmation to be **off** in Authentication →
Providers → Email. It creates clearly-named test data you can delete.

## Notes

- The repo-URL scanner option in Projects is intentionally a **v2 "coming
  soon"** placeholder, as in the brief.
- Email delivery for invites is stubbed (invites are recorded); the trigger
  pipeline ships in v2.
- All events store only 30-char match previews — never full secret values.
