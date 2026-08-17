-- ============================================================
-- PromptGuard — Supabase schema (run in the Supabase SQL editor)
-- Mirrors the brief's Component 3 schema, plus:
--   * user_profiles trigger + email column
--   * org onboarding helpers
--   * invites table (v2 email pipeline)
--   * RLS: users only see their own org's data
-- ============================================================

-- ---------- Organisations ----------
create table if not exists public.organisations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz default now(),
  plan text default 'free',
  max_projects int default 1,
  max_users int default 5
);

-- ---------- Projects ----------
create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.organisations(id) on delete cascade,
  name text not null,
  fingerprint jsonb,
  created_at timestamptz default now(),
  last_scanned_at timestamptz
);
create index if not exists idx_projects_org on public.projects(org_id);

-- ---------- User profiles (extends auth.users) ----------
create table if not exists public.user_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  org_id uuid references public.organisations(id) on delete set null,
  role text default 'developer',
  full_name text,
  email text,
  created_at timestamptz default now()
);
create index if not exists idx_profiles_org on public.user_profiles(org_id);

-- Auto-create a profile whenever an auth user signs up.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.user_profiles (id, email, full_name, role)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'full_name', new.email),
    'owner'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- Events (audit log) ----------
create table if not exists public.events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.organisations(id) on delete cascade,
  project_id uuid references public.projects(id) on delete set null,
  user_email text,
  event_type text,          -- 'blocked', 'override', 'warned', 'silent', 'redacted'
  confidence float,
  match_type text,          -- 'aws_key', 'package_name', 'class_name' etc
  match_preview text,       -- first 30 chars of what matched (not full)
  platform text,            -- 'chatgpt', 'claude', 'gemini' etc
  timestamp timestamptz default now(),
  -- Additional fields sent by the extension and shown in the dashboard:
  regex_score float,
  ai_used boolean,
  ai_label text,
  match_label text,
  project_name text,
  matched_projects jsonb,
  url text
);
create index if not exists idx_events_org_time on public.events(org_id, timestamp desc);
create index if not exists idx_events_org_type on public.events(org_id, event_type);

-- ---------- Invites (v2 email pipeline) ----------
create table if not exists public.invites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.organisations(id) on delete cascade,
  email text not null,
  role text default 'developer',
  status text default 'pending',   -- pending | accepted | revoked
  created_at timestamptz default now()
);
create index if not exists idx_invites_org on public.invites(org_id);

-- ============================================================
-- ROW LEVEL SECURITY
-- ============================================================
alter table public.organisations enable row level security;
alter table public.projects enable row level security;
alter table public.user_profiles enable row level security;
alter table public.events enable row level security;
alter table public.invites enable row level security;

-- Helper: the caller's org id (used by several policies).
create or replace function public.my_org_id()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select org_id from public.user_profiles where id = auth.uid()
$$;

-- Atomic org creation for first login (avoids the RLS chicken-and-egg where
-- the new org can't be read back until the profile points at it).
create or replace function public.create_organisation_with_owner(org_name text)
returns public.organisations
language plpgsql
security definer
set search_path = public
as $$
declare
  new_org public.organisations;
begin
  insert into public.organisations (name)
  values (org_name)
  returning * into new_org;

  update public.user_profiles
     set org_id = new_org.id,
         role = 'owner'
   where id = auth.uid();

  return new_org;
end;
$$;

grant execute on function public.create_organisation_with_owner(text) to authenticated;

-- ---------- Organisations ----------
-- Members of an org can read it; the owner can rename it. Any authenticated
-- user may create one (org onboarding happens on first signup).
drop policy if exists "org members read org" on public.organisations;
create policy "org members read org" on public.organisations
  for select using (id = public.my_org_id());

drop policy if exists "org owner update org" on public.organisations;
create policy "org owner update org" on public.organisations
  for update using (
    id = public.my_org_id()
    and exists (
      select 1 from public.user_profiles
      where id = auth.uid() and role = 'owner' and org_id = public.organisations.id
    )
  );

drop policy if exists "any authenticated user creates org" on public.organisations;
create policy "any authenticated user creates org" on public.organisations
  for insert with check (auth.uid() is not null);

-- ---------- Projects ----------
drop policy if exists "org members read projects" on public.projects;
create policy "org members read projects" on public.projects
  for select using (org_id = public.my_org_id());

drop policy if exists "org owners insert projects" on public.projects;
create policy "org owners insert projects" on public.projects
  for insert with check (
    org_id = public.my_org_id()
    and exists (
      select 1 from public.user_profiles
      where id = auth.uid() and role = 'owner' and org_id = public.projects.org_id
    )
  );

drop policy if exists "org owners update projects" on public.projects;
create policy "org owners update projects" on public.projects
  for update using (
    org_id = public.my_org_id()
    and exists (
      select 1 from public.user_profiles
      where id = auth.uid() and role = 'owner' and org_id = public.projects.org_id
    )
  );

-- ---------- User profiles ----------
drop policy if exists "profiles read self or org" on public.user_profiles;
create policy "profiles read self or org" on public.user_profiles
  for select using (id = auth.uid() or org_id = public.my_org_id());

drop policy if exists "profiles update self" on public.user_profiles;
create policy "profiles update self" on public.user_profiles
  for update using (id = auth.uid());

-- ---------- Events ----------
-- The extension POSTs events with the user's JWT; RLS restricts every read
-- and write to the caller's own org.
drop policy if exists "org members read events" on public.events;
create policy "org members read events" on public.events
  for select using (org_id = public.my_org_id());

drop policy if exists "org members insert events" on public.events;
create policy "org members insert events" on public.events
  for insert with check (org_id = public.my_org_id());

-- Members may delete ONLY diagnostic connection-test rows (used by the popup's
-- "Test Connection" button to clean up its probe event). Real audit rows can
-- never be deleted through the API.
drop policy if exists "org members delete connection test events" on public.events;
create policy "org members delete connection test events" on public.events
  for delete using (
    org_id = public.my_org_id()
    and match_type = 'connection_test'
  );

-- ---------- Invites ----------
drop policy if exists "org owners read invites" on public.invites;
create policy "org owners read invites" on public.invites
  for select using (
    org_id = public.my_org_id()
    and exists (
      select 1 from public.user_profiles
      where id = auth.uid() and role = 'owner' and org_id = public.invites.org_id
    )
  );

drop policy if exists "org owners insert invites" on public.invites;
create policy "org owners insert invites" on public.invites
  for insert with check (
    org_id = public.my_org_id()
    and exists (
      select 1 from public.user_profiles
      where id = auth.uid() and role = 'owner' and org_id = public.invites.org_id
    )
  );
