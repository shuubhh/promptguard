-- ============================================================
-- 002_org_creation_rpc.sql
-- Atomic first-login org creation.
--
-- Why: creating an organisation via a plain INSERT + SELECT fails
-- RLS on a brand-new user — the "org members read org" policy needs
-- the user's profile to already point at the org, but the profile is
-- only attached AFTER the org exists. This security-definer RPC does
-- both in one transaction and returns the new org row.
-- ============================================================

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
