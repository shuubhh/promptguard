-- ============================================================
-- PromptGuard migration 003 — allow cleanup of connection-test rows
--
-- The extension popup's "Test Connection" button POSTs a probe event to prove
-- the auth/RLS pipeline works, then deletes it so the audit log stays clean.
-- This policy permits deletion ONLY of rows where match_type =
-- 'connection_test' — real audit events can never be deleted through the API.
-- Idempotent: safe to run multiple times.
-- ============================================================

drop policy if exists "org members delete connection test events" on public.events;
create policy "org members delete connection test events" on public.events
  for delete using (
    org_id = public.my_org_id()
    and match_type = 'connection_test'
  );
