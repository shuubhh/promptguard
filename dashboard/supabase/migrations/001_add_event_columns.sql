-- ============================================================
-- 001_add_event_columns.sql
-- Adds the columns the extension sends (and the dashboard displays)
-- that were missing from the original events table definition.
-- Idempotent — safe to re-run.
-- ============================================================

alter table public.events
  add column if not exists regex_score float,
  add column if not exists ai_used boolean,
  add column if not exists ai_label text,
  add column if not exists match_label text,
  add column if not exists project_name text,
  add column if not exists matched_projects jsonb,
  add column if not exists url text;
