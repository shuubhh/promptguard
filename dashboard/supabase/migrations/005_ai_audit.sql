-- 005: AI audit fields on events (additive)
-- The dual-engine audit trail: whether Gemini Nano adjudicated an event,
-- what it said, which engine, and the deterministic regex score it blended.
alter table events
  add column if not exists ai_used boolean,
  add column if not exists ai_label text,
  add column if not exists ai_model text,
  add column if not exists regex_score double precision;
