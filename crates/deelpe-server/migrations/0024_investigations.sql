-- AI summaries of an investigation: one question over every alert and notice
-- that a filter matches. Unlike `alert_insights` one row per question, never
-- overwritten. The dossier that went out stays here word for word, as there:
-- in a tool against data loss, what left the house must stay answerable.
--
-- The same dossier asked of the same model again is answered from here
-- (`api::investigate::summary`): it is the cache that keeps a paid service
-- from billing the same answer twice.
CREATE TABLE investigations (
  id                BIGSERIAL PRIMARY KEY,
  question          TEXT NOT NULL,
  model             TEXT NOT NULL,
  endpoint          TEXT NOT NULL,
  prompt            TEXT NOT NULL,
  summary           TEXT NOT NULL,
  -- What the provider counted; zero when it does not say.
  prompt_tokens     BIGINT NOT NULL DEFAULT 0,
  completion_tokens BIGINT NOT NULL DEFAULT 0,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by        UUID REFERENCES users(id) ON DELETE SET NULL,
  created_by_name   TEXT NOT NULL
);
CREATE INDEX investigations_prompt ON investigations (md5(prompt), model, endpoint);
