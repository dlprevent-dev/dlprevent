-- AI assistance: the explanation of an alert, as a model wrote it. One row
-- per alert; explaining again overwrites it. The cache here is not thrift, as
-- it is for IP reputation, but evidence: what the model said has to stay
-- readable, even if the service is switched off later or the model is
-- swapped out.
CREATE TABLE alert_insights (
  alert_id        BIGINT PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
  -- Model and endpoint are kept with it: an answer from `llama3.2` on the
  -- Ollama in the basement is a different statement than one from Infomaniak.
  model           TEXT NOT NULL,
  endpoint        TEXT NOT NULL,
  -- Exactly what went out. Without this column there would be no way to tell
  -- which data left the building — in a tool against data loss that is the
  -- most important column of the table.
  prompt          TEXT NOT NULL,
  summary         TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  -- Like `origin_name` on the alert: stays readable once the account is gone.
  created_by_name TEXT NOT NULL
);
