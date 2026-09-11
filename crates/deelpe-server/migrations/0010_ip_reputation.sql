-- IP reputation (AbuseIPDB). The central server's cache: one row per
-- address, so that the same address does not cost quota again in every
-- report. This used to live in the Mac client, every Mac with its own key
-- and its own cache.
CREATE TABLE ip_reputations (
  ip             TEXT PRIMARY KEY,
  score          INT NOT NULL,
  country_code   TEXT,
  isp            TEXT,
  domain         TEXT,
  usage_type     TEXT,
  total_reports  INT NOT NULL DEFAULT 0,
  is_tor         BOOLEAN NOT NULL DEFAULT FALSE,
  is_whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
  checked_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Counting the daily budget and cleaning up both go by time.
CREATE INDEX ip_reputations_checked_at ON ip_reputations (checked_at);
