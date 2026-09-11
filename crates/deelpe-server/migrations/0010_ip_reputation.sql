-- IP-Ruf (AbuseIPDB). Der Cache der Zentrale: eine Zeile je Adresse, damit
-- dieselbe Adresse nicht in jedem Bericht erneut Kontingent kostet. Vorher
-- lag das im Mac-Client, jeder Mac mit eigenem Schluessel und eigenem Cache.
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

-- Tagesbudget zaehlen und aufraeumen gehen beide ueber die Zeit.
CREATE INDEX ip_reputations_checked_at ON ip_reputations (checked_at);
