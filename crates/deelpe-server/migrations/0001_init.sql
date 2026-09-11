-- de-el-pe central server, schema Z1 (2026-09-06). One installation per
-- customer: deliberately no tenant column (docs/DESIGN.md).

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
  disabled BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login TIMESTAMPTZ
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX sessions_expires ON sessions (expires_at);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL
);
INSERT INTO settings (key, value) VALUES
  ('learn_days', '7'),
  ('report_interval_secs', '30'),
  ('alert_retain_days', '730'),
  ('count_retain_days', '30'),
  ('config_generation', '1');

CREATE TABLE enroll_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  used_by UUID
);

CREATE TABLE agents (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  cert_fingerprint TEXT NOT NULL UNIQUE,
  cert_not_after TIMESTAMPTZ NOT NULL,
  enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ,
  last_addr TEXT,
  status JSONB,
  revoked_at TIMESTAMPTZ
);

-- NAS boxes and other syslog sources without an agent; identified by the sender address.
CREATE TABLE sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  address TEXT NOT NULL UNIQUE,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ,
  lines BIGINT NOT NULL DEFAULT 0,
  unparsed BIGINT NOT NULL DEFAULT 0,
  meter JSONB
);

CREATE TABLE rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  path TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all', 'agent', 'source')),
  agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
  source_id UUID REFERENCES sources(id) ON DELETE CASCADE,
  allowed_groups TEXT[] NOT NULL DEFAULT '{}',
  lockdown BOOLEAN NOT NULL DEFAULT false,
  hard_max_files INT NOT NULL DEFAULT 100,
  window_secs INT NOT NULL DEFAULT 60,
  ad_lock BOOLEAN NOT NULL DEFAULT false,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Alerts: retained for years. `detail` carries the original in wire format.
CREATE TABLE alerts (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('endpoint', 'access')),
  agent_id UUID REFERENCES agents(id) ON DELETE SET NULL,
  source_id UUID REFERENCES sources(id) ON DELETE SET NULL,
  origin_name TEXT NOT NULL,
  external_id TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL,
  last_at TIMESTAMPTZ,
  user_key TEXT,
  user_display TEXT,
  rule_id UUID REFERENCES rules(id) ON DELETE SET NULL,
  path TEXT,
  process TEXT,
  files JSONB NOT NULL DEFAULT '[]',
  file_count INT NOT NULL DEFAULT 0,
  bytes BIGINT NOT NULL DEFAULT 0,
  remote TEXT,
  verdict TEXT NOT NULL,
  reason TEXT,
  detail JSONB NOT NULL,
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX alerts_origin_external ON alerts (COALESCE(agent_id, source_id), external_id);
CREATE INDEX alerts_at ON alerts (at DESC);
CREATE INDEX alerts_open ON alerts (acknowledged_at) WHERE acknowledged_at IS NULL;

-- Counts: retained for weeks. `origin` is an agent id or a source id.
CREATE TABLE access_counts (
  origin UUID NOT NULL,
  rule_id UUID,
  path TEXT NOT NULL,
  user_key TEXT NOT NULL,
  user_display TEXT NOT NULL,
  bucket TIMESTAMPTZ NOT NULL,
  files INT NOT NULL,
  bytes BIGINT NOT NULL,
  PRIMARY KEY (origin, path, user_key, bucket)
);
CREATE INDEX access_counts_bucket ON access_counts (bucket);

CREATE TABLE audit_log (
  id BIGSERIAL PRIMARY KEY,
  at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id UUID,
  user_name TEXT NOT NULL,
  action TEXT NOT NULL,
  detail JSONB NOT NULL DEFAULT '{}'
);
