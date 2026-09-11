-- Keys for third-party access to the read-only API (SIEM, scripts). As with
-- the enrolment tokens, only the hash is stored here: reading the database
-- does not get you into the API.
--
-- No `disabled` field: a key gets deleted, and the master switch
-- `api_keys_enabled` in the settings locks them all out at once.
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- NULL means: never expires.
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);
