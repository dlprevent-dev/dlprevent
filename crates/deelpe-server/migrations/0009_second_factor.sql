-- Second factor. A TOTP secret per user (NULL: not set up) and the last
-- accepted time step, so that an intercepted code does not work a second
-- time. Passkeys in their own table: a user has several of them (phone,
-- computer, security key). `credential` is the record from webauthn-rs
-- (key, counter, backup state), stored unchanged.
ALTER TABLE users
  ADD COLUMN totp_secret BYTEA,
  ADD COLUMN totp_used_step BIGINT NOT NULL DEFAULT 0;

CREATE TABLE passkeys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  credential JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX passkeys_user ON passkeys (user_id);
