-- Zweiter Faktor. TOTP-Geheimnis je Benutzer (NULL: nicht eingerichtet) und
-- der zuletzt angenommene Zeitschritt, damit ein abgefangener Code nicht ein
-- zweites Mal gilt. Passkeys als eigene Tabelle: ein Benutzer hat mehrere
-- (Telefon, Rechner, Schluessel). `credential` ist der Datensatz von
-- webauthn-rs (Schluessel, Zaehler, Sicherungszustand), unveraendert abgelegt.
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
