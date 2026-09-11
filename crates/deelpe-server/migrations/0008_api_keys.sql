-- Schluessel fuer den Fremdzugriff auf die Lese-API (SIEM, Skripte). Wie
-- bei den Aufnahme-Token steht nur der Hash hier: wer die Datenbank liest,
-- kommt damit nicht an die API.
--
-- Kein `disabled`-Feld: ein Schluessel wird geloescht, und der Hauptschalter
-- `api_keys_enabled` in den Einstellungen sperrt alle auf einmal aus.
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  key_hash TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- NULL heisst: laeuft nicht ab.
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ
);
