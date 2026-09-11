-- Lokales Protokoll der Agenten, wie es mit den Berichten hereinkommt.
-- Damit im Dashboard steht, *was* auf einem Geraet los ist — bisher stand
-- dort nur, ob es sich gemeldet hat.
CREATE TABLE agent_log (
  id BIGSERIAL PRIMARY KEY,
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  at TIMESTAMPTZ NOT NULL,
  level TEXT NOT NULL,
  target TEXT NOT NULL,
  msg TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Die einzige Abfrage: die letzten Zeilen eines Agenten.
CREATE INDEX agent_log_agent_at ON agent_log (agent_id, at DESC, id DESC);
-- Fuer das Aufraeumen nach Alter.
CREATE INDEX agent_log_at ON agent_log (at);
-- Nimmt die Zentrale einen Bericht an und geht die Antwort verloren,
-- schickt der Agent dieselben Zeilen noch einmal. Wie bei Warnungen und
-- Zaehlungen darf das nichts verdoppeln. Der Zeitstempel hat Mikrosekunden;
-- zwei verschiedene Zeilen mit gleichem Text in derselben Mikrosekunde gibt
-- es nicht. Ueber `md5`, weil eine Meldung laenger sein darf als ein
-- Btree-Eintrag.
CREATE UNIQUE INDEX agent_log_once ON agent_log (agent_id, at, md5(msg));
