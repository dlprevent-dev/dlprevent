-- Gruppen je Agent, für die Auswahl "erlaubte Gruppen" in einer Regel.
--
-- Eigene Tabelle statt eines Feldes im Agentenstatus: der Status wird bei
-- jedem Bericht neu geschrieben, und in einer Umgebung mit Zehntausenden
-- Gruppen wäre das alle 30 Sekunden dieselbe Liste. Hier landet sie nur,
-- wenn der Agent eine Änderung meldet.
CREATE TABLE agent_groups (
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name     text NOT NULL,
    kind     text NOT NULL,
    seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, name)
);

-- Gesucht wird nach Namensteil, unabhängig von Gross- und Kleinschreibung;
-- ohne diesen Index wird das bei Zehntausenden Zeilen zäh.
CREATE INDEX agent_groups_name_lower ON agent_groups (lower(name) text_pattern_ops);
