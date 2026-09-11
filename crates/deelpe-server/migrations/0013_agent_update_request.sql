-- Ein einzelner Agent soll sein Programm holen, ohne dass es die ganze
-- Belegschaft tut.
--
-- Der Hauptschalter `agent_update_enabled` gilt fuer alle. Genau das will
-- man beim ersten Mal nicht: erst ein Geraet, nachsehen, ob es wieder
-- hochkommt, dann die uebrigen. Diese Spalte ist der Auftrag an genau
-- einen — gesetzt vom Knopf in der Agentenliste.
--
-- Sie loescht sich selbst: sobald der Agent das bereitliegende Programm
-- faehrt, raeumt `agent::report` sie weg. Eine Marke, die haengen bleibt,
-- waere ein Auftrag, den niemand mehr zurueckziehen kann, und beim
-- naechsten Hochladen holte sich dieses eine Geraet ungefragt auch das.
ALTER TABLE agents ADD COLUMN update_requested TIMESTAMPTZ;

COMMENT ON COLUMN agents.update_requested IS
  'Wann jemand fuer diesen Agenten ein Update angefordert hat; NULL heisst: kein offener Auftrag.';
