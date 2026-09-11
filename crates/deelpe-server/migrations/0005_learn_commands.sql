-- Lernanweisungen der Zentrale an einen Agenten ("Paar merken", "immer
-- melden"). Ohne sie kann ein Mensch am Dashboard eine wiederkehrende
-- Warnung nicht stillstellen: der Agent meldet ein unbekanntes Paar bei
-- jedem Fluss neu als `new`, und still wird es erst, wenn jemand am Geraet
-- selbst "Remember" drueckt.
--
-- Der Agent holt offene Zeilen mit seinem Bericht ab und meldet die
-- ausgefuehrten zurueck; erst dann wird `applied_at` gesetzt. Ein Bericht,
-- der unterwegs verlorengeht, wiederholt die Anweisung also nur.
CREATE TABLE learn_commands (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- Warnungskennung des Agenten; die Zeile in `alerts` kann laengst weg
    -- sein, die Anweisung bleibt gueltig.
    alert_id    BIGINT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('remember', 'flag')),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at  TIMESTAMPTZ
);

-- Der Bericht fragt nur die offenen ab, alle 30 Sekunden je Agent.
CREATE INDEX learn_commands_pending ON learn_commands (agent_id) WHERE applied_at IS NULL;

-- Dieselbe Anweisung zweimal zu schicken bringt nichts.
CREATE UNIQUE INDEX learn_commands_open_once ON learn_commands (agent_id, alert_id, action) WHERE applied_at IS NULL;

-- Warnungen der Lernphase sind laut Design "Tabelle ja, Meldung nein". Die
-- Zentrale hat sie bisher trotzdem als offen gefuehrt; ab jetzt kommen sie
-- erledigt herein (siehe db.rs), und die vorhandenen werden nachgezogen.
UPDATE alerts SET acknowledged_at = now() WHERE verdict = 'learning' AND acknowledged_at IS NULL;
