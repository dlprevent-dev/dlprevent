-- Learning instructions from the central server to an agent ("remember the
-- pair", "always report"). Without them a person at the dashboard cannot
-- silence a recurring alert: the agent reports an unknown pair as `new`
-- again on every flow, and it only goes quiet once somebody presses
-- "Remember" on the device itself.
--
-- The agent picks up open rows with its report and reports back the ones it
-- carried out; only then is `applied_at` set. So a report that gets lost on
-- the way merely repeats the instruction.
CREATE TABLE learn_commands (
    id          BIGSERIAL PRIMARY KEY,
    agent_id    UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- The agent's own alert id; the row in `alerts` may be long gone, the
    -- instruction stays valid.
    alert_id    BIGINT NOT NULL,
    action      TEXT NOT NULL CHECK (action IN ('remember', 'flag')),
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at  TIMESTAMPTZ
);

-- The report only asks for the open ones, every 30 seconds per agent.
CREATE INDEX learn_commands_pending ON learn_commands (agent_id) WHERE applied_at IS NULL;

-- Sending the same instruction twice achieves nothing.
CREATE UNIQUE INDEX learn_commands_open_once ON learn_commands (agent_id, alert_id, action) WHERE applied_at IS NULL;

-- By design, alerts from the learning phase are "in the table yes, reported
-- no". The central server still carried them as open until now; from here
-- on they arrive already acknowledged (see db.rs), and the existing ones
-- are brought into line.
UPDATE alerts SET acknowledged_at = now() WHERE verdict = 'learning' AND acknowledged_at IS NULL;
