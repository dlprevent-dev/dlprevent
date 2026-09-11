-- A single agent should fetch its program without the whole workforce doing
-- the same.
--
-- The master switch `agent_update_enabled` applies to everyone. That is
-- exactly what you do not want the first time round: one device first, check
-- whether it comes back up, then the rest. This column is the order to
-- exactly one of them — set by the button in the agent list.
--
-- It clears itself: as soon as the agent runs the program that was waiting
-- for it, `agent::report` clears it away. A marker that stays stuck would be
-- an order nobody can withdraw any more, and at the next upload this one
-- device would help itself to that one too, unasked.
ALTER TABLE agents ADD COLUMN update_requested TIMESTAMPTZ;

COMMENT ON COLUMN agents.update_requested IS
  'Wann jemand fuer diesen Agenten ein Update angefordert hat; NULL heisst: kein offener Auftrag.';
