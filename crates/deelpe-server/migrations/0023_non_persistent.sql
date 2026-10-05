-- Machines reset to their image every night: terminal servers, Citrix/VDI
-- pools. Nothing an agent writes to disk survives the night, so every boot is
-- a fresh enrollment. Without help each one became a new agent, alert numbers
-- started over at 1 (and overwrote yesterday's under the same agent), and the
-- learning phase never ended.
--
-- A token made for such machines re-enrolls a host name it already knows as
-- the same agent, and the central server keeps the state the agent would
-- otherwise have kept on disk (`roaming`, opaque to the server).
ALTER TABLE enroll_tokens ADD COLUMN non_persistent boolean NOT NULL DEFAULT false;
ALTER TABLE agents ADD COLUMN non_persistent boolean NOT NULL DEFAULT false;
ALTER TABLE agents ADD COLUMN roaming jsonb;

COMMENT ON COLUMN enroll_tokens.non_persistent IS 'Enrols non-persistent Windows workstations: a known host name gets its agent back.';
COMMENT ON COLUMN agents.non_persistent IS 'Enrolled with a non-persistent token; re-enrolls on every boot as the same agent.';
COMMENT ON COLUMN agents.roaming IS 'State a non-persistent agent left with the central server; handed back at enrollment. Opaque to the server.';
