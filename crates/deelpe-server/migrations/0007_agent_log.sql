-- The agents' local log, as it arrives with their reports. So that the
-- dashboard says *what* is going on on a device — until now it only said
-- whether the device had checked in.
CREATE TABLE agent_log (
  id BIGSERIAL PRIMARY KEY,
  agent_id UUID NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  at TIMESTAMPTZ NOT NULL,
  level TEXT NOT NULL,
  target TEXT NOT NULL,
  msg TEXT NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- The only query: the most recent lines of one agent.
CREATE INDEX agent_log_agent_at ON agent_log (agent_id, at DESC, id DESC);
-- For cleaning up by age.
CREATE INDEX agent_log_at ON agent_log (at);
-- If the central server accepts a report and the answer gets lost, the
-- agent sends the same lines again. As with alerts and counts, that must
-- not duplicate anything. The timestamp has microsecond resolution; two
-- different lines with the same text in the same microsecond do not exist.
-- Via `md5`, because a message may be longer than a btree entry.
CREATE UNIQUE INDEX agent_log_once ON agent_log (agent_id, at, md5(msg));
