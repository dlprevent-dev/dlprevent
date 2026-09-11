-- Groups per agent, for the "allowed groups" picker in a rule.
--
-- Its own table instead of a field in the agent status: the status is
-- rewritten with every report, and in an environment with tens of thousands
-- of groups that would be the same list every 30 seconds. Here it only
-- lands when the agent reports a change.
CREATE TABLE agent_groups (
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name     text NOT NULL,
    kind     text NOT NULL,
    seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, name)
);

-- The search is by part of the name, case-insensitive; without this index
-- it gets sluggish at tens of thousands of rows.
CREATE INDEX agent_groups_name_lower ON agent_groups (lower(name) text_pattern_ops);
