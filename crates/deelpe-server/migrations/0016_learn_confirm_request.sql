-- Finish an endpoint agent's learning phase from the dashboard.
--
-- An endpoint's learning phase does not end by itself: after `learn_days` it
-- waits in "review" for a human to confirm what it learned, and until then
-- it keeps unknown traffic silent. On a Mac that was the app's "Confirm all";
-- a Windows workstation or a Linux server had no way at all. This column is
-- the order to one agent, set by a button in the agent list.
--
-- It clears itself: once the agent reports the phase "active", `agent::report`
-- removes it, the same way `update_requested` works.
ALTER TABLE agents ADD COLUMN learn_confirm_requested TIMESTAMPTZ;

COMMENT ON COLUMN agents.learn_confirm_requested IS
  'When somebody asked this agent to finish its learning phase; NULL means no open order.';
