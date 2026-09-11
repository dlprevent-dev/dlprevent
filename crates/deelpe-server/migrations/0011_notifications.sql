-- Email notification. The SMTP server's credentials live in `settings`, like
-- the AbuseIPDB key (in, never out); here are only the two markers that keep
-- the same event from being reported twice.

-- When this alert appeared in an email. NULL means: not judged yet. The pass
-- sets the marker on **every** row it looked at, including the ones that were
-- not worth an email — otherwise the partial index below grows with every
-- learning alert over the whole retention period.
ALTER TABLE alerts ADD COLUMN notified_at TIMESTAMPTZ;

-- Existing alerts count as done: whoever switches notification on wants
-- tomorrow's messages, not last year's.
UPDATE alerts SET notified_at = now();

CREATE INDEX alerts_pending_mail ON alerts (received_at) WHERE notified_at IS NULL;

-- Since when an agent has been reported as down. Set means: the down notice
-- has gone out. It goes back to NULL only with the notice that the agent is
-- back — so each outage produces exactly one email and each return one more,
-- instead of one a minute for as long as the device stays off.
ALTER TABLE agents ADD COLUMN down_notified_at TIMESTAMPTZ;
