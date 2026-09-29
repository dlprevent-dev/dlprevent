-- Syslog is unauthenticated: a datagram from a never-seen address created a
-- source under a name of the sender's choosing, and its lines raised alerts
-- at once. A new source now waits for an administrator to confirm it before
-- its lines count or alert. Sources that already exist were accepted by
-- running, so they stay confirmed and keep working after the update.
ALTER TABLE sources ADD COLUMN confirmed BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE sources ALTER COLUMN confirmed SET DEFAULT false;
