-- Agent certificates expire (730 days). Until now there was no way to renew
-- one: once it had expired the mTLS connection no longer came up, and the
-- only remedy was a fresh enrolment, which left the old entry behind as a
-- corpse. The agent now renews on its own, while the old certificate is
-- still valid.
--
-- Between "the central server has signed" and "the agent has stored it"
-- there is a moment in which a crash would lock the agent out for good: the
-- central server already knows the new fingerprint, the agent still has the
-- old one. That is why the previous one stays valid for a grace period.
ALTER TABLE agents ADD COLUMN prev_cert_fingerprint TEXT;
ALTER TABLE agents ADD COLUMN prev_cert_until TIMESTAMPTZ;
CREATE INDEX agents_prev_cert ON agents (prev_cert_fingerprint) WHERE prev_cert_fingerprint IS NOT NULL;
