-- One token for a whole rollout instead of one per device.
--
-- Two thousand machines used to mean two thousand tokens made by hand. A
-- token now carries how many enrollments it is good for; the default of 1
-- keeps every token created so far, and every one created without a count,
-- exactly what it was.
--
-- `used_at` and `used_by` stay and now mean the latest enrollment. A token
-- is spent when `uses` reaches `max_uses`, no longer when `used_at` is set.
ALTER TABLE enroll_tokens
  ADD COLUMN max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
  ADD COLUMN uses INTEGER NOT NULL DEFAULT 0;

UPDATE enroll_tokens SET uses = 1 WHERE used_at IS NOT NULL;

COMMENT ON COLUMN enroll_tokens.max_uses IS 'How many agents may enroll with this token.';
COMMENT ON COLUMN enroll_tokens.uses IS 'How many have; used_at and used_by name the latest.';
