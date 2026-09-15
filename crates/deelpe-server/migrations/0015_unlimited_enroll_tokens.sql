-- A rollout token without a count: good for every device until it is revoked.
--
-- A count made the administrator guess the size of the rollout up front, and
-- a guess one too small leaves the last machine with "token already used".
-- `max_uses` NULL now means no limit, and a token created without a count
-- gets it. Revoking is deleting the row; enrolled agents are not affected.
-- Tokens created so far keep the count they have.
ALTER TABLE enroll_tokens
  ALTER COLUMN max_uses DROP NOT NULL,
  ALTER COLUMN max_uses DROP DEFAULT;

COMMENT ON COLUMN enroll_tokens.max_uses IS 'How many agents may enroll with this token; NULL for any number until it is deleted.';
