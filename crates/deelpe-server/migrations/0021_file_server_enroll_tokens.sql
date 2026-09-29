-- Only a token made for a file server enrols one.
--
-- A file server's own report (host names, share table) is turned into the
-- UNC paths of rules delivered to every endpoint. The kind an agent enrols as
-- came from its request alone, so any rollout token for laptops could enrol a
-- "file server" and have its shares land in everybody's policy. The dashboard
-- already asks which platform a token is for; that answer is now kept.
-- Tokens created so far did not record it and enrol no file server: a
-- rollout in progress for one needs a new token.
ALTER TABLE enroll_tokens ADD COLUMN file_server boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN enroll_tokens.file_server IS 'Whether an agent may enroll with this token as a file server (windows_server).';
