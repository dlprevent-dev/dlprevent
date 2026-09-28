-- Which provider identity an external account belongs to: issuer and the
-- provider's stable subject (`sub`). The user name can change at the
-- provider and be given to someone else; the subject does not.
--
-- Single sign-on came from the enterprise edition, which kept this table as
-- `enterprise_sso_identities` and its configuration under `enterprise.sso`.
-- A database that ran it keeps its bindings.
DO $$
BEGIN
  IF to_regclass('enterprise_sso_identities') IS NOT NULL THEN
    ALTER TABLE enterprise_sso_identities RENAME TO sso_identities;
  ELSE
    CREATE TABLE sso_identities (
      issuer TEXT NOT NULL,
      subject TEXT NOT NULL,
      user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      PRIMARY KEY (issuer, subject)
    );
  END IF;
END $$;

UPDATE settings SET key = 'sso' WHERE key = 'enterprise.sso';
