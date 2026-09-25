-- Accounts that sign in through an identity provider (single sign-on).
-- Their second factor is the provider's business: a role that demands one
-- locally does not lock them out, and a sign-in from the provider never
-- takes over a local account of the same name.
ALTER TABLE users ADD COLUMN external BOOLEAN NOT NULL DEFAULT false;
