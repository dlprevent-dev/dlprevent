-- An alert under investigation: retention leaves it alone, however old it
-- gets. Set and released by the enterprise edition; the open-source server
-- only honours it.
ALTER TABLE alerts ADD COLUMN legal_hold BOOLEAN NOT NULL DEFAULT false;
