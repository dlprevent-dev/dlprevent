-- Strict folder ("block all"): nothing may leave this folder, except to the
-- destinations in allow_destinations (IP or network, optionally :port).
-- enforce additionally stops the sending process.
ALTER TABLE rules ADD COLUMN strict BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rules ADD COLUMN allow_destinations TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE rules ADD COLUMN enforce BOOLEAN NOT NULL DEFAULT false;
