-- Strenger Ordner ("block all"): aus diesem Ordner darf nichts nach aussen,
-- ausser an die Ziele in allow_destinations (IP oder Netz, optional :Port).
-- enforce haelt zusaetzlich den sendenden Prozess an.
ALTER TABLE rules ADD COLUMN strict BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rules ADD COLUMN allow_destinations TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE rules ADD COLUMN enforce BOOLEAN NOT NULL DEFAULT false;
