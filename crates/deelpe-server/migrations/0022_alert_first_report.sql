-- What an alert said when it was first reported, kept once a later report
-- replaces it. The alert id comes from the agent, and at an equal verdict a
-- re-report still brings its own reason and detail: a forged one could
-- rewrite what the dashboard shows. It can no longer erase the original.
-- NULL while nothing has been replaced, so an alert that never changes
-- costs nothing.
ALTER TABLE alerts ADD COLUMN first_reason TEXT;
ALTER TABLE alerts ADD COLUMN first_detail JSONB;
