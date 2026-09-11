-- From now on `sessions.id` holds only the SHA-256 of the id from the cookie.
-- Old rows sit there in plain text and no longer match any request: drop
-- them, everyone signs in once more.
DELETE FROM sessions;
