-- `sessions.id` hält ab jetzt nur noch den SHA-256 der Kennung aus dem Cookie.
-- Alte Zeilen stehen im Klartext da und passen zu keiner Anfrage mehr: weg
-- damit, alle melden sich einmal neu an.
DELETE FROM sessions;
