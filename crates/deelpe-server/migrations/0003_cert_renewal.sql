-- Zertifikate der Agenten laufen ab (730 Tage). Bisher gab es keinen Weg,
-- eines zu erneuern: nach Ablauf kam die mTLS-Verbindung nicht mehr zustande
-- und es half nur eine neue Aufnahme, die den alten Eintrag als Leiche
-- zurückliess. Der Agent erneuert jetzt selbst, solange das alte Zertifikat
-- noch gilt.
--
-- Zwischen "Zentrale hat unterschrieben" und "Agent hat gespeichert" liegt
-- ein Moment, in dem ein Absturz den Agenten dauerhaft aussperren würde:
-- die Zentrale kennt schon den neuen Fingerabdruck, der Agent hat noch den
-- alten. Darum bleibt der vorige eine Gnadenfrist lang gültig.
ALTER TABLE agents ADD COLUMN prev_cert_fingerprint TEXT;
ALTER TABLE agents ADD COLUMN prev_cert_until TIMESTAMPTZ;
CREATE INDEX agents_prev_cert ON agents (prev_cert_fingerprint) WHERE prev_cert_fingerprint IS NOT NULL;
