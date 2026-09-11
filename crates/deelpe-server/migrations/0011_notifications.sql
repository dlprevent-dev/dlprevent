-- Benachrichtigung per Mail. Die Zugangsdaten des SMTP-Servers stehen wie der
-- AbuseIPDB-Schluessel in `settings` (herein, nie hinaus); hier stehen nur die
-- zwei Marken, die verhindern, dass dasselbe Ereignis zweimal gemeldet wird.

-- Wann diese Warnung in einer Mail stand. NULL heisst: noch nicht beurteilt.
-- Der Durchgang setzt die Marke auf **jede** Zeile, die er angesehen hat, auch
-- auf die, die keine Mail wert war — sonst waechst der Teilindex unten mit
-- jeder Lernwarnung ueber die ganze Aufbewahrungszeit mit.
ALTER TABLE alerts ADD COLUMN notified_at TIMESTAMPTZ;

-- Bestehende Warnungen gelten als erledigt: wer die Benachrichtigung
-- einschaltet, will die Nachrichten von morgen, nicht die von letztem Jahr.
UPDATE alerts SET notified_at = now();

CREATE INDEX alerts_pending_mail ON alerts (received_at) WHERE notified_at IS NULL;

-- Seit wann ein Agent als ausgefallen gemeldet ist. Gesetzt heisst: die
-- Ausfallmeldung ist raus. Zurueck auf NULL geht es erst mit der Meldung, dass
-- er wieder da ist — so kommt je Ausfall genau eine Mail und je Rueckkehr eine,
-- statt einer im Minutentakt, solange das Geraet aus bleibt.
ALTER TABLE agents ADD COLUMN down_notified_at TIMESTAMPTZ;
