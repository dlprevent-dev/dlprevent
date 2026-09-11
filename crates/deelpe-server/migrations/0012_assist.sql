-- KI-Unterstuetzung: die Erklaerung zu einer Warnung, wie ein Modell sie
-- geschrieben hat. Eine Zeile je Warnung; ein erneutes Erklaeren ueberschreibt
-- sie. Der Cache ist hier nicht Sparsamkeit wie beim IP-Ruf, sondern der
-- Nachweis: was das Modell gesagt hat, muss nachlesbar bleiben, auch wenn der
-- Dienst spaeter abgeschaltet oder das Modell gewechselt wird.
CREATE TABLE alert_insights (
  alert_id        BIGINT PRIMARY KEY REFERENCES alerts(id) ON DELETE CASCADE,
  -- Modell und Endpunkt stehen dabei: eine Auskunft von `llama3.2` auf dem
  -- Ollama im Keller ist eine andere Aussage als eine von Infomaniak.
  model           TEXT NOT NULL,
  endpoint        TEXT NOT NULL,
  -- Genau das, was hinausging. Ohne diese Spalte waere nicht mehr feststellbar,
  -- welche Daten das Haus verlassen haben — in einem Werkzeug gegen
  -- Datenabfluss ist das die wichtigste Spalte der Tabelle.
  prompt          TEXT NOT NULL,
  summary         TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
  -- Wie `origin_name` an der Warnung: bleibt lesbar, wenn das Konto weg ist.
  created_by_name TEXT NOT NULL
);
