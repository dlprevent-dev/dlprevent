//! Alerts persisted on disk: one JSON line per alert (the wire format of
//! `Alert`), only ever appended. At startup everything is read, entries
//! older than `retain_days` are thrown out (0 = never) and the file is
//! rewritten. An alert that keeps running (`Outcome::Updated`) is appended
//! as a new line with the same ID; when reading, the last line per ID
//! counts, and the file is compacted. Mode 0600: file names from protected
//! folders are sensitive, and clients get the alerts over the socket.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use deelpe_core::correlate::Alert;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub struct AlertLog {
    path: PathBuf,
    file: File,
    alerts: Vec<Alert>,
    next_id: u64,
}

impl AlertLog {
    pub fn open(path: &Path, retain_days: u32) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("lege {} an", dir.display()))?;
        }
        let (mut alerts, next_id, pruned) = Self::read(path, retain_days)?;
        if pruned {
            Self::rewrite(path, &alerts)?;
        }
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open {}", path.display()))?;
        // `mode` only applies on creation; an existing file gets it here.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        alerts.shrink_to_fit();
        Ok(Self { path: path.to_path_buf(), file, alerts, next_id })
    }

    /// Reads the file; returns (alerts kept, next ID, whether pruning is
    /// needed). Broken lines are skipped rather than stopping the whole
    /// service; they trigger no rewrite, so that nothing gets lost.
    fn read(path: &Path, retain_days: u32) -> Result<(Vec<Alert>, u64, bool)> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 1, false)),
            Err(e) => return Err(e).with_context(|| format!("lese {}", path.display())),
        };
        let cutoff = if retain_days == 0 { DateTime::<Utc>::MIN_UTC } else { Utc::now() - Duration::days(retain_days as i64) };
        let mut alerts: Vec<Alert> = Vec::new();
        let mut index: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        let mut next_id = 1;
        let mut pruned = false;
        for (n, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Alert>(&line) {
                Ok(a) => {
                    next_id = next_id.max(a.id + 1);
                    if a.at < cutoff {
                        pruned = true;
                    } else if let Some(&i) = index.get(&a.id) {
                        // Continuation: the last line wins, the slot stays.
                        alerts[i] = a;
                        pruned = true;
                    } else {
                        index.insert(a.id, alerts.len());
                        alerts.push(a);
                    }
                }
                Err(e) => tracing::warn!("{}:{}: skipped an unreadable alert: {e}", path.display(), n + 1),
            }
        }
        Ok((alerts, next_id, pruned))
    }

    fn rewrite(path: &Path, alerts: &[Alert]) -> Result<()> {
        let tmp = path.with_extension("jsonl.tmp");
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        for a in alerts {
            serde_json::to_writer(&mut f, a)?;
            f.write_all(b"\n")?;
        }
        f.sync_all()?;
        std::fs::rename(&tmp, path).with_context(|| format!("ersetze {}", path.display()))
    }

    /// Appends the alert. It stays in memory even if the disk refuses: the
    /// table and `show` should display it anyway.
    pub fn append(&mut self, a: &Alert) -> Result<()> {
        self.next_id = self.next_id.max(a.id + 1);
        self.alerts.push(a.clone());
        let mut line = serde_json::to_string(a)?;
        line.push('\n');
        self.file.write_all(line.as_bytes()).with_context(|| format!("schreibe {}", self.path.display()))?;
        self.file.flush()?;
        Ok(())
    }

    /// Replaces the alert with the same ID (total has grown) and appends it
    /// as a new line; it gets compacted at the next startup.
    pub fn update(&mut self, a: &Alert) -> Result<()> {
        match self.alerts.iter_mut().find(|x| x.id == a.id) {
            Some(slot) => *slot = a.clone(),
            None => return self.append(a),
        }
        let mut line = serde_json::to_string(a)?;
        line.push('\n');
        self.file.write_all(line.as_bytes()).with_context(|| format!("schreibe {}", self.path.display()))?;
        self.file.flush()?;
        Ok(())
    }

    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    /// First free ID, so IDs do not start over at 1 after a restart.
    pub fn next_id(&self) -> u64 {
        self.next_id
    }
}
