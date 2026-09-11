//! The service's link to the central server (`deelpe-server`), decision of
//! 2026-09-06. The service only connects outbound, only to the configured
//! central server, only with a client certificate. Without `CONFIG_PATH` it
//! stays offline as before.
//!
//! Enrollment (`deelpe central enroll`): fetch the CA from the server and
//! check it against the fingerprint from the dashboard, generate our own
//! key, submit a CSR with the token, store the certificate. The private key
//! never leaves the device.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use deelpe_core::central::AgentKind;
use deelpe_core::net::Credentials;
use deelpe_core::correlate::Alert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub const CONFIG_PATH: &str = "/etc/deelpe/central.json";
pub const STATE_PATH: &str = "/var/lib/deelpe/central-state.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CentralConfig {
    pub url: String,
    pub agent_id: String,
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    #[serde(default)]
    pub enrolled_at: Option<DateTime<Utc>>,
}

impl CentralConfig {
    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(raw) => Ok(Some(serde_json::from_str(&raw).with_context(|| format!("{} unlesbar", path.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(Path::new(CONFIG_PATH))
    }
    pub fn save_to(&self, path: &Path) -> Result<()> {
        write_private(path, serde_json::to_string_pretty(self)?.as_bytes())
    }
    pub fn save(&self) -> Result<()> {
        self.save_to(Path::new(CONFIG_PATH))
    }
    pub fn remove() -> Result<bool> {
        match std::fs::remove_file(CONFIG_PATH) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

/// What the service has to know between two reports.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CentralState {
    /// The central server's configuration generation last adopted.
    pub generation: i64,
    /// Folders pushed by the central server that are entered in `watched`.
    pub managed: Vec<PathBuf>,
    /// Alert ID → signature of the state last sent.
    pub sent: HashMap<u64, String>,
    /// Report counters and last error. `flatten`: on disk the four keys
    /// stay at the same level as before.
    #[serde(flatten)]
    pub tally: deelpe_core::session::Tally,
    /// Learning instructions we carried out that the central server has not
    /// ticked off yet. They ride along with the next report; until then they
    /// also survive a restart, otherwise the central server would repeat
    /// them forever.
    #[serde(default)]
    pub learn_done: Vec<i64>,
}

impl CentralState {
    pub fn load_from(path: &Path) -> Self {
        std::fs::read_to_string(path).ok().and_then(|r| serde_json::from_str(&r).ok()).unwrap_or_default()
    }
    pub fn load() -> Self {
        Self::load_from(Path::new(STATE_PATH))
    }
    pub fn save_to(&self, path: &Path) -> Result<()> {
        write_private(path, serde_json::to_string(self)?.as_bytes())
    }
    pub fn save(&self) -> Result<()> {
        self.save_to(Path::new(STATE_PATH))
    }
}

/// State of the link for the app and the CLI: the configuration without
/// key and certificate, plus the state of the reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CentralInfo {
    pub url: String,
    pub agent_id: String,
    pub enrolled_at: Option<DateTime<Utc>>,
    pub last_ok: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub reports: u64,
    pub generation: i64,
    pub managed: Vec<PathBuf>,
}

impl CentralInfo {
    pub fn from_parts(cfg: &CentralConfig, st: &CentralState) -> Self {
        Self {
            url: cfg.url.clone(),
            agent_id: cfg.agent_id.clone(),
            enrolled_at: cfg.enrolled_at,
            last_ok: st.tally.last_ok,
            last_error: st.tally.last_error.clone(),
            last_error_at: st.tally.last_error_at,
            reports: st.tally.reports,
            generation: st.generation,
            managed: st.managed.clone(),
        }
    }
}

/// Reads configuration and state from disk (needs root, runs in the service).
pub fn info() -> Option<CentralInfo> {
    let cfg = CentralConfig::load().ok().flatten()?;
    Some(CentralInfo::from_parts(&cfg, &CentralState::load()))
}

/// Signature of an alert: it is only sent again when it has changed.
pub fn alert_signature(a: &Alert) -> String {
    format!("{}|{:?}|{:?}|{:?}", a.bytes_out, a.last_at, a.verdict, a.files.len())
}

/// From the stored alerts, the ones that are new or have been continued.
/// Cleans IDs that are no longer in the log out of `sent`.
pub fn pending_alerts(alerts: &[Alert], sent: &mut HashMap<u64, String>) -> Vec<Alert> {
    let ids: std::collections::HashSet<u64> = alerts.iter().map(|a| a.id).collect();
    sent.retain(|id, _| ids.contains(id));
    alerts.iter().filter(|a| sent.get(&a.id) != Some(&alert_signature(a))).cloned().collect()
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        if let Ok(s) = std::str::from_utf8(&buf[..end]) {
            if !s.is_empty() {
                return s.to_string();
            }
        }
    }
    "unknown".into()
}

pub fn agent_kind() -> AgentKind {
    if cfg!(target_os = "macos") {
        AgentKind::Mac
    } else {
        AgentKind::Linux
    }
}

pub use deelpe_core::net::{sha256_hex, Client};

impl CentralConfig {
    /// Credentials for the shared client in `deelpe-core::net`.
    pub fn credentials(&self) -> Credentials {
        Credentials {
            url: self.url.clone(),
            agent_id: self.agent_id.clone(),
            ca_pem: self.ca_pem.clone(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
        }
    }
}

/// Enrollment with the central server; the check of the CA fingerprint
/// lives in `deelpe-core::net`, here only the platform is added.
pub async fn enroll(url: &str, token: &str, ca_sha256: &str, hostname: &str, version: &str) -> Result<CentralConfig> {
    let c = deelpe_core::net::enroll(url, token, ca_sha256, hostname, agent_kind(), version).await?;
    Ok(CentralConfig {
        url: c.url,
        agent_id: c.agent_id,
        ca_pem: c.ca_pem,
        cert_pem: c.cert_pem,
        key_pem: c.key_pem,
        enrolled_at: Some(Utc::now()),
    })
}

/// Write atomically and with mode 0600.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deelpe_core::identity::ProcessIdentity;

    fn alert(id: u64, bytes: u64) -> Alert {
        Alert {
            id,
            at: Utc::now(),
            pid: 1,
            identity: ProcessIdentity::Unknown { path: "/x".into() },
            files: vec![],
            remote: None,
            remote_port: None,
            bytes_out: bytes,
            via: None,
            last_at: None,
            verdict: Default::default(),
            reason: None,
            volume: None,
            copy_to: None,
            sender_read_directly: false,
            upload_url: None,
        }
    }

    #[test]
    fn pending_only_changed() {
        let mut sent = HashMap::new();
        let alerts = vec![alert(1, 10), alert(2, 20)];
        let p = pending_alerts(&alerts, &mut sent);
        assert_eq!(p.len(), 2);
        for a in &p {
            sent.insert(a.id, alert_signature(a));
        }
        assert!(pending_alerts(&alerts, &mut sent).is_empty());
        let alerts = vec![alert(1, 10), alert(2, 25)];
        let p = pending_alerts(&alerts, &mut sent);
        assert_eq!(p.iter().map(|a| a.id).collect::<Vec<_>>(), vec![2]);
        // ID 1 disappears from the log: out of `sent` too.
        let alerts = vec![alert(2, 25)];
        pending_alerts(&alerts, &mut sent);
        assert!(!sent.contains_key(&1));
    }

    #[test]
    fn config_roundtrip_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("central.json");
        let c = CentralConfig { url: "https://z:8444".into(), agent_id: "a".into(), ca_pem: "c".into(), cert_pem: "x".into(), key_pem: "k".into(), enrolled_at: None };
        c.save_to(&p).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(CentralConfig::load_from(&p).unwrap().unwrap().agent_id, "a");
        assert!(CentralConfig::load_from(&dir.path().join("nein.json")).unwrap().is_none());
    }
}

impl deelpe_core::session::CredentialStore for CentralConfig {
    /// Fresh credentials into the same file as the old ones. On disk
    /// first, only then does it count.
    fn store(&mut self, fresh: &Credentials) -> Result<()> {
        let mut next = self.clone();
        next.cert_pem = fresh.cert_pem.clone();
        next.key_pem = fresh.key_pem.clone();
        next.save()?;
        *self = next;
        Ok(())
    }
}
