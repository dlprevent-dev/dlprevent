//! CLI ↔ service over a unix socket, one JSON line there, one back.

use anyhow::{Context, Result};
use deelpe_core::correlate::Alert;
use deelpe_core::learn::LearnStatus;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

pub const SOCKET: &str = "/var/run/deelpe.sock";

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    WatchAdd(PathBuf),
    WatchRemove(PathBuf),
    WatchList,
    /// The most recent alerts (for tables, capped).
    Alerts,
    /// All stored alerts, oldest first (for the export).
    AlertsAll,
    Show(u64),
    Status,
    /// Exception list: signing ID, `prefix.*` or `team:ID`.
    IgnoreAdd(String),
    IgnoreRemove(String),
    IgnoreList,
    /// Learning phase (M2): phase, end, pairs.
    LearnStatus,
    /// Candidates become known, the learning phase ends (root).
    LearnConfirm,
    /// Drop a pair, key as in `Pair::key` (root).
    LearnForget(String),
    /// Remember the alert's pair: quiet from now on (root).
    LearnRemember(u64),
    /// Always report the alert's pair (root).
    LearnFlag(u64),
    /// New learning phase, all pairs gone (root).
    LearnRestart,
    /// State of the link to the central server (readable without root).
    CentralStatus,
}

impl Request {
    /// Is this root-only? The user group may read; changing things (the
    /// watch list, exceptions, learned pairs) is root-only — otherwise any
    /// program the user runs could switch off the protection without ever
    /// seeing a password.
    ///
    /// Exhaustive and without a `_` arm, deliberately: a new writing request
    /// should bring the compiler down on you instead of silently slipping
    /// through without a permission check.
    pub fn needs_root(&self) -> bool {
        match self {
            Request::WatchAdd(_)
            | Request::WatchRemove(_)
            | Request::IgnoreAdd(_)
            | Request::IgnoreRemove(_)
            | Request::LearnConfirm
            | Request::LearnForget(_)
            | Request::LearnRemember(_)
            | Request::LearnFlag(_)
            | Request::LearnRestart => true,
            Request::WatchList
            | Request::Alerts
            | Request::AlertsAll
            | Request::Show(_)
            | Request::Status
            | Request::IgnoreList
            | Request::LearnStatus
            | Request::CentralStatus => false,
        }
    }
}

/// State of a sensor. `error` is set when it has stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorState {
    pub name: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Ok(String),
    Err(String),
    Watched(Vec<PathBuf>),
    Alerts(Vec<Alert>),
    Alert(Option<Alert>),
    Ignored(Vec<String>),
    Learn(LearnStatus),
    /// `None`: not linked up.
    Central(Option<crate::central::CentralInfo>),
    Status {
        touched: usize,
        alerts: usize,
        watched: usize,
        uptime_secs: u64,
        sensors: Vec<SensorState>,
        /// Notes from the service, such as a file changed behind its back.
        #[serde(default)]
        warnings: Vec<String>,
    },
}

pub async fn client(req: Request) -> Result<Response> {
    let mut stream = UnixStream::connect(Path::new(SOCKET))
        .await
        .with_context(|| {
            format!("service not reachable at {SOCKET}. Is `deelpe daemon` running?")
        })?;
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    stream.write_all(line.as_bytes()).await?;
    let mut reader = BufReader::new(stream);
    let mut resp = String::new();
    reader.read_line(&mut resp).await?;
    Ok(serde_json::from_str(&resp)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reading without root, changing only with it. The test pins the
    /// split down; the exhaustive `match` in `needs_root` pins down that a
    /// new variant has to be classified at all.
    #[test]
    fn only_changes_need_root() {
        for r in [
            Request::WatchAdd("/a".into()),
            Request::WatchRemove("/a".into()),
            Request::IgnoreAdd("x".into()),
            Request::IgnoreRemove("x".into()),
            Request::LearnConfirm,
            Request::LearnForget("k".into()),
            Request::LearnRemember(1),
            Request::LearnFlag(1),
            Request::LearnRestart,
        ] {
            assert!(r.needs_root(), "{r:?} ändert etwas");
        }
        for r in [
            Request::WatchList,
            Request::Alerts,
            Request::AlertsAll,
            Request::Show(1),
            Request::Status,
            Request::IgnoreList,
            Request::LearnStatus,
            Request::CentralStatus,
        ] {
            assert!(!r.needs_root(), "{r:?} liest nur");
        }
    }
}
