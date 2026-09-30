//! Outbound connections and per-process send volumes via `nettop` in batch
//! mode. Polling; will be replaced by a Network Extension in v2.
//!
//! Format checked against real `nettop` output (macOS 26.6), see the test.

use crate::Sensor;
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use deelpe_core::event::{Event, NetEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct NetTop {
    interval: Duration,
}

impl NetTop {
    pub fn new(secs: u64) -> Self {
        Self {
            interval: Duration::from_secs(secs.max(1)),
        }
    }
}

#[async_trait]
impl Sensor for NetTop {
    fn name(&self) -> &'static str {
        "nettop"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        // Cumulative counters per (pid, remote) → turn them into deltas.
        let mut last: HashMap<(u32, String), (u64, u64)> = HashMap::new();
        let mut tick = tokio::time::interval(self.interval);
        loop {
            tick.tick().await;
            let out = Command::new("/usr/bin/nettop")
                .args([
                    "-x",
                    "-L",
                    "1",
                    "-J",
                    "bytes_in,bytes_out",
                    "-t",
                    "external",
                ])
                .output()
                .await
                .context("run nettop")?;
            let text = String::from_utf8_lossy(&out.stdout);
            let at = Utc::now();
            for s in parse(&text) {
                let key = (s.pid, s.remote_raw.clone());
                let (pi, po) = last.get(&key).copied().unwrap_or((0, 0));
                last.insert(key, (s.bytes_in, s.bytes_out));
                let d_out = s.bytes_out.saturating_sub(po);
                let d_in = s.bytes_in.saturating_sub(pi);
                if d_out == 0 && d_in == 0 {
                    continue;
                }
                // `nettop` names only the PID; on this platform the
                // correlator still learns the parent chain from the file
                // events.
                let ev = Event::Net(NetEvent {
                    ppid: None,
                    at,
                    pid: s.pid,
                    process_name: s.name.clone(),
                    remote: s.remote_ip,
                    remote_port: s.remote_port,
                    bytes_out: d_out,
                    bytes_in: d_in,
                });
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub pid: u32,
    pub remote_raw: String,
    pub remote_ip: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Format (nettop -x -L 1 -J bytes_in,bytes_out -t external):
/// ```text
/// ,bytes_in,bytes_out,
/// curl.1234,120,4096,
/// tcp4 10.0.0.2:5000<->1.2.3.4:443,120,4096,
/// ```
/// Process lines carry `name.pid`, connection lines carry `<->`. The
/// counters are cumulative since the process started; the sensor turns them
/// into deltas.
pub fn parse(text: &str) -> Vec<Sample> {
    let mut out = Vec::new();
    let mut cur: Option<(String, u32)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 3 {
            continue;
        }
        let label = cols[0].trim();
        if let Some((name, pid)) = split_name_pid(label) {
            cur = Some((name, pid));
            continue;
        }
        let Some((name, pid)) = cur.clone() else {
            continue;
        };
        let Some((_, rhs)) = label.split_once("<->") else {
            continue;
        };
        let (ip, port) = split_addr(rhs);
        let bytes_in = cols[1].trim().parse().unwrap_or(0);
        let bytes_out = cols[2].trim().parse().unwrap_or(0);
        out.push(Sample {
            name,
            pid,
            remote_raw: rhs.to_string(),
            remote_ip: ip,
            remote_port: port,
            bytes_in,
            bytes_out,
        });
    }
    out
}

fn split_name_pid(label: &str) -> Option<(String, u32)> {
    let (name, pid) = label.rsplit_once('.')?;
    if name.contains(' ') || name.contains("<->") {
        return None;
    }
    Some((name.to_string(), pid.parse().ok()?))
}

fn split_addr(s: &str) -> (Option<IpAddr>, Option<u16>) {
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()),
        None => (s, None),
    };
    (
        host.trim_matches(|c| c == '[' || c == ']').parse().ok(),
        port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real output from macOS 26.6.
    const REAL: &str = ",bytes_in,bytes_out,
apsd.147,849350,344693,
tcp4 192.0.2.10:64089<->17.57.146.26:5223,849350,344693,
syspolicyd.245,38192,20868,
quic4 192.0.2.10:63920<->17.248.209.74:443,32457,15291,
quic4 192.0.2.10:60299<->17.248.209.74:443,5735,5577,
mDNSResponder.247,11920435,8353813,
udp6 *.5353<->*.*,5735596,3533949,
udp4 *:5353<->*:*,6184839,4819864,
";

    #[test]
    fn parses_real_output() {
        let s = parse(REAL);
        assert_eq!(s.len(), 5);
        assert_eq!(s[0].name, "apsd");
        assert_eq!(s[0].pid, 147);
        assert_eq!(s[0].remote_ip, Some("17.57.146.26".parse().unwrap()));
        assert_eq!(s[0].remote_port, Some(5223));
        assert_eq!(s[0].bytes_out, 344693);
        assert_eq!(s[1].pid, 245);
        assert_eq!(s[2].remote_port, Some(443));
        assert_eq!(s[3].name, "mDNSResponder");
        assert_eq!(s[3].remote_ip, None);
    }
}
