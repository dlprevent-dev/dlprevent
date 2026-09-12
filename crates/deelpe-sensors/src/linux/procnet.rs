//! Per-process send volumes via `ss` in batch mode. Polling, exactly like
//! `nettop` on the Mac — and for the same reason: the kernel keeps the
//! counter, we only have to read it out often enough.
//!
//! The counter is `bytes_sent` from `tcp_info`, which the kernel keeps per
//! socket; `ss -tinp` prints it together with the process behind the
//! socket. Reading it out of `/proc/net/tcp` is not possible: the columns
//! there are the *queues*, not the total, and a sensor built on them would
//! report a number that says nothing about how much left the machine.
//!
//! Two limits, both of them named rather than papered over:
//!
//! * **TCP only.** `tcp_info` exists for TCP. An upload over QUIC (HTTP/3,
//!   which Chrome uses towards Google) is UDP and carries no byte counter
//!   in the kernel — Windows sees it through ETW, this sensor does not.
//! * **`ss` has to be there** (iproute2, on practically every distribution).
//!   Without it the sensor fails with a clear message and the service shows
//!   it as a red line instead of silently reporting nothing.
//! * **A connection that opens and closes between two polls is invisible.**
//!   `ss` lists live sockets; a closed one takes its counter with it. That
//!   is the price of polling and `nettop` on the Mac pays it too — an
//!   upload of any size stays open long enough, a two-line `curl -T` of a
//!   small file does not. Measured on 2026-09-12: `nc -N`, which hangs up
//!   immediately, produced no event; the same transfer over a connection
//!   left open produced the alert within nine seconds.

use crate::Sensor;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use deelpe_core::event::{Event, NetEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct ProcNet {
    interval: Duration,
}

impl ProcNet {
    pub fn new(secs: u64) -> Self {
        Self { interval: Duration::from_secs(secs.max(1)) }
    }
}

#[async_trait]
impl Sensor for ProcNet {
    fn name(&self) -> &'static str {
        "procnet"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        // Cumulative counters per socket → deltas. Rebuilt every round, so
        // a closed connection drops out instead of growing the table.
        let mut last: HashMap<Key, (u64, u64)> = HashMap::new();
        // The first round only fills the table. Without it, every socket
        // that is already open reports its whole life as one delta — and
        // the service restarts a failed sensor while the correlator keeps
        // its flows, so a single `ss` hiccup in the middle of an upload
        // would count that upload a second time.
        let mut primed = false;
        let mut tick = tokio::time::interval(self.interval);
        loop {
            tick.tick().await;
            let out = Command::new("ss").args(["-tinHp"]).output().await.context("run ss (package iproute2)")?;
            if !out.status.success() {
                bail!("ss ended with {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim_end());
            }
            let at = Utc::now();
            let mut seen: HashMap<Key, (u64, u64)> = HashMap::new();
            // Per round, not per socket: a browser holds dozens of them,
            // and they all belong to the same process.
            let mut parents: HashMap<u32, Option<u32>> = HashMap::new();
            for s in parse(&String::from_utf8_lossy(&out.stdout)) {
                let key = Key { pid: s.pid, local: s.local.clone(), peer: s.peer.clone() };
                let (po, pi) = last.get(&key).copied().unwrap_or((0, 0));
                seen.insert(key, (s.bytes_sent, s.bytes_received));
                if !primed {
                    continue;
                }
                // A counter that jumps backwards means the socket is a new
                // one on the same four-tuple: count it from zero, not into
                // the negative.
                let d_out = s.bytes_sent.saturating_sub(po);
                let d_in = s.bytes_received.saturating_sub(pi);
                if d_out == 0 && d_in == 0 {
                    continue;
                }
                // The one edge that only the network event knows: a process
                // that does nothing but send never appears in the file
                // events, and without its parent the search for a touched
                // ancestor ends before it begins.
                let ppid = *parents.entry(s.pid).or_insert_with(|| {
                    std::fs::read_to_string(format!("/proc/{}/status", s.pid)).ok().as_deref().and_then(super::fanotify::parse_ppid)
                });
                let ev = Event::Net(NetEvent {
                    at,
                    pid: s.pid,
                    ppid,
                    process_name: s.name,
                    remote: Some(s.peer_ip),
                    remote_port: s.peer_port,
                    bytes_out: d_out,
                    bytes_in: d_in,
                });
                if tx.send(ev).await.is_err() {
                    return Ok(());
                }
            }
            last = seen;
            primed = true;
        }
    }
}

/// A socket, as far as it stays the same between two measurements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    pid: u32,
    local: String,
    peer: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub name: String,
    pub pid: u32,
    pub local: String,
    pub peer: String,
    pub peer_ip: IpAddr,
    pub peer_port: Option<u16>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Format (`ss -tinHp`): one socket line, then an indented info line.
///
/// ```text
/// ESTAB 0 0 10.0.0.2:53220 1.2.3.4:443 users:(("curl",pid=276,fd=3))
///      cubic wscale:10,10 rto:205 bytes_sent:3000000 bytes_acked:3000001 ...
/// ```
///
/// A socket without a process (`users:` missing) is skipped: without a
/// sender there is nothing to correlate. Loopback likewise — nothing
/// leaves the machine there.
pub fn parse(text: &str) -> Vec<Sample> {
    let mut out: Vec<Sample> = Vec::new();
    // Whether the last socket line was one we kept: the info line that
    // follows belongs to it, and to nothing else.
    let mut open = false;
    for line in text.lines() {
        if line.starts_with([' ', '\t']) {
            if open {
                if let Some(s) = out.last_mut() {
                    // Assign only what is actually in this line. A second
                    // continuation line without the counters would
                    // otherwise reset them to zero, and `retain` below
                    // would then drop the socket — an upload turned
                    // invisible instead of merely mis-sized.
                    if let Some(v) = field(line, "bytes_sent:") {
                        s.bytes_sent = v;
                    }
                    if let Some(v) = field(line, "bytes_received:") {
                        s.bytes_received = v;
                    }
                }
            }
            continue;
        }
        open = false;
        let Some(s) = socket_line(line) else { continue };
        out.push(s);
        open = true;
    }
    // Sockets that never sent or received anything carry no counter and
    // would only produce empty events.
    out.retain(|s| s.bytes_sent > 0 || s.bytes_received > 0);
    out
}

fn socket_line(line: &str) -> Option<Sample> {
    let mut f = line.split_whitespace();
    // state, recv-q, send-q, local, peer, [users:(...)]
    let (_state, _rq, _sq) = (f.next()?, f.next()?, f.next()?);
    let local = f.next()?.to_string();
    let peer = f.next()?.to_string();
    let users = f.find(|t| t.starts_with("users:("))?;
    let (name, pid) = first_user(users)?;
    let (peer_ip, peer_port) = split_addr(&peer)?;
    // Nothing leaves the machine over loopback, and `0.0.0.0` is a
    // listening socket, not a peer.
    if peer_ip.is_loopback() || peer_ip.is_unspecified() {
        return None;
    }
    Some(Sample { name, pid, local, peer, peer_ip, peer_port, bytes_sent: 0, bytes_received: 0 })
}

/// `users:(("chrome",pid=8952,fd=41),("chrome",pid=8112,fd=7))` → the first
/// entry. Several processes can hold the same socket after a fork; the one
/// that opened it is the first.
fn first_user(users: &str) -> Option<(String, u32)> {
    let inner = users.strip_prefix("users:((")?;
    let (name, rest) = inner.strip_prefix('"')?.split_once('"')?;
    let pid = rest.split("pid=").nth(1)?;
    let pid = pid.trim_start_matches(|c: char| !c.is_ascii_digit());
    let end = pid.find(|c: char| !c.is_ascii_digit()).unwrap_or(pid.len());
    Some((name.to_string(), pid[..end].parse().ok()?))
}

/// `bytes_sent:3000000` out of the info line. Absent when the counter is
/// still zero — the kernel only prints what it has.
fn field(line: &str, key: &str) -> Option<u64> {
    let v = line.split_whitespace().find_map(|t| t.strip_prefix(key))?;
    v.parse().ok()
}

/// `1.2.3.4:443`, `[2001:db8::1]:443` and `[::ffff:1.2.3.4]:443`.
fn split_addr(s: &str) -> Option<(IpAddr, Option<u16>)> {
    let (host, port) = s.rsplit_once(':')?;
    let ip: IpAddr = host.trim_matches(['[', ']']).parse().ok()?;
    // A v4 address in v6 clothing is a v4 address. Otherwise the same
    // destination shows up twice in the dashboard, depending on which
    // socket carried it.
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    Some((ip, port.parse().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real output from iproute2 6.1.0 (`ss -tinHp`), with the loopback
    /// pair from the lab plus an external connection.
    const REAL: &str = "ESTAB 0      0          127.0.0.1:53220    127.0.0.1:9999  users:((\"nc\",pid=276,fd=3))
\t cubic wscale:10,10 rto:205 rtt:4.523/8.981 mss:65483 cwnd:10 bytes_sent:3000000 bytes_acked:3000001 segs_out:98
ESTAB 0      0        10.0.0.2:53222     1.2.3.4:443    users:((\"curl\",pid=8112,fd=5))
\t cubic wscale:8,7 rto:220 bytes_sent:4096 bytes_received:120 segs_out:9
ESTAB 0      0        10.0.0.2:53224  [2001:db8::1]:443 users:((\"chrome\",pid=8952,fd=41),(\"chrome\",pid=8112,fd=7))
\t cubic bytes_sent:50000 segs_out:40
LISTEN 0     4096       0.0.0.0:22          0.0.0.0:*   users:((\"sshd\",pid=1,fd=3))
";

    #[test]
    fn parses_real_output() {
        let s = parse(REAL);
        // Loopback and the listener are gone; two remain.
        assert_eq!(s.len(), 2, "{s:?}");
        assert_eq!(s[0].name, "curl");
        assert_eq!(s[0].pid, 8112);
        assert_eq!(s[0].peer_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(s[0].peer_port, Some(443));
        assert_eq!(s[0].bytes_sent, 4096);
        assert_eq!(s[0].bytes_received, 120);
        // Several holders: the first one counts.
        assert_eq!(s[1].pid, 8952);
        assert_eq!(s[1].peer_ip, "2001:db8::1".parse::<IpAddr>().unwrap());
        // No `bytes_received:` in the line means zero, not a parse failure.
        assert_eq!(s[1].bytes_received, 0);
        assert_eq!(s[1].bytes_sent, 50000);
    }

    /// A v4 address in v6 clothing is the same destination. Otherwise the
    /// dashboard shows one upload target twice.
    #[test]
    fn a_mapped_v4_address_stays_v4() {
        let (ip, port) = split_addr("[::ffff:1.2.3.4]:443").unwrap();
        assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(port, Some(443));
    }

    /// A second continuation line without the counters must not reset what
    /// the first one already delivered — that would not make the number
    /// wrong, it would make the upload disappear.
    #[test]
    fn a_second_info_line_does_not_reset_the_counters() {
        let text = "ESTAB 0 0 10.0.0.2:1 1.2.3.4:443 users:((\"curl\",pid=7,fd=3))
\t cubic bytes_sent:4096 bytes_received:120
\t timer:(keepalive,30sec,0)
";
        let s = parse(text);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].bytes_sent, 4096);
        assert_eq!(s[0].bytes_received, 120);
    }

    /// An info line without a preceding socket line we kept must not
    /// overwrite the counters of the last socket we did keep.
    #[test]
    fn a_skipped_socket_does_not_get_its_neighbours_bytes() {
        let text = "ESTAB 0 0 10.0.0.2:1 1.2.3.4:443 users:((\"curl\",pid=7,fd=3))
\t bytes_sent:4096
ESTAB 0 0 127.0.0.1:2 127.0.0.1:9999 users:((\"nc\",pid=8,fd=3))
\t bytes_sent:999999
";
        let s = parse(text);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].bytes_sent, 4096, "the loopback bytes belong to nobody");
    }
}
