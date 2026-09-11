//! Syslog intake for NAS devices without an agent (decision of 2026-09-06):
//! one parser per vendor, all mapped onto the same [`AccessEvent`]. The raw
//! line is thrown away after condensing; what gets stored are counts per
//! minute and alerts out of the access counter.

use crate::db::{self, Origin, RuleRow};
use crate::state::Shared;
use anyhow::Result;
use chrono::{DateTime, Utc};
use deelpe_core::access::{AccessMeter, AccessParams, Aggregator, RuleView};
use deelpe_core::central::UserRef;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncBufReadExt;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use uuid::Uuid;

pub const KINDS: &[&str] = &["synology", "qnap", "truenas", "samba", "unknown"];
const FLUSH_SECS: u64 = 10;
const RULES_REFRESH_SECS: i64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Delete,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessEvent {
    pub kind: &'static str,
    pub host: Option<String>,
    pub user: String,
    pub domain: Option<String>,
    pub path: String,
    pub action: Action,
    pub bytes: u64,
    pub client_ip: Option<String>,
}

// ---------- Taking lines apart ----------

/// Strips `<PRI>` and the header (RFC 3164 or 5424) and returns (host,
/// message). With an unknown header, the whole line as the message.
pub fn split_header(line: &str) -> (Option<String>, &str) {
    let mut s = line.trim();
    if let Some(rest) = s.strip_prefix('<') {
        if let Some(end) = rest.find('>') {
            if rest[..end].bytes().all(|b| b.is_ascii_digit()) {
                s = &rest[end + 1..];
            }
        }
    }
    let s = s.trim_start();
    // RFC 5424: "1 TIMESTAMP HOST APP PROCID MSGID SD MSG"
    if let Some(rest) = s.strip_prefix("1 ") {
        let mut it = rest.splitn(7, ' ');
        let _ts = it.next();
        let host = it.next().map(str::to_string);
        let _app = it.next();
        let _pid = it.next();
        let _msgid = it.next();
        let sd = it.next().unwrap_or("");
        let msg = it.next().unwrap_or("");
        let _ = sd;
        return (host.filter(|h| h != "-"), msg.trim_start());
    }
    // RFC 3164: "Mon dd HH:MM:SS HOST MSG"
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    if months.iter().any(|m| s.starts_with(m)) {
        let mut it = s.split_whitespace();
        let _mon = it.next();
        let _day = it.next();
        let _time = it.next();
        let host = it.next().map(str::to_string);
        let rest_start = it.next().map(|tok| s.find(tok).unwrap_or(0)).unwrap_or(s.len());
        return (host, s[rest_start..].trim_start());
    }
    (None, s)
}

/// Returns the event if one of the parsers understands the line.
pub fn parse_line(line: &str) -> Option<AccessEvent> {
    let (host, msg) = split_header(line);
    let mut ev = parse_synology(msg).or_else(|| parse_qnap(msg)).or_else(|| parse_samba(msg))?;
    if ev.kind == "samba" && host.as_deref().map(|h| h.to_lowercase().contains("truenas")).unwrap_or(false) {
        ev.kind = "truenas";
    }
    ev.host = host;
    Some(ev)
}

fn kv_after<'a>(msg: &'a str, keys: &[&str], key: &str) -> Option<&'a str> {
    let start = msg.find(key)? + key.len();
    let rest = &msg[start..];
    // The value ends before the next known key (", Key:"), otherwise at the end.
    let mut end = rest.len();
    for k in keys {
        if *k == key {
            continue;
        }
        if let Some(p) = rest.find(&format!(", {k}")) {
            end = end.min(p);
        }
    }
    Some(rest[..end].trim())
}

pub fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    let mut it = s.split_whitespace();
    let num: f64 = it.next().and_then(|n| n.replace(',', "").parse().ok()).unwrap_or(0.0);
    let unit = it.next().unwrap_or("B").to_ascii_uppercase();
    let mult = match unit.as_str() {
        "KB" | "K" | "KIB" => 1024.0,
        "MB" | "M" | "MIB" => 1024.0 * 1024.0,
        "GB" | "G" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "TB" | "T" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (num * mult).round().max(0.0) as u64
}

fn action_from(s: &str) -> Action {
    match s.trim().to_ascii_lowercase().as_str() {
        "read" | "download" | "copy" | "open" | "pread" => Action::Read,
        "write" | "create" | "upload" | "rename" | "move" | "pwrite" => Action::Write,
        "delete" | "unlink" => Action::Delete,
        _ => Action::Other,
    }
}

fn split_user(u: &str) -> (Option<String>, String) {
    if let Some((d, n)) = u.split_once('\\') {
        (Some(d.to_string()), n.to_string())
    } else if let Some((n, d)) = u.split_once('@') {
        (Some(d.to_string()), n.to_string())
    } else {
        (None, u.to_string())
    }
}

/// Synology DSM, the "Dateiübertragung" (file transfer) log via syslog:
/// `WinFileService Event: read, Path: /volume1/GL/x.docx, File/Folder: File, Size: 12.30 KB, User: hans, IP: 10.0.0.5`
fn parse_synology(msg: &str) -> Option<AccessEvent> {
    const KEYS: &[&str] = &["Event:", "Path:", "File/Folder:", "Size:", "User:", "IP:"];
    if !msg.contains("Event:") || !msg.contains("Path:") || !msg.contains("User:") {
        return None;
    }
    let event = kv_after(msg, KEYS, "Event:")?;
    let path = kv_after(msg, KEYS, "Path:")?.to_string();
    let user = kv_after(msg, KEYS, "User:")?;
    let size = kv_after(msg, KEYS, "Size:").map(parse_size).unwrap_or(0);
    let ip = kv_after(msg, KEYS, "IP:").map(|s| s.trim_end_matches('.').to_string()).filter(|s| !s.is_empty());
    let folder = kv_after(msg, KEYS, "File/Folder:").map(|s| s.eq_ignore_ascii_case("folder")).unwrap_or(false);
    if folder {
        return None;
    }
    let (domain, name) = split_user(user);
    Some(AccessEvent { kind: "synology", host: None, user: name, domain, path, action: action_from(event), bytes: size, client_ip: ip })
}

/// QNAP QTS/QuTS, connection log via syslog (field names as in Log Center):
/// `... Users: hans, Source IP: 10.0.0.5, Computer name: PC1, Connection type: SAMBA, Accessed resources: /GL/x.docx, Action: Read`
fn parse_qnap(msg: &str) -> Option<AccessEvent> {
    const KEYS: &[&str] = &["Users:", "Source IP:", "Computer name:", "Connection type:", "Accessed resources:", "Action:"];
    if !msg.contains("Accessed resources:") || !msg.contains("Users:") {
        return None;
    }
    let user = kv_after(msg, KEYS, "Users:")?;
    let path = kv_after(msg, KEYS, "Accessed resources:")?.to_string();
    let action = kv_after(msg, KEYS, "Action:").map(action_from).unwrap_or(Action::Other);
    let ip = kv_after(msg, KEYS, "Source IP:").map(str::to_string).filter(|s| !s.is_empty());
    let (domain, name) = split_user(user);
    Some(AccessEvent { kind: "qnap", host: None, user: name, domain, path, action, bytes: 0, client_ip: ip })
}

/// Samba `vfs_full_audit` (TrueNAS, Linux):
/// `smbd_audit: DOM\hans|10.0.0.5|pc1|GL|open|ok|r|Bericht.docx` or `…|pread|ok|Bericht.docx`
fn parse_samba(msg: &str) -> Option<AccessEvent> {
    let idx = msg.find("smbd_audit:")?;
    let body = msg[idx + "smbd_audit:".len()..].trim();
    let f: Vec<&str> = body.split('|').collect();
    if f.len() < 6 {
        return None;
    }
    let (domain, name) = split_user(f[0]);
    let ip = Some(f[1].to_string()).filter(|s| !s.is_empty());
    let share = f[3];
    let op = f[4];
    let status = f[5];
    if status != "ok" {
        return None;
    }
    let (action, file) = match op {
        "open" | "openat" => {
            let mode = f.get(6).copied().unwrap_or("");
            let file = f.get(7).copied().unwrap_or("");
            (if mode.contains('w') { Action::Write } else { Action::Read }, file)
        }
        "pread" | "read" | "pread_recv" => (Action::Read, f.get(6).copied().unwrap_or("")),
        "pwrite" | "write" | "pwrite_recv" => (Action::Write, f.get(6).copied().unwrap_or("")),
        "unlink" | "unlinkat" => (Action::Delete, f.get(6).copied().unwrap_or("")),
        _ => (Action::Other, f.get(6).copied().unwrap_or("")),
    };
    if file.is_empty() || file == "." {
        return None;
    }
    Some(AccessEvent { kind: "samba", host: None, user: name, domain, path: format!("/{share}/{}", file.trim_start_matches("./")), action, bytes: 0, client_ip: ip })
}

// ---------- Rule matching ----------

pub use deelpe_core::rules::rule_matches;

// ---------- Processing ----------

struct SourceCtx {
    id: Uuid,
    name: String,
    kind: String,
    meter: AccessMeter,
    rules: Vec<RuleRow>,
    rules_at: DateTime<Utc>,
    /// Counts and sample files; shares the code with the Windows file
    /// server agent (`deelpe_core::access`).
    agg: Aggregator,
    /// Learning phase from the settings; refreshed along with the rules,
    /// not queried per line (the intake is the hot path).
    learn_days: u32,
    lines: i64,
    unparsed: i64,
    dirty: bool,
}

/// How fast the receiver follows a flip of the switch in the settings.
const SWITCH_POLL_SECS: u64 = 5;

/// Supervision of the receiver. The switch in the settings really closes
/// the port — the sockets are released, not merely the lines thrown away.
/// An open port that nobody needs is attack surface: syslog is
/// unauthenticated, and UDP can be forged.
///
/// The default is "on", so that an existing server keeps hearing from its
/// NAS devices after the update; whoever has no syslog source switches it
/// off.
pub async fn run(state: Shared, addr: SocketAddr, stop: CancellationToken) -> Result<()> {
    let mut running: Option<(CancellationToken, tokio::task::JoinHandle<()>)> = None;
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(SWITCH_POLL_SECS));
    loop {
        tokio::select! {
            _ = stop.cancelled() => {
                if let Some((c, h)) = running {
                    c.cancel();
                    let _ = h.await;
                }
                return Ok(());
            }
            _ = tick.tick() => {}
        }
        let want = db::setting_bool(&state.pool, "syslog_enabled", true).await.unwrap_or(true);
        match (want, running.is_some()) {
            (true, false) => {
                let child = stop.child_token();
                let (st, c) = (state.clone(), child.clone());
                match listen(addr).await {
                    Ok(sockets) => {
                        info!(%addr, "Syslog (UDP+TCP)");
                        running = Some((child, tokio::spawn(async move {
                            if let Err(e) = session(st, sockets, c).await {
                                warn!("syslog listener stopped: {e:#}");
                            }
                        })));
                    }
                    // Port already taken: once more on the next tick.
                    Err(e) => warn!(%addr, "syslog listener not bound: {e:#}"),
                }
            }
            (false, true) => {
                if let Some((c, h)) = running.take() {
                    c.cancel();
                    let _ = h.await;
                    info!(%addr, "Syslog abgeschaltet");
                }
            }
            _ => {}
        }
    }
}

async fn listen(addr: SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    Ok((UdpSocket::bind(addr).await?, TcpListener::bind(addr).await?))
}

async fn session(state: Shared, (udp, tcp): (UdpSocket, TcpListener), stop: CancellationToken) -> Result<()> {
    let (tx, rx) = mpsc::channel::<(IpAddr, String)>(10_000);
    let t1 = tx.clone();
    let s1 = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let r = tokio::select! { r = udp.recv_from(&mut buf) => r, _ = s1.cancelled() => return };
            if let Ok((n, peer)) = r {
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    if !line.trim().is_empty() {
                        let _ = t1.try_send((peer.ip(), line.to_string()));
                    }
                }
            }
        }
    });
    let s2 = stop.clone();
    tokio::spawn(async move {
        loop {
            let (stream, peer) = tokio::select! { r = tcp.accept() => match r { Ok(x) => x, Err(_) => continue }, _ = s2.cancelled() => return };
            let tx = tx.clone();
            let s3 = s2.clone();
            tokio::spawn(async move {
                let mut lines = tokio::io::BufReader::new(stream).lines();
                loop {
                    let l = tokio::select! { l = lines.next_line() => l, _ = s3.cancelled() => return };
                    match l {
                        Ok(Some(line)) => {
                            if !line.trim().is_empty() {
                                let _ = tx.send((peer.ip(), line)).await;
                            }
                        }
                        _ => return,
                    }
                }
            });
        }
    });
    process(state, rx, stop).await
}

async fn process(state: Shared, mut rx: mpsc::Receiver<(IpAddr, String)>, stop: CancellationToken) -> Result<()> {
    let mut ctx: HashMap<IpAddr, SourceCtx> = HashMap::new();
    let mut flush = tokio::time::interval(std::time::Duration::from_secs(FLUSH_SECS));
    loop {
        tokio::select! {
            Some((ip, line)) = rx.recv() => {
                if let Err(e) = handle_line(&state, &mut ctx, ip, &line).await {
                    warn!(%ip, "Syslog: {e:#}");
                }
            }
            _ = flush.tick() => {
                flush_all(&state, &mut ctx).await;
            }
            _ = stop.cancelled() => {
                flush_all(&state, &mut ctx).await;
                return Ok(());
            }
        }
    }
}

async fn load_ctx(state: &Shared, ip: IpAddr, host: Option<&str>, kind: &str) -> Result<SourceCtx> {
    let row: Option<(Uuid, String, String, Option<serde_json::Value>, i64, i64)> =
        sqlx::query_as("SELECT id, name, kind, meter, lines, unparsed FROM sources WHERE address = $1").bind(ip.to_string()).fetch_optional(&state.pool).await?;
    let (id, name, kind, meter, lines, unparsed) = match row {
        Some(r) => r,
        None => {
            let name = host.map(str::to_string).unwrap_or_else(|| ip.to_string());
            let (id,): (Uuid,) = sqlx::query_as("INSERT INTO sources (name, kind, address, last_seen) VALUES ($1, $2, $3, now()) RETURNING id")
                .bind(&name)
                .bind(kind)
                .bind(ip.to_string())
                .fetch_one(&state.pool)
                .await?;
            info!(%ip, name, kind, "new syslog source");
            db::audit(&state.pool, db::Actor::SYSTEM, "source_new", serde_json::json!({ "id": id, "name": name, "kind": kind, "address": ip.to_string() })).await;
            (id, name, kind.to_string(), None, 0, 0)
        }
    };
    let meter = meter.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_else(|| AccessMeter::new(Utc::now()));
    let rules = db::rules_for_source(&state.pool, id).await?;
    let learn_days = db::setting_i64(&state.pool, "learn_days", 7).await? as u32;
    Ok(SourceCtx { id, name, kind, meter, rules, rules_at: Utc::now(), agg: Aggregator::new(), learn_days, lines, unparsed, dirty: false })
}

async fn handle_line(state: &Shared, ctx: &mut HashMap<IpAddr, SourceCtx>, ip: IpAddr, line: &str) -> Result<()> {
    let parsed = parse_line(line);
    if let std::collections::hash_map::Entry::Vacant(e) = ctx.entry(ip) {
        let (host, kind) = match &parsed {
            Some(ev) => (ev.host.clone(), ev.kind),
            None => (split_header(line).0, "unknown"),
        };
        e.insert(load_ctx(state, ip, host.as_deref(), kind).await?);
    }
    let c = ctx.get_mut(&ip).unwrap();
    c.lines += 1;
    c.dirty = true;
    let Some(ev) = parsed else {
        c.unparsed += 1;
        debug!(%ip, "not understood: {}", line.chars().take(200).collect::<String>());
        return Ok(());
    };
    if c.kind == "unknown" && ev.kind != "unknown" {
        c.kind = ev.kind.to_string();
        sqlx::query("UPDATE sources SET kind = $2 WHERE id = $1").bind(c.id).bind(&c.kind).execute(&state.pool).await?;
    }
    if ev.action != Action::Read {
        return Ok(());
    }
    let now = Utc::now();
    if now - c.rules_at > chrono::Duration::seconds(RULES_REFRESH_SECS) {
        c.rules = db::rules_for_source(&state.pool, c.id).await?;
        c.learn_days = db::setting_i64(&state.pool, "learn_days", 7).await? as u32;
        c.rules_at = now;
    }
    let user = UserRef { source: c.name.clone(), name: ev.user.clone(), domain: ev.domain.clone(), sid: None };
    let rules: Vec<RuleRow> = c.rules.iter().filter(|r| rule_matches(&r.path, &ev.path)).cloned().collect();
    for r in rules {
        let id = r.id.to_string();
        let rule = RuleView {
            id: &id,
            path: &r.path,
            params: AccessParams { hard_max_files: r.hard_max_files.max(1) as u32, window_secs: r.window_secs.max(1) as u32, learn_days: c.learn_days },
        };
        let Some(alert) = c.agg.observe(&mut c.meter, &rule, &user, &ev.path, ev.bytes, ev.client_ip.as_deref(), now) else { continue };
        let name = c.name.clone();
        let new = db::upsert_access_alert(&state.pool, Origin::Source(c.id), &name, &alert).await?;
        if new {
            warn!(source = %name, user = %user.display(), path = %r.path, "Massenzugriff: {}", alert.reason.as_deref().unwrap_or(""));
        }
    }
    Ok(())
}

async fn flush_all(state: &Shared, ctx: &mut HashMap<IpAddr, SourceCtx>) {
    let mut gone: Vec<IpAddr> = Vec::new();
    for (ip, c) in ctx.iter_mut() {
        if !c.dirty {
            continue;
        }
        let counts = c.agg.take_counts();
        if let Err(e) = db::upsert_counts(&state.pool, c.id, &counts).await {
            warn!("writing counts: {e:#}");
        }
        c.meter.prune(Utc::now());
        let r = sqlx::query("UPDATE sources SET last_seen = now(), lines = $2, unparsed = $3, meter = $4 WHERE id = $1")
            .bind(c.id)
            .bind(c.lines)
            .bind(c.unparsed)
            .bind(serde_json::to_value(&c.meter).unwrap_or_default())
            .execute(&state.pool)
            .await;
        match r {
            // Deleted in the dashboard: forget the context, the next line
            // creates the source anew. Otherwise every write fails with the
            // dead ID until the server restarts.
            Ok(res) if res.rows_affected() == 0 => {
                info!(source = %c.name, "source is gone, it will be created again");
                gone.push(*ip);
            }
            Err(e) => warn!("saving source: {e}"),
            Ok(_) => {}
        }
        c.dirty = false;
    }
    for ip in gone {
        ctx.remove(&ip);
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synology_line() {
        let l = "<14>Sep  6 10:00:01 NAS01 WinFileService Event: read, Path: /volume1/GL/Budget, 2026.xlsx, File/Folder: File, Size: 12.30 KB, User: hans, IP: 10.0.0.5";
        let ev = parse_line(l).unwrap();
        assert_eq!(ev.kind, "synology");
        assert_eq!(ev.host.as_deref(), Some("NAS01"));
        assert_eq!(ev.user, "hans");
        assert_eq!(ev.path, "/volume1/GL/Budget, 2026.xlsx");
        assert_eq!(ev.action, Action::Read);
        assert_eq!(ev.bytes, 12595);
        assert_eq!(ev.client_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn synology_folder_and_write_ignored_for_reads() {
        let l = "Sep  6 10:00:01 NAS01 WinFileService Event: read, Path: /volume1/GL, File/Folder: Folder, Size: 0 B, User: hans, IP: 10.0.0.5";
        assert!(parse_line(l).is_none());
        let l = "Sep  6 10:00:01 NAS01 WinFileService Event: write, Path: /volume1/GL/a.docx, File/Folder: File, Size: 1 MB, User: DOM\\hans, IP: 10.0.0.5";
        let ev = parse_line(l).unwrap();
        assert_eq!(ev.action, Action::Write);
        assert_eq!(ev.domain.as_deref(), Some("DOM"));
        assert_eq!(ev.bytes, 1_048_576);
    }

    #[test]
    fn rfc5424_header() {
        let l = "<134>1 2026-09-06T10:00:01.000Z nas02 WinFileService - - - Event: download, Path: /volume1/GL/x.pdf, File/Folder: File, Size: 2.5 MB, User: eva, IP: 10.0.0.9";
        let ev = parse_line(l).unwrap();
        assert_eq!(ev.host.as_deref(), Some("nas02"));
        assert_eq!(ev.user, "eva");
        assert_eq!(ev.action, Action::Read);
    }

    #[test]
    fn qnap_line() {
        let l = "<13>Sep  6 10:00:01 QNAP1 conn log: Users: hans, Source IP: 10.0.0.5, Computer name: PC1, Connection type: SAMBA, Accessed resources: /GL/Vertrag.pdf, Action: Read";
        let ev = parse_line(l).unwrap();
        assert_eq!(ev.kind, "qnap");
        assert_eq!(ev.path, "/GL/Vertrag.pdf");
        assert_eq!(ev.action, Action::Read);
        assert_eq!(ev.client_ip.as_deref(), Some("10.0.0.5"));
    }

    #[test]
    fn samba_full_audit() {
        let l = "<86>Sep  6 10:00:01 truenas smbd_audit: DOM\\hans|10.0.0.5|pc1|GL|open|ok|r|Bericht.docx";
        let ev = parse_line(l).unwrap();
        assert_eq!(ev.kind, "truenas");
        assert_eq!(ev.user, "hans");
        assert_eq!(ev.path, "/GL/Bericht.docx");
        assert_eq!(ev.action, Action::Read);
        let l = "Sep  6 10:00:01 srv smbd_audit: hans|10.0.0.5|pc1|GL|pread|ok|./Bericht.docx";
        assert_eq!(parse_line(l).unwrap().path, "/GL/Bericht.docx");
        let l = "Sep  6 10:00:01 srv smbd_audit: hans|10.0.0.5|pc1|GL|open|fail|r|Bericht.docx";
        assert!(parse_line(l).is_none());
    }

    #[test]
    fn unknown_line() {
        assert!(parse_line("<30>Sep  6 10:00:01 nas kernel: eth0 link up").is_none());
    }

    #[test]
    fn rule_matching() {
        assert!(rule_matches("GL", "/volume1/GL/x.docx"));
        assert!(rule_matches("gl", "D:\\Shares\\GL\\Sub\\x.docx"));
        assert!(!rule_matches("GL", "/volume1/GLOBAL/x.docx"));
        assert!(!rule_matches("GL", "/volume1/x/GL.docx"));
        assert!(rule_matches("/volume1/GL", "/volume1/GL/x.docx"));
        assert!(rule_matches("/volume1/GL/", "/volume1/gl/x.docx"));
        assert!(!rule_matches("/volume1/GL", "/volume2/GL/x.docx"));
        assert!(rule_matches("D:\\Shares\\GL", "D:\\Shares\\GL\\x.docx"));
        assert!(!rule_matches("", "/a"));
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("0 B"), 0);
        assert_eq!(parse_size("1.5 KB"), 1536);
        assert_eq!(parse_size("2 GB"), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_size("1,024 B"), 1024);
    }
}
