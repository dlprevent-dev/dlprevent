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
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

pub const KINDS: &[&str] = &["synology", "qnap", "truenas", "samba", "unknown"];
const FLUSH_SECS: u64 = 10;
const RULES_REFRESH_SECS: i64 = 30;

// Ceilings on what an unauthenticated sender can make the intake hold.

/// Unconfirmed sources the intake creates at most. Each one is a row, an
/// audit entry and a context in memory, and every forged address makes one.
/// Confirmed sources are bounded by the administrator, so this also bounds
/// the contexts in memory. Beyond it, lines from new addresses are dropped
/// until an administrator confirms or deletes the waiting ones.
const MAX_UNCONFIRMED_SOURCES: i64 = 100;
/// (User, rule) pairs one source's access counter follows. A large NAS has
/// a few thousand users; beyond the ceiling, only pairs already followed are
/// counted, so a flood of made-up names cannot grow the meter without end.
const MAX_USERS_PER_SOURCE: usize = 50_000;
/// Longest line taken, TCP and UDP alike. Real lines are a few hundred bytes
/// and a path is at most 4 KiB. The queue holds 10,000 lines, so this also
/// bounds it at 160 MiB. A longer TCP line closes the connection.
const MAX_LINE_BYTES: usize = 16 * 1024;
/// A TCP connection without a line for this long is closed. Generous: a NAS
/// is quiet at night, and a sender that finds its connection closed may lose
/// the first line after it. The point is that dead peers do not pin a task
/// forever.
const TCP_IDLE_SECS: u64 = 15 * 60;
/// TCP connections open at once. A NAS keeps one; without a ceiling a single
/// host could hold every file descriptor of the process (a line every 15
/// minutes keeps a connection alive), and then the dashboard and the
/// database pool could not open one either. Beyond it, new connections are
/// closed at once.
// ponytail: one global ceiling, so one host can crowd out the others over
// TCP (UDP still works); a per-address ceiling if that ever matters.
const MAX_TCP_CONNECTIONS: usize = 256;
/// A warning that could repeat per line goes out at most this often.
const LOUD_EVERY_SECS: u64 = 60;

static DROPPED: AtomicU64 = AtomicU64::new(0);
static DROPPED_SAID: AtomicU64 = AtomicU64::new(0);
static REFUSED_SAID: AtomicU64 = AtomicU64::new(0);
static CAPPED_SAID: AtomicU64 = AtomicU64::new(0);
static TCP_FULL_SAID: AtomicU64 = AtomicU64::new(0);

/// Whether a warning that can repeat per line may go out now: a flood shows
/// in the log without flooding it.
fn loud(said: &AtomicU64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let prev = said.load(Ordering::Relaxed);
    now >= prev + LOUD_EVERY_SECS
        && said
            .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

/// A line that did not fit into the queue: counted, and said now and then.
fn dropped(ip: IpAddr) {
    DROPPED.fetch_add(1, Ordering::Relaxed);
    if loud(&DROPPED_SAID) {
        warn!(%ip, dropped = DROPPED.swap(0, Ordering::Relaxed), "syslog queue full, lines dropped");
    }
}

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
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if months.iter().any(|m| s.starts_with(m)) {
        let mut it = s.split_whitespace();
        let _mon = it.next();
        let _day = it.next();
        let _time = it.next();
        let host = it.next().map(str::to_string);
        let rest_start = it
            .next()
            .map(|tok| s.find(tok).unwrap_or(0))
            .unwrap_or(s.len());
        return (host, s[rest_start..].trim_start());
    }
    (None, s)
}

/// Returns the event if one of the parsers understands the line.
pub fn parse_line(line: &str) -> Option<AccessEvent> {
    let (host, msg) = split_header(line);
    let mut ev = parse_synology(msg)
        .or_else(|| parse_qnap(msg))
        .or_else(|| parse_samba(msg))?;
    if ev.kind == "samba"
        && host
            .as_deref()
            .map(|h| h.to_lowercase().contains("truenas"))
            .unwrap_or(false)
    {
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

/// Largest size one access may report: far above any real file, and small
/// enough that no sum of them in a counter comes near `u64::MAX`.
const MAX_SIZE_BYTES: u64 = 1 << 40; // 1 TiB

pub fn parse_size(s: &str) -> u64 {
    let s = s.trim();
    let mut it = s.split_whitespace();
    // `1e400` parses as infinity and casts to u64::MAX, which overflowed the
    // byte counter downstream (vuln-0009).
    let num: f64 = it
        .next()
        .and_then(|n| n.replace(',', "").parse().ok())
        .filter(|n: &f64| n.is_finite())
        .unwrap_or(0.0);
    let unit = it.next().unwrap_or("B").to_ascii_uppercase();
    let mult = match unit.as_str() {
        "KB" | "K" | "KIB" => 1024.0,
        "MB" | "M" | "MIB" => 1024.0 * 1024.0,
        "GB" | "G" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "TB" | "T" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };
    (num * mult).round().clamp(0.0, MAX_SIZE_BYTES as f64) as u64
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
    let ip = kv_after(msg, KEYS, "IP:")
        .map(|s| s.trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty());
    let folder = kv_after(msg, KEYS, "File/Folder:")
        .map(|s| s.eq_ignore_ascii_case("folder"))
        .unwrap_or(false);
    if folder {
        return None;
    }
    let (domain, name) = split_user(user);
    Some(AccessEvent {
        kind: "synology",
        host: None,
        user: name,
        domain,
        path,
        action: action_from(event),
        bytes: size,
        client_ip: ip,
    })
}

/// QNAP QTS/QuTS, connection log via syslog (field names as in Log Center):
/// `... Users: hans, Source IP: 10.0.0.5, Computer name: PC1, Connection type: SAMBA, Accessed resources: /GL/x.docx, Action: Read`
fn parse_qnap(msg: &str) -> Option<AccessEvent> {
    const KEYS: &[&str] = &[
        "Users:",
        "Source IP:",
        "Computer name:",
        "Connection type:",
        "Accessed resources:",
        "Action:",
    ];
    if !msg.contains("Accessed resources:") || !msg.contains("Users:") {
        return None;
    }
    let user = kv_after(msg, KEYS, "Users:")?;
    let path = kv_after(msg, KEYS, "Accessed resources:")?.to_string();
    let action = kv_after(msg, KEYS, "Action:")
        .map(action_from)
        .unwrap_or(Action::Other);
    let ip = kv_after(msg, KEYS, "Source IP:")
        .map(str::to_string)
        .filter(|s| !s.is_empty());
    let (domain, name) = split_user(user);
    Some(AccessEvent {
        kind: "qnap",
        host: None,
        user: name,
        domain,
        path,
        action,
        bytes: 0,
        client_ip: ip,
    })
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
            (
                if mode.contains('w') {
                    Action::Write
                } else {
                    Action::Read
                },
                file,
            )
        }
        "pread" | "read" | "pread_recv" => (Action::Read, f.get(6).copied().unwrap_or("")),
        "pwrite" | "write" | "pwrite_recv" => (Action::Write, f.get(6).copied().unwrap_or("")),
        "unlink" | "unlinkat" => (Action::Delete, f.get(6).copied().unwrap_or("")),
        _ => (Action::Other, f.get(6).copied().unwrap_or("")),
    };
    if file.is_empty() || file == "." {
        return None;
    }
    Some(AccessEvent {
        kind: "samba",
        host: None,
        user: name,
        domain,
        path: format!("/{share}/{}", file.trim_start_matches("./")),
        action,
        bytes: 0,
        client_ip: ip,
    })
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
    /// Confirmed by an administrator; refreshed along with the rules. Until
    /// then the lines are counted and nothing else happens.
    confirmed: bool,
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
        // A receiver that died on its own (a panic, an error) is started
        // again on this very tick. Before, it stayed dead behind a live
        // server until the next restart, and nothing said so.
        if running.as_ref().is_some_and(|(_, h)| h.is_finished()) {
            let (c, h) = running.take().unwrap();
            // Its UDP and TCP readers are tasks of their own and still hold
            // the port.
            c.cancel();
            match h.await {
                Err(e) => error!(%addr, "syslog receiver died, starting it again: {e}"),
                Ok(()) => error!(%addr, "syslog receiver stopped, starting it again"),
            }
        }
        let want = db::setting_bool(&state.pool, "syslog_enabled", true)
            .await
            .unwrap_or(true);
        match (want, running.is_some()) {
            (true, false) => {
                let child = stop.child_token();
                let (st, c) = (state.clone(), child.clone());
                match listen(addr).await {
                    Ok(sockets) => {
                        info!(%addr, "Syslog (UDP+TCP)");
                        running = Some((
                            child,
                            tokio::spawn(async move {
                                if let Err(e) = session(st, sockets, c).await {
                                    warn!("syslog listener stopped: {e:#}");
                                }
                            }),
                        ));
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

async fn session(
    state: Shared,
    (udp, tcp): (UdpSocket, TcpListener),
    stop: CancellationToken,
) -> Result<()> {
    let (tx, rx) = mpsc::channel::<(IpAddr, String)>(10_000);
    let t1 = tx.clone();
    let s1 = stop.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let r =
                tokio::select! { r = udp.recv_from(&mut buf) => r, _ = s1.cancelled() => return };
            if let Ok((n, peer)) = r {
                let text = String::from_utf8_lossy(&buf[..n]);
                for line in text.lines() {
                    if !line.trim().is_empty()
                        && line.len() <= MAX_LINE_BYTES
                        && t1.try_send((peer.ip(), line.to_string())).is_err()
                    {
                        dropped(peer.ip());
                    }
                }
            }
        }
    });
    tokio::spawn(tcp_accept(tcp, tx, stop.clone(), MAX_TCP_CONNECTIONS));
    process(state, rx, stop).await
}

/// Accepts TCP senders, at most `max` at a time.
async fn tcp_accept(
    tcp: TcpListener,
    tx: mpsc::Sender<(IpAddr, String)>,
    stop: CancellationToken,
    max: usize,
) {
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(max));
    loop {
        let r = tokio::select! { r = tcp.accept() => r, _ = stop.cancelled() => return };
        let (stream, peer) = match r {
            Ok(x) => x,
            Err(e) => {
                // Out of file descriptors, most likely: an immediate retry
                // fails the same way and spins a core.
                debug!("syslog accept: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            if loud(&TCP_FULL_SAID) {
                warn!(%peer, "{max} syslog TCP connections open, new ones are closed");
            }
            continue;
        };
        let (tx, stop) = (tx.clone(), stop.clone());
        tokio::spawn(async move {
            tcp_lines(
                stream,
                peer,
                tx,
                stop,
                std::time::Duration::from_secs(TCP_IDLE_SECS),
            )
            .await;
            drop(slot);
        });
    }
}

/// One TCP connection, line by line: at most `MAX_LINE_BYTES` per line, and
/// closed after `idle` without one.
async fn tcp_lines<S: tokio::io::AsyncRead + Unpin>(
    stream: S,
    peer: SocketAddr,
    tx: mpsc::Sender<(IpAddr, String)>,
    stop: CancellationToken,
    idle: std::time::Duration,
) {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        // One byte past the ceiling: a line that long has no end in sight,
        // and the connection goes.
        let mut limited = (&mut reader).take(MAX_LINE_BYTES as u64 + 1);
        let read = limited.read_until(b'\n', &mut buf);
        let r = tokio::select! {
            r = tokio::time::timeout(idle, read) => r,
            _ = stop.cancelled() => return,
        };
        match r {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Err(_) => {
                debug!(%peer, "syslog connection idle, closed");
                return;
            }
            Ok(Ok(_)) if buf.len() > MAX_LINE_BYTES && !buf.ends_with(b"\n") => {
                warn!(%peer, "syslog line longer than {MAX_LINE_BYTES} bytes, connection closed");
                return;
            }
            Ok(Ok(_)) => {
                let line = String::from_utf8_lossy(&buf)
                    .trim_end_matches(['\r', '\n'])
                    .to_string();
                if !line.trim().is_empty() && tx.send((peer.ip(), line)).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn process(
    state: Shared,
    mut rx: mpsc::Receiver<(IpAddr, String)>,
    stop: CancellationToken,
) -> Result<()> {
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

/// The context of the source at `ip`; a new address becomes an unconfirmed
/// source. `None` when `MAX_UNCONFIRMED_SOURCES` are already waiting.
async fn load_ctx(
    state: &Shared,
    ip: IpAddr,
    host: Option<&str>,
    kind: &str,
) -> Result<Option<SourceCtx>> {
    let row: Option<(
        Uuid,
        String,
        String,
        Option<serde_json::Value>,
        i64,
        i64,
        bool,
    )> = sqlx::query_as(
        "SELECT id, name, kind, meter, lines, unparsed, confirmed FROM sources WHERE address = $1",
    )
    .bind(ip.to_string())
    .fetch_optional(&state.pool)
    .await?;
    let (id, name, kind, meter, lines, unparsed, confirmed) = match row {
        Some(r) => r,
        None => {
            // The host name in the header is whatever the sender wrote. One
            // that another source already carries is not handed out twice:
            // the newcomer is listed under its address instead. Nor is
            // another address: a source named "10.0.0.5" sending from
            // 10.0.0.66 passes for the device at 10.0.0.5.
            let taken = match host {
                Some(h) if h.parse::<IpAddr>().is_ok_and(|a| a != ip) => true,
                Some(h) => {
                    sqlx::query_scalar(
                        "SELECT EXISTS (SELECT 1 FROM sources WHERE lower(name) = lower($1))",
                    )
                    .bind(h)
                    .fetch_one(&state.pool)
                    .await?
                }
                None => false,
            };
            let name = host
                .filter(|_| !taken)
                .map(str::to_string)
                .unwrap_or_else(|| ip.to_string());
            let id: Option<Uuid> = sqlx::query_scalar(
                "INSERT INTO sources (name, kind, address, last_seen) SELECT $1, $2, $3, now() \
                 WHERE (SELECT count(*) FROM sources WHERE NOT confirmed) < $4 RETURNING id",
            )
            .bind(&name)
            .bind(kind)
            .bind(ip.to_string())
            .bind(MAX_UNCONFIRMED_SOURCES)
            .fetch_optional(&state.pool)
            .await?;
            let Some(id) = id else { return Ok(None) };
            if taken {
                warn!(%ip, claimed = host, "new syslog source claims the name of another source, listed under its address");
            }
            warn!(%ip, name, kind, "new syslog source, it raises no alerts until confirmed in the dashboard");
            db::audit(&state.pool, db::Actor::SYSTEM, "source_new", serde_json::json!({ "id": id, "name": name, "kind": kind, "address": ip.to_string(), "claimed": host, "confirmed": false })).await;
            (id, name, kind.to_string(), None, 0, 0, false)
        }
    };
    let meter = meter
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_else(|| AccessMeter::new(Utc::now()));
    let rules = db::rules_for_source(&state.pool, id).await?;
    let learn_days = db::setting_i64(&state.pool, "learn_days", 7).await? as u32;
    Ok(Some(SourceCtx {
        id,
        name,
        kind,
        meter,
        rules,
        rules_at: Utc::now(),
        agg: Aggregator::new(),
        learn_days,
        lines,
        unparsed,
        dirty: false,
        confirmed,
    }))
}

async fn handle_line(
    state: &Shared,
    ctx: &mut HashMap<IpAddr, SourceCtx>,
    ip: IpAddr,
    line: &str,
) -> Result<()> {
    let parsed = parse_line(line);
    if let std::collections::hash_map::Entry::Vacant(e) = ctx.entry(ip) {
        let (host, kind) = match &parsed {
            Some(ev) => (ev.host.clone(), ev.kind),
            None => (split_header(line).0, "unknown"),
        };
        match load_ctx(state, ip, host.as_deref(), kind).await? {
            Some(c) => e.insert(c),
            None => {
                if loud(&REFUSED_SAID) {
                    warn!(%ip, "{MAX_UNCONFIRMED_SOURCES} syslog sources wait for confirmation, lines from new addresses are dropped");
                }
                return Ok(());
            }
        };
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
        sqlx::query("UPDATE sources SET kind = $2 WHERE id = $1")
            .bind(c.id)
            .bind(&c.kind)
            .execute(&state.pool)
            .await?;
    }
    if ev.action != Action::Read {
        return Ok(());
    }
    let now = Utc::now();
    if now - c.rules_at > chrono::Duration::seconds(RULES_REFRESH_SECS) {
        c.rules = db::rules_for_source(&state.pool, c.id).await?;
        c.learn_days = db::setting_i64(&state.pool, "learn_days", 7).await? as u32;
        // Gone from the table counts as unconfirmed; `flush_all` forgets it.
        c.confirmed = sqlx::query_scalar("SELECT confirmed FROM sources WHERE id = $1")
            .bind(c.id)
            .fetch_optional(&state.pool)
            .await?
            .unwrap_or(false);
        c.rules_at = now;
    }
    if !c.confirmed {
        return Ok(());
    }
    let user = UserRef {
        source: c.name.clone(),
        name: ev.user.clone(),
        domain: ev.domain.clone(),
        sid: None,
    };
    let rules: Vec<RuleRow> = c
        .rules
        .iter()
        .filter(|r| rule_matches(&r.path, &ev.path))
        .cloned()
        .collect();
    for r in rules {
        let id = r.id.to_string();
        if c.meter.user_count() >= MAX_USERS_PER_SOURCE && !c.meter.tracks(&id, &user) {
            if loud(&CAPPED_SAID) {
                warn!(source = %c.name, "{MAX_USERS_PER_SOURCE} users followed, new users are not counted");
            }
            continue;
        }
        let rule = RuleView {
            id: &id,
            path: &r.path,
            params: AccessParams {
                hard_max_files: r.hard_max_files.max(1) as u32,
                window_secs: r.window_secs.max(1) as u32,
                learn_days: c.learn_days,
            },
        };
        let Some(alert) = c.agg.observe(
            &mut c.meter,
            &rule,
            &user,
            &ev.path,
            ev.bytes,
            ev.client_ip.as_deref(),
            now,
        ) else {
            continue;
        };
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
pub(crate) mod tests {
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

    /// vuln-0009: a size is bounded, whatever the line claims.
    #[test]
    fn absurd_sizes_are_bounded() {
        for s in [
            "1e400 B",
            "inf",
            "NaN",
            "18446744073709551615 B",
            "1000000000000 TB",
        ] {
            assert!(parse_size(s) <= MAX_SIZE_BYTES, "{s}: {}", parse_size(s));
        }
        assert_eq!(parse_size("1e400 B"), 0, "not a number is no size");
        assert_eq!(parse_size("-5 KB"), 0);
    }

    /// A shared state on the test database, as `api::tests` builds it.
    pub(crate) fn state(pool: sqlx::PgPool) -> Shared {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = std::env::temp_dir().join(format!("deelpe-syslog-test-{}", Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        std::sync::Arc::new(crate::state::AppState::new(
            pool,
            std::sync::Arc::new(pki),
            false,
            8444,
            false,
            dir,
        ))
    }

    fn free_port() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    fn read_line(user: &str, file: &str, size: &str) -> String {
        format!("<14>Sep  6 10:00:01 NAS01 WinFileService Event: read, Path: /volume1/GL/{file}, File/Folder: File, Size: {size}, User: {user}, IP: 10.0.0.5")
    }

    async fn alerts_for(pool: &sqlx::PgPool, user: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM alerts WHERE user_display = $1")
            .bind(user)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// vuln-0010: a datagram from an address nobody knows used to create a
    /// source and raise alerts in the same breath. Now the source waits for
    /// an administrator; its lines are counted, nothing more.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_new_source_raises_no_alert_until_it_is_confirmed(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO rules (name, path, hard_max_files, window_secs) VALUES ('GL', '/volume1/GL', 1, 300)").execute(&pool).await.unwrap();
        let st = state(pool.clone());
        let mut ctx = HashMap::new();
        let ip: IpAddr = "10.0.0.66".parse().unwrap();
        for f in ["a", "b", "c"] {
            handle_line(&st, &mut ctx, ip, &read_line("hans", f, "1 KB"))
                .await
                .unwrap();
        }
        assert_eq!(
            alerts_for(&pool, "hans").await,
            0,
            "an unconfirmed source raised an alert"
        );
        let (confirmed,): (bool,) =
            sqlx::query_as("SELECT confirmed FROM sources WHERE address = '10.0.0.66'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!confirmed);
        assert_eq!(ctx[&ip].lines, 3, "its lines are still counted");

        // Confirmed in the dashboard; the intake notices with the next refresh.
        sqlx::query("UPDATE sources SET confirmed = true WHERE address = '10.0.0.66'")
            .execute(&pool)
            .await
            .unwrap();
        ctx.get_mut(&ip).unwrap().rules_at -= chrono::Duration::seconds(RULES_REFRESH_SECS + 1);
        for f in ["d", "e"] {
            handle_line(&st, &mut ctx, ip, &read_line("hans", f, "1 KB"))
                .await
                .unwrap();
        }
        assert_eq!(alerts_for(&pool, "hans").await, 1);
    }

    /// vuln-0011: forged addresses cannot grow the source table and the
    /// contexts in memory without end.
    #[sqlx::test(migrations = "./migrations")]
    async fn unconfirmed_sources_stop_at_a_ceiling(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO sources (name, kind, address) SELECT 'n' || i, 'unknown', '10.1.0.' || i FROM generate_series(1, $1::int) i")
            .bind(MAX_UNCONFIRMED_SOURCES as i32)
            .execute(&pool)
            .await
            .unwrap();
        let st = state(pool.clone());
        let mut ctx = HashMap::new();
        handle_line(
            &st,
            &mut ctx,
            "10.2.0.1".parse().unwrap(),
            &read_line("hans", "a", "1 KB"),
        )
        .await
        .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sources")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, MAX_UNCONFIRMED_SOURCES);
        assert!(ctx.is_empty());
        // A source already known still gets in.
        handle_line(
            &st,
            &mut ctx,
            "10.1.0.1".parse().unwrap(),
            &read_line("hans", "a", "1 KB"),
        )
        .await
        .unwrap();
        assert_eq!(ctx.len(), 1);
    }

    /// vuln-0011: a flood of made-up user names stops at a ceiling, and the
    /// users already followed keep being counted.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_source_follows_a_bounded_number_of_users(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO rules (name, path) VALUES ('GL', '/volume1/GL')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sources (name, kind, address, confirmed) VALUES ('NAS01', 'synology', '10.0.0.5', true)").execute(&pool).await.unwrap();
        let st = state(pool.clone());
        let mut ctx = HashMap::new();
        let ip: IpAddr = "10.0.0.5".parse().unwrap();
        handle_line(&st, &mut ctx, ip, &read_line("known", "a", "1 KB"))
            .await
            .unwrap();
        let c = ctx.get_mut(&ip).unwrap();
        let p = AccessParams {
            hard_max_files: 1000,
            window_secs: 60,
            learn_days: 7,
        };
        for i in c.meter.user_count()..MAX_USERS_PER_SOURCE {
            c.meter.observe(&format!("r|u{i}"), "f", 0, &p, Utc::now());
        }
        handle_line(&st, &mut ctx, ip, &read_line("fresh", "a", "1 KB"))
            .await
            .unwrap();
        handle_line(&st, &mut ctx, ip, &read_line("known", "b", "1 KB"))
            .await
            .unwrap();
        let c = &ctx[&ip];
        assert_eq!(c.meter.user_count(), MAX_USERS_PER_SOURCE);
        let counts = c.agg.counts();
        assert!(counts.iter().all(|b| b.user.name != "fresh"));
        assert_eq!(
            counts
                .iter()
                .filter(|b| b.user.name == "known")
                .map(|b| b.files)
                .sum::<u32>(),
            2
        );
    }

    /// vuln-0011: a TCP line has a ceiling, and a silent connection does
    /// not hold its task forever.
    #[tokio::test]
    async fn a_tcp_connection_takes_bounded_lines_and_closes_when_idle() {
        use tokio::io::AsyncWriteExt;
        let idle = std::time::Duration::from_millis(200);
        let peer: SocketAddr = "10.0.0.5:40000".parse().unwrap();
        let (tx, mut rx) = mpsc::channel(10);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(tcp_lines(
            server,
            peer,
            tx.clone(),
            CancellationToken::new(),
            std::time::Duration::from_secs(60),
        ));
        client.write_all(b"first line\r\n").await.unwrap();
        assert_eq!(rx.recv().await.unwrap().1, "first line");
        client
            .write_all(&vec![b'x'; MAX_LINE_BYTES + 10])
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("an endless line keeps the connection")
            .unwrap();

        let (_client, server) = tokio::io::duplex(1024);
        let task = tokio::spawn(tcp_lines(server, peer, tx, CancellationToken::new(), idle));
        tokio::time::timeout(idle * 10, task)
            .await
            .expect("an idle connection stays open")
            .unwrap();
    }

    /// vuln-0010: the name of a known source cannot be claimed from another
    /// address — the newcomer is listed under its address.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_known_name_is_not_taken_over_from_another_address(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO sources (name, kind, address, confirmed) VALUES ('NAS01', 'synology', '10.0.0.5', true)").execute(&pool).await.unwrap();
        let st = state(pool.clone());
        let mut ctx = HashMap::new();
        // The header says "nas01" — the same name, spelled differently.
        let line = read_line("hans", "a", "1 KB").replace("NAS01", "nas01");
        handle_line(&st, &mut ctx, "10.0.0.66".parse().unwrap(), &line)
            .await
            .unwrap();
        let (name, confirmed): (String, bool) =
            sqlx::query_as("SELECT name, confirmed FROM sources WHERE address = '10.0.0.66'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!((name.as_str(), confirmed), ("10.0.0.66", false));
        // A name nobody has yet is taken from the header.
        handle_line(
            &st,
            &mut ctx,
            "10.0.0.67".parse().unwrap(),
            &line.replace("nas01", "NAS02"),
        )
        .await
        .unwrap();
        let (name,): (String,) =
            sqlx::query_as("SELECT name FROM sources WHERE address = '10.0.0.67'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(name, "NAS02");
        // Nor the address of another device as a name.
        handle_line(
            &st,
            &mut ctx,
            "10.0.0.68".parse().unwrap(),
            &line.replace("nas01", "10.0.0.7"),
        )
        .await
        .unwrap();
        let (name,): (String,) =
            sqlx::query_as("SELECT name FROM sources WHERE address = '10.0.0.68'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(name, "10.0.0.68");
    }

    /// vuln-0011: TCP senders cannot hold every file descriptor; a freed
    /// slot is taken again.
    #[tokio::test]
    async fn tcp_connections_stop_at_a_ceiling() {
        use tokio::io::AsyncReadExt;
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let (tx, _rx) = mpsc::channel(10);
        let stop = CancellationToken::new();
        tokio::spawn(tcp_accept(tcp, tx, stop.clone(), 2));
        let wait = std::time::Duration::from_millis(300);
        // Open means a read that finds nothing; closed means end of stream.
        async fn closed(c: &mut tokio::net::TcpStream, wait: std::time::Duration) -> bool {
            matches!(
                tokio::time::timeout(wait, c.read(&mut [0u8; 1])).await,
                Ok(Ok(0)) | Ok(Err(_))
            )
        }
        let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(closed(&mut c, wait).await, "a third connection was kept");
        assert!(!closed(&mut a, wait).await && !closed(&mut b, wait).await);
        drop(a);
        tokio::time::sleep(wait).await;
        let mut d = tokio::net::TcpStream::connect(addr).await.unwrap();
        assert!(
            !closed(&mut d, wait).await,
            "a freed slot was not given out again"
        );
        stop.cancel();
    }

    /// vuln-0009: one datagram with an absurd `Size:` used to kill the
    /// intake for good. Whatever a line does, a later line still arrives.
    #[sqlx::test(migrations = "./migrations")]
    async fn the_intake_still_listens_after_a_hostile_size(pool: sqlx::PgPool) {
        sqlx::query("INSERT INTO rules (name, path, hard_max_files, window_secs) VALUES ('GL', '/volume1/GL', 1, 300)").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO sources (name, kind, address, confirmed) VALUES ('NAS01', 'synology', '127.0.0.1', true)").execute(&pool).await.unwrap();
        let addr = free_port();
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(state(pool.clone()), addr, stop.clone()));
        let tx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // Two lines in one datagram: the second addition overflowed.
        let bomb = format!(
            "{}\n{}",
            read_line("bomb", "a", "1e400 B"),
            read_line("bomb", "b", "1e400 B")
        );
        // The first tick of the supervisor binds right away.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        tx.send_to(bomb.as_bytes(), addr).await.unwrap();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the intake never recorded a line after the hostile one"
            );
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let after = format!(
                "{}\n{}",
                read_line("after", "x", "1 KB"),
                read_line("after", "y", "1 KB")
            );
            tx.send_to(after.as_bytes(), addr).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            let n: i64 =
                sqlx::query_scalar("SELECT count(*) FROM alerts WHERE user_display = 'after'")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            if n > 0 {
                break;
            }
        }
        stop.cancel();
        task.await.unwrap().unwrap();
    }
}
