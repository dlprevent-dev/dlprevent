//! The network cage on macOS and Linux: whoever has read from a strict folder
//! with `enforce` can, for [`CAGE_TTL`] after the last touch, only reach the
//! destinations on the rule's allowlist and our own house.
//!
//! The bookkeeping is the Windows workstation's (`deelpe-winagent/src/wfp.rs`),
//! with one difference: a cage holds a **process**, not a program. Both
//! platforms can do that — Linux through a cgroup, the macOS content filter
//! through the audit token of every flow — and it spares the other instances
//! of the same program.
//!
//! What is underneath:
//!
//! - **Linux:** a cgroup per cage and a table in nftables, see
//!   `deelpe_sensors::linux::cage`.
//! - **macOS:** the content filter in the DLPrevent app (a Network Extension,
//!   `apps/macos/DeelpeBar/Sources/DeelpeFilter`). The service cannot talk
//!   XPC itself; it hands the whole cage table as one JSON line to
//!   `DeelpeCageRelay`, a small helper in the same app, which passes it on
//!   and answers `ok` or `error: …`.
//!
//! Both fail **open**, like on Windows — which is why [`Cages::health`] goes
//! to the dashboard: nobody notices by themselves that a cage no longer bites.

use deelpe_core::allow::{Permit, CAGE_TTL};
use deelpe_core::event::{Event, NetEvent};
use std::collections::HashMap;
use std::time::Instant;

/// Processes that never go into the cage, by the name the correlator knows
/// them by: the file name on Linux, the signing ID on macOS. A trailing `*`
/// is a prefix.
///
/// The same reasoning as `NEVER_CAGE` on Windows: the shell and the file
/// manager read from a protected folder as soon as somebody merely looks at
/// it (thumbnails, Spotlight, Quick Look). Nobody exfiltrates through them,
/// but a desktop without a network is a broken machine. Browsers are **not**
/// on the list, unlike on Windows: there is no browser connector here that
/// would say no earlier.
///
/// ponytail: a list that grows, exactly as on Windows.
const NEVER_CAGE: &[&str] = &[
    // Linux: init, login, bus, desktop, file managers, indexers
    "systemd",
    "systemd-*",
    "init",
    "sshd",
    "sshd-session",
    "dbus-daemon",
    "dbus-broker",
    "NetworkManager",
    "gnome-shell",
    "plasmashell",
    "Xorg",
    "Xwayland",
    "nautilus",
    "dolphin",
    "nemo",
    "thunar",
    "tracker-miner-fs-3",
    "gvfsd*",
    "xdg-desktop-portal*",
    // macOS (signing IDs)
    "com.apple.xpc.launchd",
    "com.apple.finder",
    "com.apple.WindowServer",
    "com.apple.dock",
    "com.apple.mds*",
    "com.apple.mdworker*",
    "com.apple.Spotlight",
    "com.apple.quicklook*",
    "com.apple.QuickLookUIService",
    // Finder's copy, file coordination and the open/save panel read a
    // protected folder whenever Finder copies out of it. The panel belongs
    // to the app that shows it: caged as its parent, that app lost its
    // network (LibreWolf, 2026-09-16).
    "com.apple.DesktopServicesHelper",
    "com.apple.filecoordinationd",
    "com.apple.appkit.xpc.openAndSavePanelService",
    "com.apple.sshd",
    "ch.deelpe.*",
    "deelpe",
];

/// The file name of a running process's executable, straight from the
/// system. `None` once it is gone.
pub fn process_name(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    #[cfg(target_os = "macos")]
    let path = {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        std::path::PathBuf::from(String::from_utf8(buf).ok()?)
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let path: std::path::PathBuf = {
        let _ = pid;
        return None;
    };
    Some(path.file_name()?.to_string_lossy().into_owned())
}

/// May this process go into the cage at all? Pure logic, checkable here.
pub fn may_cage(pid: u32, name: &str) -> Result<(), String> {
    if pid <= 1 || pid == std::process::id() {
        return Err(format!("pid {pid} is not a process we may cage"));
    }
    if name.is_empty() {
        return Err(format!("pid {pid} has no name; whom we cannot name we do not cage"));
    }
    let hit = NEVER_CAGE.iter().any(|n| match n.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *n,
    });
    if hit {
        return Err(format!("{name} is part of the system or the desktop and is never caged"));
    }
    Ok(())
}

struct Cage {
    until: Instant,
    permits: Vec<Permit>,
    children: bool,
    token: backend::Token,
}

/// All cages on this machine, one per touched process.
pub struct Cages {
    open: HashMap<u32, Cage>,
    backend: backend::Backend,
    /// Why the last cage did not come up. `None` means "it is up".
    last_error: Option<String>,
}

impl Cages {
    pub fn new() -> Self {
        Cages { open: HashMap::new(), backend: backend::Backend::new(), last_error: None }
    }

    pub fn health(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// One batch from `daemon::fresh_touches`: the reader (`children` set)
    /// and its parent. A reader that is never caged spares its parent too —
    /// the parent did not read, it merely owns a system helper that did.
    /// Whoever takes the file for real opens it itself and is the reader.
    pub fn on_touches(&mut self, touches: Vec<(u32, String, Vec<String>, bool)>, now: Instant) {
        if let Some((pid, name, ..)) = touches.iter().find(|t| t.3) {
            if let Err(e) = may_cage(*pid, name) {
                tracing::debug!(pid, "no network cage for reader or parent: {e}");
                return;
            }
        }
        for (pid, name, allow, children) in touches {
            self.on_touch(pid, &name, &allow, children, now);
        }
    }

    /// A fresh touch of a strict folder with `enforce`. `children`: the
    /// process's current children go into the cage along with it.
    pub fn on_touch(&mut self, pid: u32, name: &str, allow: &[String], children: bool, now: Instant) {
        if let Err(e) = may_cage(pid, name) {
            tracing::debug!(pid, "no network cage: {e}");
            return;
        }
        let (permits, skipped) = deelpe_core::allow::cage_permits(allow);
        match self.open.get_mut(&pid) {
            // Already caged, same list: only the deadline moves — unless the
            // process is no longer inside (its PID was handed out again) or
            // it now takes its children too (it was caged as a parent and
            // has read itself since). Then it goes in once more.
            Some(c) if c.permits == permits => {
                c.until = now + CAGE_TTL;
                if (!children || c.children) && self.backend.inside(pid) {
                    return;
                }
                c.children |= children;
                match self.backend.enter(pid, &permits, children) {
                    Ok((token, _)) => {
                        if let Some(c) = self.open.get_mut(&pid) {
                            c.token.extend(token);
                        }
                    }
                    Err(e) => tracing::warn!(pid, name, "network cage not renewed: {e:#}"),
                }
                return;
            }
            // The central changed the allowlist: the table is loaded anew,
            // the process stays where it is.
            Some(c) => {
                c.permits = permits;
                c.until = now + CAGE_TTL;
                self.sync();
                return;
            }
            None => {}
        }
        if !skipped.is_empty() {
            tracing::info!(pid, name, "allowlist names do not apply to a packet filter: {}", skipped.join(", "));
        }
        self.open.insert(pid, Cage { until: now + CAGE_TTL, permits: permits.clone(), children, token: Default::default() });
        if !self.sync() {
            self.open.remove(&pid);
            return;
        }
        match self.backend.enter(pid, &permits, children) {
            Ok((token, torn)) => {
                if let Some(c) = self.open.get_mut(&pid) {
                    c.token = token;
                }
                tracing::warn!(pid, name, permits = permits.len(), open_connections_cut = torn, "network cage armed (strict folder)");
            }
            Err(e) => {
                self.open.remove(&pid);
                self.sync();
                self.backend.leave(pid, Default::default());
                // A reader that already ended (`cat` is gone in milliseconds)
                // has nothing left to cage; that is no fault of the cage.
                if process_name(pid).is_none() {
                    tracing::debug!(pid, name, "no network cage, the process is gone: {e:#}");
                    return;
                }
                tracing::warn!(pid, name, "network cage not armed: {e:#}");
                // After the sync, which clears the error when it succeeds.
                self.last_error = Some(format!("{name}: {e:#}"));
            }
        }
    }

    /// Open the cages that have expired. Belongs on a tick: whoever stops
    /// reading also stops producing events.
    ///
    /// While cages are up and the platform refused them, or on macOS always,
    /// the table goes out again: a filter that restarted has lost it, and the
    /// relay only learns of that when it next writes.
    pub fn expire(&mut self, now: Instant) {
        let done: Vec<u32> = self.open.iter().filter(|(_, c)| c.until <= now).map(|(k, _)| *k).collect();
        if done.is_empty() {
            if !self.open.is_empty() && (cfg!(target_os = "macos") || self.last_error.is_some()) {
                self.sync();
            }
            return;
        }
        let gone: Vec<(u32, Cage)> = done.into_iter().filter_map(|pid| self.open.remove(&pid).map(|c| (pid, c))).collect();
        self.sync();
        for (pid, c) in gone {
            self.backend.leave(pid, c.token);
            tracing::info!(pid, "network cage opened again (no touch for {}s)", CAGE_TTL.as_secs());
        }
    }

    /// The flows the platform refused since the last call, as events for the
    /// correlator. Only the macOS filter reports them: a refused flow sends
    /// no byte, so nettop never sees it. Belongs on the same tick as
    /// [`Cages::expire`].
    pub fn refused(&mut self) -> Vec<Event> {
        self.backend.refused().unwrap_or_else(|e| {
            tracing::warn!("network cage refusals: {e:#}");
            Vec::new()
        })
    }

    /// Open every cage: orderly stop, and the start of a new run.
    pub fn release_all(&mut self) {
        let gone: Vec<(u32, Cage)> = self.open.drain().collect();
        self.sync();
        for (pid, c) in gone {
            self.backend.leave(pid, c.token);
        }
    }

    /// Hand the whole table to the platform. `false` if it did not take it.
    fn sync(&mut self) -> bool {
        let table: Vec<Entry> = self.open.iter().map(|(pid, c)| (*pid, c.permits.as_slice(), c.children)).collect();
        match self.backend.sync(&table) {
            Ok(()) => {
                self.last_error = None;
                true
            }
            Err(e) => {
                tracing::warn!("network cage: {e:#}");
                self.last_error = Some(format!("{e:#}"));
                false
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.open.len()
    }
}

/// One cage as the platform gets it: PID, permits, and whether the children
/// that already ran when it went up count as caged too.
pub type Entry<'a> = (u32, &'a [Permit], bool);

/// A flow the macOS filter refused: `CageRefusal` in
/// `apps/macos/DeelpeBar/Sources/DeelpeProtocol/CageRefusals.swift`.
#[derive(serde::Deserialize)]
struct Refusal {
    pid: u32,
    ppid: Option<u32>,
    ip: String,
    port: Option<u16>,
    /// Seconds since 1970.
    at: f64,
}

/// The relay's answer to `refused`: a JSON array of refusals, as events.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn refused_events(line: &str) -> anyhow::Result<Vec<Event>> {
    let refusals: Vec<Refusal> = serde_json::from_str(line)?;
    Ok(refusals
        .into_iter()
        .map(|r| {
            Event::Refused(NetEvent {
                at: chrono::DateTime::from_timestamp_millis((r.at * 1000.0) as i64).unwrap_or_else(chrono::Utc::now),
                pid: r.pid,
                ppid: r.ppid,
                process_name: process_name(r.pid).unwrap_or_default(),
                // A name instead of an address (`chatgpt.com`) stays unnamed.
                remote: r.ip.split('%').next().and_then(|ip| ip.parse().ok()),
                remote_port: r.port,
                bytes_out: 0,
                bytes_in: 0,
            })
        })
        .collect())
}

/// One line to the macOS relay: the cages and what is always let through.
/// The filter keeps no list of its own — the house comes from here, so there
/// is exactly one `INTERNAL`. A wire format: pinned below and in the Swift
/// tests (`CageTableTests`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn relay_line(table: &[Entry]) -> String {
    let cages: Vec<_> = table.iter().map(|(pid, permits, children)| serde_json::json!({ "pid": pid, "permits": permits, "children": children })).collect();
    serde_json::json!({ "cages": cages, "always": deelpe_core::allow::internal_permits() }).to_string()
}

#[cfg(all(target_os = "linux", not(test)))]
mod backend {
    use anyhow::Result;
    use deelpe_core::allow::Permit;
    use deelpe_sensors::linux::cage;
    use std::collections::HashMap;

    pub type Token = Vec<cage::Moved>;

    pub struct Backend {
        /// The table as last handed over, so `enter` can load it again with
        /// the connections it found.
        table: Vec<(u32, Vec<Permit>)>,
        /// Per cage: the connections that were already open when it went up.
        flows: HashMap<u32, Vec<cage::Flow>>,
    }

    impl Backend {
        pub fn new() -> Self {
            // Whatever an earlier run left behind goes first.
            cage::reset();
            Backend { table: Vec::new(), flows: HashMap::new() }
        }

        pub fn sync(&mut self, table: &[super::Entry]) -> Result<()> {
            self.table = table.iter().map(|(pid, p, _)| (*pid, p.to_vec())).collect();
            self.flows.retain(|id, _| table.iter().any(|(pid, _, _)| pid == id));
            self.load()
        }

        fn load(&self) -> Result<()> {
            let table: Vec<(u32, &[Permit])> = self.table.iter().map(|(pid, p)| (*pid, p.as_slice())).collect();
            let flows: Vec<cage::Flow> = self.flows.values().flatten().copied().collect();
            cage::apply(&table, &flows)
        }

        pub fn enter(&mut self, pid: u32, permits: &[Permit], children: bool) -> Result<(Token, usize)> {
            let moved = cage::enter(pid, pid, children)?;
            let pids: Vec<u32> = moved.iter().map(|m| m.pid).collect();
            let flows = cage::open_flows(&pids, permits);
            let cut = flows.len();
            if cut > 0 {
                self.flows.insert(pid, flows);
                self.load()?;
            }
            Ok((moved, cut))
        }

        pub fn leave(&mut self, pid: u32, token: Token) {
            cage::leave(pid, &token);
        }

        pub fn inside(&self, pid: u32) -> bool {
            cage::is_caged(pid)
        }

        /// nft drops without a word to us.
        pub fn refused(&mut self) -> Result<Vec<deelpe_core::event::Event>> {
            Ok(Vec::new())
        }
    }
}

#[cfg(all(target_os = "macos", not(test)))]
mod backend {
    use anyhow::{bail, Context, Result};
    use deelpe_core::allow::Permit;
    use deelpe_core::event::Event;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, ChildStdout, Command, Stdio};

    /// The helper in the app bundle. The app lives in /Applications — the
    /// system only activates a system extension from there anyway.
    const RELAY: &str = "/Applications/DLPrevent.app/Contents/MacOS/DeelpeCageRelay";
    /// Only a signed build carries it; without it the relay has nobody to talk to.
    const FILTER: &str = "/Applications/DLPrevent.app/Contents/Library/SystemExtensions/ch.deelpe.bar.filter.systemextension";

    pub type Token = Vec<()>;

    pub struct Backend {
        relay: Option<(Child, BufReader<ChildStdout>)>,
    }

    impl Backend {
        pub fn new() -> Self {
            Backend { relay: None }
        }

        pub fn sync(&mut self, table: &[super::Entry]) -> Result<()> {
            // Nothing caged and nobody listening: no need to start anything.
            if table.is_empty() && self.relay.is_none() {
                return Ok(());
            }
            match self.ask(&super::relay_line(table))?.as_str() {
                "ok" => Ok(()),
                other => bail!("network filter relay: unexpected answer {other}"),
            }
        }

        pub fn refused(&mut self) -> Result<Vec<Event>> {
            // No relay, no filter that could have refused anything.
            if self.relay.is_none() {
                return Ok(Vec::new());
            }
            super::refused_events(&self.ask("refused")?)
        }

        /// One line out, one answer back. A relay that failed is ended, the
        /// next call starts a new one.
        fn ask(&mut self, line: &str) -> Result<String> {
            let res = self.exchange(line);
            if res.is_err() {
                if let Some((mut child, _)) = self.relay.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
            res
        }

        fn exchange(&mut self, line: &str) -> Result<String> {
            if self.relay.is_none() {
                if !std::path::Path::new(FILTER).exists() {
                    bail!("no network filter in this app (built without a Developer ID, see docs/INSTALL.md)");
                }
                let mut child = Command::new(RELAY)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .with_context(|| format!("start {RELAY} (is the DLPrevent app installed?)"))?;
                let out = BufReader::new(child.stdout.take().expect("piped"));
                self.relay = Some((child, out));
            }
            let (child, out) = self.relay.as_mut().expect("just set");
            let stdin = child.stdin.as_mut().expect("piped");
            writeln!(stdin, "{line}").context("network filter relay")?;
            stdin.flush()?;
            // The relay answers within its own deadline of two seconds, or
            // dies; either way this read returns.
            let mut answer = String::new();
            out.read_line(&mut answer).context("network filter relay")?;
            match answer.trim() {
                "" => bail!("the network filter relay ended; is the filter enabled in the DLPrevent app?"),
                other if other.starts_with("error: ") => bail!("network filter: {}", other.trim_start_matches("error: ")),
                other => Ok(other.to_string()),
            }
        }

        pub fn enter(&mut self, _pid: u32, _permits: &[Permit], _children: bool) -> Result<(Token, usize)> {
            // Nothing to move: the filter walks each flow's process up to a
            // caged ancestor (`children` in the table says whether children
            // that already ran count). Connections already open are cut by
            // the filter itself at their next data.
            Ok((Vec::new(), 0))
        }

        pub fn leave(&mut self, _pid: u32, _token: Token) {}

        pub fn inside(&self, _pid: u32) -> bool {
            true
        }
    }
}

/// Neither Linux nor macOS, or a test: bookkeeping only. `FAIL_SYNC` lets a
/// test play a platform that refuses.
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos"))))]
mod backend {
    use anyhow::Result;
    use deelpe_core::allow::Permit;

    pub type Token = Vec<()>;

    pub struct Backend {
        pub fail: bool,
    }

    impl Backend {
        pub fn new() -> Self {
            Backend { fail: false }
        }
        pub fn refused(&mut self) -> Result<Vec<deelpe_core::event::Event>> {
            Ok(Vec::new())
        }
        pub fn sync(&mut self, _table: &[super::Entry]) -> Result<()> {
            if self.fail {
                anyhow::bail!("refused");
            }
            Ok(())
        }
        pub fn enter(&mut self, _pid: u32, _permits: &[Permit], _children: bool) -> Result<(Token, usize)> {
            Ok((Vec::new(), 0))
        }
        pub fn leave(&mut self, _pid: u32, _token: Token) {}
        pub fn inside(&self, _pid: u32) -> bool {
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_desktop_and_the_system_never_go_into_the_cage() {
        for name in ["systemd", "systemd-resolved", "nautilus", "gvfsd-smb", "com.apple.finder", "com.apple.mdworker_shared", "ch.deelpe.bar"] {
            assert!(may_cage(4242, name).is_err(), "{name}");
        }
        for pid in [0, 1, std::process::id()] {
            assert!(may_cage(pid, "curl").is_err(), "pid {pid}");
        }
        assert!(may_cage(4242, "").is_err());
        // The ones the cage is built for — browsers included, there is no
        // connector here.
        for name in ["curl", "python3", "com.apple.curl", "org.mozilla.firefox", "rclone", "systemd2x"] {
            assert!(may_cage(4242, name).is_ok(), "{name}");
        }
    }

    #[test]
    fn the_relay_line_is_what_the_filter_decodes() {
        let permits = [Permit { net: "203.0.113.9".parse().unwrap(), bits: 32, port: Some(443) }];
        let line = relay_line(&[(4242, &permits, false)]);
        assert!(line.starts_with(r#"{"always":[{"bits":8,"net":"10.0.0.0","port":null},"#), "{line}");
        assert!(line.ends_with(r#""cages":[{"children":false,"permits":[{"bits":32,"net":"203.0.113.9","port":443}],"pid":4242}]}"#), "{line}");
        assert!(!line.contains('\n'), "one line per table");
    }

    /// The literal comes from `testARefusalIsReportedOncePerProcessAndDestination`
    /// in apps/macos/DeelpeBar/Tests/DeelpeProtocolTests/CageTableTests.swift.
    #[test]
    fn the_refused_line_is_what_the_service_reads() {
        let evs = refused_events(r#"[{"at":1000000,"ip":"1.1.1.1","pid":300,"port":443,"ppid":100},{"at":1000001.5,"ip":"chatgpt.com","pid":301}]"#).unwrap();
        let [Event::Refused(a), Event::Refused(b)] = evs.as_slice() else { panic!("{evs:?}") };
        assert_eq!((a.pid, a.ppid, a.remote, a.remote_port, a.bytes_out), (300, Some(100), Some("1.1.1.1".parse().unwrap()), Some(443), 0));
        assert_eq!(a.at.timestamp(), 1_000_000);
        assert_eq!((b.remote, b.remote_port, b.ppid), (None, None, None));
        assert!(refused_events("[]").unwrap().is_empty());
        assert!(refused_events("error: nope").is_err());
    }

    #[test]
    fn a_running_process_has_a_name() {
        assert!(process_name(std::process::id()).is_some_and(|n| n.starts_with("deelpe")));
    }

    #[test]
    fn the_deadline_rolls_and_then_the_cage_opens() {
        let mut c = Cages::new();
        let t0 = Instant::now();
        let allow = vec!["203.0.113.9".to_string()];
        c.on_touch(4242, "curl", &allow, true, t0);
        c.on_touch(4242, "curl", &allow, true, t0 + Duration::from_secs(59));
        c.expire(t0 + Duration::from_secs(90));
        assert_eq!(c.len(), 1, "60 s after the *last* touch, not the first");
        c.expire(t0 + Duration::from_secs(120));
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn a_changed_allowlist_keeps_the_cage_with_the_new_list() {
        let mut c = Cages::new();
        let t0 = Instant::now();
        c.on_touch(4242, "curl", &["203.0.113.9".into()], true, t0);
        c.on_touch(4242, "curl", &["203.0.113.9".into(), "198.51.100.0/24".into()], true, t0);
        assert_eq!(c.len(), 1);
        assert!(c.open[&4242].permits.contains(&Permit { net: "198.51.100.0".parse().unwrap(), bits: 24, port: None }));
    }

    /// Caged as a parent first, then it reads itself: from now on its
    /// children count as well.
    #[test]
    fn a_parent_that_reads_itself_takes_its_children_along() {
        let mut c = Cages::new();
        let t0 = Instant::now();
        c.on_touch(4242, "bash", &[], false, t0);
        assert!(!c.open[&4242].children);
        c.on_touch(4242, "bash", &[], true, t0);
        assert!(c.open[&4242].children);
    }

    /// The open/save panel of a browser reads a protected folder when Finder
    /// copies out of it. The panel is part of the system; the browser owning
    /// it keeps its network. A reader that may be caged takes its parent along.
    #[test]
    fn an_exempt_reader_spares_its_parent() {
        let mut c = Cages::new();
        let now = Instant::now();
        c.on_touches(vec![(4242, "com.apple.appkit.xpc.openAndSavePanelService".into(), vec![], true), (701, "net.librewolf.librewolf".into(), vec![], false)], now);
        assert_eq!(c.len(), 0);
        c.on_touches(vec![(4243, "curl".into(), vec![], true), (4200, "bash".into(), vec![], false)], now);
        assert_eq!(c.len(), 2);
    }

    /// Fail open, and say so: a platform that refuses leaves no cage in the
    /// books and an error for the dashboard.
    #[test]
    fn a_refusing_platform_leaves_no_cage_and_an_error() {
        let mut c = Cages::new();
        c.backend.fail = true;
        c.on_touch(4242, "curl", &[], true, Instant::now());
        assert_eq!(c.len(), 0);
        assert_eq!(c.health().as_deref(), Some("refused"));
        c.backend.fail = false;
        c.on_touch(4242, "curl", &[], true, Instant::now());
        assert_eq!(c.len(), 1);
        assert_eq!(c.health(), None);
        c.release_all();
        assert_eq!(c.len(), 0);
    }
}
