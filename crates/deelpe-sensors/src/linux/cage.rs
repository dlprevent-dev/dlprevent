//! The network cage on Linux: whoever has read from a strict folder can, for
//! a while, only reach the destinations on their allowlist.
//!
//! The Windows workstation does this with a WFP filter bound to the EXE
//! (`deelpe-winagent/src/wfp.rs`). Linux has no per-program match in its
//! packet filter, but it has one per **cgroup**: nftables' `socket cgroupv2`
//! looks at the cgroup the sending socket was created in. So a caged process
//! moves into a cgroup of its own, `/sys/fs/cgroup/deelpe-cage/p<pid>`, and
//! one chain per cage in the table `inet deelpe_cage` lets through the
//! permits and rejects the rest.
//!
//! The same promises as on Windows, carried differently:
//!
//! 1. **Fail open.** If the service dies, `ExecStopPost` in `deelpe.service`
//!    deletes the table; the next start runs [`reset`] and moves every
//!    process left in a cage back out. Without the table a cgroup is just a
//!    folder — nothing is blocked by it.
//! 2. **Cut existing connections.** A socket keeps the cgroup it was created
//!    in, so the cgroup rule never sees a connection that was already open.
//!    [`open_flows`] lists those and the table rejects each by its 5-tuple:
//!    the next packet the process sends gets a reset. Not `ss -K`: that
//!    needs `CONFIG_INET_DIAG_DESTROY`, which not every kernel carries, and
//!    exits 0 when it ended nothing (OrbStack, 2026-09-15). ponytail: TCP
//!    only, like Windows — a UDP socket opened before the cage keeps sending
//!    until it is closed.
//! 3. **Bound to the process, not to the EXE** — the one place where Linux
//!    is more precise than Windows: the process and its current children
//!    move, and whatever they start later is born inside the cage. Other
//!    instances of the same program stay free.
//!
//! 4. **Report what it refuses.** A refused flow sends no byte, so the
//!    procnet sensor never sees it. Each cage chain adds the destination to
//!    its sets `r4_p<pid>` / `r6_p<pid>` before the reject; [`refused`]
//!    reads them. An element lives [`REFUSED_TIMEOUT`] and a retry does not
//!    renew it, so a drain every 5 s sees each attempt once or twice — the
//!    correlator reports a destination once.
//!
//! ponytail: the cage cgroup sits beside systemd's tree, not inside it. For
//! the 60 s a process is caged, `systemctl stop` of its unit no longer
//! reaches it. Delegation (`Delegate=yes`) is the upgrade if that bites.

use anyhow::{bail, Context, Result};
use deelpe_core::allow::Permit;
use std::collections::HashMap;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};

const CGROOT: &str = "/sys/fs/cgroup";
const CAGE_DIR: &str = "deelpe-cage";
pub const TABLE: &str = "deelpe_cage";
/// How long a refused destination stays in its cage's set: longer than the
/// service's drain tick.
const REFUSED_TIMEOUT: &str = "10s";

/// A process that was moved into a cage, and the cgroup it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Moved {
    pub pid: u32,
    pub origin: String,
}

fn cage_path(id: u32) -> String {
    format!("{CGROOT}/{CAGE_DIR}/p{id}")
}

/// The whole table for these cages, as one `nft -f` script.
///
/// Rebuilt as a whole on every change rather than edited rule by rule: the
/// script is atomic, needs no rule handles, and there are a handful of cages
/// at most. The `add table` before the `delete` makes the delete succeed on
/// a machine that has no table yet.
pub fn ruleset(cages: &[(u32, &[Permit])], flows: &[Flow]) -> String {
    let mut s = format!("add table inet {TABLE}\ndelete table inet {TABLE}\ntable inet {TABLE} {{\n");
    for (id, _) in cages {
        for (v, ty) in [(4, "ipv4_addr"), (6, "ipv6_addr")] {
            s.push_str(&format!("  set r{v}_p{id} {{ type {ty} . inet_service; flags dynamic,timeout; timeout {REFUSED_TIMEOUT}; size 512; }}\n"));
        }
    }
    s.push_str("  chain out {\n    type filter hook output priority 0; policy accept;\n");
    for f in flows {
        let family = if f.remote.is_ipv4() { "ip" } else { "ip6" };
        s.push_str(&format!(
            "    {family} saddr {} {family} daddr {} tcp sport {} tcp dport {} reject with tcp reset\n",
            f.local, f.remote, f.local_port, f.remote_port
        ));
    }
    for (id, _) in cages {
        s.push_str(&format!("    socket cgroupv2 level 2 \"{CAGE_DIR}/p{id}\" jump p{id}\n"));
    }
    s.push_str("  }\n");
    for (id, permits) in cages {
        s.push_str(&format!("  chain p{id} {{\n"));
        for p in *permits {
            let family = if p.net.is_ipv4() { "ip" } else { "ip6" };
            let port = p.port.map(|x| format!(" th dport {x}")).unwrap_or_default();
            s.push_str(&format!("    {family} daddr {}/{}{port} accept\n", network(p.net, p.bits), p.bits));
        }
        s.push_str(&format!("    meta nfproto ipv4 add @r4_p{id} {{ ip daddr . th dport }}\n"));
        s.push_str(&format!("    meta nfproto ipv6 add @r6_p{id} {{ ip6 daddr . th dport }}\n"));
        s.push_str("    meta l4proto tcp reject with tcp reset\n    drop\n  }\n");
    }
    s.push_str("}\n");
    s
}

/// The network address of a prefix: nft refuses `10.1.2.3/8`.
fn network(ip: IpAddr, bits: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - u32::from(bits.min(32))) };
            IpAddr::V4((u32::from(a) & mask).into())
        }
        IpAddr::V6(a) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - u32::from(bits.min(128))) };
            IpAddr::V6((u128::from(a) & mask).into())
        }
    }
}

/// Load the table for these cages. Their cgroups have to exist first: nft
/// resolves the path when it loads the rule.
pub fn apply(cages: &[(u32, &[Permit])], flows: &[Flow]) -> Result<()> {
    if !std::path::Path::new(&format!("{CGROOT}/cgroup.controllers")).exists() {
        bail!("no cgroup v2 hierarchy at {CGROOT}; the cage needs the unified hierarchy");
    }
    for (id, _) in cages {
        std::fs::create_dir_all(cage_path(*id)).with_context(|| format!("create {}", cage_path(*id)))?;
    }
    nft(&ruleset(cages, flows))
}

fn nft(script: &str) -> Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("run nft (package nftables)")?;
    child.stdin.take().expect("piped").write_all(script.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim_end());
    }
    Ok(())
}

/// The destinations the cages refused lately: cage PID, address, port.
pub fn refused() -> Result<Vec<(u32, IpAddr, u16)>> {
    let out = Command::new("nft").args(["-j", "list", "table", "inet", TABLE]).output().context("run nft (package nftables)")?;
    if !out.status.success() {
        bail!("nft: {}", String::from_utf8_lossy(&out.stderr).trim_end());
    }
    Ok(parse_refused(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_refused(json: &str) -> Vec<(u32, IpAddr, u16)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    let mut out = Vec::new();
    for set in v["nftables"].as_array().into_iter().flatten().filter_map(|o| o.get("set")) {
        let name = set["name"].as_str().unwrap_or_default();
        let Some(id) = name.strip_prefix("r4_p").or_else(|| name.strip_prefix("r6_p")).and_then(|x| x.parse().ok()) else { continue };
        for elem in set["elem"].as_array().into_iter().flatten() {
            // With a timeout nft wraps the value: `{"elem": {"val": …}}`.
            let val = elem.get("elem").map_or(elem, |e| &e["val"]);
            let (Some(ip), Some(port)) = (val["concat"][0].as_str().and_then(|s| s.parse().ok()), val["concat"][1].as_u64()) else { continue };
            out.push((id, ip, port as u16));
        }
    }
    out
}

/// Move the process into cage `id`, with its current descendants if
/// `children`.
pub fn enter(id: u32, pid: u32, children: bool) -> Result<Vec<Moved>> {
    let procs = cage_path(id) + "/cgroup.procs";
    let mut moved = Vec::new();
    // Never the service itself: started from a shell that later reads from
    // the folder, it would be that shell's descendant — and cage its own
    // reporting connection. Seen in the lab VM on 2026-09-15.
    let me = std::process::id();
    let family = if children { with_descendants(pid) } else { vec![pid] };
    for p in family.into_iter().filter(|p| *p != me) {
        let Some(origin) = cgroup_of(p) else { continue };
        // Already in this very cage. A process in *another* cage — a child
        // born inside its parent's — does move: it has its own touch and its
        // own deadline now, and goes back into the parent's cage when it
        // leaves, or to the root cgroup if that one is gone by then.
        if origin == format!("/{CAGE_DIR}/p{id}") {
            continue;
        }
        match std::fs::write(&procs, p.to_string()) {
            Ok(()) => moved.push(Moved { pid: p, origin }),
            // The root process must go in; a child that exited meanwhile
            // may drop out.
            Err(e) if p == pid => bail!("move pid {pid} into {procs}: {e}"),
            Err(_) => {}
        }
    }
    // Nothing moved and not already in here: the process is gone, or its
    // cgroup unreadable. "Armed" would be a lie.
    if !moved.iter().any(|m| m.pid == pid) && cgroup_of(pid) != Some(format!("/{CAGE_DIR}/p{id}")) {
        bail!("pid {pid} could not be moved into its cage (gone?)");
    }
    Ok(moved)
}

/// Is this process inside some cage right now? `false` once it is gone —
/// and for a new process that inherited the PID of a caged one.
pub fn is_caged(pid: u32) -> bool {
    cgroup_of(pid).is_some_and(|c| c.starts_with(&format!("/{CAGE_DIR}/")))
}

/// Move everything in cage `id` back out and remove its cgroup. Each process
/// goes back where it came from; one born inside the cage follows the root
/// process's origin; whose origin is gone lands in the root cgroup.
pub fn leave(id: u32, moved: &[Moved]) {
    let dir = cage_path(id);
    let fallback = moved.first().map(|m| m.origin.clone()).unwrap_or_else(|| "/".into());
    let inside = std::fs::read_to_string(format!("{dir}/cgroup.procs")).unwrap_or_default();
    for pid in inside.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
        let origin = moved.iter().find(|m| m.pid == pid).map_or(fallback.as_str(), |m| m.origin.as_str());
        if std::fs::write(format!("{CGROOT}{origin}/cgroup.procs"), pid.to_string()).is_err() {
            let _ = std::fs::write(format!("{CGROOT}/cgroup.procs"), pid.to_string());
        }
    }
    if let Err(e) = std::fs::remove_dir(&dir) {
        tracing::debug!("remove {dir}: {e}");
    }
}

/// Start clean: no table, no process left in a cage. What an earlier run
/// left behind after a crash — `ExecStopPost` covers the table, not the
/// cgroups.
pub fn reset() {
    let _ = nft(&format!("add table inet {TABLE}\ndelete table inet {TABLE}\n"));
    let Ok(dirs) = std::fs::read_dir(format!("{CGROOT}/{CAGE_DIR}")) else { return };
    for d in dirs.flatten() {
        let name = d.file_name().to_string_lossy().to_string();
        if let Some(id) = name.strip_prefix('p').and_then(|x| x.parse().ok()) {
            leave(id, &[]);
        }
    }
}

/// An open TCP connection, as a 5-tuple the table can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    pub local: IpAddr,
    pub local_port: u16,
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// This family's established TCP connections to destinations outside the
/// permits — the ones the cgroup rule cannot see, because their sockets were
/// created before the move.
pub fn open_flows(pids: &[u32], permits: &[Permit]) -> Vec<Flow> {
    let Ok(out) = Command::new("ss").args(["-tnHp", "state", "established"]).output() else { return Vec::new() };
    let mut flows = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        // A state filter drops the state column; put one back so the procnet
        // parser reads the same columns.
        let Some(s) = super::procnet::socket_line(&format!("ESTAB {line}")) else { continue };
        if !pids.contains(&s.pid) || permits.iter().any(|p| p.covers(s.peer_ip, s.peer_port)) {
            continue;
        }
        if let (Some((local, Some(local_port))), Some(remote_port)) = (super::procnet::split_addr(&s.local), s.peer_port) {
            flows.push(Flow { local, local_port, remote: s.peer_ip, remote_port });
        }
    }
    flows
}

/// `0::/user.slice/...` out of `/proc/<pid>/cgroup` — the v2 line.
fn cgroup_of(pid: u32) -> Option<String> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_cgroup(&text)
}

fn parse_cgroup(text: &str) -> Option<String> {
    text.lines().find_map(|l| l.strip_prefix("0::")).map(str::to_string)
}

/// The process and everything below it, parents first.
fn with_descendants(pid: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(dir) = std::fs::read_dir("/proc") {
        for e in dir.flatten() {
            let Some(p) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
            let status = std::fs::read_to_string(format!("/proc/{p}/status")).unwrap_or_default();
            if let Some(pp) = super::fanotify::parse_ppid(&status) {
                children.entry(pp).or_default().push(p);
            }
        }
    }
    descendants(pid, &children)
}

fn descendants(pid: u32, children: &HashMap<u32, Vec<u32>>) -> Vec<u32> {
    let mut out = vec![pid];
    let mut i = 0;
    while i < out.len() {
        if let Some(c) = children.get(&out[i]) {
            out.extend(c.iter().filter(|x| !out.contains(x)).copied().collect::<Vec<_>>());
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Permit {
        let (net, bits, port) = deelpe_core::allow::as_net(s).unwrap();
        Permit { net, bits, port }
    }

    #[test]
    fn the_ruleset_jumps_per_cage_and_rejects_the_rest() {
        let a = [p("10.1.2.3/8"), p("203.0.113.9:443"), p("fd00::1/7")];
        let flow = Flow { local: "10.0.0.2".parse().unwrap(), local_port: 53220, remote: "1.2.3.4".parse().unwrap(), remote_port: 443 };
        let r = ruleset(&[(42, &a)], &[flow]);
        assert!(r.contains("ip saddr 10.0.0.2 ip daddr 1.2.3.4 tcp sport 53220 tcp dport 443 reject with tcp reset"), "{r}");
        assert!(r.starts_with("add table inet deelpe_cage\ndelete table inet deelpe_cage\n"), "{r}");
        assert!(r.contains("socket cgroupv2 level 2 \"deelpe-cage/p42\" jump p42"), "{r}");
        assert!(r.contains("ip daddr 10.0.0.0/8 accept"), "host bits are masked: {r}");
        assert!(r.contains("ip daddr 203.0.113.9/32 th dport 443 accept"), "{r}");
        assert!(r.contains("ip6 daddr fc00::/7 accept"), "{r}");
        // Permits first, then the no.
        assert!(r.find("accept").unwrap() < r.find("reject").unwrap());
        assert!(r.contains("drop"));
    }

    /// What a cage refuses goes into its sets first: nft tells nobody.
    #[test]
    fn the_ruleset_records_what_it_refuses() {
        let r = ruleset(&[(42, &[p("10.0.0.0/8")])], &[]);
        assert!(r.contains("set r4_p42 { type ipv4_addr . inet_service; flags dynamic,timeout; timeout 10s; size 512; }"), "{r}");
        assert!(r.contains("meta nfproto ipv4 add @r4_p42 { ip daddr . th dport }"), "{r}");
        assert!(r.contains("meta nfproto ipv6 add @r6_p42 { ip6 daddr . th dport }"), "{r}");
        assert!(r.find("accept").unwrap() < r.find("add @r4_p42").unwrap(), "a permitted flow is not refused: {r}");
        assert!(r.find("add @r6_p42").unwrap() < r.find("reject").unwrap(), "{r}");
    }

    /// `nft -j list table inet deelpe_cage` on nftables 1.0.6 (OrbStack
    /// Debian, 2026-09-16), shortened.
    #[test]
    fn the_refusals_are_read_out_of_the_table() {
        let json = r#"{"nftables": [{"metainfo": {"version": "1.0.6"}}, {"table": {"family": "inet", "name": "deelpe_cage"}},
            {"set": {"family": "inet", "name": "r4_p42", "table": "deelpe_cage", "type": ["ipv4_addr", "inet_service"], "flags": ["timeout"], "timeout": 10,
              "elem": [{"elem": {"val": {"concat": ["9.9.9.9", 53]}, "expires": 9}}, {"elem": {"val": {"concat": ["1.1.1.1", 443]}, "expires": 9}}]}},
            {"set": {"family": "inet", "name": "r6_p7", "table": "deelpe_cage", "elem": [{"concat": ["2001:db8::1", 443]}]}},
            {"set": {"family": "inet", "name": "r6_p42", "table": "deelpe_cage", "timeout": 10}},
            {"chain": {"family": "inet", "table": "deelpe_cage", "name": "p42"}}]}"#;
        let r = parse_refused(json);
        assert_eq!(
            r,
            vec![(42, "9.9.9.9".parse().unwrap(), 53), (42, "1.1.1.1".parse().unwrap(), 443), (7, "2001:db8::1".parse().unwrap(), 443)]
        );
        assert!(parse_refused("not json").is_empty());
    }

    /// No cages: the table stands empty, nothing is filtered.
    #[test]
    fn without_cages_the_table_filters_nothing() {
        let r = ruleset(&[], &[]);
        assert!(!r.contains("jump") && !r.contains("drop"), "{r}");
    }

    #[test]
    fn the_v2_line_names_the_origin() {
        assert_eq!(parse_cgroup("12:pids:/x\n0::/user.slice/user-1000.slice/session-2.scope\n").as_deref(), Some("/user.slice/user-1000.slice/session-2.scope"));
        assert_eq!(parse_cgroup("1:name=systemd:/\n"), None);
    }

    #[test]
    fn descendants_follow_the_whole_tree() {
        let tree = HashMap::from([(1, vec![2, 3]), (2, vec![4]), (9, vec![10])]);
        assert_eq!(descendants(1, &tree), vec![1, 2, 3, 4]);
        assert_eq!(descendants(9, &tree), vec![9, 10]);
        assert_eq!(descendants(5, &tree), vec![5]);
    }

    /// Only on a real kernel as root: the VM recipe in docs/DEVELOPMENT.md
    /// (`-- --include-ignored`).
    #[test]
    #[ignore]
    fn a_caged_process_reaches_its_permits_and_nothing_else() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || for _ in listener.incoming() {});
        let connect = format!("sleep 1; exec 3<>/dev/tcp/127.0.0.1/{port}");
        reset();

        // Free: the connection goes through.
        assert!(Command::new("bash").args(["-c", &connect]).status().unwrap().success(), "control without a cage");

        // Caged without permits: refused — loopback runs through the output
        // hook as well. The second cage only proves nft takes every permit form.
        let mut child = Command::new("bash").args(["-c", &connect]).spawn().unwrap();
        let wide = [p("10.0.0.0/8"), p("203.0.113.9:443"), p("fd00::/8")];
        apply(&[(child.id(), &[]), (1, &wide)], &[]).expect("apply");
        let moved = enter(child.id(), child.id(), true).expect("enter");
        // The shell and its `sleep` both: children move along.
        assert_eq!(moved[0].pid, child.id());
        assert!(moved.len() >= 2, "{moved:?}");
        assert!(cgroup_of(child.id()).unwrap().starts_with("/deelpe-cage/"));
        assert!(!child.wait().unwrap().success(), "caged: must be refused");
        assert!(refused().unwrap().contains(&(child.id(), "127.0.0.1".parse().unwrap(), port)), "the refusal is recorded");

        // Opened again: through.
        leave(child.id(), &moved);
        apply(&[], &[]).unwrap();
        reset();
        assert!(Command::new("bash").args(["-c", &connect]).status().unwrap().success(), "after the cage");
        assert!(!std::path::Path::new(&cage_path(1)).exists() || std::fs::remove_dir(cage_path(1)).is_ok());
    }

    /// Also root-only: a connection that was open before the cage can no
    /// longer send; one to a permitted destination is not even listed.
    #[test]
    #[ignore]
    fn an_open_connection_is_cut_at_its_next_packet() {
        use std::io::{Read, Write};
        let ip = |args: &[&str]| Command::new("ip").args(args).status().unwrap();
        ip(&["link", "add", "dlpcage0", "type", "dummy"]);
        ip(&["addr", "add", "198.51.100.1/32", "dev", "dlpcage0"]);
        ip(&["link", "set", "dlpcage0", "up"]);
        let listener = std::net::TcpListener::bind("198.51.100.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut out = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let me = std::process::id();
        assert!(open_flows(&[me], &[p("198.51.100.0/24")]).is_empty(), "permitted: not listed");
        // Both ends are ours; only the one towards the listener counts.
        let flows: Vec<Flow> = open_flows(&[me], &[]).into_iter().filter(|f| f.remote_port == port).collect();
        assert_eq!(flows.len(), 1, "{flows:?}");

        apply(&[], &flows).expect("apply");
        let _ = out.write_all(b"secret");
        std::thread::sleep(std::time::Duration::from_millis(300));
        peer.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        assert!(!matches!(peer.read(&mut buf), Ok(n) if n > 0), "nothing arrives");
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(out.write_all(b"more").is_err() || out.write_all(b"more").is_err(), "the sender got a reset");

        apply(&[], &[]).unwrap();
        ip(&["link", "del", "dlpcage0"]);
    }
}
