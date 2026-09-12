//! File access via fanotify (kernel ≥ 4.20 for `FAN_MARK_FILESYSTEM`).
//!
//! The Linux counterpart to `eslogger` on the Mac and to the Kernel-File
//! provider on Windows: who opens, writes and executes which file. No
//! kernel module — fanotify is built into the kernel, the service only
//! needs `CAP_SYS_ADMIN` (root).
//!
//! **Marked is every filesystem, filtered is in userspace**, exactly as on
//! Windows and for the same reason: unfiltered, every open on the machine
//! goes through the channel, and under load the one access that matters is
//! the one that gets dropped. What passes is a file under a protected
//! folder — plus whatever a process writes that has just read from one,
//! because that write *is* the copy (see [`crate::filter`]).
//!
//! What this sensor cannot do, and Windows can:
//!
//! * **Rename, hard link and copy as such.** fanotify reports them only
//!   with `FAN_REPORT_FID` (kernel ≥ 5.17 for `FAN_RENAME`), and that
//!   delivers file handles instead of descriptors — a second resolution
//!   path through `open_by_handle_at`. A copy still shows up as read on the
//!   source plus write on the target, which is what the correlator works
//!   with.
//! * **Network filesystems.** Whether a CIFS or NFS mount takes a mark
//!   depends on the kernel; the mount loop therefore ignores what fails and
//!   logs what worked, so the field can see it instead of guessing.

use crate::filter::{wanted, TaintTable};
use crate::Sensor;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use deelpe_core::event::{Event, FileAction, FileEvent, ProcessRef};
use deelpe_core::identity::ProcessIdentity;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

/// A filesystem can appear while the service runs — a USB stick, a share
/// mounted later. Marking is idempotent, so the cheapest way to catch it is
/// to walk the mount table again now and then.
const MARK_RESCAN: Duration = Duration::from_secs(30);

/// Upper bound of the binary → hash table.
const MAX_HASHES: usize = 1_024;

/// Filesystems that hold no user data. Marking them would work but only
/// costs events; `/proc` in particular is read by everything all the time.
const PSEUDO_FS: &[&str] = &[
    "proc", "sysfs", "devpts", "devtmpfs", "cgroup", "cgroup2", "debugfs", "tracefs", "securityfs", "pstore", "bpf",
    "configfs", "fusectl", "mqueue", "hugetlbfs", "binfmt_misc", "autofs", "nsfs", "rpc_pipefs", "selinuxfs",
];

#[derive(Default)]
pub struct Fanotify;

#[async_trait]
impl Sensor for Fanotify {
    fn name(&self) -> &'static str {
        "fanotify"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        let fan = init()?;
        let marked = mark_all(fan.as_raw_fd(), &mount_table()?);
        if marked.is_empty() {
            bail!("fanotify: the mount table was read, but not one of its filesystems accepted a mark (the service needs root)");
        }
        tracing::info!("fanotify: {} filesystems marked: {}", marked.len(), marked.join(" "));
        let afd = AsyncFd::new(fan).context("fanotify descriptor into the reactor")?;
        let mut ctx = Ctx::default();
        let mut buf = vec![0u8; 64 * 1024];
        let mut marked = marked;
        let mut rescan = tokio::time::interval(MARK_RESCAN);
        // The first tick fires straight away and would mark everything a
        // second time for nothing.
        rescan.tick().await;
        loop {
            tokio::select! {
                _ = rescan.tick() => {
                    // A mount table that has become unreadable is not worth
                    // ending the sensor over: what is already marked keeps
                    // delivering.
                    let Ok(table) = mount_table() else { continue };
                    let now = mark_all(afd.get_ref().as_raw_fd(), &table);
                    for m in now.iter().filter(|m| !marked.contains(m)) {
                        tracing::info!("fanotify: filesystem {m} newly marked");
                    }
                    // Taking the new list over, not just reading it: without
                    // that, the same USB stick is reported as new every
                    // thirty seconds for as long as it stays plugged in.
                    marked = now;
                }
                readable = afd.readable() => {
                    let mut guard = readable.context("wait for fanotify")?;
                    match guard.try_io(|inner| read_events(inner.get_ref().as_raw_fd(), &mut buf)) {
                        // Nothing there after all: back to waiting.
                        Err(_would_block) => continue,
                        Ok(Ok(0)) => bail!("fanotify: descriptor closed"),
                        Ok(Ok(n)) => {
                            if !dispatch(&mut ctx, &buf[..n], &tx)? {
                                // Nobody listening any more.
                                return Ok(());
                            }
                        }
                        Ok(Err(e)) => return Err(e).context("read fanotify"),
                    }
                }
            }
        }
    }
}

/// What the sensor carries between events.
struct Ctx {
    tainted: TaintTable,
    /// Binary → SHA-256, keyed by size and mtime as well: a swapped binary
    /// must not keep the identity of the one that was checked.
    hashes: HashMap<(PathBuf, u64, i64), String>,
    /// Our own PID: the service reads the alert log and the config itself,
    /// and that is not a file access worth reporting.
    own: u32,
}

impl Default for Ctx {
    fn default() -> Self {
        Self { tainted: TaintTable::new(), hashes: HashMap::new(), own: std::process::id() }
    }
}

fn init() -> Result<OwnedFd> {
    // NOTIF, not PERM: this milestone watches, it does not decide. A
    // permission class would have to answer every open, and a service that
    // hangs stops the machine.
    let flags = libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK;
    let fd = unsafe { libc::fanotify_init(flags, (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        bail!("fanotify_init: {e} (the service needs root, i.e. CAP_SYS_ADMIN)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The mount table. Its own step, so that "could not be read at all" and
/// "not one filesystem accepted a mark" stay two different messages — they
/// send whoever is standing at the machine in two different directions.
fn mount_table() -> Result<String> {
    std::fs::read_to_string("/proc/mounts").context("read /proc/mounts")
}

/// Mark every filesystem from the mount table and return the mount points
/// that took the mark. Errors are deliberately swallowed per mount: which
/// filesystem accepts a mark depends on the kernel, and one that refuses
/// must not cost us all the others.
fn mark_all(fan: RawFd, table: &str) -> Vec<String> {
    let mut ok = Vec::new();
    for point in mount_points(table) {
        match mark_one(fan, &point) {
            Ok(()) => ok.push(point),
            Err(e) => tracing::debug!("fanotify: {point} not marked: {e}"),
        }
    }
    ok
}

fn mark_one(fan: RawFd, point: &str) -> Result<()> {
    // FILESYSTEM instead of MOUNT: a bind mount of the same filesystem is
    // then covered too, and marking the same filesystem twice only updates
    // the mask.
    let flags = libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM;
    // ACCESS is the read, MODIFY the write, OPEN_EXEC the start of a
    // program. OPEN is in there for the taint only, see [`event`].
    //
    // Without FAN_ONDIR no directory events arrive — and that is right:
    // browsing a folder carries nothing out (lab log 2026-09-07, where
    // Explorer counted as a reader on Windows for exactly that reason).
    let mask = libc::FAN_OPEN | libc::FAN_ACCESS | libc::FAN_MODIFY | libc::FAN_OPEN_EXEC;
    let path = CString::new(point).context("mount point with a null byte")?;
    let rc = unsafe { libc::fanotify_mark(fan, flags, mask, libc::AT_FDCWD, path.as_ptr()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Mount points from `/proc/mounts`, without the pseudo filesystems.
///
/// Pure text: the format is fixed, so this gets tested rather than guessed.
/// Whitespace in a path is octal-escaped there (`\040`).
pub fn mount_points(table: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in table.lines() {
        let mut f = line.split_whitespace();
        let (Some(_dev), Some(point), Some(fstype)) = (f.next(), f.next(), f.next()) else { continue };
        if PSEUDO_FS.contains(&fstype) {
            continue;
        }
        let point = unescape(point);
        if !out.contains(&point) {
            out.push(point);
        }
    }
    out
}

/// `\040` and friends back into their character.
///
/// Byte by byte, not character by character: a mount point with an umlaut
/// in it is UTF-8, and pushing its bytes into a `String` one at a time
/// would turn each of them into its own character. The mark would then be
/// set on a path that does not exist — and the folder would go unwatched
/// without anyone noticing.
fn unescape(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(c) = std::str::from_utf8(&b[i + 1..i + 4]).ok().and_then(|o| u8::from_str_radix(o, 8).ok()) {
                out.push(c);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_events(fan: RawFd, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = unsafe { libc::read(fan, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Walk one read buffer. `Ok(false)` means nobody is listening any more.
fn dispatch(ctx: &mut Ctx, buf: &[u8], tx: &mpsc::Sender<Event>) -> Result<bool> {
    let meta_len = std::mem::size_of::<libc::fanotify_event_metadata>();
    let mut off = 0usize;
    while off + meta_len <= buf.len() {
        // The buffer comes from the kernel and is aligned; `read_unaligned`
        // costs nothing and saves the argument about it.
        let meta = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const libc::fanotify_event_metadata) };
        // Into an owner before the first check, not after: every event
        // carries an open descriptor, and every path out of the loop below
        // — the error paths included — has to close it. A leak here runs
        // the service out of descriptors within minutes, and it would be
        // the checks that never fire in testing that leak.
        let fd = (meta.fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(meta.fd) });
        // Not a warning but the end: if the version does not match, it does
        // not match for any event either, and a loop that keeps reading
        // would throw away every descriptor it is handed. The service
        // restarts the sensor and shows it red.
        let len = meta.event_len as usize;
        if meta.vers != libc::FANOTIFY_METADATA_VERSION {
            close_rest(buf, off + len);
            bail!("fanotify: metadata version {} instead of {} — kernel and build do not fit together", meta.vers, libc::FANOTIFY_METADATA_VERSION);
        }
        if len < meta_len || off + len > buf.len() {
            tracing::warn!("fanotify: event length {len} does not fit, rest of the buffer dropped");
            // Without this the descriptors of every event still in the
            // buffer stay open — up to a few thousand out of one read, and
            // the sensor is restarted after the error, so they add up.
            close_rest(buf, off + meta_len);
            return Ok(true);
        }
        off += len;
        // The kernel queue ran over. Same promise as on Windows: what is
        // lost gets counted, because a silent loss is worse than a red line.
        if meta.mask & libc::FAN_Q_OVERFLOW != 0 {
            crate::filter::note_dropped();
            continue;
        }
        let Some(fd) = fd else { continue };
        let Some(ev) = event(ctx, &fd, meta.mask, meta.pid as u32) else { continue };
        match tx.try_send(ev) {
            Ok(()) => {}
            // The engine cannot keep up. Dropping one event beats blocking
            // the read loop: a stalled reader overflows the kernel queue,
            // and then a lot more goes missing.
            Err(mpsc::error::TrySendError::Full(_)) => crate::filter::note_dropped(),
            Err(mpsc::error::TrySendError::Closed(_)) => return Ok(false),
        }
    }
    Ok(true)
}

/// Close the descriptors of everything still in the buffer, for the paths
/// that give up on it.
///
/// Best effort: whoever gets here no longer trusts the buffer, so it walks
/// as far as the lengths stay plausible and stops at the first that does
/// not. Leaking a few descriptors on the way out beats leaking all of them.
fn close_rest(buf: &[u8], mut off: usize) {
    let meta_len = std::mem::size_of::<libc::fanotify_event_metadata>();
    while off + meta_len <= buf.len() {
        let meta = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const libc::fanotify_event_metadata) };
        let len = meta.event_len as usize;
        if meta.fd >= 0 {
            drop(unsafe { OwnedFd::from_raw_fd(meta.fd) });
        }
        if len < meta_len {
            return;
        }
        off += len;
    }
}

/// One fanotify event into a normalized one — or nothing, if the filter
/// does not want it.
fn event(ctx: &mut Ctx, fd: &OwnedFd, mask: u64, pid: u32) -> Option<Event> {
    if pid == ctx.own {
        return None;
    }
    // Nothing watched and nobody tainted: everything below — the readlink,
    // `/proc`, the hash of the binary — would run for every open on the
    // machine and be thrown away at the end. An agent that is not enrolled
    // yet and has no folder of its own sits in exactly this state, and it
    // is the state a fresh installation ships in.
    if crate::filter::watches_nothing() && !ctx.tainted.is_tainted(pid) {
        return None;
    }
    let path = readlink(&format!("/proc/self/fd/{}", fd.as_raw_fd()))?;
    // Deleted while open: the name is gone, the event says nothing useful.
    if path.ends_with(" (deleted)") {
        return None;
    }
    // The same order as in the Windows sensor: whoever reads from a
    // protected folder is tainted from that moment on, and only then do
    // their writes elsewhere count — that write is the copy.
    if wanted(&path) {
        ctx.tainted.taint(pid);
    } else if !ctx.tainted.is_tainted(pid) {
        return None;
    }
    // **Opening is not yet reading**, and the difference decides who counts
    // as having touched a protected file. `windows/etw.rs` draws the same
    // line for the same reason: everything that walks a filesystem —
    // `updatedb`, a virus scanner, a backup agent — opens every file under
    // the protected folder without ever looking at its content. Counting
    // that as a read makes each of them tainted, and from then on every
    // byte they send is correlated as an upload of protected data.
    //
    // The open still taints (above), because `cp` opens source *and*
    // target before the first byte flows; only the event is withheld.
    let action = if mask & libc::FAN_OPEN_EXEC != 0 {
        FileAction::Exec
    } else if mask & libc::FAN_MODIFY != 0 {
        FileAction::Write
    } else if mask & libc::FAN_ACCESS != 0 {
        FileAction::Open
    } else {
        return None;
    };
    let (inode, nlink) = stat_of(fd);
    let process = process_ref(ctx, pid);
    Some(Event::File(FileEvent { at: Utc::now(), process, path: PathBuf::from(path), action, target: None, inode, nlink }))
}

/// (device, inode) and link count of the object the event points at.
/// Detects the hard link that gives the same data a second name.
fn stat_of(fd: &OwnedFd) -> (Option<(u64, u64)>, Option<u32>) {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return (None, None);
    }
    (Some((st.st_dev as u64, st.st_ino as u64)), Some(st.st_nlink as u32))
}

/// Who is this process? Path from `/proc`, identity as the hash of the
/// binary — Linux has no signature the kernel would vouch for.
///
/// Never gives up. The process can be gone by the time we drain the buffer
/// — `cp` of a small file is over in well under a millisecond, and under a
/// backlog the gap is far wider. Dropping the event then would throw away
/// the file, the action and the copy trail as well, and those are exactly
/// what the correlator needs. So an unnamed sender is reported rather than
/// nothing: `Unknown` is the identity that is always worth a line anyway.
fn process_ref(ctx: &mut Ctx, pid: u32) -> ProcessRef {
    let ppid = ppid_of(pid);
    let Some(exe) = readlink(&format!("/proc/{pid}/exe")) else {
        let gone = format!("pid {pid}");
        return ProcessRef { pid, ppid, responsible: None, path: PathBuf::from(&gone), identity: ProcessIdentity::Unknown { path: gone } };
    };
    let path = PathBuf::from(&exe);
    let identity = match hash_of(ctx, &path) {
        Some(sha256) => ProcessIdentity::Hashed { path: exe, sha256 },
        // Unreadable binary (a container's own mount namespace, a race with
        // exit): reported rather than silently trusted.
        None => ProcessIdentity::Unknown { path: exe },
    };
    ProcessRef { pid, ppid, responsible: None, path, identity }
}

/// SHA-256 of the binary, cached by size and mtime.
///
// ponytail: hashed synchronously in the read loop — a first sighting of a
// very large binary stalls the drain, and a stalled drain overflows the
// kernel queue. Read in chunks so at least the memory stays bounded. If a
// binary ever shows up big enough to cost events, the identity has to be
// filled in off the event path (`spawn_blocking`), not made cheaper.
fn hash_of(ctx: &mut Ctx, path: &PathBuf) -> Option<String> {
    use std::io::Read;
    let md = std::fs::metadata(path).ok()?;
    let mtime = std::os::linux::fs::MetadataExt::st_mtime(&md);
    let key = (path.clone(), md.len(), mtime);
    if let Some(h) = ctx.hashes.get(&key) {
        return Some(h.clone());
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        match f.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => <sha2::Sha256 as sha2::Digest>::update(&mut hasher, &chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    let hex = <sha2::Sha256 as sha2::Digest>::finalize(hasher).iter().map(|b| format!("{b:02x}")).collect::<String>();
    // One entry out, not the whole table: clearing it would send every
    // binary on the machine back through the hashing above at once, which
    // is the one thing this cache exists to prevent.
    if ctx.hashes.len() >= MAX_HASHES {
        if let Some(old) = ctx.hashes.keys().next().cloned() {
            ctx.hashes.remove(&old);
        }
    }
    ctx.hashes.insert(key, hex.clone());
    Some(hex)
}

/// Parent process from `/proc/<pid>/status`. Not from `stat`: the program
/// name sits in brackets there and may itself contain brackets and spaces,
/// which shifts every field behind it.
fn ppid_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_ppid(&status)
}

/// Pure part of [`ppid_of`], so the format gets tested rather than trusted.
pub fn parse_ppid(status: &str) -> Option<u32> {
    status.lines().find_map(|l| l.strip_prefix("PPid:")).and_then(|v| v.trim().parse().ok())
}

fn readlink(path: &str) -> Option<String> {
    std::fs::read_link(path).ok()?.to_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `/proc/mounts` from a Debian container.
    const MOUNTS: &str = "overlay / overlay rw,relatime,lowerdir=/var/lib/docker 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
/dev/vda1 /etc/hosts ext4 rw,relatime 0 0
//srv/GL /mnt/Meine\\040Freigabe cifs rw,relatime 0 0
";

    #[test]
    fn only_real_filesystems_are_marked() {
        let p = mount_points(MOUNTS);
        assert!(p.contains(&"/".to_string()));
        assert!(p.contains(&"/dev".to_string()), "tmpfs holds copies");
        assert!(!p.contains(&"/proc".to_string()));
        assert!(!p.contains(&"/sys".to_string()));
        // A share is where the protected data lives: it has to be tried,
        // even if the kernel then refuses the mark.
        assert!(p.contains(&"/mnt/Meine Freigabe".to_string()), "{p:?}");
    }

    /// A mount point with an umlaut has to come back out as itself.
    /// Otherwise the mark lands on a path that does not exist and the
    /// folder goes unwatched.
    #[test]
    fn an_escaped_mount_point_survives_its_umlauts() {
        // "Büro GL" in UTF-8, with the space escaped as \040 the way
        // /proc/mounts writes it.
        let table = "//srv/GL /mnt/Büro\\040GL cifs rw 0 0\n";
        assert_eq!(mount_points(table), vec!["/mnt/Büro GL".to_string()]);
    }

    /// A mount point listed twice must not be marked twice.
    #[test]
    fn duplicate_mount_points_appear_once() {
        let t = "/dev/vda1 /data ext4 rw 0 0\n/dev/vda1 /data ext4 rw 0 0\n";
        assert_eq!(mount_points(t), vec!["/data".to_string()]);
    }

    /// A program name with brackets and spaces must not shift the parent.
    #[test]
    fn the_parent_comes_from_status_not_from_stat() {
        let status = "Name:\tbad ) name (\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t8112\n";
        assert_eq!(parse_ppid(status), Some(8112));
        assert_eq!(parse_ppid("Name:\tinit\n"), None);
    }
}
