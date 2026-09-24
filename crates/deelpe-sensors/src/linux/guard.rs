//! Opens refused before the first byte: fanotify permission events.
//!
//! Everything else on Linux acts after the fact — the touch, the cage, the
//! alert. For a guarded folder ([`deelpe_core::config::Guard`]) the kernel
//! holds the `open()` until this listener has answered, and a no comes
//! back to the caller as `EPERM`. No race, the same guarantee the browser
//! connector gives on Windows.
//!
//! The price is that every open under a marked folder **waits for us**.
//! Hence:
//!
//! * **Only the guarded folders are marked**, each directory on its own
//!   (`FAN_EVENT_ON_CHILD` covers the files directly in it) — never a mount
//!   or a filesystem, which would hang every open on the machine on this
//!   thread.
//! * **The answer comes first.** The verdict reads `/proc` and nothing else;
//!   naming the process for the alert, with the hash of its binary, runs
//!   after the answer is written.
//! * **Fail-open.** A path that does not resolve, a process that is gone, a
//!   lock that is poisoned: allowed. And when the listener dies, closing the
//!   descriptor makes the kernel allow whatever was still waiting.
//! * **Never a file of our own under a mark.** An open of ours there would
//!   wait for the one thread that could answer it. `/proc` carries no mark,
//!   and the binary of a process in a guarded folder is not hashed.
//!
//! What this does **not** do is refuse program starts
//! (`FAN_OPEN_EXEC_PERM`). The kernel raises that event before the new
//! program's arguments are copied in, so `/proc/<pid>/cmdline` still shows
//! the caller: `rm -rf /data` cannot be told from `rm /tmp/x` at that
//! moment, only `/usr/bin/rm` from `/usr/bin/ls`. And it would put every
//! start on the machine behind this thread.
//!
// ponytail: a subfolder created inside a guarded one is marked on the next
// sweep, up to REMARK later; until then its files open freely. FAN_CREATE
// would close that, but only a group that reports file handles gets it.

use super::fanotify::{cmdline, identity_of, ppid_of, readlink, Ctx};
use crate::Sensor;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use deelpe_core::event::{Event, FileAction, FileEvent, ProcessRef};
use deelpe_core::identity::ProcessIdentity;
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Walk the guarded folders again this often, for new subfolders and
/// changed rules.
const REMARK: Duration = Duration::from_secs(30);
/// Upper bound of marked directories: each one pins an inode in the kernel,
/// and older kernels stop a group at 8192 marks.
const MAX_DIRS: usize = 8_000;
/// Ancestors asked for their command line.
const CHAIN: usize = 8;
const MASK: u64 = libc::FAN_OPEN_PERM | libc::FAN_EVENT_ON_CHILD;

pub struct OpenGuard;

#[async_trait]
impl Sensor for OpenGuard {
    fn name(&self) -> &'static str {
        "open guard"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        let fan = init()?;
        // Its own thread, not the reactor: `poll` and `read` block, and so
        // does every open under a mark until this thread gets to it.
        tokio::task::spawn_blocking(move || listen(fan, tx)).await.context("open guard thread")?
    }
}

fn init() -> Result<OwnedFd> {
    // CONTENT: the class that may answer. Blocking reads, the thread is its
    // own; `poll` with a timeout lets it re-mark and notice the end.
    let flags = libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC;
    let fd = unsafe { libc::fanotify_init(flags, (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as u32) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        bail!("fanotify_init (permission class): {e} (the kernel needs CONFIG_FANOTIFY_ACCESS_PERMISSIONS, the service root)");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Returning drops `fan`, and the kernel allows every open still waiting.
fn listen(fan: OwnedFd, tx: mpsc::Sender<Event>) -> Result<()> {
    let fd = fan.as_raw_fd();
    let own = std::process::id();
    let mut ctx = Ctx::default();
    let mut marked: HashMap<(u64, u64), PathBuf> = HashMap::new();
    let mut next_mark = Instant::now();
    let mut buf = vec![0u8; 16 * 1024];
    let meta_len = std::mem::size_of::<libc::fanotify_event_metadata>();
    loop {
        if tx.is_closed() {
            return Ok(());
        }
        if Instant::now() >= next_mark {
            remark(fd, &mut marked);
            next_mark = Instant::now() + REMARK;
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        let rc = unsafe { libc::poll(&mut pfd, 1, 1_000) };
        if rc == 0 {
            continue;
        }
        let n = if rc > 0 { unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } } else { -1 };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EINTR | libc::EAGAIN)) {
                continue;
            }
            return Err(e).context("read fanotify (permission class)");
        }
        let n = n as usize;
        let mut off = 0usize;
        let mut blocked = Vec::new();
        while off + meta_len <= n {
            let meta = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const libc::fanotify_event_metadata) };
            let len = meta.event_len as usize;
            let efd = (meta.fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(meta.fd) });
            if meta.vers != libc::FANOTIFY_METADATA_VERSION || len < meta_len {
                // Whatever is left in the buffer was read and not answered;
                // dropping `fan` on the way out allows it.
                bail!("fanotify: metadata version {} or length {len} does not fit this build", meta.vers);
            }
            off += len;
            let Some(efd) = efd else { continue };
            // Resolved through our own descriptor, the verdict out of `/proc`
            // alone — no open that could wait on ourselves.
            let path = readlink(&format!("/proc/self/fd/{}", efd.as_raw_fd()));
            let pid = meta.pid as u32;
            let deny = meta.mask & libc::FAN_OPEN_PERM != 0 && pid != own && path.as_deref().is_some_and(|p| crate::filter::refuses(p, || chain(pid)));
            // Who it was, before the answer: a refused `cat` exits at once,
            // and afterwards `/proc/<pid>` is gone. Two readlinks, no open.
            let who = deny.then(|| (readlink(&format!("/proc/{pid}/exe")), ppid_of(pid)));
            respond(fd, efd.as_raw_fd(), !deny);
            drop(efd);
            if let (Some(who), Some(p)) = (who, path) {
                blocked.push((pid, who, p));
            }
        }
        // Answered, all of them: now the slow part.
        for (pid, (exe, ppid), path) in blocked {
            tracing::warn!("open guard: refused {path} to PID {pid}");
            let process = name(&mut ctx, pid, exe, ppid);
            let ev = Event::Blocked(FileEvent { at: Utc::now(), process, path: path.into(), action: FileAction::Open, target: None, inode: None, nlink: None, argv: None });
            match tx.try_send(ev) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => crate::filter::note_dropped(),
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(()),
            }
        }
    }
}

fn respond(fan: RawFd, event_fd: RawFd, allow: bool) {
    let r = libc::fanotify_response { fd: event_fd, response: if allow { libc::FAN_ALLOW } else { libc::FAN_DENY } };
    let n = unsafe { libc::write(fan, (&r as *const libc::fanotify_response).cast(), std::mem::size_of::<libc::fanotify_response>()) };
    if n < 0 {
        // Nothing to retry with: the kernel either has the answer or the
        // process is gone. Closing the group would allow it; one lost
        // answer is not worth that.
        tracing::warn!("open guard: answer not written: {}", std::io::Error::last_os_error());
    }
}

/// Command lines of the process and its ancestors, nearest first.
fn chain(mut pid: u32) -> Vec<String> {
    let mut out = Vec::new();
    for _ in 0..CHAIN {
        out.extend(cmdline(pid));
        match ppid_of(pid) {
            Some(p) if p > 1 && p != pid => pid = p,
            _ => break,
        }
    }
    out
}

/// The process for the alert. A binary inside a guarded folder is named,
/// not hashed: hashing opens it, and that open would wait on this thread.
fn name(ctx: &mut Ctx, pid: u32, exe: Option<String>, ppid: Option<u32>) -> ProcessRef {
    let exe = exe.unwrap_or_else(|| format!("pid {pid}"));
    let identity = if exe.starts_with('/') && !crate::filter::is_guarded(&exe) { identity_of(ctx, exe.clone()) } else { ProcessIdentity::Unknown { path: exe.clone() } };
    ProcessRef { pid, ppid, responsible: None, path: PathBuf::from(exe), identity }
}

/// Mark every directory under the guarded folders, unmark what fell out.
/// Keyed by inode: a folder removed and made again is a new one.
fn remark(fan: RawFd, marked: &mut HashMap<(u64, u64), PathBuf>) {
    let mut want: HashMap<(u64, u64), PathBuf> = HashMap::new();
    for g in crate::filter::guarded() {
        walk(&g.path, &mut want);
    }
    let before = marked.len();
    marked.retain(|k, p| {
        let keep = want.contains_key(k);
        if !keep {
            // The folder may be gone with its mark; an error here says only that.
            let _ = mark(fan, libc::FAN_MARK_REMOVE, p);
        }
        keep
    });
    for (k, p) in want {
        if marked.contains_key(&k) {
            continue;
        }
        match mark(fan, libc::FAN_MARK_ADD, &p) {
            Ok(()) => {
                marked.insert(k, p);
            }
            Err(e) => tracing::warn!("open guard: {} not marked: {e}", p.display()),
        }
    }
    if marked.len() != before {
        tracing::info!("open guard: {} folders marked", marked.len());
    }
}

/// The folder and every directory below it, without following links.
fn walk(root: &Path, out: &mut HashMap<(u64, u64), PathBuf>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if out.len() >= MAX_DIRS {
            tracing::warn!("open guard: more than {MAX_DIRS} folders, the rest stays unguarded");
            return;
        }
        let Ok(md) = std::fs::symlink_metadata(&dir) else { continue };
        if !md.is_dir() {
            continue;
        }
        out.insert((md.dev(), md.ino()), dir.clone());
        // Listing a folder raises no event: no FAN_ONDIR in the mask.
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        stack.extend(entries.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()));
    }
}

fn mark(fan: RawFd, op: libc::c_uint, dir: &Path) -> Result<()> {
    let path = CString::new(dir.as_os_str().as_bytes()).context("folder with a null byte")?;
    // No FAN_MARK_MOUNT, no FAN_MARK_FILESYSTEM: the directory's inode alone.
    let rc = unsafe { libc::fanotify_mark(fan, op | libc::FAN_MARK_ONLYDIR, MASK, libc::AT_FDCWD, path.as_ptr()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
