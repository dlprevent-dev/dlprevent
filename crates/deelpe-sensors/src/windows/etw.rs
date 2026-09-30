//! The endpoint sensor for Windows: one real-time Event Tracing for
//! Windows (ETW) session with two built-in providers.
//!
//! * **Kernel-File** — who opens and reads which file. On a network share
//!   too: the path then arrives as `\Device\Mup\srv\GL\…` and is turned
//!   into `\\srv\GL\…` in `crate::winpath`. That is exactly the case that
//!   matters — a file from the file server, read at a workstation.
//! * **Kernel-Network** — who sends how many bytes to which address.
//!
//! No driver, no kernel extension: both are built into Windows, just like
//! `eslogger` and `nettop` on the Mac. For this the service needs
//! `SeSystemProfilePrivilege` — LocalSystem has it, and so does an account
//! in "Performance Log Users".
//!
//! **The untested spots are called out.** We build on the Mac (see
//! `docs/DESIGN.md`); keywords and event IDs come from the manifests and
//! need cross-checking on a real machine with `deelpe-winagent trace`
//! before anyone relies on them.

use crate::winpath;
use crate::Sensor;
use anyhow::{bail, Result};
use async_trait::async_trait;
use chrono::Utc;
use deelpe_core::event::{Event, FileAction, FileEvent, NetEvent};
use std::collections::HashMap;
use tokio::sync::mpsc;
use windows::core::{GUID, PCWSTR};
use windows::Win32::System::Diagnostics::Etw::*;

/// Name of the session. Unique, so that a crashed predecessor can be found
/// and stopped instead of the start failing with "already exists".
const SESSION: &str = "DLPrevent-Endpoint";

/// `Microsoft-Windows-Kernel-File`.
const KERNEL_FILE: GUID = GUID::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
/// `Microsoft-Windows-Kernel-Network`.
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);

/// Keywords from the Kernel-File manifest. Less is worth a lot here:
/// without a restriction the provider delivers every file operation on the
/// whole system.
const FILE_KW_CREATE: u64 = 0x80;
const FILE_KW_READ: u64 = 0x100;
const FILE_KW_WRITE: u64 = 0x200;
const FILE_KW_CLOSE: u64 = 0x40000;
/// IPv4 and IPv6 from Kernel-Network.
const NET_KW_IPV4: u64 = 0x10;
const NET_KW_IPV6: u64 = 0x20;

/// Event IDs of the two providers.
const EV_FILE_CREATE: u16 = 12;
const EV_FILE_CLOSE: u16 = 14;
const EV_FILE_READ: u16 = 15;
const EV_FILE_WRITE: u16 = 16;
const EV_NET_SEND_V4: u16 = 10;
const EV_NET_SEND_V6: u16 = 26;

/// Upper bound of the file object → path table. A `Close` normally cleans
/// up; the limit catches the case where some go missing.
const MAX_OPEN_FILES: usize = 50_000;

use crate::filter::TaintTable;
/// Paths for which file events get passed on at all.
///
/// `None` means "everything" and is meant only for `trace`. In production
/// the agent puts the protected folders here, and the callback throws away
/// everything else **before** it goes into the channel.
///
/// The reason is in the lab log of 2026-09-07: unfiltered, a freshly
/// installed Windows 11 produced over 20 000 file events in five minutes,
/// from Windows Update alone. The channel filled up, and the one access
/// that mattered was precisely the one that got dropped. Filtering behind
/// the channel does not help: by then the queue is already full.
///
/// Global, because there is exactly one session per machine and the ETW
/// callback gets no state of its own.
// Filter, taint table and drop counter live in [`crate::filter`]: pure
// bookkeeping, which gets tested on every platform. What stays here is only
// what ETW itself needs.
pub use crate::filter::{dropped, set_file_filter, wanted, DEFAULT_TAINT_TTL};

/// Stops the running session. `ProcessTrace` returns as a result — without
/// it the sensor keeps running even though nobody is listening any more,
/// and the process never ends. Observed exactly like that in the lab on
/// 2026-09-07.
pub fn stop_session() {
    let name = wide(SESSION);
    let mut props = properties();
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut _,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

pub struct Etw;

#[async_trait]
impl Sensor for Etw {
    fn name(&self) -> &'static str {
        "etw"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        // `ProcessTrace` blocks until the session ends; that belongs on a
        // thread of its own, otherwise the whole runtime stalls.
        tokio::task::spawn_blocking(move || pump(tx)).await?
    }
}

/// Everything the callback needs. It gets a pointer to this via
/// `EVENT_TRACE_LOGFILEW::Context`.
struct Ctx {
    tx: mpsc::Sender<Event>,
    procs: super::procinfo::ProcCache,
    volumes: HashMap<String, String>,
    /// File object → path and the **opening process**. `Read` names only
    /// the object; the name was there at `Create` time.
    ///
    /// The PID belongs in here because the event header often gets it wrong
    /// on writes: Windows writes through the cache manager, and the delayed
    /// write runs in the system process (PID 4). Measured in the lab on
    /// 2026-09-07 — the source came in under `powershell.exe`, the target of
    /// the same copy under PID 4. Whoever opened the file is the responsible
    /// party; that is what the sensor goes by.
    open: HashMap<u64, (String, u32)>,
    /// Process → when it last read from a protected folder.
    tainted: TaintTable,
    /// End the session as soon as nobody is listening any more.
    stop: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Buffer for `EVENT_TRACE_PROPERTIES`: the struct, and behind it the name
/// of the session that `LoggerNameOffset` points at. That is how the API
/// wants it.
fn properties() -> Vec<u8> {
    let name = wide(SESSION);
    let head = std::mem::size_of::<EVENT_TRACE_PROPERTIES>();
    let mut buf = vec![0u8; head + name.len() * 2];
    unsafe {
        let p = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*p).Wnode.BufferSize = buf.len() as u32;
        (*p).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        // 1 = system time at QPC resolution.
        (*p).Wnode.ClientContext = 1;
        (*p).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*p).LoggerNameOffset = head as u32;
    }
    buf
}

fn pump(tx: mpsc::Sender<Event>) -> Result<()> {
    let name = wide(SESSION);
    // A session outlives the process that started it. So after a crash it
    // is still lying around and `StartTrace` fails with "already exists" —
    // hence clean up first.
    let mut props = properties();
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut _,
            EVENT_TRACE_CONTROL_STOP,
        );
    }

    let mut props = properties();
    let mut session = CONTROLTRACE_HANDLE::default();
    let rc = unsafe {
        StartTraceW(
            &mut session,
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut _,
        )
    };
    if rc.is_err() {
        bail!("StartTrace \"{SESSION}\" failed ({rc:?}); the service needs to run as LocalSystem or in \"Performance Log Users\"");
    }

    let enable = |guid: GUID, keywords: u64| -> Result<()> {
        let rc = unsafe {
            EnableTraceEx2(
                session,
                &guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_INFORMATION as u8,
                keywords,
                0,
                0,
                None,
            )
        };
        if rc.is_err() {
            bail!("EnableTraceEx2 for {guid:?} failed ({rc:?})");
        }
        Ok(())
    };
    let armed = (|| -> Result<()> {
        enable(
            KERNEL_FILE,
            FILE_KW_CREATE | FILE_KW_READ | FILE_KW_WRITE | FILE_KW_CLOSE,
        )?;
        enable(KERNEL_NETWORK, NET_KW_IPV4 | NET_KW_IPV6)?;
        Ok(())
    })();
    if let Err(e) = armed {
        stop(session, &name);
        return Err(e);
    }

    let mut ctx = Box::new(Ctx {
        tx,
        procs: super::procinfo::ProcCache::default(),
        volumes: super::procinfo::volume_map(),
        open: HashMap::new(),
        tainted: TaintTable::new(),
        stop: false,
    });

    let mut log = EVENT_TRACE_LOGFILEW {
        LoggerName: windows::core::PWSTR(name.as_ptr() as *mut u16),
        Context: &mut *ctx as *mut Ctx as *mut std::ffi::c_void,
        ..Default::default()
    };
    log.Anonymous1.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    log.Anonymous2.EventRecordCallback = Some(on_event);

    let trace = unsafe { OpenTraceW(&mut log) };
    if trace.Value == u64::MAX {
        stop(session, &name);
        bail!("OpenTrace \"{SESSION}\" failed");
    }
    // Runs until the session ends — the callback ends it as soon as the
    // service stops listening.
    let rc = unsafe { ProcessTrace(&[trace], None, None) };
    unsafe {
        let _ = CloseTrace(trace);
    }
    stop(session, &name);
    if rc.is_err() {
        bail!("ProcessTrace ended: {rc:?}");
    }
    Ok(())
}

fn stop(session: CONTROLTRACE_HANDLE, name: &[u16]) {
    let mut props = properties();
    unsafe {
        let _ = ControlTraceW(
            session,
            PCWSTR(name.as_ptr()),
            props.as_mut_ptr() as *mut _,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// The ETW callback. Runs on the `ProcessTrace` thread and must never
/// panic: a crash here takes the session down with it.
unsafe extern "system" fn on_event(rec: *mut EVENT_RECORD) {
    if rec.is_null() {
        return;
    }
    let ctx = unsafe { (*rec).UserContext as *mut Ctx };
    if ctx.is_null() {
        return;
    }
    let ctx = unsafe { &mut *ctx };
    if ctx.stop {
        return;
    }
    let provider = unsafe { (*rec).EventHeader.ProviderId };
    let id = unsafe { (*rec).EventHeader.EventDescriptor.Id };
    let ev = if provider == KERNEL_FILE {
        file_event(ctx, rec, id)
    } else if provider == KERNEL_NETWORK {
        net_event(ctx, rec, id)
    } else {
        None
    };
    let Some(ev) = ev else { return };
    // Whoever was newly resolved gets introduced first — together with its
    // ancestors. The correlator learns names only from file events, and
    // without names its rule against inheritance into the service root does
    // not bite (see `ProcCache::take_pending`). Before `ev`, not after: the
    // inheritance is decided in the event itself.
    for p in ctx.procs.take_pending() {
        let path = p.path.clone();
        let intro = Event::File(FileEvent {
            at: Utc::now(),
            process: p,
            path,
            action: FileAction::Exec,
            target: None,
            inode: None,
            nlink: None,
            argv: None,
        });
        if ctx.tx.try_send(intro).is_err() {
            break;
        }
    }
    // A full channel means the engine cannot keep up. Better to drop this
    // one event than to block the callback — a stalled callback makes the
    // session lose buffers, and then a lot more goes missing.
    match ctx.tx.try_send(ev) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            crate::filter::note_dropped();
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // Nobody is listening any more. The flag alone is not enough:
            // only stopping the session makes `ProcessTrace` return.
            ctx.stop = true;
            stop_session();
        }
    }
}

/// `FILE_DIRECTORY_FILE` from the call's `CreateOptions`. Inferring it from
/// the trailing separator alone was not enough: a share gets opened without
/// one too. On 2026-09-09 `\\fs-01\GL\Zahlen` showed up in a block
/// message as the file supposedly read — the folder, not the numbers in it.
/// Browsing carries nothing out.
///
/// The bit is unambiguous: with `FILE_DIRECTORY_FILE` set, `NtCreateFile`
/// fails if the target is not a directory. If the field is missing (older
/// providers), we fall back to the old inference from the separator.
fn is_directory_open(rec: *mut EVENT_RECORD) -> bool {
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    super::tdh::prop_u32(rec, "CreateOptions").is_some_and(|o| o & FILE_DIRECTORY_FILE != 0)
}

fn file_event(ctx: &mut Ctx, rec: *mut EVENT_RECORD, id: u16) -> Option<Event> {
    let obj = super::tdh::prop_u64(rec, "FileObject")?;
    match id {
        EV_FILE_CREATE => {
            let name = super::tdh::prop_string(rec, "FileName")?;
            let path = winpath::to_user_path(&name, &ctx.volumes);
            // A folder is not a file. Windows opens and "reads" directory
            // objects too — Explorer when you expand a tree, every listing.
            // Without this line every process that merely looked at the
            // protected folder counts as tainted, and with "Stop the
            // sender" it would get killed for that. Measured in the lab on
            // 2026-09-07: `sshd.exe` and the agent itself were reported,
            // with `\\srv\GL\` as the file supposedly read.
            if is_directory_open(rec) || path.ends_with('\\') || path.ends_with('/') {
                return None;
            }
            // Filtering happens here, not at read time: whatever is not in
            // the table produces no event later on, and the table stays
            // small instead of carrying every file on the system.
            //
            // Exception: a process that has just read from a protected
            // folder. Its writes *outside* are the copy that matters —
            // without this line the copy is invisible, and the filter still
            // holds back everything no such process touches.
            let pid = unsafe { (*rec).EventHeader.ProcessId };
            if wanted(&path) {
                // Already here, not at read time: `CopyFileEx` opens both
                // source *and* target before the first byte flows. Taint
                // only at read time and the target has already been thrown
                // away by then, so the copy is never seen.
                ctx.tainted.taint(pid);
            } else if !ctx.tainted.is_tainted(pid) {
                return None;
            }
            if ctx.open.len() > MAX_OPEN_FILES {
                ctx.open.clear();
            }
            ctx.open.insert(obj, (path, pid));
            // Opening alone is not yet access to the content; only reading
            // counts. Otherwise every directory tree Explorer expands would
            // taint every file inside it.
            None
        }
        EV_FILE_CLOSE => {
            ctx.open.remove(&obj);
            None
        }
        EV_FILE_READ | EV_FILE_WRITE => {
            // Not `EventHeader.ProcessId`: see `Ctx::open`.
            let (path, pid) = ctx.open.get(&obj)?.clone();
            let action = if id == EV_FILE_READ {
                FileAction::Open
            } else {
                FileAction::Write
            };
            Some(Event::File(FileEvent {
                at: Utc::now(),
                process: ctx.procs.get(pid),
                path: path.into(),
                action,
                target: None,
                inode: None,
                nlink: None,
                argv: None,
            }))
        }
        _ => None,
    }
}

fn net_event(ctx: &mut Ctx, rec: *mut EVENT_RECORD, id: u16) -> Option<Event> {
    if id != EV_NET_SEND_V4 && id != EV_NET_SEND_V6 {
        return None;
    }
    // The PID is in the payload, not in the header: for network events the
    // header often names the system process.
    let pid = super::tdh::prop_u32(rec, "PID")?;
    let bytes = super::tdh::prop_u32(rec, "size")? as u64;
    if bytes == 0 {
        return None;
    }
    let remote = super::tdh::prop_ip(rec, "daddr");
    let port = super::tdh::prop_port(rec, "dport");
    // The process reference already carries the parent process; before, it
    // was dropped here, and with it the only edge over which the correlator
    // connects a sending child process to the reading parent process.
    let proc = ctx.procs.get(pid);
    let name = proc
        .path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    Some(Event::Net(NetEvent {
        at: Utc::now(),
        pid,
        ppid: proc.ppid,
        process_name: name,
        remote,
        remote_port: port,
        bytes_out: bytes,
        bytes_in: 0,
    }))
}
