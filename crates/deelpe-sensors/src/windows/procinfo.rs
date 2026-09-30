//! Who is this process? Path, parent process and the volume table.
//!
//! We ask rarely and remember the answer: events arrive by the thousand,
//! and one `OpenProcess` per event would be the most expensive part of the
//! whole agent.

use deelpe_core::event::ProcessRef;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Default)]
pub struct ProcCache {
    known: HashMap<u32, ProcessRef>,
    signatures: super::signature::SignatureCache,
    /// Parent table from a single snapshot; refreshed when an unknown PID
    /// shows up.
    parents: HashMap<u32, u32>,
    parents_at: Option<std::time::Instant>,
    /// Freshly resolved processes the correlator does not know yet.
    /// See [`ProcCache::take_pending`].
    pending: Vec<ProcessRef>,
}

/// Shortest time between two snapshots of the process list.
const SNAPSHOT_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// This many generations above a new process get resolved along with it.
/// Covers `correlate::CHAIN_DEPTH`: that is how far inheritance climbs.
const ANCESTORS: usize = 2;

/// More introductions pending than this means nobody is picking them up.
const MAX_PENDING: usize = 512;

impl ProcCache {
    pub fn get(&mut self, pid: u32) -> ProcessRef {
        self.resolve(pid, 0)
    }

    /// The ancestors that have been newly resolved since the last call.
    ///
    /// The correlator learns names **only** from file events. On macOS,
    /// `eslogger` delivers an `Exec` for every start, so there it knows
    /// every process. On Windows there never was such a thing: the parent
    /// table carried PIDs without names, and `correlate::is_infrastructure`
    /// — the rule that stops inheritance at `services.exe` and `svchost.exe`
    /// — could not take effect at all. On 2026-09-09 that added up to 56
    /// "svchost.exe" alerts and 46 "sshd.exe" ones: `rdpclip.exe` had read
    /// from GL once, the taint climbed up into the service root, and every
    /// service on the machine hangs off that.
    ///
    /// The caller sends these processes ahead as `Exec` events.
    pub fn take_pending(&mut self) -> Vec<ProcessRef> {
        std::mem::take(&mut self.pending)
    }

    fn resolve(&mut self, pid: u32, depth: usize) -> ProcessRef {
        if let Some(p) = self.known.get(&pid) {
            return p.clone();
        }
        let path = image_path(pid).unwrap_or_default();
        let ppid = self.parent_of(pid).filter(|&pp| pp > 4 && pp != pid);
        let r = ProcessRef {
            pid,
            ppid,
            responsible: None,
            identity: self.signatures.identity(&path),
            path: PathBuf::from(&path),
        };
        // Do not grow without bound: PIDs get reused, and a server running
        // for weeks sees hundreds of thousands of them.
        if self.known.len() > 20_000 {
            self.known.clear();
        }
        self.known.insert(pid, r.clone());
        if self.pending.len() < MAX_PENDING {
            self.pending.push(r.clone());
        }
        // The ancestors right along with it: they cost one `OpenProcess`
        // each and sit in the cache afterwards.
        if depth < ANCESTORS {
            if let Some(pp) = ppid {
                self.resolve(pp, depth + 1);
            }
        }
        r
    }

    /// A process that has exited must not pass anything on: its PID comes back.
    pub fn forget(&mut self, pid: u32) {
        self.known.remove(&pid);
        self.parents.remove(&pid);
        self.pending.retain(|p| p.pid != pid);
    }

    fn parent_of(&mut self, pid: u32) -> Option<u32> {
        let stale = self
            .parents_at
            .map(|t| t.elapsed() > SNAPSHOT_EVERY)
            .unwrap_or(true);
        if !self.parents.contains_key(&pid) && stale {
            self.parents = snapshot_parents();
            self.parents_at = Some(std::time::Instant::now());
        }
        self.parents.get(&pid).copied()
    }
}

/// Full path of the EXE. `PROCESS_QUERY_LIMITED_INFORMATION` is enough for
/// that, and it is the weakest right that yields the answer.
pub fn image_path(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 260 * 2];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_WIN32,
            windows::core::PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(h);
        if !ok || len == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// PID → PPID for all running processes, from one snapshot.
fn snapshot_parents() -> HashMap<u32, u32> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = HashMap::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut e).is_ok() {
            loop {
                out.insert(e.th32ProcessID, e.th32ParentProcessID);
                if Process32NextW(snap, &mut e).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// `\Device\HarddiskVolumeN` → `C:`, for every drive letter.
/// Once at startup; if a drive is added, restarting the sensor fixes it —
/// the service restarts it after every failure anyway.
pub fn volume_map() -> HashMap<String, String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut out = HashMap::new();
    for letter in b'A'..=b'Z' {
        let dos = format!("{}:", letter as char);
        let w: Vec<u16> = dos.encode_utf16().chain(std::iter::once(0)).collect();
        let mut buf = [0u16; 512];
        let n = unsafe { QueryDosDeviceW(PCWSTR(w.as_ptr()), Some(&mut buf)) };
        if n == 0 {
            continue;
        }
        let target = String::from_utf16_lossy(&buf[..n as usize])
            .trim_end_matches('\0')
            .to_string();
        if !target.is_empty() {
            out.insert(target, dos);
        }
    }
    out
}
