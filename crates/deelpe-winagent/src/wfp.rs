//! The cage: whoever has read from a strict folder can, for a while, only
//! reach the destinations on their allowlist.
//!
//! The second half of ADR 0002. The browser asks first and gets its no at
//! the connector ([`crate::browser`]); everything else does not ask —
//! `powershell.exe`, `curl.exe`, a hand-written script. For those, a filter
//! of the Windows Filtering Platform steps in here at the ALE layer, and it
//! does so **at connect time**, that is, before a single byte flows.
//!
//! What that carries and what it does not is in ADR 0002 and is not retold
//! here. The four promises that have to be in the code:
//!
//! 1. **Dynamic session.** If the service dies, Windows closes the session
//!    and with it every filter. A DLP component that nails the network shut
//!    when it fails itself is worse than the leak.
//! 2. **Tear down existing connections.** A filter at connect time never
//!    sees a connection that is already open. Without the teardown the cage
//!    only covers what happens to start later.
//! 3. **Rolling deadline of 60 s**, a value of its own next to the
//!    reporting window of 600 s: "60 s after you stopped reading".
//! 4. **Bound to the EXE, not to the PID.** A user-mode filter only knows
//!    `ALE_APP_ID`, the image path. So every instance of the same program
//!    sits in the cage as well — for `powershell.exe` and `curl.exe` a small
//!    price, see the consequences in ADR 0002.

use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;

pub use deelpe_core::allow::{Permit, CAGE_TTL};

/// Programs that never go into the cage.
///
/// **Not the same question as [`crate::enforce::is_critical`]**, even though
/// the two overlap: there it is about who may not be killed, here about who
/// may not have the network taken away. On 2026-09-09 both were answered
/// with the same list, and that is how the start menu and the RDP clipboard
/// ended up in the cage — they are not on the kill list, but they belong in
/// the cage just as little.
///
/// Two groups:
///
/// 1. **The shell.** It reads from a protected folder as soon as somebody
///    merely looks at it — thumbnails, jump list, clipboard. Nobody
///    exfiltrates data through the start menu, but a start menu without a
///    network is a broken machine.
/// 2. **Browsers.** Per ADR 0002 they belong to the connector, not to this
///    layer: there the target URL exists and there is no race. They are
///    listed here even if they have never announced themselves on the pipe —
///    [`crate::browser::image_asks_before_sending`] only covers the ones
///    that have asked at least once.
///
/// ponytail: a list that grows. It is the short side of the bargain — the
/// alternative would be to cage only explicitly named programs, and that
/// demands a field in the rule.
const NEVER_CAGE: &[&str] = &[
    // Shell
    "explorer.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "searchapp.exe",
    "rdpclip.exe",
    "sihost.exe",
    "taskhostw.exe",
    "ctfmon.exe",
    "textinputhost.exe",
    "applicationframehost.exe",
    "dllhost.exe",
    "dwm.exe",
    "logonui.exe",
    "userinit.exe",
    "systemsettings.exe",
    // Browsers -- the connector's business, not this layer's
    "firefox.exe",
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "iexplore.exe",
];

/// May this program go into the cage at all?
///
/// Pure logic, before the first system call — the same split as with
/// [`crate::enforce::is_critical`], and for the same reason: the decision
/// has to be checkable on every platform, not only with real processes on a
/// real machine.
///
/// `name_vouched`: whether the name can be believed ([`name_is_vouched_for`]).
/// The two lists below go by name, and a name is whatever the file is called;
/// without it a tool renamed `chrome.exe` was never caged.
pub fn may_cage(pid: u32, name: &str, asks_first: bool, name_vouched: bool) -> Result<()> {
    if asks_first {
        anyhow::bail!("{name} submits its uploads for inspection; the connector decides, not the cage");
    }
    if pid <= 4 || pid == std::process::id() {
        anyhow::bail!("pid {pid} is not a process we may cage");
    }
    if name.trim().is_empty() {
        anyhow::bail!("a process we cannot name is never caged");
    }
    if !name_vouched {
        return Ok(());
    }
    let low = deelpe_core::identity::image_name(name);
    // Whoever we have to leave alive, we also have to leave the network
    // to -- an `svchost.exe` without a network is a machine without one.
    if crate::enforce::is_critical(name) {
        anyhow::bail!("{name} is a critical process and is never caged");
    }
    if NEVER_CAGE.iter().any(|n| low == *n) {
        anyhow::bail!("{name} is part of the shell or a browser and is never caged");
    }
    Ok(())
}

/// Does a name on the lists above belong to the program it claims?
///
/// Deliberately lenient — a wrong "no" takes the network from the shell or
/// a browser. Yes when the file belongs to SYSTEM, TrustedInstaller or the
/// administrators: Windows itself and whatever an installer put in place, a
/// standard user cannot create such a file. Yes for a validly signed file
/// whose original name is that name ([`signature_vouches_for`]), which covers
/// every browser installed per user (Chrome, Opera, Vivaldi, Brave). No only
/// for a file a user owns that merely carries the name — the renamed tool. Only asked when the name is on a list, and only for a process that
/// has already read a strict folder.
#[cfg(windows)]
fn name_is_vouched_for(exe: &str) -> bool {
    if privileged_owner(exe) {
        return true;
    }
    let id = deelpe_sensors::windows::signature::SignatureCache::default().identity(exe);
    signature_vouches_for(&id, short(exe))
}

/// A valid signature whose original file name (from the version resource,
/// which renaming does not change) is `name`. The publisher is not asked:
/// the lists are about not crippling the program that really is `opera.exe`,
/// whoever publishes it — and a signed tool renamed keeps its own name.
pub fn signature_vouches_for(id: &deelpe_core::identity::ProcessIdentity, name: &str) -> bool {
    use deelpe_core::identity::{image_name, ProcessIdentity};
    matches!(id, ProcessIdentity::Signed { signing_id, .. } if image_name(signing_id) == image_name(name))
}

#[cfg(not(windows))]
fn name_is_vouched_for(_exe: &str) -> bool {
    true
}

/// SYSTEM, the administrators, TrustedInstaller.
#[cfg(windows)]
const PRIVILEGED_OWNERS: &[&str] = &["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

/// Is the file owned by one of [`PRIVILEGED_OWNERS`]? An owner that cannot
/// be read counts as no: SYSTEM can read the owner of every file Windows or
/// an installer put down.
#[cfg(windows)]
fn privileged_owner(exe: &str) -> bool {
    use windows::core::{HSTRING, PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};
    let path = HSTRING::from(exe);
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe { GetNamedSecurityInfoW(PCWSTR(path.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, Some(&mut owner), None, None, None, &mut sd) };
    if rc.is_err() || owner.is_invalid() {
        return false;
    }
    let mut s = PWSTR::null();
    let sid = unsafe { ConvertSidToStringSidW(owner, &mut s) }.ok().and_then(|()| unsafe { s.to_string() }.ok());
    unsafe {
        let _ = LocalFree(Some(HLOCAL(s.0 as *mut _)));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    sid.is_some_and(|sid| PRIVILEGED_OWNERS.contains(&sid.as_str()))
}

/// Would the name alone keep this process out of the cage? Then it has to
/// be vouched for; otherwise the question does not arise.
fn exempt_by_name(name: &str) -> bool {
    let low = deelpe_core::identity::image_name(name);
    crate::enforce::is_critical(name) || NEVER_CAGE.iter().any(|n| low == *n)
}

/// Netmask from a prefix length. `/0` is 0, `/32` is everything.
fn v4_mask(bits: u8) -> u32 {
    if bits >= 32 {
        u32::MAX
    } else {
        u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0)
    }
}

/// The program name out of an image path. Both separators, as everywhere.
fn short(exe: &str) -> &str {
    exe.rsplit(['\\', '/']).next().unwrap_or(exe)
}

/// The image path of a PID. Elsewhere there is none — nothing gets caged
/// there either, and the bookkeeping about it is still testable.
#[cfg(windows)]
pub fn exe_of(pid: u32) -> Option<String> {
    deelpe_sensors::windows::procinfo::image_path(pid)
}

#[cfg(not(windows))]
pub fn exe_of(_pid: u32) -> Option<String> {
    None
}

/// A cage that is up.
struct Cage {
    /// Expires once no further touch arrives.
    until: Instant,
    /// The allowlist it was put up for. If the central changes the rule,
    /// the cage is put up anew instead of carried on.
    permits: Vec<Permit>,
    /// Filter ids that have to go again when it opens.
    filters: Vec<u64>,
}

/// All cages on this machine, one per EXE.
pub struct Cages {
    /// Image path, lower-cased → cage.
    open: HashMap<String, Cage>,
    /// Handle of the dynamic WFP session. `0` means: not open yet. As a
    /// number and not as a `HANDLE`, so that the struct may travel between
    /// Tokio tasks without an `unsafe impl Send`.
    engine: usize,
    /// The session could not be opened. Then it is not retried on every
    /// touch — the log would fill up and the error would be the same every
    /// time.
    broken: bool,
    /// Why no cage came up last time. Goes to the central, not only into
    /// the log: this component fails **open**, so nobody notices by
    /// themselves that it no longer bites — the same gap the browser
    /// connector had until 2026-09-08.
    last_error: Option<String>,
}

impl Default for Cages {
    fn default() -> Self {
        Self::new()
    }
}

impl Cages {
    pub fn new() -> Self {
        Cages { open: HashMap::new(), engine: 0, broken: false, last_error: None }
    }

    /// For the status report to the central: `None` means "it is up".
    pub fn health(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// How many cages are up. For the tests only: in production every
    /// single one is logged when it closes and when it opens.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.open.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Is a cage up for this EXE?
    pub fn holds(&self, exe: &str) -> bool {
        self.open.contains_key(&exe.to_lowercase())
    }

    /// A touch: put up a cage or renew its deadline.
    ///
    /// Same allowlist means: only the deadline moves. Only a changed list
    /// costs new filters — otherwise every file read would write a dozen
    /// filters into the machine.
    pub fn arm(&mut self, pid: u32, exe: &str, permits: &[Permit], now: Instant) {
        let key = exe.to_lowercase();
        match self.open.get_mut(&key) {
            // Already caged, same list: only the deadline moves.
            Some(c) if c.permits.as_slice() == permits => {
                c.until = now + CAGE_TTL;
                return;
            }
            // The central changed the allowlist: tear down and start over.
            Some(_) => {
                if let Some(old) = self.open.remove(&key) {
                    self.delete(&old.filters);
                }
            }
            None => {}
        }
        let filters = match self.add(exe, permits) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(exe, "network cage not armed: {e:#}");
                self.last_error = Some(format!("{}: {e:#}", short(exe)));
                return;
            }
        };
        self.last_error = None;
        // A filter at connect time never sees the connection that is
        // already open. Without this teardown the cage only covers what
        // happens to start later — and that is no corner case (ADR 0002).
        let torn = self.tear_down(pid);
        tracing::warn!(exe, pid, filters = filters.len(), permits = permits.len(), torn, "network cage armed (strict folder)");
        self.open.insert(key, Cage { until: now + CAGE_TTL, permits: permits.to_vec(), filters });
    }

    /// A fresh touch: cage the process if it qualifies.
    ///
    /// Two groups stay outside, and both for the same reason as with the
    /// kill: whoever we have to leave alive, we also have to leave the
    /// network to — an `svchost.exe` without a network is a machine without
    /// one. And whoever submits their uploads anyway (browser connector)
    /// needs no cage: their no comes earlier and lands more precisely.
    pub fn on_touch(&mut self, pid: u32, allow: &[String], now: Instant) {
        // ponytail: one `OpenProcess` per touched file. Touches are rare
        // compared to events, and consecutive identical ones already drop
        // out in the correlator. Should this ever get hot, a pid → image
        // path cache belongs here, like in `procinfo::ProcCache`.
        let Some(exe) = exe_of(pid) else { return };
        let name = short(&exe).to_string();
        // Does this **program** ask first? Not this PID: on 2026-09-09
        // `firefox.exe` was caged and lost seven connections because the new
        // PID had not announced itself yet.
        let asks = crate::browser::image_asks_before_sending(&exe);
        let vouched = !exempt_by_name(&name) || name_is_vouched_for(&exe);
        if !vouched {
            tracing::warn!(pid, exe = %exe, "{name} carries a protected name but belongs to a user and is unsigned; caged like any other program");
        }
        if let Err(e) = may_cage(pid, &name, asks, vouched) {
            tracing::debug!(pid, "no network cage: {e}");
            return;
        }
        // Our own house always stands open: what gets blocked is what goes
        // out. See `deelpe_core::allow::cage_permits`.
        let (permits, skipped) = deelpe_core::allow::cage_permits(allow);
        // Once per cage, not per file read.
        if !skipped.is_empty() && !self.holds(&exe) {
            tracing::info!(exe = %name, "allowlist names hold at the browser connector, not here: {}", skipped.join(", "));
        }
        self.arm(pid, &exe, &permits, now);
    }

    /// Open the cages that have expired. Belongs on a tick, not on an
    /// event: whoever stops reading also stops producing events — and would
    /// otherwise stay caged forever.
    pub fn expire(&mut self, now: Instant) {
        let done: Vec<String> = self.open.iter().filter(|(_, c)| c.until <= now).map(|(k, _)| k.clone()).collect();
        for key in done {
            if let Some(c) = self.open.remove(&key) {
                self.delete(&c.filters);
                tracing::info!(exe = %key, "network cage opened again (no touch for {}s)", CAGE_TTL.as_secs());
            }
        }
    }

    /// Open every cage. Part of the orderly stop of the service: the
    /// dynamic session does clean up by itself, but only once the process is
    /// really gone.
    pub fn release_all(&mut self) {
        for (_, c) in std::mem::take(&mut self.open) {
            self.delete(&c.filters);
        }
    }
}

// ---------------------------------------------------------------------------
// Windows: the filters themselves
// ---------------------------------------------------------------------------

#[cfg(windows)]
impl Cages {
    /// Open the session, once. `FWPM_SESSION_FLAG_DYNAMIC` is the fail-open
    /// promise: handle closed, filters gone.
    fn engine(&mut self) -> Result<windows::Win32::Foundation::HANDLE> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{FwpmEngineOpen0, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC};

        if self.engine != 0 {
            return Ok(HANDLE(self.engine as *mut std::ffi::c_void));
        }
        if self.broken {
            anyhow::bail!("the filtering engine could not be opened earlier");
        }
        let session = FWPM_SESSION0 { flags: FWPM_SESSION_FLAG_DYNAMIC, ..Default::default() };
        let mut h = HANDLE::default();
        // 10 is `RPC_C_AUTHN_WINNT`, the authentication that the example in
        // the documentation uses locally.
        let rc = unsafe { FwpmEngineOpen0(None, 10, None, Some(&session), &mut h) };
        if rc != 0 {
            self.broken = true;
            anyhow::bail!("FwpmEngineOpen0: 0x{rc:08x}");
        }
        self.engine = h.0 as usize;
        tracing::info!("filtering engine open (dynamic session: the cage opens by itself if the service dies)");
        Ok(h)
    }

    /// One block filter and one permit filter per allowlist entry, for IPv4
    /// and IPv6. Within the same sublayer the higher weight wins — which is
    /// why the block sits at 0 and every permit above it.
    fn add(&mut self, exe: &str, permits: &[Permit]) -> Result<Vec<u64>> {
        use windows::core::HSTRING;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
            FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWP_BYTE_BLOB,
        };

        let engine = self.engine()?;
        let file = HSTRING::from(exe);
        let mut app: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let rc = unsafe { FwpmGetAppIdFromFileName0(&file, &mut app) };
        if rc != 0 || app.is_null() {
            anyhow::bail!("FwpmGetAppIdFromFileName0({exe}): 0x{rc:08x}");
        }
        let mut ids = Vec::new();
        let mut err = None;
        for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
            let v4 = layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            match win::block_all(engine, layer, app, exe) {
                Ok(id) => ids.push(id),
                Err(e) => err = Some(e),
            }
            for p in permits.iter().filter(|p| p.net.is_ipv4() == v4) {
                match win::permit(engine, layer, app, exe, p) {
                    Ok(id) => ids.push(id),
                    Err(e) => err = Some(e),
                }
            }
        }
        unsafe { FwpmFreeMemory0(&mut (app as *mut std::ffi::c_void)) };
        // A half-built block is worse than none: it blocks without knowing
        // the permits. Then rather go all the way back.
        if let Some(e) = err {
            self.delete(&ids);
            return Err(e);
        }
        Ok(ids)
    }

    fn delete(&self, ids: &[u64]) {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteById0;
        if self.engine == 0 {
            return;
        }
        let engine = HANDLE(self.engine as *mut std::ffi::c_void);
        for id in ids {
            let rc = unsafe { FwpmFilterDeleteById0(engine, *id) };
            if rc != 0 {
                tracing::debug!(id, "FwpmFilterDeleteById0: 0x{rc:08x}");
            }
        }
    }

    fn tear_down(&self, pid: u32) -> usize {
        win::kill_tcp_of(pid)
    }
}

#[cfg(windows)]
mod win {
    use super::{v4_mask, Permit};
    use anyhow::Result;
    use windows::core::{GUID, HSTRING, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    /// Weight of the block. Everything that is let through weighs more.
    const W_BLOCK: u8 = 0;
    const W_PERMIT: u8 = 8;

    fn app_cond(app: *mut FWP_BYTE_BLOB) -> FWPM_FILTER_CONDITION0 {
        let mut c = FWPM_FILTER_CONDITION0::default();
        c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
        c.conditionValue.Anonymous.byteBlob = app;
        c
    }

    /// Add a filter. The conditions point at the caller's memory and have
    /// to outlive the call — which is why the function takes them as a slice
    /// and allocates nothing itself.
    fn add(engine: HANDLE, layer: GUID, name: &HSTRING, weight: u8, action: FWP_ACTION_TYPE, conds: &mut [FWPM_FILTER_CONDITION0]) -> Result<u64> {
        let mut f = FWPM_FILTER0::default();
        f.displayData.name = PWSTR(name.as_ptr() as *mut u16);
        f.layerKey = layer;
        f.subLayerKey = FWPM_SUBLAYER_UNIVERSAL;
        f.weight.r#type = FWP_UINT8;
        f.weight.Anonymous.uint8 = weight;
        f.action.r#type = action;
        f.numFilterConditions = conds.len() as u32;
        f.filterCondition = conds.as_mut_ptr();
        let mut id = 0u64;
        let rc = unsafe { FwpmFilterAdd0(engine, &f, None, Some(&mut id)) };
        if rc != 0 {
            anyhow::bail!("FwpmFilterAdd0: 0x{rc:08x}");
        }
        Ok(id)
    }

    pub fn block_all(engine: HANDLE, layer: GUID, app: *mut FWP_BYTE_BLOB, exe: &str) -> Result<u64> {
        let name = HSTRING::from(format!("DLPrevent: {exe} may not leave the strict folder"));
        let mut conds = [app_cond(app)];
        add(engine, layer, &name, W_BLOCK, FWP_ACTION_BLOCK, &mut conds)
    }

    pub fn permit(engine: HANDLE, layer: GUID, app: *mut FWP_BYTE_BLOB, exe: &str, p: &Permit) -> Result<u64> {
        let name = HSTRING::from(format!("DLPrevent: {exe} may reach {}/{}", p.net, p.bits));
        // These two live until the end of the function and thus beyond the
        // call — the condition points at them.
        let mut v4 = FWP_V4_ADDR_AND_MASK::default();
        let mut v6 = FWP_V6_ADDR_AND_MASK::default();
        let mut conds = Vec::with_capacity(3);
        conds.push(app_cond(app));

        let mut c = FWPM_FILTER_CONDITION0::default();
        c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        c.matchType = FWP_MATCH_EQUAL;
        match p.net {
            std::net::IpAddr::V4(a) => {
                v4.addr = u32::from(a);
                v4.mask = v4_mask(p.bits);
                c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                c.conditionValue.Anonymous.v4AddrMask = &mut v4;
            }
            std::net::IpAddr::V6(a) => {
                v6.addr = a.octets();
                v6.prefixLength = p.bits;
                c.conditionValue.r#type = FWP_V6_ADDR_MASK;
                c.conditionValue.Anonymous.v6AddrMask = &mut v6;
            }
        }
        conds.push(c);

        if let Some(port) = p.port {
            let mut c = FWPM_FILTER_CONDITION0::default();
            c.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.r#type = FWP_UINT16;
            c.conditionValue.Anonymous.uint16 = port;
            conds.push(c);
        }
        add(engine, layer, &name, W_PERMIT, FWP_ACTION_PERMIT, &mut conds)
    }

    /// Tear down this process's open TCP connections.
    ///
    /// Returns the number that were torn down.
    ///
    /// ponytail: IPv4 only. `SetTcpEntry` has no IPv6 counterpart in user
    /// mode; whoever needs that needs a callout driver — and with it the EV
    /// certificate from ADR 0001. New connect attempts are blocked across
    /// both families; what stays open is only an **already established**
    /// IPv6 connection.
    pub fn kill_tcp_of(pid: u32) -> usize {
        use windows::Win32::NetworkManagement::IpHelper::{
            GetExtendedTcpTable, SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
            MIB_TCP_STATE_DELETE_TCB, TCP_TABLE_OWNER_PID_ALL,
        };
        const AF_INET: u32 = 2;

        let mut size = 0u32;
        unsafe { GetExtendedTcpTable(None, &mut size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) };
        if size == 0 {
            return 0;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = unsafe { GetExtendedTcpTable(Some(buf.as_mut_ptr().cast()), &mut size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) };
        if rc != 0 {
            tracing::debug!("GetExtendedTcpTable: 0x{rc:08x}");
            return 0;
        }
        let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let n = unsafe { (*table).dwNumEntries } as usize;
        let rows = unsafe { std::ptr::addr_of!((*table).table) } as *const MIB_TCPROW_OWNER_PID;
        let mut torn = 0;
        for i in 0..n {
            let r = unsafe { *rows.add(i) };
            if r.dwOwningPid != pid {
                continue;
            }
            let row = MIB_TCPROW_LH {
                Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB },
                dwLocalAddr: r.dwLocalAddr,
                dwLocalPort: r.dwLocalPort,
                dwRemoteAddr: r.dwRemoteAddr,
                dwRemotePort: r.dwRemotePort,
            };
            if unsafe { SetTcpEntry(&row) } == 0 {
                torn += 1;
            }
        }
        torn
    }
}

// ---------------------------------------------------------------------------
// Elsewhere: the cage is a Windows thing, the bookkeeping is not
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
impl Cages {
    fn add(&mut self, _exe: &str, _permits: &[Permit]) -> Result<Vec<u64>> {
        Ok(Vec::new())
    }
    fn delete(&self, _ids: &[u64]) {}
    fn tear_down(&self, _pid: u32) -> usize {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn p(s: &str) -> Permit {
        let (net, bits, port) = deelpe_core::allow::as_net(s).unwrap();
        Permit { net, bits, port }
    }

    /// The same `.mui` suffix as with [`crate::enforce::is_critical`]: the
    /// cage carries a list of its own, and that one compared just as
    /// exactly.
    #[test]
    fn a_windows_resource_name_is_not_caged_either() {
        assert!(may_cage(4242, "EXPLORER.EXE.MUI", false, true).is_err());
        assert!(may_cage(4242, "rdpclip.exe.mui", false, true).is_err());
        assert!(may_cage(4242, "FIREFOX.EXE.MUI", false, true).is_err());
        assert!(may_cage(4242, "curl.exe.mui", false, true).is_ok());
    }

    /// The exemptions go by name, and a name is whatever the file is called:
    /// an exfiltration tool renamed to `chrome.exe` or `explorer.exe` was
    /// never caged — the same effect as pentest 8840/0003. A name counts only
    /// when something vouches for it (the file belongs to the system or an
    /// installer, or it carries the browser vendor's signature); otherwise
    /// the process is caged like any other.
    #[test]
    fn a_protected_name_nobody_vouches_for_protects_nothing() {
        for renamed in ["chrome.exe", "msedge.exe", "explorer.exe", "svchost.exe", "EXPLORER.EXE.MUI"] {
            assert!(may_cage(1234, renamed, false, false).is_ok(), "{renamed}");
            assert!(may_cage(1234, renamed, false, true).is_err(), "{renamed}, vouched for");
        }
        // What does not rest on the name stays as it was.
        assert!(may_cage(4, "chrome.exe", false, false).is_err(), "the kernel is never caged");
        assert!(may_cage(std::process::id(), "x.exe", false, false).is_err(), "nor the agent itself");
        assert!(may_cage(4242, "", false, false).is_err(), "nor what we cannot name");
        assert!(may_cage(1234, "chrome.exe", true, false).is_err(), "a browser that asked is judged by the connector");
    }

    /// Review 2026-09-30: Opera and Vivaldi install per user, and so does
    /// Brave without elevation — owned by the user, signed by their vendor.
    /// Checking against the three connector browsers caged them. Any valid
    /// signature whose original file name is the protected name vouches;
    /// a renamed tool keeps its own original name, or has none.
    #[test]
    fn a_signature_under_the_same_name_vouches_for_it() {
        use deelpe_core::identity::ProcessIdentity;
        let signed = |p: &str, n: &str| ProcessIdentity::Signed { team_id: p.into(), signing_id: n.into() };
        assert!(signature_vouches_for(&signed("Opera Norway AS", "opera.exe"), "opera.exe"));
        assert!(signature_vouches_for(&signed("Vivaldi Technologies AS", "vivaldi.exe"), "Vivaldi.exe"));
        assert!(signature_vouches_for(&signed("Brave Software, Inc.", "brave.exe"), "brave.exe"));
        assert!(signature_vouches_for(&signed("Microsoft Corporation", "EXPLORER.EXE.MUI"), "explorer.exe"));
        assert!(!signature_vouches_for(&signed("Microsoft Corporation", "curl.exe"), "chrome.exe"), "a signed tool renamed");
        assert!(!signature_vouches_for(&ProcessIdentity::Unknown { path: "chrome.exe".into() }, "chrome.exe"), "unsigned");
    }

    /// Whoever cages the shell takes the machine's operability away without
    /// preventing anything. Happened in the lab on 2026-09-09.
    #[test]
    fn the_shell_and_the_browsers_never_go_into_the_cage() {
        for shell in ["StartMenuExperienceHost.exe", "rdpclip.exe", "explorer.exe", "dllhost.exe", "sihost.exe"] {
            assert!(may_cage(1234, shell, false, true).is_err(), "{shell}");
        }
        // Browsers belong to the connector -- even if they have never
        // announced themselves here.
        for browser in ["firefox.exe", "chrome.exe", "msedge.exe"] {
            assert!(may_cage(1234, browser, false, true).is_err(), "{browser}");
        }
        // Critical services inherit the exception from `is_critical`.
        assert!(may_cage(1234, "svchost.exe", false, true).is_err());
        assert!(may_cage(1234, "sshd.exe", false, true).is_err());
        // 0 and 4 are idle and system, 1..=4 belong to the kernel.
        for pid in [0, 1, 2, 3, 4] {
            assert!(may_cage(pid, "irgendwas.exe", false, true).is_err(), "pid {pid}");
        }
        assert!(may_cage(std::process::id(), "curl.exe", false, true).is_err(), "sich selbst sperrt der Agent nie ein");
        assert!(may_cage(4242, "", false, true).is_err(), "wen wir nicht benennen koennen, sperren wir nicht ein");
        // And the ones the cage is built for.
        assert!(may_cage(1234, "powershell.exe", false, true).is_ok());
        assert!(may_cage(1234, "curl.exe", false, true).is_ok());
        // Whoever asks first does not need it.
        assert!(may_cage(1234, "curl.exe", true, true).is_err());
    }

    #[test]
    fn prefix_lengths_become_masks() {
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(8), 0xff00_0000);
        assert_eq!(v4_mask(24), 0xffff_ff00);
        assert_eq!(v4_mask(32), u32::MAX);
    }

    /// The deadline rolls: every further touch pushes it ahead. Whoever
    /// stops reading gets out 60 s later.
    #[test]
    fn the_deadline_rolls_and_then_the_cage_opens() {
        let mut c = Cages::new();
        let t0 = Instant::now();
        let ps = vec![p("10.0.0.0/8")];
        c.arm(1234, r"C:\Windows\System32\curl.exe", &ps, t0);
        assert!(c.holds(r"c:\windows\system32\CURL.EXE"), "der Bildpfad zaehlt ohne Gross- und Kleinschreibung");

        // Touched again shortly before it expires: the deadline moves along.
        c.arm(1234, r"C:\Windows\System32\curl.exe", &ps, t0 + Duration::from_secs(59));
        c.expire(t0 + Duration::from_secs(90));
        assert_eq!(c.len(), 1, "60 s nach der *letzten* Beruehrung, nicht nach der ersten");

        c.expire(t0 + Duration::from_secs(120));
        assert!(c.is_empty());
    }

    /// A changed allowlist puts the cage up anew, an unchanged one does not.
    #[test]
    fn a_changed_allowlist_rebuilds_the_cage() {
        let mut c = Cages::new();
        let t0 = Instant::now();
        c.arm(1, "curl.exe", &[p("10.0.0.0/8")], t0);
        c.arm(1, "curl.exe", &[p("10.0.0.0/8")], t0 + Duration::from_secs(1));
        assert_eq!(c.len(), 1);
        c.arm(1, "curl.exe", &[p("10.0.0.0/8"), p("192.168.0.0/16")], t0 + Duration::from_secs(2));
        assert_eq!(c.len(), 1);
        assert_eq!(c.open["curl.exe"].permits.len(), 2);
    }

    #[test]
    fn release_all_opens_every_cage() {
        let mut c = Cages::new();
        let t0 = Instant::now();
        c.arm(1, "curl.exe", &[], t0);
        c.arm(2, "powershell.exe", &[], t0);
        assert_eq!(c.len(), 2);
        c.release_all();
        assert!(c.is_empty());
    }
}
