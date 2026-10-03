//! Credentials and state on disk. Counterpart to `central.rs` in the Mac
//! service: 0600 there, here a DACL that only admits administrators and
//! SYSTEM — the agent's private key lies in it.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use deelpe_core::access::AccessMeter;
use deelpe_core::net::Credentials;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DIR: &str = r"C:\ProgramData\deelpe";
pub const CONFIG_PATH: &str = r"C:\ProgramData\deelpe\central.json";
pub const STATE_PATH: &str = r"C:\ProgramData\deelpe\state.json";
pub const LOG_PATH: &str = r"C:\ProgramData\deelpe\agent.log";

/// Only administrators (BA), SYSTEM (SY) — and the account the agent runs
/// under. Inheritance switched off (P).
///
/// Our own account has to be in there ever since the service runs under a
/// dedicated account instead of LocalSystem: otherwise the agent locks its
/// own credentials and its own state away from itself, and the read cursor
/// no longer survives a restart.
const SDDL_PRIVATE_BASE: &str = "D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CentralConfig {
    pub url: String,
    pub agent_id: String,
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    #[serde(default)]
    pub enrolled_at: Option<DateTime<Utc>>,
    /// The role this agent was enrolled in. Missing on installations from
    /// before endpoint operation — those are file servers.
    #[serde(default)]
    pub kind: Option<deelpe_core::central::AgentKind>,
}

impl CentralConfig {
    pub fn from_credentials(c: Credentials, kind: deelpe_core::central::AgentKind) -> Self {
        Self {
            url: c.url,
            agent_id: c.agent_id,
            ca_pem: c.ca_pem,
            cert_pem: c.cert_pem,
            key_pem: c.key_pem,
            enrolled_at: Some(Utc::now()),
            kind: Some(kind),
        }
    }

    /// File server, as long as nothing else is written there.
    pub fn kind(&self) -> deelpe_core::central::AgentKind {
        self.kind
            .unwrap_or(deelpe_core::central::AgentKind::WindowsServer)
    }

    pub fn credentials(&self) -> Credentials {
        Credentials {
            url: self.url.clone(),
            agent_id: self.agent_id.clone(),
            ca_pem: self.ca_pem.clone(),
            cert_pem: self.cert_pem.clone(),
            key_pem: self.key_pem.clone(),
        }
    }

    pub fn load() -> Result<Option<Self>> {
        match std::fs::read_to_string(CONFIG_PATH) {
            Ok(raw) => Ok(Some(
                serde_json::from_str(&raw).with_context(|| format!("{CONFIG_PATH} unreadable"))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        write_private(
            Path::new(CONFIG_PATH),
            serde_json::to_string_pretty(self)?.as_bytes(),
        )
    }
}

/// What the agent has to keep across restarts. The meter is in there too, so
/// that window and baseline survive a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub generation: i64,
    /// Highest EventRecordID of the security log already processed.
    pub last_record_id: u64,
    /// Report counters and the last error. `flatten`: on disk the four keys
    /// stay on the same level as before.
    #[serde(flatten)]
    pub tally: deelpe_core::session::Tally,
    /// Access meter per rule id.
    #[serde(default)]
    pub meters: std::collections::HashMap<String, AccessMeter>,
    /// Rule folders for which policy and SACL have already been set.
    #[serde(default)]
    pub prepared: Vec<String>,
    /// Endpoint operation: learning phase, open alerts of the correlator and
    /// the next alert number. Only filled in if the agent was enrolled as an
    /// endpoint.
    #[serde(default)]
    pub learner: Option<deelpe_core::learn::Learner>,
    #[serde(default)]
    pub pending_endpoint_alerts: Vec<deelpe_core::correlate::Alert>,
    #[serde(default)]
    pub next_alert_id: u64,
    /// The alerts most recently reported, so that a learning instruction
    /// from the central still finds its pair. An instruction inevitably comes
    /// **after** the report — whoever clicks in the dashboard is already
    /// looking at the alert —, and `pending_endpoint_alerts` has long been
    /// emptied by then. The Mac service has its alert log for this; this here
    /// is the counterpart, only trimmed.
    #[serde(default)]
    pub reported_endpoint_alerts: Vec<deelpe_core::correlate::Alert>,
    /// Learning instructions carried out that the central has not ticked off
    /// yet. Without this it sends the same one again in every report.
    #[serde(default)]
    pub learn_done: Vec<i64>,
    /// What no central has accepted yet. Without this a restart during an
    /// outage costs exactly the accesses that happened during the outage.
    #[serde(default)]
    pub pending_counts: Vec<deelpe_core::central::CountBucket>,
    #[serde(default)]
    pub pending_alerts: Vec<deelpe_core::central::AccessAlert>,
    /// Share name (lower-cased) → local path, learned from 5145. Fills the
    /// gap when the service account may not read the share table.
    #[serde(default)]
    pub share_paths: std::collections::HashMap<String, String>,
    /// Checksum of the group list most recently reported. Only when it
    /// changes does the list go out again.
    #[serde(default)]
    pub groups_digest: String,
    /// The rule version most recently taken over from the central. Without
    /// it the endpoint protects **nothing** after a restart as long as the
    /// central does not answer: sensor without folders, no cage, empty driver
    /// policy, and the browser connector lets every upload through (lab
    /// 2026-09-09). The Mac service has always kept its configuration in
    /// `/etc/deelpe/config.json`; this here is the counterpart.
    #[serde(default)]
    pub central_config: Option<deelpe_core::central::AgentConfig>,
}

impl Default for AgentState {
    fn default() -> Self {
        Self {
            generation: 0,
            last_record_id: 0,
            tally: Default::default(),
            meters: Default::default(),
            prepared: Vec::new(),
            learner: None,
            pending_endpoint_alerts: Vec::new(),
            next_alert_id: 1,
            reported_endpoint_alerts: Vec::new(),
            learn_done: Vec::new(),
            pending_counts: Vec::new(),
            pending_alerts: Vec::new(),
            share_paths: Default::default(),
            groups_digest: String::new(),
            central_config: None,
        }
    }
}

impl AgentState {
    pub fn load() -> Self {
        std::fs::read_to_string(STATE_PATH)
            .ok()
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) -> Result<()> {
        write_private(
            Path::new(STATE_PATH),
            serde_json::to_string(self)?.as_bytes(),
        )
    }
}

/// Fresh credentials belong in the same file as the old ones.
///
/// First on disk, then in memory: if the write fails, the version in memory
/// stays the old one — otherwise the agent would carry a certificate that
/// does not survive a restart.
impl deelpe_core::session::CredentialStore for CentralConfig {
    fn store(&mut self, fresh: &deelpe_core::net::Credentials) -> Result<()> {
        let mut next = self.clone();
        next.cert_pem = fresh.cert_pem.clone();
        next.key_pem = fresh.key_pem.clone();
        next.save()?;
        *self = next;
        Ok(())
    }
}

pub fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// The 8.3 short name of a folder — `C:\Freigaben\GL` → `C:\FREIG~1\GL`.
///
/// Both spellings are real directory entries on NTFS, and both event tracing
/// on the workstation and the security log on the file server report
/// whichever one was opened. A rule written with the long name would
/// otherwise miss a read through the short one, and no amount of string
/// normalising can undo that — `FREIG~1` cannot be turned back into
/// `Freigaben` without asking the file system. So it is asked once per
/// ruleset, never per event.
///
/// `None` when the folder is not there, when the volume carries no short
/// names (`fsutil 8dot3name`, and a good idea on a file server) or when
/// nothing about the path shortens. The buffer is generous on purpose: a
/// short name is never longer than the long one, so whatever does not fit in
/// it is not an answer worth having.
#[cfg(windows)]
pub fn short_name(path: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::GetShortPathNameW;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = [0u16; 1024];
    let n = unsafe { GetShortPathNameW(PCWSTR(wide.as_ptr()), Some(&mut buf)) };
    if n == 0 || n as usize > buf.len() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&buf[..n as usize])))
}

/// On the machine the agent is built on there is no such thing. The halves
/// that decide are pure and get tested here anyway
/// (`deelpe_core::config::add_path_aliases`, `agent::add_rule_aliases`).
#[cfg(not(windows))]
pub fn short_name(_: &Path) -> Option<PathBuf> {
    None
}

/// The fully qualified name of the machine, e.g. `fs-01.corp.example`.
///
/// Not assembled from `COMPUTERNAME` + `USERDNSDOMAIN`: the second variable
/// carries the domain of the logged-on **user**, and the service runs as
/// `LocalSystem`. The operating system is what gets asked.
///
/// Empty text if the machine carries none (not in a domain) or the call
/// fails — the short name is untouched by that, and an empty field is more
/// honest than a guessed name.
#[cfg(windows)]
pub fn fqdn() -> String {
    use windows::core::PWSTR;
    use windows::Win32::System::SystemInformation::{
        ComputerNameDnsFullyQualified, GetComputerNameExW,
    };
    let mut n = 0u32;
    // First call without a buffer: it fails as expected with
    // `ERROR_MORE_DATA` and sets the required length while doing so.
    unsafe {
        let _ = GetComputerNameExW(ComputerNameDnsFullyQualified, None, &mut n);
    }
    if n == 0 {
        return String::new();
    }
    let mut buf = vec![0u16; n as usize];
    // After the second call `n` is the length **without** the trailing NUL.
    if unsafe {
        GetComputerNameExW(
            ComputerNameDnsFullyQualified,
            Some(PWSTR(buf.as_mut_ptr())),
            &mut n,
        )
    }
    .is_err()
    {
        return String::new();
    }
    let name = String::from_utf16_lossy(&buf[..(n as usize).min(buf.len())]);
    // Without a domain Windows returns the bare machine name here. That one
    // is already in `hostname` — reporting it a second time would mean
    // claiming a qualified name that does not exist.
    if name.eq_ignore_ascii_case(&hostname()) {
        return String::new();
    }
    name
}

/// Elsewhere the machine carries no name that this service reports.
#[cfg(not(windows))]
pub fn fqdn() -> String {
    String::new()
}

/// Write atomically and set the DACL afterwards.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    std::fs::create_dir_all(DIR)?;
    let tmp: PathBuf = path.with_extension("tmp");
    // A file left behind from an aborted write still carries the old,
    // protected access list — after a change of the service account it is
    // then unwritable for the agent, and saving fails forever. So away with
    // it first; the agent may do that through its right on the folder, even
    // without a right on the file.
    let _ = std::fs::remove_file(&tmp);
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    restrict(&tmp)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// SID of the account this process runs under.
#[cfg(windows)]
pub(crate) fn own_sid() -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            len,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        if !ok {
            return None;
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut out = windows::core::PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut out).ok()?;
        let s = out.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(out.0 as *mut _)));
        s
    }
}

/// Elsewhere there is no account SID; the access list stays the base one.
#[cfg(not(windows))]
pub(crate) fn own_sid() -> Option<String> {
    None
}

/// Access list for the private files, extended by our own account.
fn sddl_private() -> String {
    match own_sid() {
        // LocalSystem and the administrators are already in there.
        Some(sid) if sid != "S-1-5-18" => format!("{SDDL_PRIVATE_BASE}(A;OICI;FA;;;{sid})"),
        _ => SDDL_PRIVATE_BASE.to_string(),
    }
}

/// Limit the DACL to administrators, SYSTEM and our own account, switch
/// inheritance off.
#[cfg(windows)]
fn restrict(path: &Path) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };

    let sddl = HSTRING::from(sddl_private());
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .context("SDDL of the credentials file")?;
    }
    let p = HSTRING::from(path.as_os_str());
    let r = unsafe {
        SetFileSecurityW(
            PCWSTR(p.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            psd,
        )
    };
    unsafe {
        let _ =
            windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(psd.0)));
    }
    r.ok()
        .with_context(|| format!("set permissions on {}", path.display()))?;
    Ok(())
}

/// Elsewhere there is no DACL. The file comes into being with the user's
/// permissions — only tests run here, no agent's credentials.
#[cfg(not(windows))]
fn restrict(_path: &Path) -> Result<()> {
    Ok(())
}

/// A service has no console. Everything into the file next to the state —
/// and into the ring from which the reports supply the central.
pub fn init_file_logging() {
    deelpe_core::agentlog::init(Some(Path::new(LOG_PATH)), false);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `state.json` from before this version has to stay readable:
    /// `AgentState::load` discards an unreadable file **silently**, so an
    /// error here would cost the read cursor, the learning phase and open
    /// alerts. And the rule version has to survive the detour over the disk —
    /// otherwise the restart protects nothing again.
    #[test]
    fn state_keeps_the_central_config_and_reads_older_files() {
        let old = r#"{"generation":3,"last_record_id":42,"ok":0,"failed":0}"#;
        let st: AgentState = serde_json::from_str(old).expect("older state.json");
        assert_eq!(st.generation, 3);
        assert!(st.central_config.is_none());

        let mut st = st;
        st.central_config = Some(deelpe_core::central::AgentConfig {
            api_version: 1,
            generation: 3,
            report_interval_secs: 60,
            learn_days: 14,
            rules: Vec::new(),
            allow_processes: Vec::new(),
            update_to_sha256: None,
            finish_learning: false,
            chrome_enrollment_token: None,
            edge_enrollment_token: None,
        });
        let back: AgentState = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
        let c = back.central_config.expect("rules survive a restart");
        assert_eq!((c.generation, c.learn_days), (3, 14));
    }
}
