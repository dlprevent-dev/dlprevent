//! Enumerate the groups of the domain and of the server.
//!
//! Purpose: in the dashboard nobody should have to type group names in order
//! to create a rule. At a customer's site those quickly run into tens of
//! thousands, so the same applies here as with the shares — the agent knows
//! them, the central gets them, the dashboard searches in them.
//!
//! **Only send on a change.** The report goes out every 30 seconds; the group
//! list changes maybe once a week. The agent therefore forms a checksum and
//! sends the list only if it differs. That does not just save bandwidth, it
//! stops the central from rewriting the same rows around the clock.
//!
//! Rights: every domain account may **read** groups. The service account
//! needs nothing beyond the three rights it has anyway for that.

use deelpe_core::central::GroupInfo;
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetGroupEnum, NetLocalGroupEnum, GROUP_INFO_0, LOCALGROUP_INFO_0,
    MAX_PREFERRED_LENGTH,
};

#[cfg(windows)]
const NERR_SUCCESS: u32 = 0;
#[cfg(windows)]
const ERROR_MORE_DATA: u32 = 234;

#[cfg(windows)]
fn pwstr(p: windows::core::PWSTR) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = unsafe { p.to_string() }.ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Global groups of the domain plus local groups of the server.
///
/// The domain name is put in front (`CORP\\Vorstand`), so that the rule is
/// unambiguous: "Vorstand" may exist both locally and in the domain, and the
/// rule has to say which one is meant.
#[cfg(windows)]
pub fn list() -> Vec<GroupInfo> {
    let domain = std::env::var("USERDOMAIN").ok().filter(|s| !s.is_empty());
    let mut out = Vec::new();
    for name in enum_domain() {
        let full = match &domain {
            Some(d) => format!("{d}\\{name}"),
            None => name,
        };
        out.push(GroupInfo {
            name: full,
            kind: "domain".into(),
        });
    }
    for name in enum_local() {
        out.push(GroupInfo {
            name,
            kind: "local".into(),
        });
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
    out
}

/// Elsewhere there is no group table.
#[cfg(not(windows))]
pub fn list() -> Vec<GroupInfo> {
    Vec::new()
}

/// Checksum over the list; decides whether it gets sent.
pub fn digest(groups: &[GroupInfo]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for g in groups {
        h.update(g.name.as_bytes());
        h.update([0]);
        h.update(g.kind.as_bytes());
        h.update([0]);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Global groups of the domain. The call pages: with tens of thousands the
/// answer does not come in one piece.
#[cfg(windows)]
fn enum_domain() -> Vec<String> {
    let mut out = Vec::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let rc = unsafe {
            NetGroupEnum(
                PCWSTR::null(),
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                Some(&mut resume as *mut usize),
            )
        };
        if (rc != NERR_SUCCESS && rc != ERROR_MORE_DATA) || buf.is_null() {
            if rc != NERR_SUCCESS && rc != ERROR_MORE_DATA {
                tracing::debug!(rc, "NetGroupEnum: no domain groups (not a domain member?)");
            }
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf as *const _)) };
            }
            return out;
        }
        let items =
            unsafe { std::slice::from_raw_parts(buf as *const GROUP_INFO_0, read as usize) };
        out.extend(items.iter().filter_map(|i| pwstr(i.grpi0_name)));
        unsafe { NetApiBufferFree(Some(buf as *const _)) };
        if rc != ERROR_MORE_DATA {
            return out;
        }
    }
}

/// Local groups of the server — usable without a domain too.
#[cfg(windows)]
fn enum_local() -> Vec<String> {
    let mut out = Vec::new();
    let mut resume: usize = 0;
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let rc = unsafe {
            NetLocalGroupEnum(
                PCWSTR::null(),
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                Some(&mut resume as *mut usize),
            )
        };
        if (rc != NERR_SUCCESS && rc != ERROR_MORE_DATA) || buf.is_null() {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(Some(buf as *const _)) };
            }
            return out;
        }
        let items =
            unsafe { std::slice::from_raw_parts(buf as *const LOCALGROUP_INFO_0, read as usize) };
        out.extend(items.iter().filter_map(|i| pwstr(i.lgrpi0_name)));
        unsafe { NetApiBufferFree(Some(buf as *const _)) };
        if rc != ERROR_MORE_DATA {
            return out;
        }
    }
}
