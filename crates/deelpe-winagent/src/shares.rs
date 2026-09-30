//! Read out the file server's shares, so that somebody in the dashboard can
//! create a rule without sitting down at the server.
//!
//! **A question of rights.** `NetShareEnum` only returns the local path of a
//! share from level 2 on, and that one demands administrator rights. Which is
//! exactly what the service account is not supposed to have. Hence two steps:
//!
//! 1. Try level 2. If it works (admin or explicitly allowed), name **and**
//!    path are there.
//! 2. Otherwise level 1 — name and description, readable for every account.
//!    The agent learns the path from `ShareLocalPath` in the 5145 events, as
//!    soon as somebody uses the share.
//!
//! That keeps the account small, and the dashboard still shows every share —
//! with the path it then says where it came from.

use deelpe_core::central::ShareInfo;
use std::collections::HashMap;
#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::NetworkManagement::NetManagement::NetApiBufferFree;
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    NetShareEnum, SHARE_INFO_1, SHARE_INFO_2, STYPE_DISKTREE, STYPE_MASK,
};

/// `STYPE_SPECIAL`: `C$`, `ADMIN$`, `IPC$` — administrative shares that
/// nobody means as a rule.
const STYPE_SPECIAL: u32 = 0x8000_0000;
/// `STYPE_MASK` and `STYPE_DISKTREE` from `lmshare.h`, as bare numbers: the
/// verdict on what an ordinary share is should be checkable on every
/// platform and not only where the windows crate compiles. That the numbers
/// are right is checked by the target build one line further down.
const STYPE_MASK_BITS: u32 = 0x0000_00FF;
const STYPE_DISKTREE_BITS: u32 = 0;

#[cfg(windows)]
const _: () = {
    assert!(STYPE_MASK_BITS == STYPE_MASK.0);
    assert!(STYPE_DISKTREE_BITS == STYPE_DISKTREE.0);
};

#[cfg(windows)]
const ERROR_ACCESS_DENIED: u32 = 5;
#[cfg(windows)]
const NERR_SUCCESS: u32 = 0;

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

fn is_ordinary(share_type: u32) -> bool {
    share_type & STYPE_SPECIAL == 0 && (share_type & STYPE_MASK_BITS) == STYPE_DISKTREE_BITS
}

/// Reads the shares. `learned` are paths the agent knows from the 5145
/// events.
///
/// Measured on the real machine (2026-09-06, Server 2025 as a domain
/// controller): level 2 returned names and paths to the service account
/// **without** admin rights as well. The documentation demands admin rights
/// for level 2; so there is no relying on it in either direction. Hence the
/// union: whatever the enumeration gives, plus whatever was learned from the
/// 5145 events. The latter costs not a single extra right and carries even
/// where the enumeration stays silent.
#[cfg(windows)]
pub fn list(learned: &HashMap<String, String>) -> Vec<ShareInfo> {
    let enumerated = match enum_level2() {
        Some(v) => v,
        None => enum_level1(),
    };
    merge(enumerated, learned)
}

/// Elsewhere there is no share table. What was learned from the 5145 events
/// still applies — otherwise no test would check the union.
#[cfg(not(windows))]
pub fn list(learned: &HashMap<String, String>) -> Vec<ShareInfo> {
    merge(Vec::new(), learned)
}

/// Unite what the enumeration gave with what the agent has learned from the
/// 5145 events. Pure logic, before any system call — the same split as with
/// [`crate::wfp::may_cage`].
fn merge(mut out: Vec<ShareInfo>, learned: &HashMap<String, String>) -> Vec<ShareInfo> {
    // Add paths to shares we already know …
    for s in out.iter_mut() {
        if s.path.is_none() {
            if let Some(p) = learned.get(&s.name.to_lowercase()) {
                s.path = Some(p.clone());
                s.path_from = Some("events".into());
            }
        }
    }
    // … and take in shares the enumeration did not give at all.
    for (name, path) in learned {
        if !out.iter().any(|s| s.name.eq_ignore_ascii_case(name)) {
            out.push(ShareInfo {
                name: name.clone(),
                path: Some(path.clone()),
                remark: None,
                path_from: Some("events".into()),
            });
        }
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out
}

/// Level 2: with the local path, needs admin rights. `None` means "not
/// allowed" — that is the normal case with a small service account and not an
/// error anybody should trip over.
#[cfg(windows)]
fn enum_level2() -> Option<Vec<ShareInfo>> {
    let mut buf: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    let rc = unsafe {
        NetShareEnum(
            PCWSTR::null(),
            2,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            None,
        )
    };
    if rc != NERR_SUCCESS || buf.is_null() {
        if rc == ERROR_ACCESS_DENIED {
            tracing::debug!("share table with path not readable (level 2 needs admin rights), falling back to level 1");
        } else if rc != ERROR_ACCESS_DENIED {
            tracing::debug!(rc, "NetShareEnum level 2 failed");
        }
        if !buf.is_null() {
            unsafe { NetApiBufferFree(Some(buf as *const _)) };
        }
        return None;
    }
    let items = unsafe { std::slice::from_raw_parts(buf as *const SHARE_INFO_2, read as usize) };
    let out = items
        .iter()
        .filter(|i| is_ordinary(i.shi2_type.0))
        .filter_map(|i| {
            Some(ShareInfo {
                name: pwstr(i.shi2_netname)?,
                path: pwstr(i.shi2_path),
                remark: pwstr(i.shi2_remark),
                path_from: Some("enum".into()),
            })
        })
        .collect();
    unsafe { NetApiBufferFree(Some(buf as *const _)) };
    Some(out)
}

/// Level 1: only name and description, readable for every account.
#[cfg(windows)]
fn enum_level1() -> Vec<ShareInfo> {
    let mut buf: *mut u8 = std::ptr::null_mut();
    let (mut read, mut total) = (0u32, 0u32);
    let rc = unsafe {
        NetShareEnum(
            PCWSTR::null(),
            1,
            &mut buf,
            u32::MAX,
            &mut read,
            &mut total,
            None,
        )
    };
    if rc != NERR_SUCCESS || buf.is_null() {
        tracing::warn!(rc, "shares not readable");
        if !buf.is_null() {
            unsafe { NetApiBufferFree(Some(buf as *const _)) };
        }
        return Vec::new();
    }
    let items = unsafe { std::slice::from_raw_parts(buf as *const SHARE_INFO_1, read as usize) };
    let out = items
        .iter()
        .filter(|i| is_ordinary(i.shi1_type.0))
        .filter_map(|i| {
            Some(ShareInfo {
                name: pwstr(i.shi1_netname)?,
                path: None,
                remark: pwstr(i.shi1_remark),
                path_from: None,
            })
        })
        .collect();
    unsafe { NetApiBufferFree(Some(buf as *const _)) };
    out
}

/// Turn `ShareName` (`\\*\GL`) into the bare name.
pub fn share_name(raw: &str) -> String {
    raw.rsplit('\\').next().unwrap_or(raw).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_share_name() {
        assert_eq!(share_name(r"\\*\GL"), "gl");
        assert_eq!(share_name(r"\\SERVER\Daten"), "daten");
        assert_eq!(share_name("GL"), "gl");
    }

    #[test]
    fn skips_administrative_shares() {
        assert!(is_ordinary(STYPE_DISKTREE_BITS));
        assert!(!is_ordinary(STYPE_DISKTREE_BITS | STYPE_SPECIAL)); // C$, ADMIN$
        assert!(!is_ordinary(3)); // IPC$
        assert!(!is_ordinary(1)); // print queue
    }

    fn enumerated(name: &str, path: Option<&str>) -> ShareInfo {
        ShareInfo {
            name: name.into(),
            path: path.map(Into::into),
            remark: None,
            path_from: path.map(|_| "enum".into()),
        }
    }

    /// The union is the reason the service account may stay small: what
    /// level 1 gave without a path gets it from the events, and what the
    /// enumeration did not know at all is added.
    #[test]
    fn a_learned_path_fills_a_share_the_enumeration_left_blank() {
        let learned = HashMap::from([("gl".to_string(), r"C:\Freigaben\GL".to_string())]);
        let out = merge(vec![enumerated("GL", None)], &learned);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path.as_deref(), Some(r"C:\Freigaben\GL"));
        assert_eq!(out[0].path_from.as_deref(), Some("events"));
    }

    #[test]
    fn a_share_only_the_events_knew_is_added_and_the_list_is_sorted() {
        let learned = HashMap::from([("hr".to_string(), r"C:\Freigaben\HR".to_string())]);
        let out = merge(
            vec![enumerated("Projekte", Some(r"C:\Freigaben\Projekte"))],
            &learned,
        );
        assert_eq!(
            out.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["hr", "Projekte"]
        );
        assert_eq!(out[0].path_from.as_deref(), Some("events"));
    }

    /// The enumeration wins: whoever already knows the path leaves it be.
    #[test]
    fn an_enumerated_path_is_not_overwritten_by_a_learned_one() {
        let learned = HashMap::from([("gl".to_string(), r"D:\anders".to_string())]);
        let out = merge(vec![enumerated("GL", Some(r"C:\Freigaben\GL"))], &learned);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].path.as_deref(), Some(r"C:\Freigaben\GL"));
        assert_eq!(out[0].path_from.as_deref(), Some("enum"));
    }
}
