//! The agent sets the auditing up itself — that is the part that has to work
//! at the customer's site (decision of 2026-09-06).
//!
//! Two layers, both needed, otherwise nothing lands in the log:
//! 1. **System policy**: "Object access → File system" and "File share" on
//!    success. Through `AuditQuerySystemPolicy`/`AuditSetSystemPolicy` with
//!    the subcategory GUIDs — not through `auditpol.exe`: its output is
//!    localised ("File System" is called "Dateisystem" on a German Windows),
//!    the API returns a bitmask.
//! 2. **SACL** on the folder: without an audit entry on the object the policy
//!    alone produces not a single event.

#[cfg(windows)]
use anyhow::{bail, Context, Result};
#[cfg(windows)]
use tracing::info;

/// Subcategories of the security log, language-independent by GUID
/// (cross-checked on Windows Server 2025 with `auditpol /list /subcategory:*`).
pub const SUB_FILE_SYSTEM: &str = "{0CCE921D-69AE-11D9-BED3-505054503030}";
/// "Detailed File Share" — this is where 5145 lives, the event for SMB
/// accesses. Not to be confused with "File Share" ({0CCE9224-…}), which only
/// yields 5140 per share connection; that was the mistake in the planning.
pub const SUB_DETAILED_FILE_SHARE: &str = "{0CCE9244-69AE-11D9-BED3-505054503030}";

/// The constants above are written as text because that way they stay
/// readable in the self-check and in error messages as well.
#[cfg(windows)]
fn guid(s: &str) -> windows::core::GUID {
    // `try_from` wants the bare form without curly braces.
    windows::core::GUID::try_from(s.trim_matches(|c| c == '{' || c == '}')).expect("GUID constant")
}

/// Queries the system policy and returns the audit bits per subcategory.
#[cfg(windows)]
fn policy_bits(subs: &[&str]) -> Result<Vec<u32>> {
    use windows::Win32::Security::Authentication::Identity::{
        AuditFree, AuditQuerySystemPolicy, AUDIT_POLICY_INFORMATION,
    };
    let guids: Vec<windows::core::GUID> = subs.iter().map(|s| guid(s)).collect();
    let mut p: *mut AUDIT_POLICY_INFORMATION = std::ptr::null_mut();
    let ok = unsafe { AuditQuerySystemPolicy(&guids, &mut p) };
    if !ok || p.is_null() {
        bail!("AuditQuerySystemPolicy failed (account needs \"Manage auditing and security log\")");
    }
    let out = (0..guids.len())
        .map(|i| unsafe { (*p.add(i)).AuditingInformation })
        .collect();
    unsafe { AuditFree(p as *mut _) };
    Ok(out)
}

/// Switch success auditing on for file system and file share. Idempotent: if
/// it is already set, nothing happens.
#[cfg(windows)]
pub fn ensure_policy() -> Result<()> {
    use windows::Win32::Security::Authentication::Identity::{
        AuditSetSystemPolicy, AUDIT_POLICY_INFORMATION, POLICY_AUDIT_EVENT_SUCCESS,
    };
    enable_security_privilege().context("SeSecurityPrivilege")?;
    let subs = [SUB_FILE_SYSTEM, SUB_DETAILED_FILE_SHARE];
    let bits = policy_bits(&subs)?;
    let todo: Vec<AUDIT_POLICY_INFORMATION> = subs
        .iter()
        .zip(bits.iter())
        .filter(|(_, b)| **b & POLICY_AUDIT_EVENT_SUCCESS as u32 == 0)
        .map(|(s, b)| AUDIT_POLICY_INFORMATION {
            AuditSubCategoryGuid: guid(s),
            // Keep the existing bits: whoever already audits failures keeps that.
            AuditingInformation: b | POLICY_AUDIT_EVENT_SUCCESS as u32,
            AuditCategoryGuid: windows::core::GUID::zeroed(),
        })
        .collect();
    if todo.is_empty() {
        return Ok(());
    }
    let ok = unsafe { AuditSetSystemPolicy(&todo) };
    if !ok {
        bail!("AuditSetSystemPolicy failed");
    }
    for t in &todo {
        info!(subcategory = ?t.AuditSubCategoryGuid, "audit policy enabled");
    }
    Ok(())
}

#[cfg(windows)]
fn policy_has_success(sub: &str) -> Result<bool> {
    use windows::Win32::Security::Authentication::Identity::POLICY_AUDIT_EVENT_SUCCESS;
    Ok(policy_bits(&[sub])?.first().copied().unwrap_or(0) & POLICY_AUDIT_EVENT_SUCCESS as u32 != 0)
}

#[cfg(windows)]
pub fn policy_state() -> Vec<(&'static str, &'static str, bool)> {
    [
        ("file system", SUB_FILE_SYSTEM),
        ("share (detailed)", SUB_DETAILED_FILE_SHARE),
    ]
    .into_iter()
    .map(|(n, g)| (n, g, policy_has_success(g).unwrap_or(false)))
    .collect()
}

/// Audit entry on the folder: success, read, for everyone, inherited down to
/// subfolders and files. As SDDL, because building an ACL by hand would be
/// three times as much code that makes nothing better.
/// `AU` = audit ACE, `OICI` = inheritance, `SA` = on success, `FR` = read,
/// `WD` = everyone.
#[cfg(windows)]
const SACL_AUDIT_READ: &str = "S:(AU;OICISA;FR;;;WD)";

/// Sets the SACL on `path`. Needs `SeSecurityPrivilege`.
#[cfg(windows)]
pub fn ensure_sacl(path: &str) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, ProgressInvokeNever,
        TreeSetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT, TREE_SEC_INFO_SET,
    };
    use windows::Win32::Security::{
        GetSecurityDescriptorSacl, ACL, PSECURITY_DESCRIPTOR, SACL_SECURITY_INFORMATION,
        UNPROTECTED_SACL_SECURITY_INFORMATION,
    };

    enable_security_privilege().context("SeSecurityPrivilege")?;

    let sddl = HSTRING::from(SACL_AUDIT_READ);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .context("SDDL of the SACL")?;
    }
    let mut present = windows::core::BOOL::default();
    let mut defaulted = windows::core::BOOL::default();
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let res = (|| -> Result<()> {
        unsafe {
            GetSecurityDescriptorSacl(psd, &mut present, &mut sacl, &mut defaulted)
                .context("read SACL")?
        };
        if !present.as_bool() || sacl.is_null() {
            bail!("SDDL yields no SACL");
        }
        let p = HSTRING::from(path);
        // Two things measured on the lab DC on 2026-09-06, without which the
        // auditing only covers the folder itself — every file inside it
        // stayed without an entry, not a single 4663:
        // * `UNPROTECTED_…`: otherwise Windows writes the SACL as protected
        //   (`S:PAI`), and subfolders accept nothing.
        // * `TreeSetNamedSecurityInfoW` instead of `SetNamedSecurityInfoW`:
        //   only the tree version passes the inheritable entry down to what
        //   is already there. New files inherit anyway.
        let what = SACL_SECURITY_INFORMATION | UNPROTECTED_SACL_SECURITY_INFORMATION;
        let rc = unsafe {
            TreeSetNamedSecurityInfoW(
                PCWSTR(p.as_ptr()),
                SE_FILE_OBJECT,
                what,
                None,
                None,
                None,
                Some(sacl),
                TREE_SEC_INFO_SET,
                None,
                ProgressInvokeNever,
                None,
            )
        };
        if rc.is_err() {
            bail!("set SACL on {path}: {rc:?}");
        }
        Ok(())
    })();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    res
}

/// True if the folder carries an audit entry at all.
#[cfg(windows)]
pub fn has_sacl(path: &str) -> bool {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{ACL, PSECURITY_DESCRIPTOR, SACL_SECURITY_INFORMATION};

    if enable_security_privilege().is_err() {
        return false;
    }
    let p = HSTRING::from(path);
    let mut sacl: *mut ACL = std::ptr::null_mut();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(p.as_ptr()),
            SE_FILE_OBJECT,
            SACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(&mut sacl),
            &mut psd,
        )
    };
    let ok = rc.is_ok() && !sacl.is_null() && unsafe { (*sacl).AceCount } > 0;
    if !psd.is_invalid() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
        }
    }
    ok
}

/// Switch `SeSecurityPrivilege` on in our own token; without it nobody may
/// read or write a SACL, not even an administrator.
#[cfg(windows)]
fn enable_security_privilege() -> Result<()> {
    use windows::core::w;
    use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .context("OpenProcessToken")?;
        let mut luid = LUID::default();
        let r = LookupPrivilegeValueW(None, w!("SeSecurityPrivilege"), &mut luid);
        if r.is_err() {
            let _ = CloseHandle(token);
            bail!("LookupPrivilegeValue: {r:?}");
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let r = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        let last = windows::Win32::Foundation::GetLastError();
        let _ = CloseHandle(token);
        if r.is_err() {
            bail!("AdjustTokenPrivileges: {r:?}");
        }
        // AdjustTokenPrivileges reports success even when the right is missing.
        if last.is_err() {
            bail!("SeSecurityPrivilege not assigned (service account needs \"Manage auditing and security log\")");
        }
    }
    Ok(())
}

/// For `deelpe-winagent check`.
#[cfg(windows)]
pub fn print_check() -> Result<()> {
    println!("audit policy:");
    for (name, guid, on) in policy_state() {
        println!(
            "  {name:<17} {} {guid}",
            if on { "success ON " } else { "OFF        " }
        );
    }
    let st = crate::config::AgentState::load();
    if st.prepared.is_empty() {
        println!("SACL: no rule folders taken over yet.");
    } else {
        println!("SACL:");
        for p in &st.prepared {
            println!(
                "  {} {}",
                if has_sacl(p) { "set    " } else { "MISSING" },
                p
            );
        }
    }
    Ok(())
}

/// Sets the auditing up for one concrete folder. `None` means "armed",
/// `Some(reason)` names the reason in plain words — that goes to the central,
/// because a folder without a SACL produces not a single event, and that must
/// not look like "everything is fine" in the dashboard.
///
/// A folder that does not exist yet is normal at a customer's site (rule
/// created, share comes later) — hence a reason, not a crash.
#[cfg(windows)]
pub fn prepare(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return Some("folder does not exist (yet)".into());
    }
    match ensure_sacl(path) {
        Ok(()) => {
            info!(path, "SACL set");
            None
        }
        // Measured on the lab DC on 2026-09-06: `SeSecurityPrivilege` alone
        // is not enough when the folder's DACL does not let the service
        // account in at all — `SetNamedSecurityInfo` then ends with error 5.
        // If the audit entry is in place anyway (set by hand or by an earlier
        // run), the folder is armed; the agent just may not write it anew.
        Err(_) if has_sacl(path) => {
            info!(path, "SACL already in place, could not rewrite it");
            None
        }
        // Without a SACL only local access on the server (4663) is missing.
        // SMB accesses still land in the log as 5145 as soon as the policy is
        // in place — also measured on the lab DC.
        Err(e) => Some(format!(
            "{e:#}; SMB access is still recorded, local access on the server is not"
        )),
    }
}

#[cfg(windows)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The constants are written as text; a typo must not surface only on
    /// the file server.
    #[test]
    fn subcategory_guids_parse() {
        for s in [SUB_FILE_SYSTEM, SUB_DETAILED_FILE_SHARE] {
            let g = guid(s);
            assert_ne!(g, windows::core::GUID::zeroed(), "{s}");
        }
        assert_eq!(guid(SUB_FILE_SYSTEM).data1, 0x0CCE921D);
        assert_eq!(guid(SUB_DETAILED_FILE_SHARE).data1, 0x0CCE9244);
    }
}

// ---------------------------------------------------------------------------
// Elsewhere: there is no audit policy and no SACL. The agent's bookkeeping
// runs all the same, so that it stays testable -- the same split as with
// `wfp::Cages`.
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
pub fn ensure_policy() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn policy_state() -> Vec<(&'static str, &'static str, bool)> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn has_sacl(_path: &str) -> bool {
    false
}

/// The folder that does not exist is the common case at a customer's site
/// elsewhere too -- and the verdict on it is pure logic, not a system call.
#[cfg(not(windows))]
pub fn prepare(path: &str) -> Option<String> {
    if !std::path::Path::new(path).exists() {
        return Some("folder does not exist (yet)".into());
    }
    Some("audit policy is a windows feature".into())
}
