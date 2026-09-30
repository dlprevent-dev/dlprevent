//! Rights of the service account — as few as possible, as many as needed.
//!
//! The agent needs **exactly three** things, and for each of them it can be
//! said what breaks without it:
//!
//! | Right | What for | Without it |
//! |---|---|---|
//! | `SeServiceLogonRight` | start as a service | the service does not start |
//! | `SeSecurityPrivilege` | set audit policy and SACL, read security log | no events, no SACL |
//! | Group `Event Log Readers` | read the security log | empty query, no alerts |
//!
//! **Deliberately not granted:** membership in `Administrators`. The agent
//! gets by without it; all it loses is the local path in the share list (see
//! `shares.rs`) — a display detail, not operation.
//!
//! `SeSecurityPrivilege` is itself a strong right: whoever holds it can read
//! the security log **and clear it**. Less is not possible if the agent is to
//! set the auditing up itself; that belongs said to the customer and not
//! hidden.
//!
//! Best is a **gMSA** (`DOMAIN\name$`): the domain manages the password,
//! nobody knows it, nobody types it in anywhere.

use anyhow::{bail, Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL, NTSTATUS};
use windows::Win32::Security::Authentication::Identity::{
    LsaAddAccountRights, LsaClose, LsaEnumerateAccountRights, LsaFreeMemory, LsaNtStatusToWinError,
    LsaOpenPolicy, LsaRemoveAccountRights, LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING,
    POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES, POLICY_VIEW_LOCAL_INFORMATION,
};
use windows::Win32::Security::PSID;

/// The rights the agent actually uses.
pub const NEEDED: &[(&str, &str)] = &[
    ("SeServiceLogonRight", "start as a service"),
    (
        "SeSecurityPrivilege",
        "set audit policy and SACL, read the security event log",
    ),
];

/// SID of the built-in group "Event Log Readers"; by SID, because the name
/// is localised.
pub const EVENT_LOG_READERS_SID: &str = "S-1-5-32-573";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn lsa_str(buf: &[u16]) -> LSA_UNICODE_STRING {
    // Length without the trailing NUL, in bytes — that is how the API wants it.
    let chars = buf.len().saturating_sub(1);
    LSA_UNICODE_STRING {
        Length: (chars * 2) as u16,
        MaximumLength: (buf.len() * 2) as u16,
        Buffer: windows::core::PWSTR(buf.as_ptr() as *mut u16),
    }
}

fn check(st: NTSTATUS, what: &str) -> Result<()> {
    if st.0 == 0 {
        return Ok(());
    }
    let win = unsafe { LsaNtStatusToWinError(st) };
    bail!("{what} failed (windows error {win})");
}

/// SID of an account (`CORP\deelpe-svc`, `deelpe-svc`, `DOMAIN\name$`).
fn account_sid(account: &str) -> Result<(Vec<u8>, String)> {
    use windows::Win32::Security::LookupAccountNameW;
    use windows::Win32::Security::SID_NAME_USE;
    let name = wide(account);
    let mut sid_len = 0u32;
    let mut dom_len = 0u32;
    let mut kind = SID_NAME_USE::default();
    unsafe {
        // The first call only determines the sizes and fails as expected.
        let _ = LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            None,
            &mut sid_len,
            None,
            &mut dom_len,
            &mut kind,
        );
    }
    if sid_len == 0 {
        bail!("account '{account}' does not exist (spelling: DOMAIN\\name, gMSA ends with $)");
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut dom = vec![0u16; dom_len.max(1) as usize];
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            PCWSTR(name.as_ptr()),
            Some(PSID(sid.as_mut_ptr() as *mut _)),
            &mut sid_len,
            Some(windows::core::PWSTR(dom.as_mut_ptr())),
            &mut dom_len,
            &mut kind,
        )
        .with_context(|| format!("look up account '{account}'"))?;
    }
    let text = sid_to_string(&mut sid);
    Ok((sid, text))
}

fn sid_to_string(sid: &mut [u8]) -> String {
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut out = windows::core::PWSTR::null();
    unsafe {
        if ConvertSidToStringSidW(PSID(sid.as_mut_ptr() as *mut _), &mut out).is_ok() {
            let s = out.to_string().unwrap_or_default();
            let _ = LocalFree(Some(HLOCAL(out.0 as *mut _)));
            return s;
        }
    }
    String::new()
}

fn policy(access: i32) -> Result<LSA_HANDLE> {
    let attrs = LSA_OBJECT_ATTRIBUTES::default();
    let mut h = LSA_HANDLE::default();
    let st = unsafe { LsaOpenPolicy(None, &attrs, access as u32, &mut h) };
    check(st, "LsaOpenPolicy (run as administrator)")?;
    Ok(h)
}

/// Grants exactly the rights from [`NEEDED`] and adds the account to the
/// group of event log readers. Idempotent.
pub fn grant(account: &str) -> Result<()> {
    let (mut sid, sid_text) = account_sid(account)?;
    let h = policy(POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES)?;
    let bufs: Vec<Vec<u16>> = NEEDED.iter().map(|(r, _)| wide(r)).collect();
    let rights: Vec<LSA_UNICODE_STRING> = bufs.iter().map(|b| lsa_str(b)).collect();
    let st = unsafe { LsaAddAccountRights(h, PSID(sid.as_mut_ptr() as *mut _), &rights) };
    unsafe {
        let _ = LsaClose(h);
    }
    check(st, "grant privileges")?;
    for (r, why) in NEEDED {
        println!("  granted: {r:<22} ({why})");
    }
    match add_to_event_log_readers(&mut sid) {
        Ok(true) => println!("  granted: group \"Event Log Readers\" ({EVENT_LOG_READERS_SID})"),
        Ok(false) => println!("  already a member: group \"Event Log Readers\""),
        Err(e) => println!("  NOT granted: group \"Event Log Readers\" — {e:#}"),
    }
    println!("\naccount {account} ({sid_text}) now has exactly the privileges the agent needs.");
    println!("deliberately NOT granted: membership in Administrators.");
    Ok(())
}

/// Allows the service account to replace its own program.
///
/// The swap puts `deelpe-winagent.exe.new` **next to** the running file and
/// renames twice; both are changes to the folder, not to the file. A service
/// account has nothing there out of the box — the installer grants read and
/// execute on the file and modify on the data directory. Under LocalSystem
/// that does not show, under a dedicated account it does.
///
/// **Deliberately a command of its own and not a default.** Whoever grants
/// this allows the service account to change the contents of its program
/// folder — no privilege escalation, it runs as that account anyway, but the
/// property "under `Program Files` only administrators write" is gone for
/// this folder. Whoever keeps distributing the agent by GPO or by script does
/// not need it and should not get it.
pub fn allow_self_update(account: &str) -> Result<()> {
    let exe = std::env::current_exe().context("own path")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no folder", exe.display()))?;
    grant_modify(dir, account)?;
    println!("account {account} may now replace {}", exe.display());
    println!(
        "  granted: modify on {} (create the new file, rename the running one aside)",
        dir.display()
    );
    println!();
    println!("check it:   icacls \"{}\"", dir.display());
    println!(
        "undo it:    icacls \"{}\" /remove:g \"{account}\"",
        dir.display()
    );
    Ok(())
}

/// Takes the rights away again — for the uninstall.
pub fn revoke(account: &str) -> Result<()> {
    let (mut sid, _) = account_sid(account)?;
    let h = policy(POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES)?;
    let bufs: Vec<Vec<u16>> = NEEDED.iter().map(|(r, _)| wide(r)).collect();
    let rights: Vec<LSA_UNICODE_STRING> = bufs.iter().map(|b| lsa_str(b)).collect();
    let st = unsafe {
        LsaRemoveAccountRights(h, PSID(sid.as_mut_ptr() as *mut _), false, Some(&rights))
    };
    unsafe {
        let _ = LsaClose(h);
    }
    check(st, "revoke privileges")?;
    println!("privileges of {account} revoked.");
    Ok(())
}

/// Shows what the account has and what is missing.
pub fn show(account: &str) -> Result<()> {
    let (mut sid, sid_text) = account_sid(account)?;
    let h = policy(POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION)?;
    let mut buf: *mut LSA_UNICODE_STRING = std::ptr::null_mut();
    let mut count = 0u32;
    let st = unsafe {
        LsaEnumerateAccountRights(h, PSID(sid.as_mut_ptr() as *mut _), &mut buf, &mut count)
    };
    let have: Vec<String> = if st.0 == 0 && !buf.is_null() {
        let items = unsafe { std::slice::from_raw_parts(buf, count as usize) };
        let v = items
            .iter()
            .map(|u| unsafe { std::slice::from_raw_parts(u.Buffer.0, (u.Length / 2) as usize) })
            .map(String::from_utf16_lossy)
            .collect();
        unsafe {
            let _ = LsaFreeMemory(Some(buf as *mut _));
        }
        v
    } else {
        Vec::new()
    };
    unsafe {
        let _ = LsaClose(h);
    }

    println!("account {account} ({sid_text}):");
    for (r, why) in NEEDED {
        let ok = have.iter().any(|h| h.eq_ignore_ascii_case(r));
        println!("  [{}] {r:<22} {why}", if ok { "x" } else { " " });
    }
    println!(
        "\nother privileges of this account: {}",
        if have.is_empty() {
            "none".into()
        } else {
            have.join(", ")
        }
    );
    Ok(())
}

/// Add the account to the built-in group of event log readers.
/// `Ok(false)` means: was already in it.
fn add_to_event_log_readers(sid: &mut [u8]) -> Result<bool> {
    use windows::Win32::NetworkManagement::NetManagement::{
        NetLocalGroupAddMembers, LOCALGROUP_MEMBERS_INFO_0,
    };
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;

    const ERROR_MEMBER_IN_ALIAS: u32 = 1378;
    let mut group_sid = PSID::default();
    let s = wide(EVENT_LOG_READERS_SID);
    unsafe { ConvertStringSidToSidW(PCWSTR(s.as_ptr()), &mut group_sid).context("group SID")? };
    let name = crate::rights::group_name_of(group_sid)?;
    let group = wide(&name);
    let member = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: PSID(sid.as_mut_ptr() as *mut _),
    };
    let rc = unsafe {
        NetLocalGroupAddMembers(
            PCWSTR::null(),
            PCWSTR(group.as_ptr()),
            0,
            &member as *const _ as *const u8,
            1,
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(group_sid.0 as *mut _)));
    }
    match rc {
        0 => Ok(true),
        ERROR_MEMBER_IN_ALIAS => Ok(false),
        other => bail!("NetLocalGroupAddMembers: windows error {other}"),
    }
}

/// Get the localised name of a built-in group from its SID.
fn group_name_of(sid: PSID) -> Result<String> {
    use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};
    let mut name_len = 0u32;
    let mut dom_len = 0u32;
    let mut kind = SID_NAME_USE::default();
    unsafe {
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            None,
            &mut name_len,
            None,
            &mut dom_len,
            &mut kind,
        );
    }
    if name_len == 0 {
        bail!("no group found for the SID");
    }
    let mut name = vec![0u16; name_len as usize];
    let mut dom = vec![0u16; dom_len.max(1) as usize];
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(windows::core::PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(windows::core::PWSTR(dom.as_mut_ptr())),
            &mut dom_len,
            &mut kind,
        )
        .context("look up group name")?;
    }
    Ok(String::from_utf16_lossy(&name[..name_len as usize]))
}

/// Gives `account` read and execute on `path` — no more, no writing.
///
/// Sounds obvious, it is not: whoever moves the `.exe` into place with
/// `Move-Item` out of `C:\Windows\Temp` or out of the downloads folder takes
/// the access list from there along — the file then does **not** inherit from
/// `C:\Program Files`, and the service starts with "access denied" without
/// saying to what. Which is why the installer checks this itself.
pub fn grant_read_execute(path: &std::path::Path, account: &str) -> Result<()> {
    grant_file(path, account, false)
}

/// Modify (read, write, delete) including inheritance — for the data
/// directory with credentials and state.
pub fn grant_modify(path: &std::path::Path, account: &str) -> Result<()> {
    grant_file(path, account, true)
}

fn grant_file(path: &std::path::Path, account: &str, modify: bool) -> Result<()> {
    use windows::core::{HSTRING, PWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW, EXPLICIT_ACCESS_W,
        GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_NAME, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
        PSECURITY_DESCRIPTOR,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    };

    let p = HSTRING::from(path.as_os_str());
    let mut old: *mut ACL = std::ptr::null_mut();
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            &p,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old),
            None,
            &mut psd,
        )
    };
    if rc.is_err() {
        bail!("read permissions of {}: {rc:?}", path.display());
    }
    let mut name: Vec<u16> = account.encode_utf16().chain(std::iter::once(0)).collect();
    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: if modify {
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | 0x0001_0000
        /* DELETE */
        } else {
            FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0
        },
        grfAccessMode: GRANT_ACCESS,
        // Folders inherit onto their contents, files do not.
        grfInheritance: if modify {
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        } else {
            windows::Win32::Security::ACE_FLAGS(0)
        },
        Trustee: TRUSTEE_W {
            TrusteeForm: TRUSTEE_IS_NAME,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(name.as_mut_ptr()),
            ..Default::default()
        },
    };
    let mut new: *mut ACL = std::ptr::null_mut();
    let rc = unsafe { SetEntriesInAclW(Some(&[ea]), Some(old), &mut new) };
    if rc.is_err() || new.is_null() {
        unsafe {
            if !psd.is_invalid() {
                let _ = LocalFree(Some(HLOCAL(psd.0)));
            }
        }
        bail!("build access list for {account}: {rc:?}");
    }
    let rc = unsafe {
        SetNamedSecurityInfoW(
            &p,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new),
            None,
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(new as *mut _)));
        if !psd.is_invalid() {
            let _ = LocalFree(Some(HLOCAL(psd.0)));
        }
    }
    if rc.is_err() {
        bail!("set permissions on {}: {rc:?}", path.display());
    }
    Ok(())
}
