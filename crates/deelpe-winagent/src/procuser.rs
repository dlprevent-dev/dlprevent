//! Whose process is it? On a terminal server a dozen people share one
//! machine, and "chrome.exe sent it" names none of them. The alert carries
//! the account the process runs under, in the same shape as the file
//! server's (`UserRef`), so the central server files both under the SID.
//!
//! Asked when an alert is filed, not per event: alerts are rare, events
//! arrive by the thousand. ponytail: a process that has exited by then
//! names nobody — the carry-forward keeps the first answer
//! (`client::file_pending`). Upgrade path: resolve at first sight in the
//! sensor's `ProcCache` and carry it on `ProcessRef`.

use deelpe_core::central::UserRef;

/// The account process `pid` runs under. `None` if the process is gone or
/// its token is closed to the service account (LocalSystem may read every
/// one).
#[cfg(windows)]
pub fn of(pid: u32) -> Option<UserRef> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
    let user = with_token_user(h, |sid| {
        let s = sid_string(sid)?;
        let (name, domain) = account_of(&s, sid);
        Some(UserRef {
            source: crate::config::hostname(),
            name,
            domain,
            sid: Some(s),
        })
    });
    unsafe {
        let _ = CloseHandle(h);
    }
    user
}

#[cfg(not(windows))]
pub fn of(_pid: u32) -> Option<UserRef> {
    None
}

/// Hand the SID of `process`'s token to `f`. The SID lives in a buffer
/// that is gone afterwards, hence the closure.
#[cfg(windows)]
pub(crate) fn with_token_user<T>(
    process: windows::Win32::Foundation::HANDLE,
    f: impl FnOnce(windows::Win32::Security::PSID) -> Option<T>,
) -> Option<T> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows::Win32::System::Threading::OpenProcessToken;
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token).ok()?;
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
        f(user.User.Sid)
    }
}

#[cfg(windows)]
pub(crate) fn sid_string(sid: windows::Win32::Security::PSID) -> Option<String> {
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    unsafe {
        let mut out = windows::core::PWSTR::null();
        ConvertSidToStringSidW(sid, &mut out).ok()?;
        let s = out.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(out.0 as *mut _)));
        s
    }
}

/// Name and domain of a SID, remembered: for a domain account the lookup
/// goes to a domain controller, and the same few people raise most alerts.
/// A SID nobody can name stays its own name — still the same key.
#[cfg(windows)]
fn account_of(sid_str: &str, sid: windows::Win32::Security::PSID) -> (String, Option<String>) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    type Account = (String, Option<String>);
    static KNOWN: Mutex<Option<HashMap<String, Account>>> = Mutex::new(None);
    if let Some(hit) = KNOWN
        .lock()
        .ok()
        .and_then(|k| k.as_ref().and_then(|m| m.get(sid_str).cloned()))
    {
        return hit;
    }
    let found = lookup(sid).unwrap_or_else(|| (sid_str.to_string(), None));
    if let Ok(mut k) = KNOWN.lock() {
        let m = k.get_or_insert_with(HashMap::new);
        // People, not processes: a terminal server has hundreds at most.
        if m.len() > 10_000 {
            m.clear();
        }
        m.insert(sid_str.to_string(), found.clone());
    }
    found
}

#[cfg(windows)]
fn lookup(sid: windows::Win32::Security::PSID) -> Option<(String, Option<String>)> {
    use windows::core::{PCWSTR, PWSTR};
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
        return None;
    }
    let mut name = vec![0u16; name_len as usize];
    let mut dom = vec![0u16; dom_len.max(1) as usize];
    unsafe {
        LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut name_len,
            Some(PWSTR(dom.as_mut_ptr())),
            &mut dom_len,
            &mut kind,
        )
        .ok()?;
    }
    let domain = String::from_utf16_lossy(&dom[..dom_len as usize]);
    Some((
        String::from_utf16_lossy(&name[..name_len as usize]),
        (!domain.is_empty()).then_some(domain),
    ))
}
