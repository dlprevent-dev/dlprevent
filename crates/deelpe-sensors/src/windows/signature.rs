//! Who is a program on Windows? The publisher from the Authenticode
//! signature, plus the original name from the version resource.
//!
//! The Mac has Apple's team ID and signing ID for this. Windows has no
//! counterpart that would be just as unambiguous, but it has a usable pair:
//!
//! * **Publisher** — the name in the signing certificate ("Google LLC",
//!   "Microsoft Corporation"). Forging it would mean getting a certificate
//!   issued to that name.
//! * **Original name** — `OriginalFilename` from the EXE's version
//!   resource, not the name on disk. Renaming `chrome.exe` to `svchost.exe`
//!   changes nothing about it.
//!
//! That becomes [`ProcessIdentity::Signed`], and with it the same exception
//! rules apply as on the Mac: `Google LLC/chrome.exe`, `Google LLC/*` or
//! `team:Microsoft Corporation`.
//!
//! Whatever is **not** validly signed becomes [`ProcessIdentity::Unknown`]
//! and is therefore always reported and never learned — the same decision
//! as on the Mac for unsigned programs.
//!
//! The check is expensive (certificate chain) and is therefore cached per
//! path. It deliberately does **not go out to the network**: revocation
//! lists are not fetched, only the local cache is used. The service has no
//! outbound network access, and a signature check does not change that.

use deelpe_core::identity::ProcessIdentity;
use std::collections::HashMap;

/// Identity of a program, cached per path: many processes share the same
/// EXE, and the check is the most expensive part.
#[derive(Default)]
pub struct SignatureCache {
    known: HashMap<String, ProcessIdentity>,
}

impl SignatureCache {
    pub fn identity(&mut self, path: &str) -> ProcessIdentity {
        if path.is_empty() {
            return ProcessIdentity::Unknown { path: String::new() };
        }
        if let Some(id) = self.known.get(path) {
            return id.clone();
        }
        let id = identity_of(path);
        // Over weeks a machine sees a lot of programs; the table must not
        // grow without bound.
        if self.known.len() > 5_000 {
            self.known.clear();
        }
        self.known.insert(path.to_string(), id.clone());
        id
    }
}

fn identity_of(path: &str) -> ProcessIdentity {
    match (verify(path), publisher(path)) {
        (true, Some(p)) if !p.is_empty() => ProcessIdentity::Signed {
            team_id: p,
            signing_id: original_filename(path).unwrap_or_else(|| file_name(path)),
        },
        // Validly signed, but no readable publisher: that is not an ID an
        // exception rule should rest on.
        _ => ProcessIdentity::Unknown { path: path.to_string() },
    }
}

pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Is the file validly signed? Without network access: do not fetch
/// revocation lists, only use the local cache.
fn verify(path: &str) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
        WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };
    let p = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR(p.as_ptr()),
        hFile: HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let rc = unsafe { WinVerifyTrust(windows::Win32::Foundation::HWND::default(), &mut action, &mut data as *mut _ as *mut std::ffi::c_void) };
    // The second call releases the state; without it every check leaks.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(windows::Win32::Foundation::HWND::default(), &mut action, &mut data as *mut _ as *mut std::ffi::c_void);
    }
    rc == 0
}

/// The name in the signing certificate, for instance "Google LLC".
fn publisher(path: &str) -> Option<String> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
        CryptQueryObject, CERT_FIND_SUBJECT_CERT, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CERT_QUERY_ENCODING_TYPE, CMSG_SIGNER_INFO_PARAM, CMSG_SIGNER_INFO,
        HCERTSTORE, X509_ASN_ENCODING, PKCS_7_ASN_ENCODING,
    };
    let p = wide(path);
    let mut store = HCERTSTORE::default();
    let mut msg: *mut std::ffi::c_void = std::ptr::null_mut();
    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            p.as_ptr() as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        )
        .ok()?;
    }
    let out = (|| -> Option<String> {
        // First the size, then fetch the signer information.
        let mut len = 0u32;
        unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut len).ok()? };
        let mut buf = vec![0u8; len as usize];
        unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, Some(buf.as_mut_ptr() as *mut std::ffi::c_void), &mut len).ok()? };
        let signer = unsafe { &*(buf.as_ptr() as *const CMSG_SIGNER_INFO) };
        // Issuer and serial number identify the certificate in the store
        // that came along with the file.
        let mut find = windows::Win32::Security::Cryptography::CERT_INFO {
            Issuer: signer.Issuer,
            SerialNumber: signer.SerialNumber,
            ..Default::default()
        };
        let ctx = unsafe {
            CertFindCertificateInStore(
                store,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                0,
                CERT_FIND_SUBJECT_CERT,
                Some(&mut find as *mut _ as *const std::ffi::c_void),
                None,
            )
        };
        if ctx.is_null() {
            return None;
        }
        let n = unsafe { CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None) };
        let name = if n > 1 {
            let mut w = vec![0u16; n as usize];
            unsafe { CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut w)) };
            Some(String::from_utf16_lossy(&w).trim_end_matches('\0').to_string())
        } else {
            None
        };
        unsafe { let _ = CertFreeCertificateContext(Some(ctx)); }
        name
    })();
    unsafe {
        let _ = CryptMsgClose(Some(msg));
        let _ = CertCloseStore(Some(store), 0);
    }
    out
}

/// `OriginalFilename` from the version resource. Survives a rename, unlike
/// the name on disk.
fn original_filename(path: &str) -> Option<String> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
    let p = wide(path);
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(p.as_ptr()), None) };
    if size == 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    unsafe { GetFileVersionInfoW(PCWSTR(p.as_ptr()), None, size, data.as_mut_ptr() as *mut _).ok()? };

    // Language and code page are in the resource; hard-coding "040904b0"
    // goes wrong for a non-English program.
    let mut tr: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut tr_len = 0u32;
    let key = wide(r"\VarFileInfo\Translation");
    let langs: Vec<(u16, u16)> = unsafe {
        if VerQueryValueW(data.as_ptr() as *const _, PCWSTR(key.as_ptr()), &mut tr, &mut tr_len).as_bool() && tr_len >= 4 {
            std::slice::from_raw_parts(tr as *const u16, (tr_len / 2) as usize)
                .chunks_exact(2)
                .map(|c| (c[0], c[1]))
                .collect()
        } else {
            // With nothing stated, the usual case: English (US), Unicode.
            vec![(0x0409, 0x04b0)]
        }
    };
    for (lang, cp) in langs {
        let q = wide(&format!("\\StringFileInfo\\{lang:04x}{cp:04x}\\OriginalFilename"));
        let mut val: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut len = 0u32;
        let ok = unsafe { VerQueryValueW(data.as_ptr() as *const _, PCWSTR(q.as_ptr()), &mut val, &mut len).as_bool() };
        if ok && len > 0 && !val.is_null() {
            let s = unsafe { std::slice::from_raw_parts(val as *const u16, len as usize) };
            let s = String::from_utf16_lossy(s).trim_end_matches('\0').trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
    }
    None
}
