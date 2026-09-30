//! Decoding of the paths and number formats that come out of Windows event
//! tracing. Pure logic, which is why it lives here and not in the `windows`
//! module: it gets tested on the Mac, where the agent is built.
//!
//! ETW delivers **kernel paths**, not paths as a human knows them:
//!
//! | ETW | means |
//! |---|---|
//! | `\Device\HarddiskVolume3\Users\hans\a.txt` | `C:\Users\hans\a.txt` |
//! | `\Device\Mup\srv01\GL\zahlen.xlsx` | `\\srv01\GL\zahlen.xlsx` |
//! | `\Device\LanmanRedirector\srv01\GL\a.docx` | `\\srv01\GL\a.docx` |
//!
//! The third row is the case that matters: a file on the file server, read
//! from a workstation. Without this conversion no rule path matches, and
//! the protected folder would stay invisible.

use std::collections::HashMap;

/// The two names under which the SMB redirector shows up in the kernel.
const REDIRECTORS: &[&str] = &[r"\device\mup", r"\device\lanmanredirector"];

/// Translate a kernel path into a path as it appears in a rule.
///
/// `volumes` maps `\Device\HarddiskVolumeN` onto the drive letter (`C:`);
/// on Windows that table comes from `QueryDosDeviceW`. A path that matches
/// nothing comes back unchanged: better a kernel path in the alert than no
/// alert at all.
pub fn to_user_path(kernel: &str, volumes: &HashMap<String, String>) -> String {
    let lower = kernel.to_lowercase();
    for r in REDIRECTORS {
        if let Some(rest) = lower.strip_prefix(r) {
            if rest.is_empty() || rest.starts_with('\\') {
                // Keep the original's casing, replace only the head.
                return unc(&kernel[r.len()..]);
            }
        }
    }
    // The redirector also reports without a device name in front, in which
    // case the path starts right at the semicolon section — with one
    // separator or with two, depending on the version.
    if lower.trim_start_matches('\\').starts_with(';') {
        return unc(kernel);
    }
    // Longest match first: HarddiskVolume1 must not match
    // HarddiskVolume11.
    let mut keys: Vec<&String> = volumes.keys().collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.len()));
    for k in keys {
        let kl = k.to_lowercase();
        if let Some(rest) = lower.strip_prefix(&kl) {
            if rest.is_empty() || rest.starts_with('\\') {
                return format!("{}{}", volumes[k], &kernel[k.len()..]);
            }
        }
    }
    kernel.to_string()
}

/// Turn the remainder behind the redirector into `\\server\share\…`.
///
/// In between sit **sections with a semicolon**, when the share hangs off a
/// drive letter:
///
/// ```text
/// \Device\Mup\;LanmanRedirector\;X:000000000285daa0\srv01\GL\a.txt
///               ^^^^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^
/// ```
///
/// They belong to the mapping, not to the location. If they stayed, the
/// path would be `\\;LanmanRedirector\;X:000000000285daa0\srv01\GL\a.txt`
/// — and that matches no rule. Measured exactly like this in the lab on
/// 2026-09-08: the same file opened over the UNC path arrived as
/// `\\srv\freigabe\…` and was detected, while over the mapped letter it
/// stayed invisible. Because group policy puts the shares on drive letters,
/// that made *every* access from the workstations invisible.
///
/// A server name with a leading semicolon is not possible on Windows, so
/// the loop cannot throw away anything real.
fn unc(rest: &str) -> String {
    let mut s = rest.trim_start_matches('\\');
    while s.starts_with(';') {
        s = s.split_once('\\').map(|(_, r)| r).unwrap_or("");
    }
    format!(r"\\{s}")
}

/// UTF-16 string from raw bytes, up to the first null.
pub fn utf16_from_bytes(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// IPv4 or IPv6 from the raw bytes of an address field.
pub fn ip_from_bytes(b: &[u8]) -> Option<std::net::IpAddr> {
    match b.len() {
        4 => Some(std::net::IpAddr::from([b[0], b[1], b[2], b[3]])),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b[..16]);
            Some(std::net::IpAddr::from(a))
        }
        _ => None,
    }
}

/// In the network events, port numbers are in network byte order (big
/// endian). Without this swap, 443 turns into 47873 and no allowlist
/// matches.
pub fn port_from_bytes(b: &[u8]) -> Option<u16> {
    if b.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vols() -> HashMap<String, String> {
        HashMap::from([
            (r"\Device\HarddiskVolume1".to_string(), "C:".to_string()),
            (r"\Device\HarddiskVolume11".to_string(), "D:".to_string()),
        ])
    }

    #[test]
    fn share_paths_become_unc() {
        assert_eq!(
            to_user_path(r"\Device\Mup\srv01\GL\zahlen.xlsx", &vols()),
            r"\\srv01\GL\zahlen.xlsx"
        );
        assert_eq!(
            to_user_path(r"\Device\LanmanRedirector\srv01\GL\a.docx", &vols()),
            r"\\srv01\GL\a.docx"
        );
        // Casing arrives differently depending on the version.
        assert_eq!(
            to_user_path(r"\DEVICE\MUP\srv01\GL\a", &vols()),
            r"\\srv01\GL\a"
        );
    }

    #[test]
    fn a_mapped_drive_is_still_the_share_it_points_at() {
        // Measured on 2026-09-08 on a Windows 11 client, share on X:.
        assert_eq!(
            to_user_path(
                r"\Device\Mup\;LanmanRedirector\;X:000000000285daa0\127.0.0.1\c$\dlptest\a.txt",
                &vols()
            ),
            r"\\127.0.0.1\c$\dlptest\a.txt"
        );
        assert_eq!(
            to_user_path(
                r"\Device\LanmanRedirector\;G:0000000000012345\srv01\GL\zahlen.xlsx",
                &vols()
            ),
            r"\\srv01\GL\zahlen.xlsx"
        );
        // Also without a device name in front.
        assert_eq!(
            to_user_path(
                r"\\;LanmanRedirector\;X:000000000285daa0\srv01\GL\a",
                &vols()
            ),
            r"\\srv01\GL\a"
        );
        // Without a drive letter it stays as it was.
        assert_eq!(
            to_user_path(r"\Device\Mup\srv01\GL\a", &vols()),
            r"\\srv01\GL\a"
        );
    }

    #[test]
    fn volumes_use_the_longest_match() {
        assert_eq!(
            to_user_path(r"\Device\HarddiskVolume1\Users\hans\a.txt", &vols()),
            r"C:\Users\hans\a.txt"
        );
        // Without "longest first" this one ended up on C: instead of D:.
        assert_eq!(
            to_user_path(r"\Device\HarddiskVolume11\Daten\b.txt", &vols()),
            r"D:\Daten\b.txt"
        );
        // No partial match in the middle of a name.
        assert_eq!(
            to_user_path(r"\Device\HarddiskVolume1Extra\x", &vols()),
            r"\Device\HarddiskVolume1Extra\x"
        );
    }

    #[test]
    fn unknown_paths_survive_unchanged() {
        assert_eq!(
            to_user_path(r"\Device\Something\x", &vols()),
            r"\Device\Something\x"
        );
        assert_eq!(to_user_path("", &vols()), "");
    }

    #[test]
    fn payload_decoding() {
        let utf16: Vec<u8> = "GL\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(utf16_from_bytes(&utf16), "GL");
        assert_eq!(utf16_from_bytes(&[]), "");
        assert_eq!(
            ip_from_bytes(&[10, 0, 0, 7]).unwrap().to_string(),
            "10.0.0.7"
        );
        assert_eq!(
            ip_from_bytes(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
                .unwrap()
                .to_string(),
            "2001:db8::1"
        );
        assert!(ip_from_bytes(&[1, 2, 3]).is_none());
        // 443 = 0x01BB, big endian.
        assert_eq!(port_from_bytes(&[0x01, 0xBB]).unwrap(), 443);
        assert!(port_from_bytes(&[1]).is_none());
    }
}
