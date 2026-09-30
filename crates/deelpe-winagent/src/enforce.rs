//! Intervention at the endpoint: lock and delete the copy that has just come
//! into being. Nobody kills the sending process here any more since
//! 2026-09-09 — see the addendum to ADR 0002.
//!
//! More than that is not possible today without a signed driver. It is a
//! mop-up, not a prevention — event tracing reports the send after it has
//! happened. With a large upload it breaks off in the middle, with a small
//! file the file is gone and the alert is what remains.
//!
//! In a mop-up what counts is therefore how short the window is in which the
//! copy sits there readable. Deleting alone does not make it short: the
//! copier still holds the target file open, and [`delete_copy_later`] keeps
//! trying for up to ten seconds. That is why [`lock_copy`] goes first —
//! changing the permissions works on an open file too.
//!
//! Before the first byte, the network cage in [`crate::wfp`] blocks: a filter
//! of the Windows Filtering Platform at the ALE layer, bound to the process's
//! EXE. It does not replace this mop-up — it bites at connection *setup*, and
//! it never sees a connection that is already open. That one runs to the end
//! and gets reported; cutting it off would mean killing the process, and that
//! is exactly what cost the user their desktop twice on 2026-09-09.

use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
/// Processes that every intervention goes past, no matter what the rule says.
/// Whoever cripples them cripples the machine or the remote access - and a
/// DLP tool that shoots the machine down is worse than the leak. `sshd` is in
/// there deliberately: in the lab its death took the whole remote access with
/// it.
///
/// Since 2026-09-09 no process is killed any more; what has stayed is the
/// cage, and taking the network away from an `svchost.exe` is the same damage
/// with more steps. The only reader of this list is therefore
/// [`crate::wfp::may_cage`].
const CRITICAL: &[&str] = &[
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "sshd.exe",
    "explorer.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "conhost.exe",
    "runtimebroker.exe",
    "deelpe-winagent.exe",
];

/// Is this a process that every intervention has to go past?
///
/// The agent's most safety-critical decision: if it comes out wrong, the
/// machine stops. It is pure logic and runs **before** the first system call
/// — which is why it sits apart from the execution and is checked on every
/// platform, not only under Windows.
///
/// The comparison is **exact**, in the form from
/// [`deelpe_core::identity::image_name`] — lower-cased and without Windows'
/// `.mui`. The name alone would spare an EXE of one's own called
/// `explorer.exe`; the cage therefore believes it only for a file that
/// belongs to the system or an installer (`wfp::name_is_vouched_for`). Where
/// that cannot be told, sparing stays the direction: reporting an outflow
/// instead of intervening is the cheaper mistake than crippling a machine.
///
/// Without a name the answer is yes. If the signature check yields no image
/// path, the name is empty -- and an empty name used to be on no list at all,
/// which made every unreadable process fair game.
pub fn is_critical(name: &str) -> bool {
    if name.trim().is_empty() {
        return true;
    }
    let low = deelpe_core::identity::image_name(name);
    CRITICAL.iter().any(|n| low == *n)
}

/// Where a file really lies is inside a protected folder: the question
/// every touch of a copy asks first. A closure over the configuration, so the
/// background retry can carry it along.
pub type Protected = std::sync::Arc<dyn Fn(&Path) -> bool + Send + Sync>;

/// What became of a copy.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    Done,
    /// Was already gone.
    Gone,
    /// Leads — through a junction or a link — into a protected folder, to
    /// this file. Left alone (pentest 8840/0004).
    Refused(PathBuf),
}

/// Remove the copy that has just come into being — the intervention for a
/// copy out of a strict folder onto the local disk, a stick or a network
/// drive. Stopping the copying process does not help there: that is Explorer,
/// and it is on [`CRITICAL`] for good reason.
///
/// Where the file really lies is decided on the file itself, not on its
/// spelling: through a junction a path outside leads into the share, and the
/// service would delete the real file there as SYSTEM. On Windows the file
/// is opened once, checked by the path of the open handle and deleted
/// through that same handle, so no folder can be swapped for a junction in
/// between.
pub fn delete_copy(path: &Path, protected: &Protected) -> Result<Outcome> {
    let out = remove(path, protected);
    match &out {
        Ok(Outcome::Done) => {
            tracing::warn!("BLOCKED: copy {} deleted (strict folder)", path.display())
        }
        Ok(Outcome::Refused(real)) => tracing::error!(
            "copy {} leads into the protected folder ({}); not deleted",
            path.display(),
            real.display()
        ),
        _ => {}
    }
    out
}

#[cfg(windows)]
fn remove(path: &Path, protected: &Protected) -> Result<Outcome> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    const DELETE: u32 = 0x0001_0000;
    let f = match open_checked(path, DELETE, protected) {
        Ok(Ok(f)) => f,
        Ok(Err(real)) => return Ok(Outcome::Refused(real)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::Gone),
        Err(e) => bail!("delete {}: {e}", path.display()),
    };
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(f.as_raw_handle()),
            FileDispositionInfo,
            &info as *const _ as *const std::ffi::c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|e| anyhow::anyhow!("delete {}: {e}", path.display()))?;
    // Gone once the handle closes.
    Ok(Outcome::Done)
}

/// Elsewhere by path: resolve, check, delete. The agent runs on Windows;
/// this keeps the decision testable on every machine.
#[cfg(not(windows))]
fn remove(path: &Path, protected: &Protected) -> Result<Outcome> {
    let real = match resolved(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::Gone),
        Err(e) => bail!("delete {}: {e}", path.display()),
    };
    if protected(&real) {
        return Ok(Outcome::Refused(real));
    }
    match std::fs::remove_file(&real) {
        Ok(()) => Ok(Outcome::Done),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Outcome::Gone),
        Err(e) => bail!("delete {}: {e}", path.display()),
    }
}

/// Open the file with `access` (sharing everything, so the copier holding it
/// is no obstacle where it need not be) and say where the open file really
/// lies. `Ok(Err(real))` when that is inside a protected folder.
#[cfg(windows)]
fn open_checked(
    path: &Path,
    access: u32,
    protected: &Protected,
) -> std::io::Result<Result<std::fs::File, PathBuf>> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS,
        VOLUME_NAME_DOS,
    };
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    const SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
    let f = std::fs::OpenOptions::new()
        .access_mode(access | FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_ALL)
        .open(path)?;
    let mut buf = vec![0u16; 1024];
    loop {
        let n = unsafe {
            GetFinalPathNameByHandleW(
                HANDLE(f.as_raw_handle()),
                &mut buf,
                GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
            )
        } as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n < buf.len() {
            buf.truncate(n);
            break;
        }
        buf.resize(n + 1, 0);
    }
    let real = PathBuf::from(plain(&String::from_utf16_lossy(&buf)));
    Ok(if protected(&real) { Err(real) } else { Ok(f) })
}

/// Access list for a copy that is to go.
///
/// In it are SYSTEM, the administrators and — if the service runs under a
/// dedicated account — that account. **Not** in it is the user who did the
/// copying: that is exactly the point. `P` switches inheritance off,
/// otherwise the target folder's access list pulls them straight back in.
///
/// Administrators stay on purpose: whoever is a local administrator takes
/// ownership back anyway, and without them the operator could no longer get
/// at a copy that stayed behind.
fn quarantine_sddl(own: Option<&str>) -> String {
    let mut s = String::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)");
    // SYSTEM and the administrators are already in there.
    if let Some(sid) = own.filter(|s| *s != "S-1-5-18" && *s != "S-1-5-32-544") {
        s.push_str(&format!("(A;;FA;;;{sid})"));
    }
    s
}

/// Lock the copy: from now on nobody except the service can open it any
/// more. The intervention for the window in which it is still there.
///
/// The reason this succeeds where [`delete_copy`] fails: the NTFS sharing
/// check (`ERROR_SHARING_VIOLATION`) applies to reading, writing and deleting
/// — not to `WRITE_DAC`. So the permission change gets through **while** the
/// copier still holds the file open. Without it the copy would lie readable
/// on the desktop for up to ten seconds while [`delete_copy_later`] tries
/// twenty times in vain.
///
/// Two limits that belong in the telling:
/// - Whoever **already has the file open** keeps their access. The permission
///   check runs at open time, not on every read.
/// - On FAT and exFAT — that is, on most sticks — there is no access list.
///   There this fails, and deleting is all that is left.
///
/// Elsewhere there is no access list to set; the copy is deleted all the
/// same. The verdict on that is in [`quarantine_sddl`].
#[cfg(not(windows))]
pub fn lock_copy(path: &Path, protected: &Protected) -> Result<Outcome> {
    match resolved(path) {
        Ok(real) if protected(&real) => Ok(Outcome::Refused(real)),
        Ok(_) => Ok(Outcome::Done),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Outcome::Gone),
        Err(e) => bail!("lock {}: {e}", path.display()),
    }
}

/// On Windows through the handle, like [`delete_copy`]: checked where the
/// open file really lies, and the access list set on exactly that file.
#[cfg(windows)]
pub fn lock_copy(path: &Path, protected: &Protected) -> Result<Outcome> {
    use anyhow::Context;
    use std::os::windows::io::AsRawHandle;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    const WRITE_DAC: u32 = 0x0004_0000;

    let f = match open_checked(path, WRITE_DAC, protected) {
        Ok(Ok(f)) => f,
        Ok(Err(real)) => return Ok(Outcome::Refused(real)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::Gone),
        Err(e) => bail!("lock {}: {e}", path.display()),
    };
    let sddl = HSTRING::from(quarantine_sddl(crate::config::own_sid().as_deref()));
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .context("SDDL for the quarantined copy")?;
    }
    let r = unsafe {
        SetKernelObjectSecurity(
            HANDLE(f.as_raw_handle()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            psd,
        )
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    r.with_context(|| format!("lock {}", path.display()))?;
    tracing::warn!("BLOCKED: copy {} locked (strict folder)", path.display());
    Ok(Outcome::Done)
}

/// Where a path really leads — through junctions and symbolic links — in
/// the spelling the rules use: without the `\\?\` that Windows puts in
/// front of a resolved path.
#[cfg(not(windows))]
fn resolved(path: &Path) -> std::io::Result<PathBuf> {
    Ok(PathBuf::from(plain(
        &std::fs::canonicalize(path)?.to_string_lossy(),
    )))
}

/// `\\?\C:\x` → `C:\x`, `\\?\UNC\srv\gl\x` → `\\srv\gl\x`.
fn plain(s: &str) -> String {
    match s.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => s.strip_prefix(r"\\?\").unwrap_or(s).to_string(),
    }
}

/// Second attempt in the background: the first time round the copying process
/// often still holds the target file open, and Windows then does not let it
/// be deleted. The callback must not stall for that, otherwise events get
/// lost — hence a task of its own instead of a wait loop inside the event
/// loop.
pub fn delete_copy_later(path: PathBuf, protected: Protected) {
    tokio::spawn(async move {
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            // Checked again on every attempt, on the file itself: a folder on
            // the way swapped for a junction since is refused, not followed.
            match delete_copy(&path, &protected) {
                Ok(Outcome::Done | Outcome::Gone | Outcome::Refused(_)) => return,
                Err(e) => tracing::warn!("copy still there: {e:#}"),
            }
        }
        tracing::error!("copy {} could NOT be deleted", path.display());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resolved_windows_path_loses_its_prefix() {
        assert_eq!(
            plain(r"\\?\C:\Freigaben\GL\a.docx"),
            r"C:\Freigaben\GL\a.docx"
        );
        assert_eq!(plain(r"\\?\UNC\fs-01\GL\a.docx"), r"\\fs-01\GL\a.docx");
        assert_eq!(plain("/Users/me/a"), "/Users/me/a");
    }

    /// Every entry of the list is spared, in every spelling.
    /// Until 2026-09-08 nobody checked that: the list sat in the same
    /// function as `TerminateProcess` and was only reachable on a real
    /// Windows machine with real processes.
    #[test]
    fn critical_processes_are_never_stopped() {
        for name in CRITICAL {
            assert!(is_critical(name), "{name} muesste verschont werden");
            assert!(
                is_critical(&name.to_uppercase()),
                "{name} in Grossschreibung"
            );
        }
        // Spot checks that would be expensive in the lab: the remote access
        // and the logon.
        assert!(is_critical("SSHD.exe"));
        assert!(is_critical("LsaSS.EXE"));
        // And the agent itself — otherwise nobody warns from there on.
        assert!(is_critical("deelpe-winagent.exe"));
    }

    /// Windows likes to append a `.mui` to the names from the resource
    /// table. On 2026-09-09 Explorer's identity came in as
    /// `EXPLORER.EXE.MUI`, the list compared exactly, and the agent shot the
    /// user's desktop down twice — 06:15 and 08:02 UTC, each time for 330
    /// respectively 446 bytes of telemetry to Microsoft.
    #[test]
    fn a_windows_resource_name_still_names_the_process() {
        assert!(
            is_critical("EXPLORER.EXE.MUI"),
            "der Explorer, wie er wirklich hereinkommt"
        );
        assert!(is_critical("svchost.exe.mui"));
        assert!(is_critical("LSASS.EXE.MUI"));
        // An ordinary program stays stoppable, suffix or no suffix.
        assert!(!is_critical("curl.exe.mui"));
    }

    /// If the signature check yields no image path, the name is empty -- and
    /// an empty name was on none of the protection lists. That made every
    /// process whose EXE the agent cannot read fair game.
    #[test]
    fn a_sender_without_a_name_is_never_stopped() {
        for name in ["", "   "] {
            assert!(is_critical(name), "leerer Name: {name:?}");
        }
    }

    /// The comparison is exact, not "contains". Otherwise a substring hit
    /// would spare arbitrary programs.
    #[test]
    fn only_an_exact_name_is_spared() {
        assert!(!is_critical("curl.exe"));
        assert!(!is_critical("notexplorer.exe"));
        assert!(!is_critical("explorer.exe.bak"));
        assert!(!is_critical("my-lsass.exe"));
    }

    /// The locked copy has to stay reachable for the service — otherwise it
    /// can no longer delete it afterwards, and the lock would turn into an
    /// undeletable leftover on the desktop. The copying user is not in it,
    /// and the target folder's inheritance is off.
    #[test]
    fn a_locked_copy_stays_reachable_for_the_service() {
        let s = quarantine_sddl(None);
        assert!(s.starts_with("D:P"), "Vererbung muss aus sein: {s}");
        assert!(
            s.contains("(A;;FA;;;SY)"),
            "SYSTEM muss loeschen koennen: {s}"
        );
        assert!(
            s.contains("(A;;FA;;;BA)"),
            "Administratoren bleiben drin: {s}"
        );
        assert_eq!(s.matches("(A;").count(), 2, "niemand sonst: {s}");
        // A dedicated service account is added; the built-in ones not twice.
        assert!(
            quarantine_sddl(Some("S-1-5-21-1-2-3-1001")).ends_with("(A;;FA;;;S-1-5-21-1-2-3-1001)")
        );
        assert_eq!(
            quarantine_sddl(Some("S-1-5-18")),
            s,
            "SYSTEM steht schon drin"
        );
        assert_eq!(
            quarantine_sddl(Some("S-1-5-32-544")),
            s,
            "Administratoren stehen schon drin"
        );
    }

    /// Pentest 8840/0004 at the function every path goes through, the retry
    /// included: a copy that leads into the protected folder is neither
    /// locked nor deleted. A symbolic link stands in for the junction.
    #[cfg(unix)]
    #[test]
    fn a_copy_that_leads_into_the_share_is_neither_locked_nor_deleted() {
        let dir = std::env::temp_dir().join(format!("deelpe-enforce-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let share = dir.join("GL");
        std::fs::create_dir_all(&share).unwrap();
        let share = std::fs::canonicalize(&share).unwrap();
        std::fs::write(share.join("a.docx"), b"real").unwrap();
        std::os::unix::fs::symlink(&share, dir.join("in")).unwrap();
        let inside = share.clone();
        let protected: Protected = std::sync::Arc::new(move |p: &Path| p.starts_with(&inside));
        let via = dir.join("in").join("a.docx");
        assert_eq!(
            lock_copy(&via, &protected).unwrap(),
            Outcome::Refused(share.join("a.docx"))
        );
        assert_eq!(
            delete_copy(&via, &protected).unwrap(),
            Outcome::Refused(share.join("a.docx"))
        );
        assert!(share.join("a.docx").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// "Was already gone" is not an error: the caller may knock on every
    /// report, and `delete_copy_later` tries twenty times.
    #[test]
    fn deleting_a_copy_that_is_gone_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("deelpe-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("kopie.txt");
        let none: Protected = std::sync::Arc::new(|_: &Path| false);
        assert_eq!(
            delete_copy(&f, &none).unwrap(),
            Outcome::Gone,
            "nicht vorhanden"
        );
        std::fs::write(&f, b"geheim").unwrap();
        assert_eq!(delete_copy(&f, &none).unwrap(), Outcome::Done, "vorhanden");
        assert!(!f.exists(), "die Kopie ist weg");
        assert_eq!(
            delete_copy(&f, &none).unwrap(),
            Outcome::Gone,
            "und bleibt weg"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
