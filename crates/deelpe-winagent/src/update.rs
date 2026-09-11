//! Replace yourself when the central holds a different program ready.
//!
//! The road there already exists: the operator uploads the EXE in the
//! dashboard (`binaries.rs`), the agent reports the fingerprint of the
//! program it is running in every report, and gets back the checksum of the
//! program it is supposed to run (`AgentConfig::update_to_sha256`). Here
//! that turns into a file swap.
//!
//! **The checksum decides, not the connection.** The download goes over the
//! same mTLS connection as the report, but nothing is written until the
//! bytes add up to the announced checksum. Otherwise the central would be a
//! way to bring any program at all onto the staff's machines — and nobody
//! could check the arithmetic.
//!
//! The service is **not** restarted from here: the swap sets a flag, the
//! loop stops, and `service::serve` reports a failure to the service control
//! manager. Its recovery action restarts the service — set up in
//! `service::install` and reapplied on every `service start`. A service that
//! stops and starts itself would need rights on itself that a dedicated
//! service account precisely does not have.

use anyhow::{bail, Context, Result};
use deelpe_core::session::Session;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{info, warn};

/// This many times the same checksum is tried, then it is quiet until the
/// restart. Without the limit, an agent whose download keeps breaking
/// fetches four and a half megabytes on every report — and the central does
/// keep ordering the update, because it keeps seeing the old fingerprint.
const MAX_ATTEMPTS: u8 = 3;

static RESTART: AtomicBool = AtomicBool::new(false);

/// Has the program been swapped and is it waiting to be started?
/// `service::serve` asks when the loop comes back.
pub fn restart_requested() -> bool {
    RESTART.load(Ordering::Relaxed)
}

/// What is left of the update attempts between two rounds.
///
/// Deliberately in memory only: after a restart it may be tried again. The
/// restart is precisely what separates a swapped program from a failed
/// attempt.
#[derive(Default)]
pub struct Updater {
    tried: Option<(String, u8)>,
}

impl Updater {
    /// May this checksum (still) be downloaded? Counts the attempt right
    /// away. A different checksum starts over — the operator has then
    /// uploaded something else, and that may well be the thing that fixes
    /// the last failure.
    pub fn may_try(&mut self, sha: &str) -> bool {
        match &mut self.tried {
            Some((s, n)) if s == sha => {
                if *n >= MAX_ATTEMPTS {
                    return false;
                }
                *n += 1;
                true
            }
            _ => {
                self.tried = Some((sha.to_string(), 1));
                true
            }
        }
    }
}

/// One update if one is due: download, check, swap.
///
/// `Ok(true)` means: swapped, the service has to restart. `Ok(false)`
/// means: this checksum has been tried without success often enough.
pub async fn apply(session: &Session, want: &str, tries: &mut Updater) -> Result<bool> {
    // What comes in here comes off the wire. Before anything is computed,
    // truncated or downloaded with it, it has to have the shape it is
    // supposed to have: `short` cuts by bytes, and a string whose twelfth
    // byte sits in the middle of a character would otherwise take the whole
    // task down with it.
    if !is_sha256(want) {
        bail!("central announced something that is not a SHA-256: {want:?}");
    }
    if !tries.may_try(want) {
        return Ok(false);
    }
    let exe = std::env::current_exe().context("own path")?;
    // **Before** the download, not after. The swap needs write permission in
    // the program folder, and a service account that is not LocalSystem
    // usually does not have it there: the installer grants read and execute
    // on the file and modify on the data directory — on the folder nothing.
    // Whoever only notices that after downloading has fetched four and a
    // half megabytes for nothing, and does so on every attempt.
    can_replace(&exe)?;
    // And who starts the service again afterwards? A swap without a way to
    // restart replaces an outdated, running agent with none at all.
    #[cfg(windows)]
    crate::service::restart_is_arranged()?;
    info!(want = short(want), "central holds a different agent program, fetching it");
    let bytes = session.binary().await.context("downloading the agent program")?;
    verify(&bytes, want)?;
    swap(&exe, &bytes)?;
    RESTART.store(true, Ordering::Relaxed);
    info!(bytes = bytes.len(), want = short(want), "agent program replaced, restarting into the new one");
    Ok(true)
}

/// Does that even look like a SHA-256? Sixty-four hex digits, no more and
/// no less.
///
/// Stands before everything else in [`apply`], because `short` cuts by
/// **bytes**: a string whose twelfth byte sits in the middle of a character
/// would otherwise take the whole task down with it — and before anything
/// has been checked at that.
pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// May this process replace its own program?
///
/// What gets checked is what the swap really needs: creating a file in the
/// **program folder** and clearing it away again. A right on our own file is
/// not enough — `swap` puts `.new` next to it and renames twice, and both of
/// those are changes to the folder.
///
/// On 2026-09-10 on the lab DC: the service runs there as a domain account
/// and downloaded four and a half megabytes three times, only to fail on
/// this line afterwards.
pub fn can_replace(exe: &Path) -> Result<()> {
    let dir = exe.parent().ok_or_else(|| anyhow::anyhow!("{} has no folder", exe.display()))?;
    let probe = sibling(exe, "probe");
    std::fs::write(&probe, b"deelpe").map_err(|e| {
        anyhow::anyhow!(
            "cannot replace the program: {} is not writable for the account this service runs under ({e}).              Grant it modify on that folder, or roll the agent out the way you did before — see docs/INSTALL.md.",
            dir.display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Can this agent renew itself? As a status for the dashboard.
///
/// Sits next to the sensors because it is the same kind of statement:
/// something that has to be set up and may not be. Without it the dashboard
/// says "outdated" and "Update sent", and **why** nothing happens is found
/// only by whoever opens the device's log.
pub fn readiness() -> deelpe_core::central::SensorHealth {
    let out = std::env::current_exe()
        .map_err(anyhow::Error::from)
        .and_then(|e| can_replace(&e))
        // The two belong together: being allowed to write **and** being
        // started again. Whoever has only one of them swaps into nothing.
        .and_then(|()| {
            #[cfg(windows)]
            {
                crate::service::restart_is_arranged()
            }
            #[cfg(not(windows))]
            {
                Ok(())
            }
        });
    deelpe_core::central::SensorHealth {
        name: "self-update".into(),
        ok: out.is_ok(),
        error: out.err().map(|e| format!("{e:#}")),
    }
}

/// Are these the bytes the central announced?
pub fn verify(bytes: &[u8], want: &str) -> Result<()> {
    let got: String = Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect();
    if !got.eq_ignore_ascii_case(want.trim()) {
        bail!("checksum does not match: downloaded {got}, central announced {want}. nothing was written.");
    }
    Ok(())
}

/// Replace the running program with the new bytes.
///
/// A running file cannot be overwritten under Windows, but it can be
/// renamed — hence the three steps. The old one stays behind as `.old` and
/// is cleared away on the next start: until then it is what a human can copy
/// back if the new program does not come up.
pub fn swap(exe: &Path, bytes: &[u8]) -> Result<()> {
    let new = sibling(exe, "new");
    let old = sibling(exe, "old");
    // Write it **next to it**, not somewhere else and then move it in: a
    // file that comes into being in this folder inherits that folder's
    // access list. One that is moved in brings its own — and then the
    // service account may no longer read its own program and the service
    // starts with "access denied" without saying to what. That is exactly
    // what `service::repair_access` cleans up after on every start; here the
    // error does not arise in the first place.
    std::fs::write(&new, bytes).with_context(|| format!("writing {}", new.display()))?;
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old).with_context(|| format!("moving {} aside", exe.display()))?;
    if let Err(e) = std::fs::rename(&new, exe) {
        // Without this the service stands there without a program and never
        // starts again.
        let back = std::fs::rename(&old, exe);
        bail!(
            "could not put the new program in place ({e}); the old one is {}",
            if back.is_ok() { "back where it was" } else { "gone as well — restore it by hand" }
        );
    }
    Ok(())
}

/// Clear away the previous version.
///
/// **Only after an accepted report**, not at startup. That a program starts
/// says little — it can still fail afterwards on its configuration, on the
/// connection or on the first report. For exactly that case the previous
/// version is the net underneath, and a cleanup at startup would have cut
/// that net first thing. Whoever has reported in to the central once is
/// really running.
///
/// Costs one `exists()` per round after that; that is cheaper than a flag
/// somebody has to maintain.
pub fn cleanup_old() {
    let Ok(exe) = std::env::current_exe() else { return };
    let old = sibling(&exe, "old");
    if !old.exists() {
        return;
    }
    match std::fs::remove_file(&old) {
        Ok(()) => info!(path = %old.display(), "previous agent program removed"),
        // No reason to stop: the file bothers nobody, it is merely lying
        // around. Try again on the next start.
        Err(e) => warn!(path = %old.display(), "previous agent program stays: {e:#}"),
    }
}

/// `deelpe-winagent.exe` + `old` → `deelpe-winagent.exe.old`. The suffix is
/// **appended**, not replaced: a `deelpe-winagent.old` would be a second
/// program in the same folder, and a start script that works with wildcards
/// would find two.
fn sibling(exe: &Path, suffix: &str) -> PathBuf {
    let mut name = exe.file_name().unwrap_or_default().to_os_string();
    name.push(".");
    name.push(suffix);
    exe.with_file_name(name)
}

/// For the log: the first few digits are enough to recognise it.
fn short(sha: &str) -> &str {
    &sha[..sha.len().min(deelpe_core::central::BUILD_FINGERPRINT_HEX)]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_LEER: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Only what the central announced gets written. Without this check the
    /// connection to the central would be a way to bring an arbitrary
    /// program with system rights onto every machine.
    #[test]
    fn only_the_announced_bytes_pass() {
        assert!(verify(b"", SHA_LEER).is_ok());
        assert!(verify(b"", &SHA_LEER.to_uppercase()).is_ok(), "Schreibweise entscheidet nicht");
        assert!(verify(b"etwas anderes", SHA_LEER).is_err());
        assert!(verify(b"", "").is_err());
    }

    /// The swap: new program in its place, old one next to it.
    #[test]
    fn the_new_program_takes_the_place_and_the_old_one_waits_next_to_it() {
        let dir = std::env::temp_dir().join(format!("deelpe-update-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("deelpe-winagent.exe");
        std::fs::write(&exe, b"alt").unwrap();

        swap(&exe, b"neu").unwrap();

        assert_eq!(std::fs::read(&exe).unwrap(), b"neu");
        assert_eq!(std::fs::read(dir.join("deelpe-winagent.exe.old")).unwrap(), b"alt");
        assert!(!dir.join("deelpe-winagent.exe.new").exists(), "die Zwischendatei bleibt nicht liegen");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// What comes off the wire is not believed. `short` cuts by **bytes**: a
    /// checksum whose twelfth byte sits in the middle of a character would
    /// otherwise take the whole task down with it — and before anything has
    /// been checked at that. So the bolt sits right at the front of `apply`,
    /// before `may_try` and before the download.
    #[test]
    fn only_something_shaped_like_a_checksum_gets_that_far() {
        assert!(is_sha256(&"ab".repeat(32)));
        assert!(is_sha256(&"AB".repeat(32)));
        for junk in ["", "kurz", &"ü".repeat(32), &"zz".repeat(32), &"ab".repeat(33), &"ab".repeat(31)] {
            assert!(!is_sha256(junk), "{junk:?} ist keine SHA-256");
        }
        // And what gets through survives the truncation for the log.
        assert_eq!(short(&"ab".repeat(32)), "ababababababa"[..12].to_string());
    }

    /// Whoever may not write should notice it **before** the download.
    #[test]
    fn a_folder_that_cannot_be_written_is_found_before_anything_is_downloaded() {
        let dir = std::env::temp_dir().join(format!("deelpe-probe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("deelpe-winagent.exe");
        std::fs::write(&exe, b"alt").unwrap();
        can_replace(&exe).expect("ein beschreibbarer Ordner geht durch");
        // And the probe leaves nothing behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "nur die EXE bleibt liegen");

        // A folder that does not exist is just as unwritable as one without
        // permission — and the message names it.
        let gone = dir.join("weg").join("deelpe-winagent.exe");
        let e = can_replace(&gone).unwrap_err().to_string();
        assert!(e.contains("cannot replace the program"), "{e}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Three times, then quiet: an agent whose download keeps breaking would
    /// otherwise download again on every report — the central does keep
    /// ordering the same update, because it keeps seeing the old
    /// fingerprint.
    #[test]
    fn the_same_checksum_is_not_tried_forever() {
        let mut u = Updater::default();
        assert!(u.may_try("aa"));
        assert!(u.may_try("aa"));
        assert!(u.may_try("aa"));
        assert!(!u.may_try("aa"));
        assert!(!u.may_try("aa"));
        // Something else uploaded: that may be exactly the thing that fixes
        // the failure.
        assert!(u.may_try("bb"));
    }
}
