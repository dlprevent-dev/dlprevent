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

use anyhow::{Context, Result};
use deelpe_core::session::Session;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::info;

// Checking, swapping and the attempt counter are shared with the Linux
// service; see `deelpe_core::update`.
pub use deelpe_core::update::{can_replace, cleanup_old, Updater};
use deelpe_core::update::{is_sha256, short, swap, verify};

static RESTART: AtomicBool = AtomicBool::new(false);

/// Has the program been swapped and is it waiting to be started?
/// `service::serve` asks when the loop comes back.
pub fn restart_requested() -> bool {
    RESTART.load(Ordering::Relaxed)
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
        anyhow::bail!("central announced something that is not a SHA-256: {want:?}");
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

