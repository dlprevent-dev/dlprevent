//! Machines reset to their image every night: terminal servers, Citrix and
//! VDI pools. Nothing the agent writes survives the night, so it enrolls
//! again on every boot — with the token from [`Bootstrap`], which the image
//! carries — and the central server hands back the agent this machine was
//! yesterday, together with the state it kept for it ([`Roaming`]).
//!
//! [`Roaming`]: crate::config::Roaming

use crate::config::{self, needs_enrollment, AgentState, Bootstrap, CentralConfig};
use anyhow::{bail, Result};
use deelpe_core::central::AgentKind;
use tokio::sync::watch;
use tracing::{info, warn};

/// Longest wait between two attempts. At boot the network is often not up
/// yet; after that, a central server that is down for maintenance should
/// not be hammered by a whole pool.
const MAX_WAIT_SECS: u64 = 300;

/// Enroll and put credentials and state where the agent looks for them.
/// The state on disk is replaced, not merged: whatever lies there belongs
/// to another identity — the master's, or none.
pub async fn enroll(b: &Bootstrap, hostname: &str) -> Result<CentralConfig> {
    let mut e = deelpe_core::net::enroll(
        &b.url,
        &b.token,
        &b.ca_sha256,
        hostname,
        AgentKind::WindowsClient,
        env!("CARGO_PKG_VERSION"),
    )
    .await?;
    if !e.non_persistent {
        bail!("the token is not one for non-persistent machines — make one in the dashboard with \"Non-persistent\" ticked");
    }
    let roaming = e.roaming.take();
    let cfg = CentralConfig::from_enrolled(e, AgentKind::WindowsClient, hostname);
    AgentState::from_roaming(roaming, chrono::Utc::now()).save()?;
    cfg.save()?;
    Ok(cfg)
}

/// Before the agent runs: enroll if this is a non-persistent machine whose
/// credentials are not its own (see [`needs_enrollment`]). Tries until it
/// works or the service is stopped; `false` means stopped.
pub async fn ensure_enrolled(stop: &mut watch::Receiver<bool>) -> Result<bool> {
    let Some(b) = Bootstrap::load()? else {
        return Ok(true);
    };
    let host = config::hostname();
    if !needs_enrollment(CentralConfig::load()?.as_ref(), &host) {
        return Ok(true);
    }
    let mut wait = 5u64;
    loop {
        match enroll(&b, &host).await {
            Ok(cfg) => {
                info!(
                    agent_id = cfg.agent_id,
                    host, "non-persistent machine enrolled"
                );
                return Ok(true);
            }
            Err(e) => {
                warn!("enrollment of the non-persistent machine failed, again in {wait} s: {e:#}")
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
            _ = stop.changed() => return Ok(false),
        }
        wait = (wait * 2).min(MAX_WAIT_SECS);
    }
}
