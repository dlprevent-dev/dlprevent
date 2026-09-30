//! An agent's session with the central server: send, endure the failure,
//! renew the certificate, keep to the cadence.
//!
//! Lives here because there are **three** agents turning the same loop —
//! the Mac service, the Windows file server and the Windows workstation —
//! and it had drifted apart into three versions: only one waited longer
//! after a failure, only one set the log's read pointer at the same place,
//! and each one clamped the interval for itself.
//!
//! The rule this is about now stands in one place: **nothing is adopted
//! until the central server has accepted the report.** Otherwise the lines
//! of a failed transmission are lost — and those are exactly the ones that
//! explain why it failed.
//!
//! What every agent keeps for itself stays with it: its backlog, its state
//! file, its error message for the dashboard. The session owns only what
//! all three have to do the same way.

use crate::central::{Report, ReportResponse};
use crate::net::{renew_if_due, Client, Credentials};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

/// The four numbers every agent keeps about its reports.
///
/// They stood separately in both state types — `CentralState` in the Mac
/// service and `AgentState` in the Windows agent — and were carried
/// forward by hand in three places: three lines each for success, two for
/// failure. Six executions of the same bookkeeping.
///
/// `#[serde(flatten)]` at the callers keeps the files on disk unchanged:
/// the same four keys at the same level. No agent loses its counter
/// reading on an update.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Tally {
    /// **Accepted** reports, not attempts.
    #[serde(default)]
    pub reports: u64,
    #[serde(default)]
    pub last_ok: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub last_error_at: Option<DateTime<Utc>>,
}

impl Tally {
    /// The central server has accepted the report.
    pub fn ok(&mut self, now: DateTime<Utc>) {
        self.reports += 1;
        self.last_ok = Some(now);
        self.last_error = None;
    }

    /// The report did not arrive. The counter stays put — what gets
    /// counted is what arrived. `last_ok` stays put as well: it answers
    /// "last heard from when", not "last tried when".
    pub fn failed(&mut self, err: &anyhow::Error, now: DateTime<Utc>) {
        self.last_error = Some(format!("{err:#}"));
        self.last_error_at = Some(now);
    }
}

/// Limits for the interval the central server hands out. An agent that is
/// accidentally sent a `0` must not send continuously.
pub const MIN_INTERVAL_SECS: u64 = 10;
pub const MAX_INTERVAL_SECS: u64 = 3600;
/// Without an answer the pause grows longer, instead of running against a
/// dead line once a second. On the first failure the starting value
/// doubles, and on from there up to [`BACKOFF_MAX_SECS`].
///
/// It starts at **one** second: a break usually does not last a minute — a
/// tunnel being restarted, a network that is briefly gone —, and whoever
/// then waits half a minute stands in the dashboard as "offline" for
/// minutes on end, even though the line has long been back up.
const BACKOFF_START_SECS: u64 = 1;
/// Upper bound of the pause. It only takes effect if the central server
/// has handed out an even longer cadence; otherwise the normal report
/// cadence already caps [`Session::wait`].
const BACKOFF_MAX_SECS: u64 = 60;

/// Default until the central server's first answer names an interval.
const DEFAULT_INTERVAL_SECS: u64 = 30;

/// Where this agent puts its credentials.
///
/// The session renews the certificate; **where** it belongs only the agent
/// knows. Until 2026-09-10 every caller therefore passed in the same
/// closure on *every* `send` — three times the same thing character for
/// character, in the Mac service, in the workstation agent and in the file
/// server agent. Saying it once at construction is enough.
///
/// Store first, then it counts: if saving fails, the old certificate stays
/// — and that one is still valid during the central server's grace period.
pub trait CredentialStore: Send + Sync {
    fn store(&mut self, fresh: &Credentials) -> Result<()>;
}

pub struct Session {
    client: Client,
    /// Where fresh credentials belong. See [`CredentialStore`].
    store: Box<dyn CredentialStore>,
    creds: Credentials,
    hostname: String,
    user_agent: String,
    /// How far the local log has been reported. Deliberately in memory
    /// only: after a restart the ring is empty anyway.
    log_seq: u64,
    /// Attempts since the last accepted report.
    failures: u32,
    backoff: u64,
    interval: u64,
}

impl Session {
    pub fn new(
        creds: Credentials,
        hostname: impl Into<String>,
        user_agent: impl Into<String>,
        store: Box<dyn CredentialStore>,
    ) -> Result<Self> {
        let user_agent = user_agent.into();
        Ok(Self {
            client: Client::with_user_agent(&creds, &user_agent)?,
            store,
            creds,
            hostname: hostname.into(),
            user_agent,
            log_seq: 0,
            failures: 0,
            backoff: BACKOFF_START_SECS,
            interval: DEFAULT_INTERVAL_SECS,
        })
    }

    pub fn url(&self) -> &str {
        &self.creds.url
    }

    /// Attempts since the last accepted report; 0 means "the line is up".
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// How long until the next attempt: the central server's interval as
    /// long as it answers — otherwise the growing pause.
    ///
    /// The pause never grows longer than the normal cadence. A dead line
    /// therefore costs at most as many attempts as a healthy agent sends
    /// reports, and a line that comes back never waits longer than one
    /// ordinary report cadence for somebody to notice. Before, the pause
    /// grew up to five minutes: the agent had long been reachable again
    /// and still stood there as "offline".
    pub fn wait(&self) -> Duration {
        Duration::from_secs(if self.failures > 0 { self.backoff.min(self.interval) } else { self.interval })
    }

    /// Fetch the agent program that lies ready. Over the same connection
    /// as the report, with the same certificate. With it the release
    /// statement, when the central server has one.
    pub async fn binary(&self) -> Result<(Vec<u8>, Option<String>)> {
        self.client.binary().await
    }

    /// Send a report.
    ///
    /// The session appends the new log lines itself and adopts the read
    /// pointer **only on acceptance**; it clamps the interval from the
    /// answer, counts failed attempts and writes them into the log. After
    /// that it renews the certificate when the time has come — regardless
    /// of whether the report was accepted: all that needs is the
    /// connection. A report the central server rejects permanently (a
    /// different API version after a server update, a packet that is too
    /// big) would otherwise use up the renewal window and lock the agent
    /// out.
    ///
    /// New credentials are stored by the [`CredentialStore`] this session
    /// was given at construction.
    pub async fn send(&mut self, report: &mut Report) -> Result<ReportResponse> {
        // Fetched last, so that this round's lines go along too.
        let (log_next, log) = crate::agentlog::since(self.log_seq);
        report.log = log;
        let out = self.client.report(report).await;
        match &out {
            Ok(resp) => {
                if self.failures > 0 {
                    info!(attempts = self.failures, central = %self.creds.url, "central answers again");
                }
                self.accepted(resp, log_next);
            }
            Err(e) => {
                // Every attempt into the log, not only the first: the
                // dashboard should show that the agent keeps trying — and
                // what it fails on.
                self.rejected();
                warn!(attempt = self.failures, central = %self.creds.url, "report not accepted: {e:#}");
            }
        }
        self.renew().await;
        out
    }

    /// Accepted: adopt the read pointer, follow the central server's
    /// cadence, reset the pause.
    fn accepted(&mut self, resp: &ReportResponse, log_next: u64) {
        self.log_seq = log_next;
        self.interval = (resp.config.report_interval_secs as u64).clamp(MIN_INTERVAL_SECS, MAX_INTERVAL_SECS);
        self.backoff = BACKOFF_START_SECS;
        self.failures = 0;
    }

    /// Rejected: the read pointer stays put — this attempt's lines go
    /// along once more with the next one.
    fn rejected(&mut self) {
        self.failures += 1;
        self.backoff = (self.backoff * 2).min(BACKOFF_MAX_SECS);
    }

    /// Renew the agent's own certificate in time. Without that it is over
    /// after 730 days: the handshake fails, the agent looks like a
    /// switched-off device in the central server, and only a fresh
    /// enrollment by hand helps.
    ///
    /// Save first, then rebuild the client. If the client cannot be built
    /// with the fresh certificate, it stays standing on the old one — it
    /// is saved, and the next start takes it.
    async fn renew(&mut self) {
        match renew_if_due(&self.client, &self.creds, &self.hostname).await {
            Ok(None) => {}
            Ok(Some((fresh, not_after))) => match self.store.store(&fresh) {
                Ok(()) => match Client::with_user_agent(&fresh, &self.user_agent) {
                    Ok(c) => {
                        self.client = c;
                        self.creds = fresh;
                        info!(%not_after, "certificate renewed");
                    }
                    Err(e) => warn!("new certificate, client not built: {e:#}"),
                },
                Err(e) => warn!("new certificate not saved, keeping the old one: {e:#}"),
            },
            Err(e) => warn!("renewal failed: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tally_tests {
    use super::*;

    /// The agents' state files live on disk. `flatten` must not change
    /// their shape — otherwise every agent would lose its counter reading
    /// on an update and report itself as "never heard from".
    #[derive(Serialize, Deserialize, Default)]
    struct StateLike {
        generation: i64,
        #[serde(flatten)]
        tally: Tally,
    }

    #[test]
    fn an_old_state_file_is_read_and_written_unchanged() {
        // Exactly the shape that was written before the consolidation.
        let old = r#"{"generation":7,"reports":42,"last_ok":"2026-09-08T10:00:00Z","last_error":"boom","last_error_at":"2026-09-08T09:00:00Z"}"#;
        let st: StateLike = serde_json::from_str(old).expect("alte Datei lesbar");
        assert_eq!(st.generation, 7);
        assert_eq!(st.tally.reports, 42);
        assert_eq!(st.tally.last_error.as_deref(), Some("boom"));

        // And back again: the same four keys at the same level, no nested
        // "tally".
        let back: serde_json::Value = serde_json::to_value(&st).unwrap();
        for k in ["generation", "reports", "last_ok", "last_error", "last_error_at"] {
            assert!(back.get(k).is_some(), "{k} fehlt auf oberster Ebene: {back}");
        }
        assert!(back.get("tally").is_none(), "die Zahlen duerfen nicht verschachtelt werden: {back}");
    }

    /// A file from a time before the counters stays readable.
    #[test]
    fn a_state_file_without_the_counters_still_loads() {
        let st: StateLike = serde_json::from_str(r#"{"generation":1}"#).expect("lesbar");
        assert_eq!(st.tally.reports, 0);
        assert!(st.tally.last_ok.is_none());
    }

    /// A failure does not count as a report, and it does not erase when
    /// the central server was last heard from.
    #[test]
    fn a_failure_does_not_count_and_does_not_erase_the_last_success() {
        let mut t = Tally::default();
        let t0 = Utc::now();
        t.ok(t0);
        assert_eq!(t.reports, 1);
        t.failed(&anyhow::anyhow!("kaputt"), t0);
        assert_eq!(t.reports, 1, "Versuche zaehlen nicht");
        assert_eq!(t.last_ok, Some(t0), "wann zuletzt gehoert bleibt stehen");
        assert_eq!(t.last_error.as_deref(), Some("kaputt"));
        // And the next success clears the error away.
        t.ok(t0);
        assert_eq!(t.reports, 2);
        assert!(t.last_error.is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::central::{AgentConfig, ReportResponse, API_VERSION};

    /// Stores nothing: these tests renew no certificate.
    struct NoStore;
    impl CredentialStore for NoStore {
        fn store(&mut self, _fresh: &Credentials) -> Result<()> {
            Ok(())
        }
    }

    fn session() -> Session {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        let creds = Credentials {
            url: "https://central.invalid".into(),
            agent_id: "a1".into(),
            ca_pem: pem.clone(),
            cert_pem: pem,
            key_pem: key.serialize_pem(),
        };
        Session::new(creds, "host01", "test", Box::new(NoStore)).unwrap()
    }

    fn answer(interval: u32) -> ReportResponse {
        ReportResponse {
            accepted_alerts: 0,
            accepted_access_alerts: 0,
            accepted_counts: 0,
            config: AgentConfig { api_version: API_VERSION, generation: 1, report_interval_secs: interval, learn_days: 7, rules: Vec::new(), allow_processes: Vec::new(), update_to_sha256: None, finish_learning: false },
            learn: Vec::new(),
        }
    }

    /// The contract of the loop that each of the three agents previously
    /// wrote for itself: the log's read pointer moves on **only** on
    /// acceptance, and without an answer the pause grows longer instead of
    /// staying the same.
    #[test]
    fn log_pointer_waits_for_acceptance_and_the_pause_grows() {
        let mut s = session();
        assert_eq!(s.log_seq, 0);
        assert_eq!(s.failures(), 0);

        // Three failures: the read pointer stays, the pause doubles —
        // starting at seconds, not at half a minute.
        s.rejected();
        assert_eq!(s.log_seq, 0, "nicht angenommen, also nichts uebernehmen");
        assert_eq!(s.wait(), Duration::from_secs(2));
        s.rejected();
        assert_eq!(s.wait(), Duration::from_secs(4));
        s.rejected();
        assert_eq!((s.failures(), s.wait()), (3, Duration::from_secs(8)));

        // Accepted: read pointer moves on, the central server's cadence,
        // pause reset.
        s.accepted(&answer(45), 17);
        assert_eq!(s.log_seq, 17);
        assert_eq!(s.failures(), 0);
        assert_eq!(s.wait(), Duration::from_secs(45));

        // And from the start again, not at the old pause.
        s.rejected();
        assert_eq!(s.wait(), Duration::from_secs(2));
    }

    /// How long does an agent stay away after a disruption, **after** the
    /// line is back up? That is exactly what the viewer sees in the
    /// dashboard: until this report arrives, the device stands at
    /// "offline".
    ///
    /// Measured without the time a failed attempt costs on its own (up to
    /// 20 s timeout) — so in reality it is no better.
    fn recovery_delay_secs(outage: u64) -> u64 {
        let mut s = session();
        let mut t = 0;
        loop {
            if t >= outage {
                return t - outage;
            }
            s.rejected();
            t += s.wait().as_secs();
        }
    }

    /// When the line comes back, the agent tries again right away — not
    /// only once the grown pause has run out.
    #[test]
    fn a_returning_link_is_picked_up_quickly() {
        for outage in [5, 30, 60, 120, 300, 600, 3600] {
            let d = recovery_delay_secs(outage);
            assert!(d <= DEFAULT_INTERVAL_SECS, "Stoerung {outage}s: erst {d}s nach Rueckkehr der Leitung wieder da");
        }
    }

    #[test]
    fn the_pause_has_a_ceiling_and_the_interval_has_limits() {
        let mut s = session();
        for _ in 0..20 {
            s.rejected();
        }
        // The pause never grows beyond the normal cadence: a dead line
        // never costs more attempts than a healthy agent sends reports, and
        // nobody stays away unnoticed for longer than one cadence.
        assert_eq!(s.wait(), Duration::from_secs(DEFAULT_INTERVAL_SECS));
        // If the cadence does not cap it, the upper bound does.
        s.accepted(&answer(MAX_INTERVAL_SECS as u32), 1);
        s.rejected();
        for _ in 0..20 {
            s.rejected();
        }
        assert_eq!(s.wait(), Duration::from_secs(BACKOFF_MAX_SECS));
        s.accepted(&answer(30), 1);
        // An accidental 0 from the central server must not lead to
        // continuous sending, an absurdly large one not to going silent.
        s.accepted(&answer(0), 1);
        assert_eq!(s.wait(), Duration::from_secs(MIN_INTERVAL_SECS));
        s.accepted(&answer(999_999), 2);
        assert_eq!(s.wait(), Duration::from_secs(MAX_INTERVAL_SECS));
    }
}
