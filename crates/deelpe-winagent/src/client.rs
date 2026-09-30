//! The endpoint agent for **Windows workstations**.
//!
//! Counterpart to `deelpe daemon` on the Mac, and deliberately with the same
//! core: correlation, learning phase and the strict folder live in
//! `deelpe-core` and are only fed with different sensors here. What is new
//! are the sensors (`deelpe-sensors::windows`) and this flow.
//!
//! The case it exists for: somebody drags a file from the file server's share
//! into a session of an AI service in the browser. The file server cannot see
//! that — to it an authorised user is reading a file, just like opening it in
//! Word. It only becomes visible here: the same process that read from
//! `\\srv\GL` sends outwards afterwards.
//!
//! If the folder is in the rule as a **strict folder**, every destination
//! outside the allow list is forbidden, and with "Stop the sender" the
//! sending process is halted. The same goes for the copy to one's own disk,
//! to a stick or to a network drive: there is no sender there — the copier is
//! Explorer, and it does not get halted. What has to go instead of it is the
//! copy.

use crate::config::{AgentState, CentralConfig};
use anyhow::{Context, Result};
use chrono::Utc;
use deelpe_core::central::{AgentConfig, AgentStatus, Report, Rule, SensorHealth, API_VERSION};
use deelpe_core::config::{Config, Strict};
use deelpe_core::correlate::Correlator;
use deelpe_core::event::Event;
use deelpe_core::learn::Learner;
use deelpe_core::session::Session;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

const UA: &str = concat!("deelpe-winagent/", env!("CARGO_PKG_VERSION"));
/// Buffer between sensor and correlation. Generous: a full channel costs
/// events, and the sensor must not come to a halt for that.
const QUEUE: usize = 8_192;
/// Upper bound of the alerts waiting for a reachable central.
const MAX_PENDING: usize = 2_000;
/// How many reported alerts stay kept so that a learn command from the
/// central can still find its pair. The click in the dashboard comes seconds
/// to hours after the alert; two hundred cover that without the state on disk
/// growing.
const MAX_REPORTED: usize = 200;
/// Blocks by the browser connector waiting for their alert. Small: a human
/// clicks slowly, and a full channel must never hold up the verdict.
const BLOCKED_QUEUE: usize = 256;

/// Shortest gap between two reports.
///
/// A new alert wakes the reporting loop right away — but a flood of alerts
/// must not set off a flood of reports. `Notify` folds several wake-up calls
/// into one anyway; this pause covers the rest, namely alerts that keep
/// coming in steadily every second.
///
/// Five seconds: imperceptible against any reporting interval, and the alerts
/// of this flood go out together instead of one by one.
const MIN_REPORT_GAP: std::time::Duration = std::time::Duration::from_secs(5);

/// Who has to know the ruleset version — and all of them together at that.
///
/// Three places hang off one version, and they must never drift apart: the
/// **sensor** decides which file events come into being at all, the **browser
/// connector** judges out of its own task before the bytes go (ADR 0002), and
/// the **correlator** holds the touches.
///
/// On 2026-09-09 one of the three had a `Config::default()`, and every upload
/// out of a strict folder went out while everything looked green in the
/// dashboard. Back then that was fixed by the three lines standing next to
/// each other — an agreement, not a seam: it holds exactly as long as until
/// somebody inserts something in between.
///
/// Hence one version, one call. [`Policy::adopt`] is the only place in the
/// agent that calls `set_config`; whoever adopts a version reaches all three
/// with it, or none.
struct Policy {
    /// The handle the browser connector reads from. Its own lock, not the
    /// state's: it must never wait on the correlator, which holds that one
    /// while it processes events.
    connector: Arc<tokio::sync::RwLock<Config>>,
    state: Arc<Mutex<State>>,
}

impl Policy {
    /// Start closed: until the first version is there, there is no protected
    /// folder — so nothing that would be worth a file event either. Without
    /// that the channel fills up in the first seconds.
    ///
    /// Sits here and not at the caller so that the sensor learns of this
    /// state too only through this type.
    fn new(state: Arc<Mutex<State>>) -> Self {
        deelpe_sensors::set_watched(deelpe_sensors::Watch::Folders {
            paths: &[],
            // Without folders nothing can be touched yet; the expiry only
            // counts from the first version on, see [`Policy::adopt`].
            taint_ttl: Config::default().sensor_taint_ttl(),
        });
        Self { connector: Arc::new(tokio::sync::RwLock::new(Config::default())), state }
    }

    /// The handle for the connector's task.
    fn connector(&self) -> Arc<tokio::sync::RwLock<Config>> {
        self.connector.clone()
    }

    /// Adopt a ruleset version — everywhere.
    async fn adopt(&self, mut cfg: Config) {
        // A protected folder is reachable under its 8.3 short name as well,
        // and event tracing reports whichever spelling the program opened.
        // Asked once per ruleset, never per event — see
        // [`deelpe_core::config::add_path_aliases`].
        deelpe_core::config::add_path_aliases(&mut cfg, crate::config::short_name);
        // The sensor has to know the protected folders, otherwise it pushes
        // every file event of the system through the channel and under load
        // drops the interesting one of all things (lab log 2026-09-07). Its
        // expiry follows `touch_ttl_secs` of this version: it must never be
        // the narrower filter, otherwise it drops the copy the correlator is
        // still waiting for.
        let watched: Vec<String> = cfg.watched.iter().map(|p| p.display().to_string()).collect();
        deelpe_sensors::set_watched(deelpe_sensors::Watch::Folders { paths: &watched, taint_ttl: cfg.sensor_taint_ttl() });
        *self.connector.write().await = cfg.clone();
        self.state.lock().await.corr.set_config(cfg);
    }
}

struct State {
    corr: Correlator,
    learner: Learner,
    /// Not yet accepted by the central. The central writes them over the
    /// `external_id`, so sending again does no harm.
    pending: Vec<deelpe_core::correlate::Alert>,
    /// Already reported but still kept: a learn command names an alert id,
    /// and only the agent knows the pair behind it.
    reported: Vec<deelpe_core::correlate::Alert>,
}

pub async fn run(mut stop: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let cfg = CentralConfig::load()?.context("not enrolled — run `deelpe-winagent enroll` first")?;
    let mut session = Session::new(cfg.credentials(), crate::config::hostname(), UA, Box::new(cfg.clone()))?;
    let mut st = AgentState::load();
    // Counts the update attempts per checksum; see `update::Updater`.
    let mut updater = crate::update::Updater::default();
    let started = Utc::now();

    // The learning phase belongs to the stored ruleset version: after a
    // restart without the central it would otherwise be seven days again,
    // although the central said something else long ago.
    let learn_days = st.central_config.as_ref().map_or(7u32, |c| c.learn_days);
    let state = Arc::new(Mutex::new(State {
        corr: Correlator::with_next_id(Config::for_endpoint(Vec::new(), Vec::new(), learn_days), st.next_alert_id),
        learner: st.learner.take().unwrap_or_else(|| Learner::new(learn_days, Utc::now())),
        pending: std::mem::take(&mut st.pending_endpoint_alerts),
        reported: std::mem::take(&mut st.reported_endpoint_alerts),
    }));
    // Its own lock, not the state's: putting up a cage costs an `OpenProcess`
    // and several calls to the filter service, and neither the reporting loop
    // nor the browser connector may wait that long.
    let cages = Arc::new(Mutex::new(crate::wfp::Cages::new()));
    // A new alert wakes the reporting loop instead of leaving it lying until
    // the next tick. The block itself falls long before that and locally
    // (`pipeline::enforce` further down) — this is only about when the
    // central learns of it.
    let alerted = Arc::new(tokio::sync::Notify::new());

    // Sensors run for themselves and are restarted after a failure: event
    // tracing can break off because somebody ended the session by hand or
    // because buffers were lost.
    let policy = Policy::new(state.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(QUEUE);
    let sensor_error = Arc::new(Mutex::new(None::<String>));
    for spec in deelpe_sensors::platform_sensors() {
        let tx = tx.clone();
        let err = sensor_error.clone();
        tokio::spawn(async move {
            let mut wait = 2u64;
            loop {
                let s = (spec.make)(3);
                match s.run(tx.clone()).await {
                    Ok(()) => return,
                    Err(e) => {
                        let msg = format!("{e:#}");
                        warn!(sensor = spec.name, "{msg}");
                        *err.lock().await = Some(msg);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(wait)).await;
                wait = (wait * 2).min(60);
            }
        });
    }
    // The browser asks before it sends — the only place without a race (ADR
    // 0002). Its own task: it has to answer even while the event loop is
    // busy.
    let mut skipped: Vec<String> = Vec::new();
    // The ruleset version adopted last applies again **before** the first
    // report. Without that, a workstation whose central does not answer at
    // startup protected nothing at all: the sensor knew no folder, the cage
    // no strict one, the driver had an empty policy — and the browser
    // connector let every upload through (lab 2026-09-09). Sits up here so
    // that even the connector's first question already lands on the right
    // policy.
    //
    // Deliberate consequence: a stored rule keeps applying until the central
    // sends a new one — like the Mac service, see docs/SERVER.md.
    if let Some(c) = st.central_config.clone() {
        apply(&c, &policy, &mut skipped).await;
    }
    // Until 2026-09-08 a block by the connector wrote only a log line — in
    // the dashboard the one intervention that comes before the bytes was
    // invisible. Now it creates an alert, like any other finding.
    let (blocked_tx, mut blocked_rx) = tokio::sync::mpsc::channel::<crate::browser::Blocked>(BLOCKED_QUEUE);
    {
        let policy = policy.connector();
        tokio::spawn(async move {
            if let Err(e) = crate::browser::serve(crate::browser::PIPE_NAME, policy, blocked_tx).await {
                warn!("content analysis connector stopped: {e:#}");
            }
        });
    }
    {
        let st_blocked = state.clone();
        tokio::spawn(async move {
            while let Some(b) = blocked_rx.recv().await {
                let mut s = st_blocked.lock().await;
                match s.pending.iter_mut().find(|a| crate::browser::same_action(a, &b)) {
                    // The same action again: the alert grows, the list does
                    // not.
                    Some(prev) => prev.last_at = Some(b.at),
                    None => {
                        let id = s.corr.take_id();
                        let a = crate::browser::alert_for(&b, id);
                        warn!("ALERT #{} blocked {} -> {}", a.id, a.identity.short(), b.url.as_deref().unwrap_or("-"));
                        push_pending(&mut s, a);
                    }
                }
            }
        });
    }

    drop(tx);

    // Process events as long as any come.
    let st_ev = state.clone();
    let cages_ev = cages.clone();
    let alerted_ev = alerted.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            // The cage hangs off the touch, not off the finding: it has to
            // be up already when nobody has sent yet. That is exactly where
            // the difference to catching up afterwards lies (ADR 0002).
            //
            // The lookup happens under the state lock, **the caging without
            // it**: the filter service answers in milliseconds, and the lock
            // would otherwise hold up the reporting loop here.
            let (outcome, touches) = {
                let mut s = st_ev.lock().await;
                (s.corr.ingest(&ev), fresh_touches(&mut s))
            };
            if !touches.is_empty() {
                let now = std::time::Instant::now();
                let mut c = cages_ev.lock().await;
                for (pid, allow) in touches {
                    c.on_touch(pid, &allow, now);
                }
            }
            let Some(o) = outcome else { continue };
            let mut s = st_ev.lock().await;
            // The learning phase's verdict, the intervention and the reason
            // live in `deelpe_core::pipeline` — the same place as in the Mac
            // service. What stands here is only what this agent can intervene
            // with, and how it files the alert.
            // A copy, not a reference: behind the `MutexGuard` lies a value,
            // and `&mut s.learner` is already holding it.
            let allow = s.corr.config().allow_processes.clone();
            let Some((mut judged, _is_new)) = deelpe_core::pipeline::judge(&mut s.learner, &allow, o, Utc::now()) else { continue };
            let cfg = s.corr.config();
            deelpe_core::pipeline::enforce(cfg, &mut judged, &EndpointEnforcer { ev: &ev, cfg });
            let a = judged.into_alert();
            warn!("ALERT #{} {:?} {} -> {:?} {} B", a.id, a.verdict, a.identity, a.remote, a.bytes_out);
            match s.pending.iter_mut().find(|p| p.id == a.id) {
                Some(prev) => *prev = a,
                None => push_pending(&mut s, a),
            }
            // On an update too: the numbers in it are new.
            alerted_ev.notify_one();
        }
    });

    // Whoever stops reading produces no more events — so the expiry has to
    // run out from outside, not at the next touch.
    {
        let cages_tick = cages.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tick.tick().await;
                cages_tick.lock().await.expire(std::time::Instant::now());
            }
        });
    }

    info!(central = %cfg.url, "endpoint agent running");
    loop {
        // Fetched before the state lock so that the reporting loop does not
        // wait on a cage that is just being put up.
        let cage_health = cages.lock().await.health();
        let (status, alerts, configured) = {
            let s = state.lock().await;
            let watched: Vec<String> = s.corr.config().watched.iter().map(|p| p.display().to_string()).collect();
            // The same question as `unconfigured` further down, and
            // deliberately the same expression: whoever judges differently
            // here than there reports a generation it is not running at all
            // — and never gets the rules again.
            let configured = !watched.is_empty();
            let phase = serde_json::to_value(s.learner.phase(Utc::now())).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
            (
                AgentStatus {
                    version: env!("CARGO_PKG_VERSION").into(),
                    build: deelpe_core::central::build_fingerprint().into(),
                    hostname: crate::config::hostname(),
                    fqdn: crate::config::fqdn(),
                    started_at: started,
                    sensors: sensors(&*sensor_error.lock().await, &skipped, cage_health),
                    watched,
                    learn_phase: phase,
                    shares: Vec::new(),
                    addrs: deelpe_core::netaddr::local_addrs(),
                    arch: deelpe_core::central::arch().into(),
                    learn_until: s.learner.status(Utc::now()).until,
                },
                s.pending.clone(),
                configured,
            )
        };
        let mut report = Report {
            api_version: Some(API_VERSION),
            status: Some(status),
            alerts,
            // Only report what we really run: then the central leaves the
            // rules out of the answer. Without a ruleset version we report
            // none and get them with the next report.
            generation: configured.then_some(st.generation),
            // What has already been carried out, so that the central ticks
            // it off and does not repeat the same command in every report.
            learn_done: st.learn_done.clone(),
            // `log` adds the session to it so that the read cursor only
            // moves on once it is accepted.
            ..Default::default()
        };
        // Which alerts really went along — not how many. While sending,
        // other tasks may append, and with a full backlog `push_pending`
        // throws away the oldest in the process: then the front half of the
        // list is no longer the sent one, and truncating by count would have
        // discarded unsent alerts.
        let sent: std::collections::HashSet<u64> = report.alerts.iter().map(|a| a.id).collect();
        // Log lines, error counters, wait time and the renewal of the
        // certificate are the session's job; what stays here is what only
        // this agent knows.
        let result = session
            .send(&mut report)
            .await;
        match result {
            Ok(resp) => {
                // Taken completely apart, without `..`: a new field in the
                // wire format breaks here instead of vanishing silently. See
                // `ReportResponse`.
                let deelpe_core::central::ReportResponse {
                    accepted_alerts,
                    accepted_access_alerts: _,
                    accepted_counts: _,
                    config: new_config,
                    learn,
                } = resp;
                let _ = accepted_alerts;
                // Picked off before the adoption: the ruleset version moves
                // into the state right away, and the update order does
                // **not** hang off the generation — an agent that already
                // runs the current one would otherwise never get a new
                // program.
                let want_update = new_config.update_to_sha256.clone();
                // The operator ended the learning phase in the dashboard. Not
                // tied to the generation either, and idempotent: the server
                // stops asking once the status says "active".
                if new_config.finish_learning {
                    let mut s = state.lock().await;
                    if s.learner.phase(Utc::now()) != deelpe_core::learn::Phase::Active {
                        s.learner.confirm();
                        info!("central: learning phase finished, {} pairs known", s.learner.pair_count());
                    }
                }
                st.tally.ok(Utc::now());
                // An accepted report means: this program really runs. Now
                // the previous version may go.
                crate::update::cleanup_old();
                let done_sent: Vec<i64> = report.learn_done.clone();
                {
                    let mut s = state.lock().await;
                    // Only what was sent along: whatever came in meanwhile
                    // stays lying. Reported does not mean forgotten — the
                    // alert moves into the ring so that a later learn command
                    // can still find its pair.
                    let (gone, stay): (Vec<_>, Vec<_>) = std::mem::take(&mut s.pending).into_iter().partition(|a| sent.contains(&a.id));
                    s.pending = stay;
                    for a in gone {
                        push_reported(&mut s, a);
                    }
                }
                // Ticked off is ticked off: what the central has accepted
                // does not have to be reported again.
                st.learn_done.retain(|id| !done_sent.contains(id));
                // Learn commands do not hang off the generation: they apply
                // once and come again until the agent reports them.
                if !learn.is_empty() {
                    let mut s = state.lock().await;
                    let alerts: Vec<_> = s.reported.iter().cloned().chain(s.pending.iter().cloned()).collect();
                    let out = deelpe_core::pipeline::apply_learn(&mut s.learner, &alerts, &learn, &st.learn_done);
                    for (action, key) in &out.learned {
                        info!("central: {action:?} {key}");
                    }
                    st.learn_done.extend(out.done);
                }
                // The same question as with the file server agent, and now
                // the same expression too.
                let configured = !state.lock().await.corr.config().watched.is_empty();
                if deelpe_core::central::adopt_generation(new_config.generation, st.generation, configured) {
                    apply(&new_config, &policy, &mut skipped).await;
                    st.generation = new_config.generation;
                    // Only the adopted version, never a merely received
                    // one: otherwise something else would apply after the
                    // next restart than does right now. Agents that already
                    // reported a generation before this version come past
                    // here exactly once via `configured`.
                    //
                    // The update order stays out: what gets stored is the
                    // ruleset version that is meant to survive a restart. An
                    // update applies once, and after the restart the agent
                    // runs the new program anyway.
                    st.central_config = Some(deelpe_core::central::AgentConfig { update_to_sha256: None, finish_learning: false, ..new_config });
                }
                if let Some(want) = want_update {
                    if let Err(e) = crate::update::apply(&session, &want, &mut updater).await {
                        warn!("agent update: {e:#}");
                    }
                }
            }
            Err(e) => {
                st.tally.failed(&e, Utc::now());
            }
        }
        {
            let s = state.lock().await;
            st.pending_endpoint_alerts = s.pending.clone();
            st.reported_endpoint_alerts = s.reported.clone();
            st.next_alert_id = s.corr.next_id();
            st.learner = Some(s.learner.clone());
        }
        if let Err(e) = st.save() {
            warn!("saving state: {e:#}");
        }
        // Only after the state is on disk: the new agent carries on at the
        // same read cursor, with the same backlog.
        if crate::update::restart_requested() {
            info!("stopping so the service manager starts the new program");
            // One more report before it is over.
            //
            // Log lines travel along with the **next** report — and out of
            // this process there is no next one. Without this, of all things
            // the lines that make up the whole procedure get lost ("fetching
            // it", "program replaced"): the new process starts with an empty
            // ring, and the dashboard would show only a version that changed
            // unexplained. In a product that keeps evidence, exactly that
            // belongs in the central log.
            let mut last = Report { api_version: Some(API_VERSION), generation: Some(st.generation), ..Default::default() };
            if let Err(e) = session.send(&mut last).await {
                warn!("the last report before the restart did not get through: {e:#}");
            }
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(session.wait()) => {}
            // Sit out the minimum pause first, then listen for an alert. If
            // one came during the pause, there is a note lying at `Notify`
            // and `notified()` returns right away — so nothing gets lost, it
            // only goes out in a bundle.
            _ = async {
                tokio::time::sleep(MIN_REPORT_GAP).await;
                alerted.notified().await;
            } => {}
            _ = stop.changed() => {
                if *stop.borrow() {
                    // The dynamic session cleans up by itself, but only
                    // once the process is really gone. Whoever stops in an
                    // orderly way leaves nobody caged behind.
                    cages.lock().await.release_all();
                    info!("stop signal, endpoint agent shuts down");
                    return Ok(());
                }
            }
        }
    }
}

/// Fresh touches with their allow list — everything the cage needs, fetched
/// in one go under the state lock.
///
/// Only a **strict folder that is meant to enforce** blocks the network: a
/// merely watched one reports, nothing more — otherwise switching watching on
/// would cost function right away.
fn fresh_touches(s: &mut State) -> Vec<(u32, Vec<String>)> {
    let mut out = Vec::new();
    for (pid, origin) in s.corr.drain_tainted() {
        if let Some(x) = s.corr.config().strict_for(&origin).filter(|x| x.enforce) {
            out.push((pid, x.allow.clone()));
        }
    }
    out
}

/// Keep a reported alert so that a learn command can still find it. The
/// oldest flies out first.
fn push_reported(s: &mut State, a: deelpe_core::correlate::Alert) {
    if let Some(x) = s.reported.iter_mut().find(|x| x.id == a.id) {
        *x = a;
        return;
    }
    if s.reported.len() >= MAX_REPORTED {
        s.reported.remove(0);
    }
    s.reported.push(a);
}

/// Append and keep the upper bound while doing it: with a central
/// unreachable for days the newest counts more than the oldest.
fn push_pending(s: &mut State, a: deelpe_core::correlate::Alert) {
    if s.pending.len() >= MAX_PENDING {
        s.pending.remove(0);
    }
    s.pending.push(a);
}

/// Translate the central's rules into the correlator's configuration.
///
/// A **relative** rule path (`GL`) cannot be resolved at the workstation: the
/// agent has no share table it could derive it from. It gets skipped — and
/// the central learns of it, otherwise the dashboard would show a green rule
/// that protects nothing.
fn to_config(c: &AgentConfig, skipped: &mut Vec<String>) -> Config {
    let usable: Vec<&Rule> = c.rules.iter().filter(|r| r.enabled && crate::agent::is_absolute(&r.path)).collect();
    *skipped = c
        .rules
        .iter()
        .filter(|r| r.enabled && !crate::agent::is_absolute(&r.path))
        .map(|r| r.path.clone())
        .collect();
    Config::for_endpoint(
        usable.iter().map(|r| PathBuf::from(&r.path)).collect(),
        usable
            .iter()
            .filter(|r| r.strict)
            .map(|r| Strict { path: PathBuf::from(&r.path), allow: r.allow_destinations.clone(), enforce: r.enforce })
            .collect(),
        c.learn_days,
    )
    .with_allowed(&c.allow_processes)
}

async fn apply(c: &AgentConfig, policy: &Policy, skipped: &mut Vec<String>) {
    let cfg = to_config(c, skipped);
    let n = cfg.watched.len();
    let strict = cfg.strict.len();
    // The kernel minifilter gets the strict folders reported in the main
    // loop, every round — not here: otherwise it would stand there without a
    // policy when it is loaded or reloaded after a ruleset adoption.
    policy.adopt(cfg).await;
    info!(generation = c.generation, folders = n, strict, skipped = skipped.len(), "configuration applied");
    for p in skipped.iter() {
        warn!(path = %p, "rule path is relative; an endpoint cannot resolve it — use the full path, e.g. \\\\srv01\\GL");
    }
}

fn sensors(err: &Option<String>, skipped: &[String], cage: Option<String>) -> Vec<SensorHealth> {
    // Dropped events are no cosmetic flaw: what is missing here the
    // correlator never saw. That belongs in the dashboard, not in the log.
    let dropped = deelpe_sensors::dropped_events();
    let etw_err = match (err, dropped) {
        (Some(e), _) => Some(e.clone()),
        (None, 0) => None,
        (None, n) => Some(format!("{n} events dropped: the engine could not keep up")),
    };
    let mut out = vec![SensorHealth { name: "etw".into(), ok: etw_err.is_none(), error: etw_err }];
    // The network cage deliberately fails **open** (ADR 0002). That is
    // exactly why its failure has to be listed here: otherwise it no longer
    // protects and everything looks green in the dashboard.
    out.push(SensorHealth { name: "network cage".into(), ok: cage.is_none(), error: cage });
    // Can it renew itself? Otherwise the dashboard says "outdated" and
    // "Update sent", and why nothing happens is found only by whoever opens
    // the device's log.
    out.push(crate::update::readiness());
    for p in skipped {
        out.push(SensorHealth {
            name: format!("rule {p}"),
            ok: false,
            error: Some("relative path; an endpoint needs the full path, e.g. \\\\srv01\\GL".into()),
        });
    }
    out
}

/// What this agent can do against a forbidden outflow.
///
/// The second adapter at the seam that `deelpe_core::pipeline` spans; the
/// first one sits in the Mac service. This one alone can remove the copy —
/// for that it needs the event, because which destination was written is not
/// in the alert.
struct EndpointEnforcer<'a> {
    ev: &'a Event,
    cfg: &'a deelpe_core::config::Config,
}

impl deelpe_core::pipeline::Enforcer for EndpointEnforcer<'_> {
    fn delete_copy(&self, _a: &deelpe_core::correlate::Alert) -> String {
        // Never delete anything in the protected folder itself: a mistake
        // here would clear out the share.
        match copied_file(self.ev).filter(|p| !self.cfg.is_watched(p)) {
            None => "copy NOT deleted: unknown target".into(),
            // Lock first, then delete. The permission change gets through
            // even while the copier still holds the file open — the deletion
            // does not. Without it the copy would lie there readable for up
            // to ten seconds while `delete_copy_later` tries in vain.
            Some(path) => {
                // The spelling is not enough (pentest 8840/0004): through a
                // junction a path outside can lead into the share, and the
                // service would delete — as SYSTEM — the real file there.
                // Where the path really leads decides, and from here on only
                // that resolved path is touched.
                let path = match crate::enforce::resolved(path) {
                    Ok(real) if !self.cfg.is_watched(&real) => real,
                    Ok(real) => return format!("copy NOT deleted: it leads into the protected folder ({})", real.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return "copy already gone".into(),
                    Err(e) => return format!("copy NOT deleted: cannot tell where it leads ({e})"),
                };
                let path = path.as_path();
                let locked = crate::enforce::lock_copy(path);
                match crate::enforce::delete_copy(path) {
                    Ok(_) => "copy deleted".into(),
                    // The copier still holds the file open; keep trying in
                    // the background. Until then nobody gets at it any more.
                    Err(e) => {
                        crate::enforce::delete_copy_later(path.to_path_buf());
                        match locked {
                            Ok(()) => format!("copy locked, deletion pending ({e})"),
                            Err(le) => format!("copy NOT deleted ({e}) and NOT locked ({le}), retrying"),
                        }
                    }
                }
            }
        }
    }
}

/// The file that came into being outside the protected folder at this event.
/// On `Copy`/`Rename` the target, on a plain write the written file itself —
/// on Windows the sensor delivers only the second case.
fn copied_file(ev: &Event) -> Option<&std::path::Path> {
    match ev {
        Event::File(f) => Some(f.target.as_deref().unwrap_or(&f.path)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deelpe_core::central::{LearnAction, LearnCommand};
    use deelpe_core::correlate::Alert;
    use deelpe_core::identity::ProcessIdentity;
    use deelpe_core::learn::Verdict;

    const GL_DIR: &str = r"C:\Freigaben\GL";
    const GL_FILE: &str = r"C:\Freigaben\GL\Zahlen.xlsx";

    /// Pentest 8840/0004: `mklink /J %USERPROFILE%\in C:\Share\GL`, then
    /// a tainted process writes `in\colleague.docx`. The path is spelled
    /// outside the protected folder, so the check let it through — and the
    /// service, as SYSTEM, deleted the real file inside the share. A symbolic
    /// link stands in for the junction here; both are followed the same way.
    #[cfg(unix)]
    #[test]
    fn a_copy_that_leads_into_the_protected_folder_is_not_deleted() {
        let dir = std::env::temp_dir().join(format!("deelpe-junction-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let share = dir.join("GL");
        std::fs::create_dir_all(&share).unwrap();
        let share = std::fs::canonicalize(&share).unwrap();
        std::fs::write(share.join("colleague.docx"), b"real").unwrap();
        let link = dir.join("in");
        std::os::unix::fs::symlink(&share, &link).unwrap();

        let cfg = Config { watched: vec![share.clone()], ..Default::default() };
        let ev = Event::File(deelpe_core::event::FileEvent {
            at: Utc::now(),
            process: deelpe_core::event::ProcessRef { pid: 4242, ppid: None, responsible: None, path: "curl.exe".into(), identity: ProcessIdentity::Unknown { path: "curl.exe".into() } },
            path: link.join("colleague.docx"),
            action: deelpe_core::event::FileAction::Write,
            target: None,
            inode: None,
            nlink: None,
            argv: None,
        });
        let said = deelpe_core::pipeline::Enforcer::delete_copy(&EndpointEnforcer { ev: &ev, cfg: &cfg }, &alert(1));
        assert!(said.contains("NOT deleted"), "{said}");
        assert!(share.join("colleague.docx").exists(), "the file in the share is still there");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn state() -> State {
        State {
            corr: Correlator::new(Config::for_endpoint(Vec::new(), Vec::new(), 0)),
            learner: Learner::new(0, Utc::now()),
            pending: Vec::new(),
            reported: Vec::new(),
        }
    }

    fn alert(id: u64) -> Alert {
        Alert {
            id,
            at: Utc::now(),
            pid: 10,
            identity: ProcessIdentity::Signed { signing_id: "curl.exe".into(), team_id: "TEAM1".into() },
            files: Vec::new(),
            remote: Some("1.2.3.4".parse().unwrap()),
            remote_port: Some(443),
            bytes_out: 1000,
            via: None,
            last_at: None,
            verdict: Verdict::New,
            reason: None,
            volume: None,
            copy_to: None,
            sender_read_directly: false,
            upload_url: None,
        }
    }

    /// The reason the ring exists: a learn command inevitably comes
    /// **after** the report — whoever clicks in the dashboard has already
    /// seen the alert, after all. Until 2026-09-10 the agent emptied
    /// `pending` on sending and dropped `resp.learn`; the click never took
    /// effect, and the central kept sending the same command every 30
    /// seconds.
    #[test]
    fn a_learn_command_still_finds_an_alert_that_was_already_reported() {
        let mut s = state();
        s.learner.confirm();
        let a = alert(1);
        // Reported and out of `pending` — exactly the state the command
        // arrives in.
        push_reported(&mut s, a.clone());
        assert!(s.pending.is_empty());

        let cmds = [LearnCommand { id: 7, alert_id: 1, action: LearnAction::Remember }];
        let alerts: Vec<_> = s.reported.iter().cloned().chain(s.pending.iter().cloned()).collect();
        let out = deelpe_core::pipeline::apply_learn(&mut s.learner, &alerts, &cmds, &[]);

        assert_eq!(out.done, vec![7], "die Anweisung muss abgehakt werden");
        assert_eq!(out.learned.len(), 1, "und das Paar muss wirklich gelernt sein");

        let mut next = alert(2);
        next.id = 2;
        assert!(
            matches!(s.learner.judge(&next, true, Utc::now()), deelpe_core::learn::Decision::Drop),
            "nach dem Merken muss dasselbe Paar still sein"
        );
    }

    /// The reason [`Policy`] exists.
    ///
    /// A ruleset version has to reach the sensor, the browser connector
    /// **and** the correlator. On 2026-09-09 one of the three had a
    /// `Config::default()`, and every upload out of a strict folder went out
    /// while everything looked green in the dashboard. Back then that was
    /// fixed by the three lines standing next to each other -- which holds
    /// exactly as long as until somebody inserts something in between. Now
    /// this run-through holds it.
    ///
    /// It has only been possible since `client.rs` compiles on the Mac too.
    #[tokio::test]
    async fn adopting_a_ruleset_reaches_the_sensor_the_connector_and_the_correlator() {
        let state = Arc::new(Mutex::new(state()));
        let policy = Policy::new(state.clone());

        // Started closed: without a version no folder is protected.
        assert!(!deelpe_sensors::filter::wanted(GL_FILE), "vor der ersten Fassung darf nichts durch");

        let gl = std::path::PathBuf::from(GL_DIR);
        let cfg = Config::for_endpoint(vec![gl.clone()], Vec::new(), 0);
        policy.adopt(cfg).await;

        // 1. The sensor lets the folder's events through -- and only those.
        assert!(deelpe_sensors::filter::wanted(GL_FILE), "der Sensor kennt den Ordner nicht");
        assert!(!deelpe_sensors::filter::wanted(r"C:\Freigaben\HR\Lohn.xlsx"));
        // 2. The browser connector judges on the same version.
        assert_eq!(policy.connector().read().await.watched, vec![gl.clone()], "der Connector haelt eine andere Fassung");
        // 3. And the correlator too.
        assert_eq!(state.lock().await.corr.config().watched, vec![gl], "der Korrelator haelt eine andere Fassung");
    }

    /// The ring keeps its upper bound, and the same alert reported twice
    /// stays one entry — otherwise the state on disk grows.
    #[test]
    fn the_reported_ring_stays_bounded_and_does_not_duplicate() {
        let mut s = state();
        for id in 0..(MAX_REPORTED as u64 + 50) {
            push_reported(&mut s, alert(id));
        }
        assert_eq!(s.reported.len(), MAX_REPORTED);
        // The oldest has given way, the newest is in there.
        assert_eq!(s.reported.last().expect("nicht leer").id, MAX_REPORTED as u64 + 49);

        let n = s.reported.len();
        let again = s.reported[0].clone();
        push_reported(&mut s, again);
        assert_eq!(s.reported.len(), n, "dieselbe Kennung darf nicht zweimal liegen");
    }
}
