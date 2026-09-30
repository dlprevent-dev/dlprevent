//! Root service: start the sensors, correlate events, hold on to alerts,
//! serve the CLI over a unix socket. Alerts live permanently in `ALERT_LOG`
//! (JSONL, 0600), the correlator's memory in `STATE`; SQLite for events and
//! learning arrives with M2.
//!
//! Permissions on the socket: the user group may read, changing things (the
//! watch list, exceptions) is root-only. Otherwise any program the user
//! runs could switch off the protection without ever seeing a password. The
//! app and the CLI get admin rights for that (`sudo deelpe …`, in the app
//! the password dialog). Every change ends up in `CHANGES`.

use deelpe::alertlog::AlertLog;
use deelpe::ipc::{Request, Response, SensorState, SOCKET};
use anyhow::{Context, Result};
use deelpe_core::config::{validate_ignore_rule, Config};
use deelpe_core::correlate::{Correlator, Snapshot};
use deelpe_core::event::Event;
use deelpe_core::learn::Learner;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};

const CONFIG: &str = "/etc/deelpe/config.json";
const ALERT_LOG: &str = "/var/lib/deelpe/alerts.jsonl";
const STATE: &str = "/var/lib/deelpe/state.json";
const CHANGES: &str = "/var/lib/deelpe/changes.log";
/// The service's running log. The central server gets it line by line with
/// the reports too — see `deelpe_core::agentlog`.
pub const LOG: &str = "/var/lib/deelpe/agent.log";
const LEARNED: &str = "/var/lib/deelpe/learned.json";
/// The table in the app and the CLI shows no more than this; `AlertsAll`
/// delivers everything. 500 instead of 50, so one loud source does not
/// crowd the others out.
const RECENT_ALERTS: usize = 500;
/// Write the memory to disk at most this often.
const STATE_SAVE_SECS: u64 = 30;
/// Restart of a dead sensor: wait briefly at first, then up to a minute.
const SENSOR_RETRY_MIN_SECS: u64 = 5;
const SENSOR_RETRY_MAX_SECS: u64 = 60;
/// Shortest gap between two reports. A new alert wakes the reporting loop
/// immediately — but a flood of alerts must not trigger a flood of reports.
/// The same five seconds as on the Windows workstation.
const MIN_REPORT_GAP: Duration = Duration::from_secs(5);
const NEEDS_ROOT: &str = "changes need root: `sudo deelpe ...` or the admin password in the app";

struct State {
    corr: Correlator,
    /// Checksums of the files as the service last wrote or read them. If
    /// the disk differs, somebody edited behind the service's back.
    integrity: Integrity,
    /// The hashes changed (our own writes): save `STATE` again.
    integrity_dirty: bool,
    alerts: AlertLog,
    started: Instant,
    sensors: Vec<SensorState>,
    /// There have been file events since the last save.
    dirty: bool,
    learner: Learner,
    learn_dirty: bool,
}

/// Hashes of the configuration files (`CONFIG`, `LEARNED`), stored in
/// `STATE`. Root can forge anything, but a silent edit, or a script that
/// trims the watch list, becomes visible: in `CHANGES`, in the log, and as
/// a warning in the status.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Integrity {
    config_sha256: String,
    learned_sha256: String,
    /// Survives restarts until the service writes the file itself again:
    /// until then the foreign content is what counts.
    #[serde(default)]
    warnings: Vec<String>,
}

impl Integrity {
    fn expected(&self, path: &str) -> &str {
        if path == CONFIG { &self.config_sha256 } else { &self.learned_sha256 }
    }

    fn set(&mut self, path: &str, hash: String) {
        if path == CONFIG { self.config_sha256 = hash } else { self.learned_sha256 = hash }
    }

    /// Our own write: the user acted through the service, so the warning
    /// about this file is settled.
    fn written(&mut self, path: &str) {
        self.set(path, sha256_file(path));
        let name = file_name(path);
        self.warnings.retain(|w| !w.starts_with(&name));
    }

    /// Compares the file against the remembered hash. On a mismatch:
    /// remember a warning, write `CHANGES`, adopt the new hash (report
    /// once).
    fn check(&mut self, path: &str) {
        let now = sha256_file(path);
        let expected = self.expected(path);
        if expected.is_empty() || now == expected {
            self.set(path, now);
            return;
        }
        let msg = format!("{} changed outside the service", file_name(path));
        tracing::warn!("{msg} (sha256 {expected} → {now})");
        record_line(&format!("EXTERNAL_EDIT {path} sha256 {expected} -> {now}"));
        if !self.warnings.contains(&msg) {
            self.warnings.push(msg);
        }
        self.set(path, now);
    }
}

fn file_name(path: &str) -> String {
    Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()
}

/// Hex SHA-256 of the file, empty when it is missing.
fn sha256_file(path: &str) -> String {
    use sha2::{Digest, Sha256};
    match std::fs::read(path) {
        Ok(data) => Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect(),
        Err(_) => String::new(),
    }
}

/// The correlator's memory on disk, with an ID for the current boot:
/// PID-bound parts only hold as long as no PIDs have been handed out
/// again.
#[derive(Serialize, Deserialize)]
struct StateFile {
    boot_id: String,
    snapshot: Snapshot,
    #[serde(default)]
    integrity: Integrity,
}

pub async fn run() -> Result<()> {
    let cfg = Config::load(Path::new(CONFIG))?;
    tighten(Path::new(CONFIG));
    tracing::info!("DLPrevent service starting, {} protected folders", cfg.watched.len());
    let net_poll = cfg.net_poll_secs;
    let alerts = AlertLog::open(Path::new(ALERT_LOG), cfg.alert_retain_days)?;
    tracing::info!("{} stored alerts from {ALERT_LOG}", alerts.alerts().len());
    let learner = load_learner(&alerts, cfg.learn_days);
    let mut corr = Correlator::with_next_id(cfg, alerts.next_id());
    let mut integrity = restore_state(&mut corr);
    integrity.check(CONFIG);
    integrity.check(LEARNED);
    arm_sensors(corr.config());
    let specs = deelpe_sensors::platform_sensors();
    let state = Arc::new(Mutex::new(State {
        corr,
        integrity,
        integrity_dirty: true,
        alerts,
        started: Instant::now(),
        sensors: specs.iter().map(|s| SensorState { name: s.name.into(), error: None }).collect(),
        dirty: false,
        learner,
        learn_dirty: false,
    }));

    // A new alert wakes the reporting loop instead of leaving it lying
    // around until the next tick — the same promise as on the Windows
    // workstation (`winagent/src/client.rs`).
    let alerted = Arc::new(tokio::sync::Notify::new());
    // The network cage of strict folders with `enforce`. Its own lock, as on
    // the Windows workstation: putting a cage up talks to nft or the filter,
    // and the reporting loop must not wait on that.
    let cages = Arc::new(Mutex::new(crate::cage::Cages::new()));

    let (tx, mut rx) = mpsc::channel::<Event>(4096);
    for spec in specs {
        let tx = tx.clone();
        let st = state.clone();
        tokio::spawn(async move {
            // If a sensor dies, the service would otherwise keep running
            // blind. So restart it, with a growing pause; until then the
            // error sits in the status.
            let mut wait = SENSOR_RETRY_MIN_SECS;
            loop {
                let sensor = (spec.make)(net_poll);
                set_sensor_error(&st, spec.name, None).await;
                let run_started = Instant::now();
                let err = match sensor.run(tx.clone()).await {
                    Ok(()) => return,
                    Err(e) => format!("{e:#}"),
                };
                tracing::error!("sensor {} stopped: {err}", spec.name);
                set_sensor_error(&st, spec.name, Some(err)).await;
                if tx.is_closed() {
                    return;
                }
                // If it ran for more than a minute it was not a permanent
                // failure: wait only briefly.
                if run_started.elapsed() > Duration::from_secs(SENSOR_RETRY_MAX_SECS) {
                    wait = SENSOR_RETRY_MIN_SECS;
                }
                tokio::time::sleep(Duration::from_secs(wait)).await;
                wait = (wait * 2).min(SENSOR_RETRY_MAX_SECS);
            }
        });
    }
    // The cage's refusals go in with the sensors' events.
    let refused_tx = tx.clone();
    drop(tx);

    let st = state.clone();
    let alerted_ev = alerted.clone();
    let cages_ev = cages.clone();
    tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            // Every tool call of an AI agent into the log, which the
            // dashboard shows per agent: what the agent did, not only what
            // became an alert. The same metadata line an alert carries —
            // never a prompt or an answer.
            if let Event::Agent(a) = &ev {
                tracing::info!("{}", deelpe_core::agent::note(a));
            }
            let (outcome, touches) = {
                let mut s = st.lock().await;
                if matches!(ev, Event::File(_) | Event::Exit(_)) {
                    s.dirty = true;
                }
                (s.corr.ingest(&ev), fresh_touches(&mut s.corr))
            };
            // The cage hangs off the touch, not off the finding: it has to
            // be up before anybody sends (ADR 0002).
            if !touches.is_empty() {
                let now = Instant::now();
                cages_ev.lock().await.on_touches(touches, now);
            }
            let Some(o) = outcome else { continue };
            let mut s = st.lock().await;
            s.learn_dirty = true;
            // The learning phase's verdict, the intervention and the
            // reasoning live in `deelpe_core::pipeline` — the same place as
            // on the Windows workstation. All that is here is what this
            // service can intervene with, and how it files the alert.
            // A copy, not a reference: behind the `MutexGuard` sits a value,
            // and `&mut s.learner` is already holding it.
            let allow = s.corr.config().allow_processes.clone();
            let Some((mut judged, is_new)) = deelpe_core::pipeline::judge(&mut s.learner, &allow, o, chrono::Utc::now()) else { continue };
            deelpe_core::pipeline::enforce(s.corr.config(), &mut judged, &MacEnforcer);
            let a = judged.into_alert();
            // On failure it stays in memory (AlertLog), only the disk copy
            // is missing.
            let res = if is_new || !s.alerts.alerts().iter().any(|x| x.id == a.id) {
                tracing::warn!("ALERT #{} {:?} {} -> {:?} {} B", a.id, a.verdict, a.identity, a.remote, a.bytes_out);
                s.alerts.append(&a)
            } else {
                tracing::info!("ALERT #{} now {} B", a.id, a.bytes_out);
                s.alerts.update(&a)
            };
            if let Err(e) = res {
                tracing::error!("alert #{} not written to disk: {e:#}", a.id);
            }
            // On a continuation too: the numbers in it are new.
            alerted_ev.notify_one();
        }
    });

    let st = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(STATE_SAVE_SECS));
        loop {
            tick.tick().await;
            save_learner(&st).await;
            {
                let mut s = st.lock().await;
                let mut i = std::mem::take(&mut s.integrity);
                i.check(CONFIG);
                i.check(LEARNED);
                s.integrity = i;
            }
            save_state(&st).await;
        }
    });

    // Whoever stops reading produces no more events: the expiry runs on a tick.
    let cages_tick = cages.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            let refused = {
                let mut cages = cages_tick.lock().await;
                cages.expire(Instant::now());
                cages.refused()
            };
            for ev in refused {
                let _ = refused_tx.send(ev).await;
            }
        }
    });

    // Central server (optional): reports status and alerts, fetches rules.
    let st = state.clone();
    let cages_central = cages.clone();
    // The program was replaced: stop the way a SIGTERM would, and systemd
    // (`Restart=always`) starts the new one.
    let restart = Arc::new(tokio::sync::Notify::new());
    let restart_central = restart.clone();
    tokio::spawn(async move { central_loop(st, alerted, cages_central, restart_central).await });

    let result = tokio::select! {
        r = serve(state.clone()) => r,
        _ = shutdown_signal() => {
            tracing::info!("shutting down, saving memory");
            Ok(())
        }
        _ = restart.notified() => {
            tracing::info!("agent program replaced, stopping so the service manager starts the new one");
            Ok(())
        }
    };
    // The pairs first, then the state: the state carries the checksum of
    // learned.json, otherwise the next start reports a foreign change.
    save_learner(&state).await;
    save_state(&state).await;
    cages.lock().await.release_all();
    let _ = std::fs::remove_file(SOCKET);
    result
}

// --- Central server

/// Without `central.json` the loop sleeps and checks once a minute whether
/// an enrollment has happened. Errors do not hold the service up.
async fn central_loop(st: Arc<Mutex<State>>, alerted: Arc<tokio::sync::Notify>, cages: Arc<Mutex<crate::cage::Cages>>, restart: Arc<tokio::sync::Notify>) {
    use deelpe::central::{self, CentralConfig, CentralState};
    use deelpe_core::session::Session;
    const UA: &str = concat!("deelpe/", env!("CARGO_PKG_VERSION"));
    // The key is (address, agent ID): if either of the two changes, the
    // session needs rebuilding.
    let mut session: Option<(String, Session)> = None;
    let mut cstate = CentralState::load();
    // Counts the update attempts per checksum; see `deelpe_core::update::Updater`.
    let mut updater = deelpe_core::update::Updater::default();
    loop {
        let cfg = match CentralConfig::load() {
            Ok(Some(c)) => c,
            Ok(None) => {
                session = None;
                // Disconnected is disconnected: the central server's
                // folders and blocks go with it. Otherwise the service would
                // keep blocking after `central remove`, and nobody could
                // switch the rule off any more — the central server that
                // would take it back is gone, after all.
                if !cstate.managed.is_empty() {
                    release_central_config(&st, &mut cstate).await;
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
            Err(e) => {
                tracing::warn!("central: {e:#}");
                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
        };
        let key = format!("{}|{}", cfg.url, cfg.agent_id);
        if session.as_ref().map(|(k, _)| k != &key).unwrap_or(true) {
            match Session::new(cfg.credentials(), central::hostname(), UA, Box::new(cfg.clone())) {
                Ok(s) => {
                    tracing::info!("central {} as agent {}", cfg.url, cfg.agent_id);
                    session = Some((key, s));
                }
                Err(e) => {
                    tracing::error!("central: client: {e:#}");
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    continue;
                }
            }
        }
        let (_, session) = session.as_mut().expect("gerade gesetzt");
        // Before the state lock, so the state is not held while a cage goes up
        // (that takes nft or the relay, milliseconds; this does wait for it).
        let cage_health = cages.lock().await.health();
        let mut report = {
            let s = st.lock().await;
            let now = chrono::Utc::now();
            let started_at = now - chrono::Duration::from_std(s.started.elapsed()).unwrap_or_default();
            deelpe_core::central::Report {
                api_version: Some(deelpe_core::central::API_VERSION),
                // What this service is currently running; the central
                // server then leaves the rules out. `0` means "none yet"
                // (which is also what the service sets when a central server
                // is removed) -- and then we do want them sent to us.
                generation: (cstate.generation > 0).then_some(cstate.generation),
                status: Some(deelpe_core::central::AgentStatus {
                    version: env!("CARGO_PKG_VERSION").into(),
                    build: deelpe_core::central::build_fingerprint().into(),
                    hostname: central::hostname(),
                    // The Mac service is not a file server; it does not
                    // carry a fully qualified name.
                    fqdn: String::new(),
                    started_at,
                    sensors: s
                        .sensors
                        .iter()
                        .map(|x| deelpe_core::central::SensorHealth { name: x.name.clone(), ok: x.error.is_none(), error: x.error.clone() })
                        // The cage fails open: its failure has to show in the
                        // dashboard, or it stops protecting while all is green.
                        .chain(std::iter::once(deelpe_core::central::SensorHealth { name: "network cage".into(), ok: cage_health.is_none(), error: cage_health.clone() }))
                        // Can it renew itself? Linux only: the Mac service
                        // sits in an app bundle and is not ordered to.
                        .chain(cfg!(target_os = "linux").then(update_readiness))
                        .collect(),
                    watched: s.corr.config().watched.iter().map(|p| p.display().to_string()).collect(),
                    shares: Vec::new(),
                    learn_phase: serde_json::to_value(s.learner.phase(now)).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
                    addrs: deelpe_core::netaddr::local_addrs(),
                    arch: deelpe_core::central::arch().into(),
                    learn_until: s.learner.status(now).until,
                }),
                alerts: central::pending_alerts(s.alerts.alerts(), &mut cstate.sent),
                // Only the server agent reports groups: on an endpoint
                // there are none that belong in a folder rule.
                groups: None,
                learn_done: cstate.learn_done.clone(),
                ..Default::default()
            }
        };
        let sent_ids: Vec<(u64, String)> = report.alerts.iter().map(|a| (a.id, central::alert_signature(a))).collect();
        let done_sent = report.learn_done.clone();
        // Log lines, error counters, the wait time and the renewal of the
        // certificate are the session's job; what stays here is what only
        // this service knows.
        let sent = session
            .send(&mut report)
            .await;
        match sent {
            Ok(resp) => {
                for (id, sig) in sent_ids {
                    cstate.sent.insert(id, sig);
                }
                // Taken apart completely, without `..`: a new field in the
                // wire format breaks here instead of silently disappearing.
                // See `ReportResponse`.
                let deelpe_core::central::ReportResponse {
                    accepted_alerts,
                    accepted_access_alerts: _,
                    accepted_counts: _,
                    config: new_config,
                    learn,
                } = resp;
                cstate.tally.ok(chrono::Utc::now());
                // Reported in on the new program: the previous one is no
                // longer needed as the way back.
                deelpe_core::update::cleanup_old();
                if !report.alerts.is_empty() {
                    tracing::info!("central: reported {accepted_alerts} alerts");
                }
                // Ticked off is ticked off: what the central server has
                // accepted does not need reporting again.
                cstate.learn_done.retain(|id| !done_sent.contains(id));
                // The same question as in the Windows agents, the same
                // expression. `configured` is always true here: the service
                // keeps its configuration in /etc/deelpe/config.json and
                // merges it — it cannot end up unconfigured the way an
                // endpoint without a stored version can.
                if deelpe_core::central::adopt_generation(new_config.generation, cstate.generation, true) {
                    apply_central_config(&st, &mut cstate, &new_config).await;
                }
                // Learning instructions do not hang off the generation:
                // they apply once and come back until the agent reports
                // them.
                if !learn.is_empty() {
                    apply_learn(&st, &mut cstate, &learn).await;
                }
                // The operator ended the learning phase in the dashboard —
                // "Confirm all" from afar. Idempotent: the server stops asking
                // once the status says "active".
                if new_config.finish_learning {
                    let mut s = st.lock().await;
                    if s.learner.phase(chrono::Utc::now()) != deelpe_core::learn::Phase::Active {
                        s.learner.confirm();
                        s.learn_dirty = true;
                        let n = s.learner.pair_count();
                        drop(s);
                        tracing::info!("central: learning phase finished, {n} pairs known");
                        record_change(&format!("Central learn confirm ({n} pairs)"));
                    }
                }
                if let Some(want) = &new_config.update_to_sha256 {
                    match self_update(session, want, &mut updater).await {
                        Ok(true) => {
                            let _ = cstate.save();
                            restart.notify_one();
                            return;
                        }
                        Ok(false) => {}
                        Err(e) => tracing::warn!("agent update: {e:#}"),
                    }
                }
            }
            Err(e) => {
                cstate.tally.failed(&e, chrono::Utc::now());
            }
        }
        if let Err(e) = cstate.save() {
            tracing::warn!("central: state not saved: {e:#}");
        }
        tokio::select! {
            _ = tokio::time::sleep(session.wait()) => {}
            // Sit out the minimum gap first, then listen for an alert. If
            // one came in during the pause, `Notify` has a note waiting and
            // `notified()` returns immediately — so nothing is lost, it just
            // goes out in a batch.
            _ = async {
                tokio::time::sleep(MIN_REPORT_GAP).await;
                alerted.notified().await;
            } => {}
        }
    }
}

/// Replace this program with the one the central server holds ready.
/// `Ok(true)`: swapped, the service has to restart into it.
///
/// Linux only. The central server orders it of a Linux agent that reports
/// its architecture; the Mac is never ordered to (its program sits inside
/// the app bundle), and a stray order there is refused here rather than
/// swapping a binary out of a signed bundle.
///
/// `/usr/bin/deelpe` belongs to the `.deb`: after a swap `dpkg -V deelpe`
/// reports it changed, and the next `apt install` of a package puts the
/// package's file back — both expected.
async fn self_update(session: &deelpe_core::session::Session, want: &str, tries: &mut deelpe_core::update::Updater) -> Result<bool> {
    use deelpe_core::update::{can_replace, check_release, is_sha256, short, swap, verify};
    if !cfg!(target_os = "linux") {
        return Ok(false);
    }
    // Off the wire: shape first, before anything is cut or downloaded.
    if !is_sha256(want) {
        anyhow::bail!("central announced something that is not a SHA-256: {want:?}");
    }
    if !tries.may_try(want) {
        return Ok(false);
    }
    let exe = std::env::current_exe().context("own path")?;
    can_replace(&exe)?;
    tracing::info!(want = short(want), "central holds a different agent program, fetching it");
    let (bytes, statement) = session.binary().await.context("downloading the agent program")?;
    verify(&bytes, want)?;
    let slot = format!("deelpe-linux-{}", deelpe_core::central::arch());
    check_release(&bytes, statement.as_deref(), deelpe_core::signing::BUILT_IN_PUBKEY, &slot, env!("CARGO_PKG_VERSION"))?;
    // The permissions of the file it replaces: `fs::write` creates 0644.
    swap(&exe, &bytes)?;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).context("making the new program executable")?;
    tracing::info!(bytes = bytes.len(), want = short(want), "agent program replaced");
    Ok(true)
}

/// Can this agent renew itself? As a sensor line for the dashboard, like
/// the Windows agent's: otherwise "outdated" and "update sent" stand there
/// and why nothing happens is only in the device's log.
fn update_readiness() -> deelpe_core::central::SensorHealth {
    let out = std::env::current_exe().map_err(anyhow::Error::from).and_then(|e| deelpe_core::update::can_replace(&e));
    deelpe_core::central::SensorHealth { name: "self-update".into(), ok: out.is_ok(), error: out.err().map(|e| format!("{e:#}")) }
}

/// Carry out the central server's learning instructions. They carry this
/// device's alert ID; the pair (process, target network) is only known
/// here. An alert that has since rolled out of the log counts as settled —
/// otherwise the central server would get it back in every report.
async fn apply_learn(st: &Mutex<State>, cstate: &mut deelpe::central::CentralState, cmds: &[deelpe_core::central::LearnCommand]) {
    let mut s = st.lock().await;
    let alerts = s.alerts.alerts().to_vec();
    let out = deelpe_core::pipeline::apply_learn(&mut s.learner, &alerts, cmds, &cstate.learn_done);
    for (action, key) in &out.learned {
        tracing::info!("central: {action:?} {key}");
        record_change(&format!("Central learn {action:?} {key}"));
    }
    if !out.done.is_empty() {
        s.learn_dirty = true;
        cstate.learn_done.extend(out.done);
    }
}

/// Adopt the central server's rules: absolute paths become protected
/// folders, ones that are no longer distributed fly back out. Locally
/// created folders stay. Disconnecting from the central server: hand its
/// folders back and lift every block. Strict folders come exclusively from
/// the central server, so they go completely. What the user protected
/// themselves stays.
async fn release_central_config(st: &Mutex<State>, cstate: &mut deelpe::central::CentralState) {
    let managed = std::mem::take(&mut cstate.managed);
    let res = {
        let mut s = st.lock().await;
        update_config(&mut s, |c| {
            c.watched.retain(|p| !managed.contains(p));
            c.strict.clear();
        })
    };
    match res {
        Ok(()) => {
            tracing::info!("central: connection gone, {} distributed folders released", managed.len());
            record_change(&format!("Central removed, released {managed:?}"));
            // As after a fresh enrollment: what had been reported does not
            // count for the next central server.
            cstate.generation = 0;
            cstate.sent.clear();
            cstate.learn_done.clear();
            if let Err(e) = cstate.save() {
                tracing::warn!("central: state not saved: {e:#}");
            }
        }
        Err(e) => {
            tracing::error!("central: folders not released: {e:#}");
            cstate.managed = managed;
        }
    }
}

async fn apply_central_config(st: &Mutex<State>, cstate: &mut deelpe::central::CentralState, cfg: &deelpe_core::central::AgentConfig) {
    let mine: Vec<&deelpe_core::central::Rule> = cfg.rules.iter().filter(|r| r.enabled && r.path.starts_with('/')).collect();
    let wanted: Vec<std::path::PathBuf> = mine.iter().map(|r| std::path::PathBuf::from(&r.path)).collect();
    // Strict folders come entirely from the central server: leaving them
    // standing here would keep a block in place after a rule was switched
    // off.
    let strict: Vec<deelpe_core::config::Strict> = mine
        .iter()
        .filter(|r| r.strict)
        .map(|r| deelpe_core::config::Strict {
            path: std::path::PathBuf::from(&r.path),
            allow: r.allow_destinations.clone(),
            enforce: r.enforce,
        })
        .collect();
    let old = std::mem::take(&mut cstate.managed);
    let mut s = st.lock().await;
    let res = update_config(&mut s, |c| {
        c.watched.retain(|p| !old.contains(p) || wanted.contains(p));
        for p in &wanted {
            if !c.watched.contains(p) {
                c.watched.push(p.clone());
            }
        }
        c.strict = strict.clone();
        // Like the strict folders: the list comes entirely from the
        // central server. Leaving it standing here would keep a process
        // allowed after the dashboard took it off the list.
        c.allow_processes = cfg.allow_processes.iter().map(|s| deelpe_core::identity::image_name(s)).collect();
    });
    match res {
        Ok(()) => {
            tracing::info!("central: configuration {} applied, {} distributed folders, {} strict", cfg.generation, wanted.len(), strict.len());
            record_change(&format!("Central generation {} managed {:?}", cfg.generation, wanted));
            cstate.managed = wanted;
            cstate.generation = cfg.generation;
        }
        Err(e) => {
            tracing::error!("central: configuration not applied: {e:#}");
            cstate.managed = old;
        }
    }
}

/// Fresh touches of strict folders with `enforce`, as cage orders: PID, the
/// name the cage judges by, the allowlist, and whether the process's
/// current children go along.
///
/// Drained after every event, so one batch is one read: the reader first,
/// then the ancestors it was inherited to, up the whole chain — right for
/// reporting, far too wide for a cage. Seen in the lab VM on 2026-09-15: the
/// chain reached the machine's guest agent, and every shell started after
/// that was born inside the cage. So the cage takes the **reader with its
/// children**, and its **parent alone**: whatever the parent starts next
/// (`x=$(cat f); curl …`) is born inside, but the parent's other children
/// and every ancestor above stay free.
///
/// ponytail: a pipe sibling started at the same moment (`cat f | curl …`)
/// already runs and stays outside; it is reported, not stopped.
fn fresh_touches(corr: &mut Correlator) -> Vec<(u32, String, Vec<String>, bool)> {
    let batch = corr.drain_tainted();
    let Some(&(reader, _)) = batch.first() else { return Vec::new() };
    let parent = corr.parent_of(reader);
    let mut out = Vec::new();
    for (pid, origin) in batch {
        if pid != reader && Some(pid) != parent {
            continue;
        }
        let Some(x) = corr.config().strict_for(&origin).filter(|x| x.enforce) else { continue };
        let name = corr.touched_identity(pid).map(|i| i.short()).unwrap_or_default();
        // An ancestor the sensors never named, or a reader gone before it
        // was named, is a placeholder (`pid 123`). The cage judges by name,
        // so ask the system once more.
        let name = if name.starts_with("pid ") { crate::cage::process_name(pid).unwrap_or(name) } else { name };
        out.push((pid, name, x.allow.clone(), pid == reader));
    }
    out
}

/// What this service can do about a forbidden exfiltration.
///
/// An adapter on the seam that `deelpe_core::pipeline` opens up; the second
/// one sits in the Windows workstation agent and can additionally remove
/// the copy.
struct MacEnforcer;

impl deelpe_core::pipeline::Enforcer for MacEnforcer {
    fn delete_copy(&self, _a: &deelpe_core::correlate::Alert) -> String {
        // A copy out of a strict folder is forbidden too, but the process
        // doing the copying is the Finder: killing it helps nobody.
        // Removing the copy only exists on the Windows workstation so far.
        "copy NOT deleted: only Windows endpoints can do that".into()
    }
}

async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

async fn set_sensor_error(st: &Mutex<State>, name: &str, err: Option<String>) {
    if let Some(sensor) = st.lock().await.sensors.iter_mut().find(|x| x.name == name) {
        sensor.error = err;
    }
}

async fn serve(state: Arc<Mutex<State>>) -> Result<()> {
    let _ = std::fs::remove_file(SOCKET);
    let listener = UnixListener::bind(SOCKET).with_context(|| format!("socket {SOCKET} (needs root)"))?;
    // The CLI and the menu bar app run without root, but not every local
    // process may read: access for root and the user group only.
    restrict_socket(Path::new(SOCKET))?;
    tracing::info!("ready on {SOCKET}");
    loop {
        let (stream, _) = listener.accept().await?;
        let st = state.clone();
        tokio::spawn(async move {
            let uid = peer_uid(&stream);
            let (r, mut w) = stream.into_split();
            let mut line = String::new();
            if BufReader::new(r).read_line(&mut line).await.is_err() {
                return;
            }
            let resp = match serde_json::from_str::<Request>(&line) {
                Ok(req) => handle(&st, req, uid).await,
                Err(e) => Response::Err(format!("invalid request: {e}")),
            };
            let mut out = serde_json::to_string(&resp).unwrap_or_default();
            out.push('\n');
            let _ = w.write_all(out.as_bytes()).await;
        });
    }
}

/// UID of the peer on the socket; with no answer the client counts as a
/// stranger.
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    stream.peer_cred().ok().map(|c| c.uid())
}

async fn handle(state: &Mutex<State>, req: Request, uid: Option<u32>) -> Response {
    let mut st = state.lock().await;
    let mutating = req.needs_root();
    if mutating && uid != Some(0) {
        tracing::warn!("refused (uid {uid:?}): {req:?}");
        return Response::Err(NEEDS_ROOT.into());
    }
    let text = format!("{req:?}");
    let resp = apply(&mut st, req);
    if mutating && matches!(resp, Response::Ok(_)) {
        record_change(&text);
    }
    resp
}

fn apply(st: &mut State, req: Request) -> Response {
    match req {
        Request::WatchAdd(p) => update_config(st, |c| {
            if !c.watched.contains(&p) {
                c.watched.push(p.clone());
            }
        })
        .map(|_| Response::Ok(format!("{} is now protected", p.display())))
        .unwrap_or_else(|e| Response::Err(e.to_string())),
        Request::WatchRemove(p) => update_config(st, |c| c.watched.retain(|x| x != &p))
            .map(|_| Response::Ok(format!("{} no longer protected", p.display())))
            .unwrap_or_else(|e| Response::Err(e.to_string())),
        Request::WatchList => Response::Watched(st.corr.config().watched.clone()),
        Request::IgnoreAdd(r) => {
            let r = r.trim().to_string();
            if let Err(e) = validate_ignore_rule(&r) {
                return Response::Err(e);
            }
            update_config(st, |c| {
                if !c.ignored.contains(&r) {
                    c.ignored.push(r.clone());
                }
            })
            .map(|_| Response::Ok(format!("{r} is ignored from now on")))
            .unwrap_or_else(|e| Response::Err(e.to_string()))
        }
        Request::IgnoreRemove(r) => {
            let r = r.trim().to_string();
            update_config(st, |c| c.ignored.retain(|x| x != &r))
                .map(|_| Response::Ok(format!("{r} is reported again")))
                .unwrap_or_else(|e| Response::Err(e.to_string()))
        }
        Request::IgnoreList => Response::Ignored(st.corr.config().ignored.clone()),
        Request::LearnStatus => Response::Learn(st.learner.status(chrono::Utc::now())),
        Request::LearnConfirm => {
            st.learner.confirm();
            st.learn_dirty = true;
            Response::Ok(format!("{} pairs confirmed; from now on only new and deviating traffic is reported", st.learner.pair_count()))
        }
        Request::LearnForget(key) => {
            if st.learner.forget(&key) {
                st.learn_dirty = true;
                Response::Ok(format!("{key} dropped"))
            } else {
                Response::Err(format!("no pair {key}"))
            }
        }
        Request::LearnRemember(id) | Request::LearnFlag(id) => {
            let remember = matches!(req, Request::LearnRemember(_));
            let Some(a) = st.alerts.alerts().iter().find(|a| a.id == id).cloned() else {
                return Response::Err(format!("no alert #{id}"));
            };
            let key = if remember { st.learner.remember(&a) } else { st.learner.flag(&a) };
            match key {
                Some(k) => {
                    st.learn_dirty = true;
                    Response::Ok(if remember { format!("{k} remembered: silent from now on") } else { format!("{k} is always reported") })
                }
                None => Response::Err("unsigned processes are always reported and never learned".into()),
            }
        }
        Request::LearnRestart => {
            let days = st.corr.config().learn_days;
            st.learner.restart(days, chrono::Utc::now());
            st.learn_dirty = true;
            Response::Ok(format!("new learning phase, {days} days"))
        }
        Request::Alerts => Response::Alerts(st.alerts.alerts().iter().rev().take(RECENT_ALERTS).cloned().collect()),
        Request::AlertsAll => Response::Alerts(st.alerts.alerts().to_vec()),
        Request::Show(id) => Response::Alert(st.alerts.alerts().iter().find(|a| a.id == id).cloned()),
        Request::CentralStatus => Response::Central(deelpe::central::info()),
        Request::Status => Response::Status {
            touched: st.corr.touched_count(),
            alerts: st.alerts.alerts().len(),
            watched: st.corr.config().watched.len(),
            uptime_secs: st.started.elapsed().as_secs(),
            sensors: st.sensors.clone(),
            warnings: st.integrity.warnings.clone(),
        },
    }
}

/// Every change to the watch, exception or pair list stays traceable.
fn record_change(req: &str) {
    tracing::warn!("configuration: {req}");
    record_line(req);
}

fn record_line(text: &str) {
    let line = format!("{} {text}\n", chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let res = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(CHANGES)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = res {
        tracing::error!("{CHANGES}: {e}");
    }
}

/// Set the socket to 0660 and assign it to the user group (macOS: `staff`,
/// Linux: `deelpe`, falling back to `users`).
fn restrict_socket(sock: &Path) -> Result<()> {
    let candidates: &[&str] = if cfg!(target_os = "macos") { &["staff"] } else { &["deelpe", "users"] };
    let gid = candidates.iter().find_map(|g| group_id(g));
    match gid {
        Some(gid) => {
            std::os::unix::fs::chown(sock, None, Some(gid))?;
            std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o660))?;
        }
        None => {
            tracing::warn!("no user group found ({candidates:?}), the socket stays root-only");
            std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn group_id(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: getgrnam_r is reentrant; every buffer is ours and lives until
    // after the call. `result` points at `grp` or is NULL.
    let rc = unsafe {
        libc::getgrnam_r(cname.as_ptr(), &mut grp, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut result)
    };
    if rc == 0 && !result.is_null() { Some(grp.gr_gid) } else { None }
}

fn update_config(st: &mut State, f: impl FnOnce(&mut Config)) -> Result<()> {
    let mut cfg = st.corr.config().clone();
    f(&mut cfg);
    cfg.save(Path::new(CONFIG))?;
    st.corr.set_config(cfg);
    arm_sensors(st.corr.config());
    st.integrity.written(CONFIG);
    st.integrity_dirty = true;
    Ok(())
}

/// Tell the sensors which folders matter — at startup and on every change
/// to the configuration, because the folders come from the central server
/// and arrive while the service is running.
///
/// Only the Linux sensor asks: fanotify sees the whole machine, and without
/// this it pushes every open on the system through the channel and under
/// load drops the one that mattered. That is the lesson from the Windows
/// workstation (lab log 2026-09-07), and it holds here for the same reason.
/// `eslogger` on the Mac ignores the filter and lets the correlator decide.
fn arm_sensors(cfg: &Config) {
    let paths: Vec<String> = cfg.watched.iter().map(|p| p.display().to_string()).collect();
    deelpe_sensors::set_watched(deelpe_sensors::Watch::Folders { paths: &paths, taint_ttl: cfg.sensor_taint_ttl() });
    deelpe_sensors::set_guarded(&cfg.guarded);
}

/// Tighten an existing file to 0600 (older versions wrote 0644).
fn tighten(path: &Path) {
    if path.exists() {
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!("{}: permissions not set: {e}", path.display());
        }
    }
}

// --- Learning phase

/// Loads the learned pairs; on the first start, the stored alerts of the
/// last `learn_days` already count as observations.
fn load_learner(alerts: &AlertLog, learn_days: u32) -> Learner {
    let now = chrono::Utc::now();
    match std::fs::read_to_string(LEARNED) {
        Ok(raw) => match serde_json::from_str::<Learner>(&raw) {
            Ok(l) => {
                tracing::info!("learning phase: {:?}, {} pairs", l.phase(now), l.pair_count());
                return l;
            }
            Err(e) => tracing::warn!("{LEARNED} unreadable, starting a new learning phase: {e}"),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!("{LEARNED}: {e}"),
    }
    let mut l = Learner::new(learn_days, now);
    l.seed(alerts.alerts(), learn_days, now);
    tracing::info!("learning phase starts, {} pairs from the log", l.pair_count());
    l
}

async fn save_learner(st: &Mutex<State>) {
    let json = {
        let mut s = st.lock().await;
        if !s.learn_dirty {
            return;
        }
        s.learn_dirty = false;
        serde_json::to_string(&s.learner)
    };
    let res = json.map_err(anyhow::Error::from).and_then(|j| write_private(LEARNED, j.as_bytes()));
    match res {
        Err(e) => tracing::error!("learned data not saved: {e:#}"),
        Ok(()) => {
            let mut s = st.lock().await;
            s.integrity.written(LEARNED);
            s.integrity_dirty = true;
        }
    }
}

/// Write atomically and with mode 0600.
fn write_private(path: &str, data: &[u8]) -> Result<()> {
    let tmp = format!("{path}.tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// --- The correlator's memory

fn restore_state(corr: &mut Correlator) -> Integrity {
    let raw = match std::fs::read_to_string(STATE) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Integrity::default(),
        Err(e) => {
            tracing::warn!("{STATE}: {e}");
            return Integrity::default();
        }
    };
    match serde_json::from_str::<StateFile>(&raw) {
        Ok(f) => {
            let same_boot = !f.boot_id.is_empty() && f.boot_id == boot_id();
            corr.restore(f.snapshot, same_boot);
            tracing::info!(
                "memory loaded: {} touched processes, {} derived files{}",
                corr.touched_count(),
                corr.derived_count(),
                if same_boot { "" } else { " (after a reboot: files only)" }
            );
            f.integrity
        }
        Err(e) => {
            tracing::warn!("{STATE} unreadable, discarded: {e}");
            Integrity::default()
        }
    }
}

async fn save_state(st: &Mutex<State>) {
    let file = {
        let mut s = st.lock().await;
        if !s.dirty && !s.integrity_dirty {
            return;
        }
        s.integrity_dirty = false;
        s.dirty = false;
        StateFile { boot_id: boot_id(), snapshot: s.corr.snapshot(), integrity: s.integrity.clone() }
    };
    let res = serde_json::to_vec(&file).map_err(anyhow::Error::from).and_then(|j| write_private(STATE, &j));
    if let Err(e) = res {
        tracing::error!("memory not saved: {e:#}");
    }
}

/// ID of the current boot; after a reboot the PIDs start over.
fn boot_id() -> String {
    #[cfg(target_os = "macos")]
    {
        let mut tv: libc::timeval = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::timeval>();
        let name = std::ffi::CString::new("kern.boottime").expect("static");
        // SAFETY: buffer and length match `timeval`, the way sysctl delivers
        // it for kern.boottime.
        let rc = unsafe { libc::sysctlbyname(name.as_ptr(), &mut tv as *mut _ as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0) };
        if rc == 0 { tv.tv_sec.to_string() } else { String::new() }
    }
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_string()).unwrap_or_default()
    }
}
