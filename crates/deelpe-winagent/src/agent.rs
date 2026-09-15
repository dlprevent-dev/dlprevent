//! The loop: read events, condense them locally, report.
//!
//! Condensing uses the same `AccessMeter` as the NAS path of the central, so
//! that both ways behave alike (decision of 2026-09-06). What goes out are
//! counts per (user, rule, minute) and alerts — never raw events.

use crate::audit;
use crate::config::{AgentState, CentralConfig};
use crate::evtlog::{self, FILE_READ_DATA};
use anyhow::{Context, Result};
use chrono::Utc;
use deelpe_core::access::{AccessMeter, AccessParams, Aggregator, RuleView};
use deelpe_core::central::{AccessAlert, AgentConfig, AgentStatus, Report, Rule, SensorHealth, ShareInfo, UserRef, API_VERSION};
use deelpe_core::session::Session;
use deelpe_core::rules::rule_matches;
use std::collections::HashMap;
use tracing::{info, warn};

const MAX_EVENTS_PER_ROUND: usize = 20_000;

/// Runs until `stop` goes `true` (service stop) or — with `run` on the
/// command line — until Ctrl-C.
pub async fn run(mut stop: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let cfg = CentralConfig::load()?.context("not enrolled — run `deelpe-winagent enroll` first")?;
    const UA: &str = concat!("deelpe-winagent/", env!("CARGO_PKG_VERSION"));
    let mut session = Session::new(cfg.credentials(), crate::config::hostname(), UA, Box::new(cfg.clone()))?;
    let mut st = AgentState::load();
    // Counts the update attempts per checksum; see `update::Updater`.
    let mut updater = crate::update::Updater::default();
    let started = Utc::now();

    // Without a policy nothing lands in the log; that is not worth a
    // warning, it is an error the operator has to see.
    let policy = match audit::ensure_policy() {
        Ok(()) => None,
        Err(e) => {
            warn!("audit policy not set: {e:#}");
            Some(format!("{e:#}"))
        }
    };

    let mut rules: Vec<Rule> = Vec::new();
    let mut learn_days = 7u32;
    // Folders whose auditing is not up, with the reason. In memory only:
    // at startup everything is checked afresh anyway.
    let mut not_armed: HashMap<String, String> = HashMap::new();
    // Counts and sample files; shares its code with the syslog condensation
    // of the central (`deelpe_core::access`).
    let mut agg = Aggregator::new();

    // Rules first, then read. The other way round the agent discards after
    // every restart exactly the events that arose while it was away: the
    // first pass pushes `last_record_id` to the end of the log without a
    // single rule being loaded. If the central is unreachable at startup, we
    // wait instead of reading on blindly.
    let mut configured = false;

    info!(central = %cfg.url, "file server agent running");
    // Counts and alerts stay put until the central has accepted them.
    // Otherwise every minute without a connection costs exactly the accesses
    // that happened in that minute — and that is the minute in which somebody
    // could have cut the line. Both sides are idempotent: the central writes
    // counts by (source, path, user, minute) and alerts by `external_id`.
    let mut alerts: Vec<AccessAlert> = std::mem::take(&mut st.pending_alerts);
    agg.restore_counts(std::mem::take(&mut st.pending_counts));
    if !agg.is_empty() || !alerts.is_empty() {
        info!(counts = agg.len(), alerts = alerts.len(), "carrying over what the central has not accepted yet");
    }
    loop {
        // Every round, not only on a new configuration: a folder that was
        // missing or locked on the first attempt would otherwise never be
        // armed again until somebody touches a rule.
        arm(&rules, &mut st, &mut not_armed);

        match if configured { evtlog::read_since(st.last_record_id, MAX_EVENTS_PER_ROUND) } else { Ok(Vec::new()) } {
            Ok(events) => {
                for e in events {
                    st.last_record_id = st.last_record_id.max(e.record_id);
                    // Share → local path, without a single extra right.
                    if e.event_id == 5145 {
                        if let (Some(n), Some(p)) = (e.get("ShareName"), e.get("ShareLocalPath")) {
                            let p = p.trim_start_matches(r"\??\").to_string();
                            st.share_paths.insert(crate::shares::share_name(n), p);
                        }
                    }
                    if let Some(a) = access_from(&e) {
                        observe(a, &rules, learn_days, &mut st.meters, &mut agg, &mut alerts);
                    }
                }
            }
            Err(e) => warn!("security event log: {e:#}"),
        }

        trim(&mut agg, &mut alerts);
        let bucketed = agg.counts();

        // Groups cost one enumeration pass; that is cheap compared to what
        // an unnecessarily sent list sets off in the central.
        let all_groups = crate::groups::list();
        let digest = crate::groups::digest(&all_groups);
        let send_groups = digest != st.groups_digest;

        let mut report = Report {
            api_version: Some(API_VERSION),
            // Only report it when we are actually running rules -- the same
            // expression as the second condition in `apply`. Without rules we
            // report nothing, and the central sends them again.
            generation: (!rules.is_empty()).then_some(st.generation),
            status: Some(AgentStatus {
                version: env!("CARGO_PKG_VERSION").into(),
                    build: deelpe_core::central::build_fingerprint().into(),
                hostname: crate::config::hostname(),
                fqdn: crate::config::fqdn(),
                started_at: started,
                sensors: sensors(&policy, &st.prepared, &not_armed),
                watched: rules.iter().map(|r| r.path.clone()).collect(),
                learn_phase: learn_phase(&st.meters, learn_days),
                shares: crate::shares::list(&st.share_paths),
                addrs: deelpe_core::netaddr::local_addrs(),
                arch: deelpe_core::central::arch().into(),
            }),
            alerts: Vec::new(),
            access_alerts: alerts.clone(),
            counts: bucketed,
            groups: if send_groups { Some(all_groups) } else { None },
            // Learning instructions apply to the (process, destination) pair
            // of the endpoint correlator; the server agent has none.
            learn_done: Vec::new(),
            // `log` adds the session, so that the read cursor only moves on
            // once the report is accepted.
            ..Default::default()
        };

        // Log lines, error counters, the wait time and the renewal of the
        // certificate are the session's business; what stays here is what
        // only this agent knows.
        let sent = session
            .send(&mut report)
            .await;
        match sent {
            Ok(resp) => {
                // Taken completely apart, without `..`: a new field in the
                // wire format breaks here instead of quietly disappearing.
                // See `ReportResponse`.
                let deelpe_core::central::ReportResponse {
                    accepted_alerts: _,
                    accepted_access_alerts: _,
                    accepted_counts: _,
                    config: new_config,
                    // Learning instructions apply to the (process,
                    // destination) pair of the endpoint correlator; a file
                    // server has none. Whoever does have one here some day
                    // trips over it at compile time.
                    learn: _,
                } = resp;
                st.tally.ok(Utc::now());
                // An accepted report means: this program really runs. Now
                // the previous version may go.
                crate::update::cleanup_old();
                // Arrived — now it may go.
                agg.clear_counts();
                alerts.clear();
                // Only remember it after an accepted report: otherwise a
                // list counts as reported that never arrived.
                if send_groups {
                    st.groups_digest = digest;
                    info!("Gruppenliste gemeldet");
                }
                apply(&new_config, &mut rules, &mut learn_days, &mut st);
                if !configured {
                    configured = true;
                    info!(rules = rules.len(), "rules received, starting to read");
                }
                // Does **not** hang on the generation: an agent that already
                // runs the current one would otherwise never get a new
                // program.
                if let Some(want) = &new_config.update_to_sha256 {
                    if let Err(e) = crate::update::apply(&session, want, &mut updater).await {
                        warn!("agent update: {e:#}");
                    }
                }
            }
            Err(e) => {
                st.tally.failed(&e, Utc::now());
            }
        }
        for m in st.meters.values_mut() {
            m.prune(Utc::now());
        }
        // The backlog belongs in the state, not only in memory.
        st.pending_counts = agg.counts();
        st.pending_alerts = alerts.clone();
        if let Err(e) = st.save() {
            warn!("saving state: {e:#}");
        }
        // Only after the state is on disk: the new agent carries on at the
        // same read cursor, with the same backlog.
        if crate::update::restart_requested() {
            info!("stopping so the service manager starts the new program");
            // One more report before it is over.
            //
            // Log lines travel along with the **next** report — and there is
            // no next one out of this process. Without this, of all things
            // the lines that make up the whole operation get lost ("fetching
            // it", "program replaced"): the new process starts with an empty
            // ring, and the dashboard would show only a version that changed
            // without explanation. In a product that keeps evidence, exactly
            // that belongs in the central log.
            let mut last = Report { api_version: Some(API_VERSION), generation: Some(st.generation), ..Default::default() };
            if let Err(e) = session.send(&mut last).await {
                warn!("the last report before the restart did not get through: {e:#}");
            }
            return Ok(());
        }
        // On a stop the state is already written: the read cursor is right,
        // the next start carries on there.
        tokio::select! {
            _ = tokio::time::sleep(session.wait()) => {}
            _ = stop.changed() => {
                if *stop.borrow() {
                    info!("stop signal, agent shuts down");
                    return Ok(());
                }
            }
        }
    }
}

fn learn_phase(meters: &HashMap<String, AccessMeter>, learn_days: u32) -> String {
    let p = AccessParams { learn_days, ..Default::default() };
    let now = Utc::now();
    if meters.is_empty() || meters.values().any(|m| m.is_learning(&p, now)) {
        "learning".into()
    } else {
        "active".into()
    }
}

/// Take over a new configuration: set the rules, and set up policy and SACL
/// for every new rule folder.
fn apply(c: &AgentConfig, rules: &mut Vec<Rule>, learn_days: &mut u32, st: &mut AgentState) {
    // The same question as with the endpoint agent, and now the same
    // expression too.
    if !deelpe_core::central::adopt_generation(c.generation, st.generation, !rules.is_empty()) {
        return;
    }
    st.generation = c.generation;
    *learn_days = c.learn_days.max(1);
    *rules = c.rules.iter().filter(|r| r.enabled).cloned().collect();
    info!(generation = c.generation, rules = rules.len(), "configuration applied");

    // Rules that are gone lose their meter.
    let ids: std::collections::HashSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    st.meters.retain(|k, _| ids.contains(k.split('|').next().unwrap_or("")));
}

/// Upper bounds for what waits on a reachable central. At half a minute per
/// round that is enough for days; beyond that the newest counts for more than
/// the oldest.
const MAX_PENDING_COUNTS: usize = 20_000;
const MAX_PENDING_ALERTS: usize = 2_000;

/// Caps the backlog, so that a server unreachable for days does not let the
/// agent fill up.
fn trim(agg: &mut Aggregator, alerts: &mut Vec<AccessAlert>) {
    let dropped = agg.trim_counts(MAX_PENDING_COUNTS);
    if dropped > 0 {
        warn!(dropped, "central unreachable for too long, dropping the oldest counts");
    }
    if alerts.len() > MAX_PENDING_ALERTS {
        let drop = alerts.len() - MAX_PENDING_ALERTS;
        alerts.drain(..drop);
        warn!(dropped = drop, "central unreachable for too long, dropping the oldest alerts");
    }
}

/// Report to the central: one entry per watched folder. Without it the
/// dashboard shows a green agent while the folders it is supposed to guard
/// produce no events at all.
fn sensors(policy: &Option<String>, armed: &[String], not_armed: &HashMap<String, String>) -> Vec<SensorHealth> {
    let mut out = vec![
        SensorHealth { name: "security-eventlog".into(), ok: policy.is_none(), error: policy.clone() },
        crate::update::readiness(),
    ];
    let mut rest: Vec<SensorHealth> = armed
        .iter()
        .map(|p| SensorHealth { name: format!("file audit {p}"), ok: true, error: None })
        .chain(not_armed.iter().map(|(p, e)| SensorHealth { name: format!("file audit {p}"), ok: false, error: Some(e.clone()) }))
        .collect();
    rest.sort_by(|a, b| a.name.cmp(&b.name));
    out.extend(rest);
    out
}

/// Absolute means: drive (`C:\…`), UNC (`\\srv\…`) or Unix root.
pub fn is_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    p.starts_with(r"\\") || p.starts_with('/') || (b.len() >= 2 && b[1] == b':')
}

/// A rule path may be relative (`Finance`) — in the dashboard it is picked
/// from the reported share list. On the file server a real folder has to come
/// out of it, otherwise no SACL is set and not a single event arises.
/// Observed exactly like that on the lab DC on 2026-09-06.
fn resolve(rule_path: &str, shares: &[ShareInfo]) -> Vec<String> {
    if is_absolute(rule_path) {
        return vec![rule_path.to_string()];
    }
    let mut out = Vec::new();
    for s in shares {
        let Some(root) = s.path.as_deref().map(|p| p.trim_end_matches('\\')) else { continue };
        if s.name.eq_ignore_ascii_case(rule_path) {
            out.push(root.to_string());
        } else {
            // A folder below a share as well, e.g. rule "Buchhaltung" in
            // the share "Finance".
            let cand = format!("{root}\\{rule_path}");
            if std::path::Path::new(&cand).is_dir() {
                out.push(cand);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Policy and SACL for all rule folders. Runs every round; what is already
/// in place costs nothing.
fn arm(rules: &[Rule], st: &mut AgentState, not_armed: &mut HashMap<String, String>) {
    // Without rules nothing is known — cleaning up here would discard the
    // folders rescued across the restart before the central answers.
    if rules.is_empty() {
        return;
    }
    let shares = crate::shares::list(&st.share_paths);
    let mut wanted: Vec<String> = Vec::new();
    let mut bad: HashMap<String, String> = HashMap::new();
    for r in rules.iter() {
        let paths = resolve(&r.path, &shares);
        if paths.is_empty() {
            bad.insert(r.path.clone(), format!("no folder found for rule \"{}\"", r.path));
            continue;
        }
        for p in paths {
            wanted.push(p.clone());
            // Do not blindly believe our own state: if somebody takes the
            // audit entry away, the agent would otherwise never notice and
            // keep reporting "fine" while nothing arrives any more.
            if st.prepared.contains(&p) && audit::has_sacl(&p) {
                continue;
            }
            st.prepared.retain(|q| q != &p);
            match audit::prepare(&p) {
                None => st.prepared.push(p),
                Some(e) => {
                    bad.insert(p, e);
                }
            }
        }
    }
    st.prepared.retain(|p| wanted.contains(p));
    // Into the log only on a change, otherwise a permanently locked share
    // writes the same line every half minute.
    for (path, reason) in bad.iter() {
        if not_armed.get(path) != Some(reason) {
            warn!(path, "local file auditing is not armed: {reason}");
        }
    }
    *not_armed = bad;
}

/// One access, no matter which event it came from. 5145 (SMB) brings the
/// client IP and the share path with it, 4663 covers local access on the
/// server.
pub struct Access {
    pub path: String,
    pub user: UserRef,
    pub client_ip: Option<String>,
    /// Opened for reading: this is what the access counter counts.
    pub read: bool,
    /// Opened for writing: a candidate for an arrival in the folder. An
    /// open can be both — Word opens a document for reading and writing.
    pub write: bool,
}

pub fn access_from(e: &evtlog::RawEvent) -> Option<Access> {
    if e.get("ObjectType").map(|t| !t.eq_ignore_ascii_case("File")).unwrap_or(false) {
        return None;
    }
    let mask = evtlog::parse_mask(e.get("AccessMask")?);
    let read = mask & FILE_READ_DATA != 0;
    // **Not yet seen on the real machine.** That a 5145 carries the write
    // bits when a file is put into the share comes from the manifest, not
    // from the lab log — unlike everything around it, which was measured on
    // 2026-09-06. `deelpe-winagent probe` shows the mask of the last events;
    // copy a file into the share and look for one that is not 0x12008
    // something. The SACL on the folder only audits reading
    // (`audit::SACL_AUDIT_READ`), so a **local** write on the server
    // console produces no 4663 either — over SMB, the case this is about,
    // 5145 arises without a SACL.
    let write = mask & (evtlog::FILE_WRITE_DATA | evtlog::FILE_APPEND_DATA) != 0;
    if !read && !write {
        return None;
    }
    let name = e.get("SubjectUserName")?;
    // Machine accounts and the service itself are not a human being.
    if name.ends_with('$') || name.eq_ignore_ascii_case("SYSTEM") || name.eq_ignore_ascii_case("ANONYMOUS LOGON") {
        return None;
    }
    let full = match e.event_id {
        5145 => evtlog::share_path(e.get("ShareLocalPath")?, e.get("RelativeTargetName").unwrap_or("")),
        4663 => e.get("ObjectName")?.to_string(),
        _ => return None,
    };
    // Alternate data streams belong to the file, not next to it.
    let path = evtlog::strip_stream(&full).to_string();
    if path.is_empty() {
        return None;
    }
    Some(Access {
        path,
        user: UserRef {
            source: crate::config::hostname(),
            name: name.to_string(),
            domain: e.get("SubjectDomainName").map(str::to_string),
            sid: e.get("SubjectUserSid").map(str::to_string),
        },
        client_ip: e.get("IpAddress").map(str::to_string),
        read,
        write,
    })
}

fn observe(a: Access, rules: &[Rule], learn_days: u32, meters: &mut HashMap<String, AccessMeter>, agg: &mut Aggregator, alerts: &mut Vec<AccessAlert>) {
    let Access { path, user, client_ip, read, write } = a;
    let now = Utc::now();
    // Asked at the first matching rule, not for every event: a `stat` on
    // a file nobody has a rule for is a syscall for nothing.
    let mut arrived: Option<bool> = None;

    for r in rules.iter().filter(|r| rule_matches(&r.path, &path)) {
        let rule = RuleView {
            id: &r.id,
            path: &r.path,
            params: AccessParams { hard_max_files: r.hard_max_files.max(1), window_secs: r.window_secs.max(1), learn_days },
        };
        let arrived = *arrived.get_or_insert_with(|| {
            write && deelpe_core::inbound::just_created(std::path::Path::new(&path), std::time::SystemTime::now(), deelpe_core::inbound::FRESH)
        });
        if arrived {
            if let Some(alert) = agg.inbound(&rule, &user, &path, client_ip.as_deref(), now) {
                if push(alerts, alert) {
                    info!(user = %user.display(), path = %r.path, "a file landed in the folder");
                }
            }
        }
        if !read {
            continue;
        }
        // One meter per rule: a newly distributed rule gets its own learning
        // phase that way, instead of inheriting the device's.
        let meter = meters.entry(r.id.clone()).or_insert_with(|| AccessMeter::new(now));
        // The file server knows no bytes: the security log says *that*
        // something was read, not how much.
        let Some(alert) = agg.observe(meter, &rule, &user, &path, 0, client_ip.as_deref(), now) else { continue };
        let reason = alert.reason.clone().unwrap_or_default();
        if push(alerts, alert) {
            warn!(user = %user.display(), path = %r.path, "mass access: {reason}");
        }
    }
}

/// Within one round, send only the most recent version of each alert.
/// Returns `true` if this one is the first of its kind in the round — the
/// log line hangs off that, otherwise every further file writes one.
fn push(alerts: &mut Vec<AccessAlert>, alert: AccessAlert) -> bool {
    match alerts.iter_mut().find(|x| x.external_id == alert.external_id) {
        Some(prev) => {
            *prev = alert;
            false
        }
        None => {
            alerts.push(alert);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(name: &str, path: &str) -> ShareInfo {
        ShareInfo { name: name.into(), path: Some(path.into()), remark: None, path_from: Some("enum".into()) }
    }

    #[test]
    fn absolute_paths_stay_as_they_are() {
        assert!(is_absolute(r"C:\Freigaben\GL"));
        assert!(is_absolute(r"\\srv\daten"));
        assert!(is_absolute("/volume1/daten"));
        assert!(!is_absolute("Finance"));
        assert_eq!(resolve(r"C:\Freigaben\GL", &[]), vec![r"C:\Freigaben\GL".to_string()]);
    }

    fn raw(mask: &str, path: &str) -> evtlog::RawEvent {
        let mut data = HashMap::new();
        for (k, v) in [
            ("SubjectUserSid", "S-1-5-21-1-2-3-1108"),
            ("SubjectUserName", "dl-anna"),
            ("SubjectDomainName", "CORP"),
            ("ShareName", r"\\*\GL"),
            ("ShareLocalPath", r"\??\C:\Freigaben\GL"),
            ("AccessMask", mask),
            ("IpAddress", "192.0.2.10"),
        ] {
            data.insert(k.to_string(), v.to_string());
        }
        data.insert("RelativeTargetName".into(), path.into());
        evtlog::RawEvent { event_id: 5145, record_id: 1, data }
    }

    /// Until now the agent threw away everything that was not a read — and
    /// with it every file that somebody put into the share.
    #[test]
    fn a_write_over_smb_is_an_access_too() {
        let w = access_from(&raw("0x120116", "neu.xlsx")).expect("write");
        assert!(w.write && !w.read);
        assert_eq!(w.path, r"C:\Freigaben\GL\neu.xlsx");
        let r = access_from(&raw("0x120089", "Zahlen.xlsx")).expect("read");
        assert!(r.read && !r.write);
        // Attribute access alone stays what it was: nothing.
        assert!(access_from(&raw("0x80", "Zahlen.xlsx")).is_none());
    }

    /// A file that has just come into being is an arrival; the same file
    /// opened for writing a second time is not a second one, and an old
    /// document that gets saved over is none at all.
    #[test]
    fn a_new_file_in_the_folder_becomes_an_arrival_alert() {
        let dir = std::env::temp_dir().join(format!("deelpe-arrival-agent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rules = vec![Rule {
            id: "11111111-1111-1111-1111-111111111111".into(),
            name: "GL".into(),
            path: dir.to_string_lossy().to_string(),
            allowed_groups: Vec::new(),
            lockdown: false,
            allow_destinations: Vec::new(),
            strict: false,
            enforce: false,
            hard_max_files: 100,
            window_secs: 60,
            ad_lock: false,
            enabled: true,
        }];
        let mut agg = Aggregator::new();
        let mut meters = HashMap::new();
        let mut alerts = Vec::new();
        let file = dir.join("neu.xlsx");
        std::fs::write(&file, b"x").unwrap();

        let access = |write: bool, path: &std::path::Path| Access {
            path: path.to_string_lossy().to_string(),
            user: UserRef { source: "srv".into(), name: "dl-anna".into(), domain: Some("CORP".into()), sid: None },
            client_ip: Some("192.0.2.10".into()),
            read: !write,
            write,
        };

        observe(access(true, &file), &rules, 7, &mut meters, &mut agg, &mut alerts);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        assert_eq!(alerts[0].verdict.label(), "inbound");
        assert_eq!(alerts[0].files, 1);
        assert_eq!(alerts[0].sample_files, vec![file.to_string_lossy().to_string()]);

        // The same file once more: one alert, still one file.
        observe(access(true, &file), &rules, 7, &mut meters, &mut agg, &mut alerts);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].files, 1);

        // A second file counts up in the same alert.
        let second = dir.join("noch-eine.xlsx");
        std::fs::write(&second, b"x").unwrap();
        observe(access(true, &second), &rules, 7, &mut meters, &mut agg, &mut alerts);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].files, 2);

        // Reading produces no arrival — that is the counter's business.
        observe(access(false, &file), &rules, 7, &mut meters, &mut agg, &mut alerts);
        assert_eq!(alerts.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bug from the lab: a relative rule never found a folder, so no
    /// SACL was ever set, so no event ever arrived.
    #[test]
    fn relative_rule_resolves_via_share_table() {
        let shares = vec![share("Finance", r"C:\Freigaben\Finance"), share("GL", r"C:\Freigaben\GL\")];
        assert_eq!(resolve("finance", &shares), vec![r"C:\Freigaben\Finance".to_string()]);
        assert_eq!(resolve("GL", &shares), vec![r"C:\Freigaben\GL".to_string()]);
        assert!(resolve("Personal", &shares).is_empty());
    }
}
