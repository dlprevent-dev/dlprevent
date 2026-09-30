//! M2 learning phase (design "Learning (model 3)"). A *pair* is (process
//! identity, destination network:port); the destination network is /24
//! (IPv4) or /48 (IPv6), because CDN addresses change within a network.
//!
//! 1. Learning phase (`learn_days`): every alert from the correlator is
//!    stored and marked as `Verdict::Learning` (table yes, notification
//!    no); the pair becomes a candidate.
//! 2. Then *review*: same behaviour, the app pushes for confirmation. The
//!    user strikes out what is unknown (`forget`) and confirms (`confirm`).
//! 3. Active: new pair → `Verdict::New`. Known pair → silent, unless the
//!    amount is over four times the largest so far or the time of day has
//!    never been seen (`Verdict::Deviation`). With `remember` a pair
//!    becomes known, with `flag` it is always reported
//!    (`Verdict::Flagged`).
//!
//! Unsigned processes are never learned: always `New`.

use crate::correlate::{Alert, Target};
use crate::identity::{image_name, ProcessIdentity};
use chrono::{DateTime, Duration, Local, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// An allow list from text: one line per program name, `#` is a comment.
/// The comparison form is [`image_name`] — the same as everywhere else, so
/// that a `TEAMS.EXE.MUI` does not slip past an entry `teams.exe`.
///
/// The list is maintained in the dashboard; here it only says how a set is
/// made out of the text field. Both ends use this function, so that the
/// central server and the agent never split it differently.
///
/// ponytail: only the program name, no path and no fingerprint. Whoever
/// names their malware `teams.exe` gets past this list — but not past the
/// strict folder, see [`crate::pipeline::judge`]. Upgrade path: `name
/// sha256` per line, compared against `ProcessIdentity::Hashed`.
pub fn parse_allowlist(raw: &str) -> BTreeSet<String> {
    raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(image_name)
        .collect()
}

/// Minimum observations before a deviation in amount is reported.
const MIN_SAMPLES_BYTES: u64 = 3;
/// Minimum observations before an unusual time of day is reported.
const MIN_SAMPLES_HOUR: u64 = 20;
/// Factor above the previous maximum at which the amount deviates.
const BYTES_FACTOR: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Unknown pair (or unsigned): report. Default for old rows.
    #[default]
    New,
    /// Learning or review phase: stored, not reported.
    Learning,
    /// Known pair, but amount or time deviate (`reason`).
    Deviation,
    /// Marked by the user as "always report".
    Flagged,
    /// Strict folder: the destination is not on its allow list. Never
    /// learned and never silenced — otherwise "block all" would be exactly
    /// that no longer after the learning phase.
    Denied,
    /// A file has landed *in* a protected folder ([`crate::inbound`]).
    /// Not a flow out of the folder, so the learning phase has nothing to
    /// say about it: it knows pairs of (process, destination), and an
    /// arrival has no destination outside. It is reported as a notice, not
    /// as an alarm, and no intervention hangs off it.
    Inbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairState {
    /// Seen during the learning phase, not yet confirmed.
    Candidate,
    Known,
    Flagged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pair {
    pub key: String,
    pub process: String,
    pub identity: ProcessIdentity,
    pub destination: String,
    pub port: Option<u16>,
    pub state: PairState,
    /// Observed flows (alerts from the correlator, carry-forwards do not count).
    pub count: u64,
    /// Largest total of a flow, including the current one.
    pub bytes_max: u64,
    /// Largest total without the current flow: the comparison base for
    /// deviations.
    #[serde(default)]
    prev_max: u64,
    #[serde(default)]
    last_id: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// Observations per hour (local time), 24 entries.
    #[serde(default)]
    pub hours: Vec<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Learning,
    Review,
    Active,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnStatus {
    pub phase: Phase,
    /// End of the learning phase (in Learning and Review).
    pub until: Option<DateTime<Utc>>,
    pub pairs: Vec<Pair>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Store {
        verdict: Verdict,
        reason: Option<String>,
    },
    Drop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Learner {
    until: DateTime<Utc>,
    confirmed: bool,
    pairs: BTreeMap<String, Pair>,
    /// Running deviations: carry-forwards of the same alert stay visible.
    #[serde(skip)]
    reported: HashMap<u64, String>,
}

impl Learner {
    pub fn new(learn_days: u32, now: DateTime<Utc>) -> Self {
        Self {
            until: now + Duration::days(learn_days as i64),
            confirmed: false,
            pairs: BTreeMap::new(),
            reported: HashMap::new(),
        }
    }

    /// First start with an existing log: alerts from the last `learn_days`
    /// already count as observations, and the learning phase ends
    /// correspondingly earlier.
    pub fn seed(&mut self, alerts: &[Alert], learn_days: u32, now: DateTime<Utc>) {
        let since = now - Duration::days(learn_days as i64);
        let mut oldest = now;
        for a in alerts
            .iter()
            .filter(|a| a.at >= since && a.identity.is_trusted_form())
        {
            oldest = oldest.min(a.at);
            self.observe(a, PairState::Candidate);
        }
        self.until = (oldest + Duration::days(learn_days as i64)).max(now);
    }

    pub fn phase(&self, now: DateTime<Utc>) -> Phase {
        if self.confirmed {
            Phase::Active
        } else if now < self.until {
            Phase::Learning
        } else {
            Phase::Review
        }
    }

    pub fn status(&self, now: DateTime<Utc>) -> LearnStatus {
        let phase = self.phase(now);
        LearnStatus {
            phase,
            until: if phase == Phase::Active {
                None
            } else {
                Some(self.until)
            },
            pairs: self.pairs.values().cloned().collect(),
        }
    }

    /// Decides about an alert from the correlator. `is_new` = first report
    /// of this flow, otherwise a carry-forward.
    pub fn judge(&mut self, a: &Alert, is_new: bool, now: DateTime<Utc>) -> Decision {
        // A forbidden destination outranks everything: no learning phase
        // and no known pair silences it.
        if a.verdict == Verdict::Denied {
            return Decision::Store {
                verdict: Verdict::Denied,
                reason: a.reason.clone(),
            };
        }
        // An arrival goes past the learning phase for the same reason as
        // the strict folder, only the other way round: there is no pair to
        // learn here. Whoever finds it too loud silences the process on the
        // allow list — that question is asked one layer up, in
        // `pipeline::judge`, and this fast path deliberately sits behind it.
        if a.verdict == Verdict::Inbound {
            return Decision::Store {
                verdict: Verdict::Inbound,
                reason: a.reason.clone(),
            };
        }
        if !a.identity.is_trusted_form() {
            // The correlator's reason stays: the LLM guard's findings come
            // with no nameable sender, and their reason is the finding.
            return Decision::Store {
                verdict: Verdict::New,
                reason: a.reason.clone(),
            };
        }
        let key = pair_key(a);
        match self.phase(now) {
            Phase::Learning | Phase::Review => {
                self.observe(a, PairState::Candidate);
                Decision::Store {
                    verdict: Verdict::Learning,
                    reason: None,
                }
            }
            Phase::Active => match self.pairs.get(&key).map(|p| p.state) {
                None => Decision::Store {
                    verdict: Verdict::New,
                    reason: None,
                },
                Some(PairState::Flagged) => {
                    self.observe(a, PairState::Flagged);
                    Decision::Store {
                        verdict: Verdict::Flagged,
                        reason: None,
                    }
                }
                Some(PairState::Candidate) | Some(PairState::Known) => {
                    let reason = self
                        .reported
                        .get(&a.id)
                        .cloned()
                        .or_else(|| deviation(&self.pairs[&key], a, is_new));
                    self.observe(a, PairState::Known);
                    match reason {
                        Some(r) => {
                            self.reported.insert(a.id, r.clone());
                            Decision::Store {
                                verdict: Verdict::Deviation,
                                reason: Some(r),
                            }
                        }
                        None => Decision::Drop,
                    }
                }
            },
        }
    }

    fn observe(&mut self, a: &Alert, state_if_new: PairState) {
        let key = pair_key(a);
        let p = self.pairs.entry(key.clone()).or_insert_with(|| Pair {
            key,
            process: a.identity.short(),
            identity: a.identity.clone(),
            // For a copy, `destination` carries the target in plain text
            // and there is no port; for a network flow, the destination
            // network and the port.
            destination: match a.target() {
                Target::Net { .. } => dest_net(a.remote),
                _ => dest_of(a),
            },
            port: match a.target() {
                Target::Net { port, .. } => port,
                _ => None,
            },
            state: state_if_new,
            count: 0,
            bytes_max: 0,
            prev_max: 0,
            last_id: 0,
            first_seen: a.at,
            last_seen: a.at,
            hours: vec![0; 24],
        });
        if p.hours.len() != 24 {
            p.hours = vec![0; 24];
        }
        if p.last_id != a.id {
            p.prev_max = p.bytes_max;
            p.last_id = a.id;
            p.count += 1;
            p.hours[local_hour(a.at)] += 1;
        }
        p.bytes_max = p.bytes_max.max(a.bytes_out);
        p.first_seen = p.first_seen.min(a.at);
        p.last_seen = p.last_seen.max(a.last_at.unwrap_or(a.at));
    }

    /// All candidates become known; from now on what is new gets reported.
    pub fn confirm(&mut self) {
        for p in self.pairs.values_mut() {
            if p.state == PairState::Candidate {
                p.state = PairState::Known;
            }
        }
        self.confirmed = true;
    }

    pub fn forget(&mut self, key: &str) -> bool {
        self.pairs.remove(key).is_some()
    }

    /// "Remember": the pair of this alert counts as known, the alert is
    /// the first observation.
    pub fn remember(&mut self, a: &Alert) -> Option<String> {
        if !a.identity.is_trusted_form() {
            return None;
        }
        self.observe(a, PairState::Known);
        let key = pair_key(a);
        self.pairs.get_mut(&key)?.state = PairState::Known;
        Some(key)
    }

    /// "Keep reporting": the pair is always reported, even as a known one.
    pub fn flag(&mut self, a: &Alert) -> Option<String> {
        if !a.identity.is_trusted_form() {
            return None;
        }
        self.observe(a, PairState::Flagged);
        let key = pair_key(a);
        self.pairs.get_mut(&key)?.state = PairState::Flagged;
        Some(key)
    }

    /// From the start: all pairs gone, a new learning phase.
    pub fn restart(&mut self, learn_days: u32, now: DateTime<Utc>) {
        *self = Self::new(learn_days, now);
    }

    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }
}

/// Does the alert deviate from what was learned? The base is the maximum
/// of *other* flows, otherwise a growing upload would compare itself with
/// itself.
fn deviation(p: &Pair, a: &Alert, is_new: bool) -> Option<String> {
    let same_flow = p.last_id == a.id && !is_new;
    let samples = if same_flow {
        p.count.saturating_sub(1)
    } else {
        p.count
    };
    let base = if same_flow { p.prev_max } else { p.bytes_max };
    if samples >= MIN_SAMPLES_BYTES && base > 0 && a.bytes_out > base.saturating_mul(BYTES_FACTOR) {
        return Some(format!(
            "amount {} is over {}× the usual maximum of {}",
            human_bytes(a.bytes_out),
            BYTES_FACTOR,
            human_bytes(base)
        ));
    }
    if samples >= MIN_SAMPLES_HOUR && p.hours.len() == 24 {
        let h = local_hour(a.at);
        let seen = [23 + h, h, h + 1].iter().any(|i| p.hours[i % 24] > 0);
        if !seen {
            return Some(format!(
                "unusual time: never sent around {h:02}:00 in {samples} observations"
            ));
        }
    }
    None
}

fn local_hour(at: DateTime<Utc>) -> usize {
    at.with_timezone(&Local).hour() as usize
}

/// /24 or /48: CDN and cloud addresses change within the network.
pub fn dest_net(ip: Option<IpAddr>) -> String {
    match ip {
        Some(IpAddr::V4(v)) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Some(IpAddr::V6(v)) => {
            let s = v.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        None => "?".into(),
    }
}

fn identity_key(id: &ProcessIdentity) -> String {
    match id {
        ProcessIdentity::Signed {
            team_id,
            signing_id,
        } => format!("{team_id}/{signing_id}"),
        ProcessIdentity::Hashed { path, sha256 } => {
            format!("hash:{path}:{}", &sha256[..12.min(sha256.len())])
        }
        ProcessIdentity::Unknown { path } => format!("unsigned:{path}"),
    }
}

pub fn pair_key(a: &Alert) -> String {
    format!("{}→{}", identity_key(&a.identity), dest_of(a))
}

/// Destination of an alert as text: network:port, `volume:<Mount>` or
/// `copy:<Ordner>`.
fn dest_of(a: &Alert) -> String {
    // This string goes via `pair_key` into the stored `learned.json`. It
    // has to stay identical letter for letter, otherwise the learner does
    // not find its pairs again and everything known counts as new again —
    // exactly the flood of alerts the learning phase is built against.
    match a.target() {
        Target::Volume(v) => format!("volume:{}", v.display()),
        Target::Copy(d) => format!("copy:{}", d.display()),
        Target::Net { port, .. } => format!(
            "{}:{}",
            dest_net(a.remote),
            port.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
        ),
        Target::Upload(u) => format!("upload:{u}"),
        Target::Unknown => format!("{}:{}", dest_net(None), "?"),
    }
}

/// Also for the CLI and notifications (`ui::human_bytes`).
pub fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(id: u64, ip: &str, bytes: u64, at: DateTime<Utc>) -> Alert {
        Alert {
            id,
            at,
            pid: 1,
            identity: ProcessIdentity::Signed {
                team_id: "APPLE".into(),
                signing_id: "com.apple.curl".into(),
            },
            files: vec![],
            remote: Some(ip.parse().unwrap()),
            remote_port: Some(443),
            bytes_out: bytes,
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

    fn store(v: Verdict) -> Decision {
        Decision::Store {
            verdict: v,
            reason: None,
        }
    }

    #[test]
    fn denied_is_never_learned_and_never_silenced() {
        let t0 = Utc::now();
        let mut l = Learner::new(7, t0);
        // First learn the same pair as known and confirm it.
        l.judge(&alert(1, "1.2.3.4", 5000, t0), true, t0);
        l.confirm();
        let later = t0 + Duration::days(8);
        assert_eq!(
            l.judge(&alert(2, "1.2.3.4", 5000, later), true, later),
            Decision::Drop,
            "bekannt, also still"
        );
        // The same connection out of a strict folder: reported anyway.
        let mut a = alert(3, "1.2.3.4", 5000, later);
        a.verdict = Verdict::Denied;
        a.reason = Some("destination is not on the allowlist of /w/GL".into());
        assert_eq!(
            l.judge(&a, true, later),
            Decision::Store {
                verdict: Verdict::Denied,
                reason: a.reason.clone()
            }
        );
        assert_eq!(l.pair_count(), 1, "verbotene Flüsse werden nicht zu Paaren");
    }

    #[test]
    fn learning_stores_silently_then_review_then_active() {
        let t0 = Utc::now();
        let mut l = Learner::new(7, t0);
        assert_eq!(l.phase(t0), Phase::Learning);
        assert_eq!(
            l.judge(&alert(1, "1.2.3.4", 5000, t0), true, t0),
            store(Verdict::Learning)
        );
        let later = t0 + Duration::days(8);
        assert_eq!(l.phase(later), Phase::Review);
        assert_eq!(
            l.judge(&alert(2, "1.2.3.9", 5000, later), true, later),
            store(Verdict::Learning),
            "gleiches /24, weiter Kandidat"
        );
        assert_eq!(l.pair_count(), 1);
        l.confirm();
        assert_eq!(l.phase(later), Phase::Active);
        assert_eq!(
            l.judge(&alert(3, "1.2.3.7", 5000, later), true, later),
            Decision::Drop,
            "bekanntes Paar ist still"
        );
        assert_eq!(
            l.judge(&alert(4, "9.9.9.9", 5000, later), true, later),
            store(Verdict::New),
            "neues Ziel"
        );
        let st = l.status(later);
        assert_eq!(st.phase, Phase::Active);
        assert_eq!(st.until, None);
        assert_eq!(st.pairs[0].state, PairState::Known);
        assert_eq!(st.pairs[0].count, 3);
    }

    #[test]
    fn unsigned_is_always_new() {
        let t0 = Utc::now();
        let mut l = Learner::new(7, t0);
        let mut a = alert(1, "1.2.3.4", 5000, t0);
        a.identity = ProcessIdentity::Unknown {
            path: "/tmp/evil".into(),
        };
        assert_eq!(l.judge(&a, true, t0), store(Verdict::New));
        assert_eq!(l.pair_count(), 0);
        assert!(l.remember(&a).is_none());
    }

    #[test]
    fn amount_deviation_uses_other_flows_as_base() {
        let t0 = Utc::now();
        let mut l = Learner::new(0, t0);
        for i in 1..=3 {
            l.judge(&alert(i, "1.2.3.4", 10_000, t0), true, t0);
        }
        l.confirm();
        // If a flow grows beyond four times, it reports; carry-forwards
        // stay visible.
        assert_eq!(
            l.judge(&alert(4, "1.2.3.4", 20_000, t0), true, t0),
            Decision::Drop
        );
        match l.judge(&alert(4, "1.2.3.4", 50_000, t0), false, t0) {
            Decision::Store {
                verdict: Verdict::Deviation,
                reason: Some(r),
            } => assert!(r.contains("4×"), "{r}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            l.judge(&alert(4, "1.2.3.4", 60_000, t0), false, t0),
            Decision::Store {
                verdict: Verdict::Deviation,
                ..
            }
        ));
        // After that 60 000 is the maximum: 100 000 is no longer a deviation.
        assert_eq!(
            l.judge(&alert(5, "1.2.3.4", 100_000, t0), true, t0),
            Decision::Drop
        );
    }

    #[test]
    fn hour_deviation_after_enough_samples() {
        let t0 = Utc::now();
        let mut l = Learner::new(0, t0);
        for i in 1..=20 {
            l.judge(&alert(i, "1.2.3.4", 1000, t0), true, t0);
        }
        l.confirm();
        let odd = t0 + Duration::hours(12);
        match l.judge(&alert(21, "1.2.3.4", 1000, odd), true, odd) {
            Decision::Store {
                verdict: Verdict::Deviation,
                reason: Some(r),
            } => assert!(r.contains("unusual time"), "{r}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            l.judge(
                &alert(22, "1.2.3.4", 1000, t0 + Duration::minutes(30)),
                true,
                t0
            ),
            Decision::Drop,
            "±1 h ist gewohnt"
        );
    }

    #[test]
    fn remember_flag_forget_and_restart() {
        let t0 = Utc::now();
        let mut l = Learner::new(0, t0);
        l.confirm();
        let a = alert(1, "1.2.3.4", 5000, t0);
        assert_eq!(l.judge(&a, true, t0), store(Verdict::New));
        let key = l.remember(&a).unwrap();
        assert_eq!(
            l.judge(&alert(2, "1.2.3.5", 5000, t0), true, t0),
            Decision::Drop
        );
        l.flag(&a);
        assert_eq!(
            l.judge(&alert(3, "1.2.3.5", 5000, t0), true, t0),
            store(Verdict::Flagged)
        );
        assert!(l.forget(&key));
        assert!(!l.forget(&key));
        assert_eq!(
            l.judge(&alert(4, "1.2.3.5", 5000, t0), true, t0),
            store(Verdict::New)
        );
        l.restart(7, t0);
        assert_eq!(l.phase(t0), Phase::Learning);
        assert_eq!(l.pair_count(), 0);
    }

    #[test]
    fn seed_from_history_shortens_learning() {
        let now = Utc::now();
        let mut l = Learner::new(7, now);
        let old = vec![
            alert(1, "1.2.3.4", 100, now - Duration::days(2)),
            alert(2, "1.2.3.4", 200, now - Duration::days(30)),
        ];
        l.seed(&old, 7, now);
        assert_eq!(l.pair_count(), 1);
        assert_eq!(l.status(now).pairs[0].count, 1, "30 Tage alt zählt nicht");
        assert_eq!(
            l.phase(now + Duration::days(5) + Duration::hours(1)),
            Phase::Review,
            "endet 7 Tage nach der ältesten Warnung"
        );
        assert_eq!(l.phase(now + Duration::days(4)), Phase::Learning);
    }

    #[test]
    fn keys_and_nets() {
        assert_eq!(
            dest_net(Some("10.20.30.40".parse().unwrap())),
            "10.20.30.0/24"
        );
        assert_eq!(
            dest_net(Some("2a00:1450:4001:82f::200e".parse().unwrap())),
            "2a00:1450:4001::/48"
        );
        assert_eq!(dest_net(None), "?");
        assert_eq!(
            pair_key(&alert(1, "1.2.3.4", 1, Utc::now())),
            "APPLE/com.apple.curl→1.2.3.0/24:443"
        );
        let usb = Alert {
            volume: Some("/Volumes/USB".into()),
            remote: None,
            remote_port: None,
            ..alert(1, "1.2.3.4", 1, Utc::now())
        };
        assert_eq!(pair_key(&usb), "APPLE/com.apple.curl→volume:/Volumes/USB");
        let cp = Alert {
            copy_to: Some("/Users/me/Desktop".into()),
            remote: None,
            remote_port: None,
            ..alert(1, "1.2.3.4", 1, Utc::now())
        };
        assert_eq!(pair_key(&cp), "APPLE/com.apple.curl→copy:/Users/me/Desktop");
        let json = serde_json::to_string(&Learner::new(1, Utc::now())).unwrap();
        let back: Learner = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pair_count(), 0);
    }

    /// The remaining key shapes, so that **every** one is pinned down.
    ///
    /// `pair_key` is at the same time the key in memory and the key in the
    /// stored `learned.json`: `pairs` is a `BTreeMap`, and its keys sit on
    /// disk as JSON field names. Anyone who changes the format in
    /// `identity_key` or `dest_of` does not find the stored pairs again —
    /// and everything known counts as new again, exactly the flood of
    /// alerts the learning phase is built against. Until 2026-09-10 that
    /// hung on one comment and three pinned-down shapes; the other four
    /// stood free.
    #[test]
    fn every_key_shape_is_pinned() {
        let base = alert(1, "1.2.3.4", 1, Utc::now());

        let hashed = Alert {
            identity: ProcessIdentity::Hashed {
                path: "/usr/bin/tool".into(),
                sha256: "0123456789abcdefdeadbeef".into(),
            },
            ..base.clone()
        };
        assert_eq!(
            pair_key(&hashed),
            "hash:/usr/bin/tool:0123456789ab→1.2.3.0/24:443"
        );

        let unsigned = Alert {
            identity: ProcessIdentity::Unknown {
                path: "/tmp/x".into(),
            },
            ..base.clone()
        };
        assert_eq!(pair_key(&unsigned), "unsigned:/tmp/x→1.2.3.0/24:443");

        let upload = Alert {
            upload_url: Some("https://ai.example.com/v1".into()),
            ..base.clone()
        };
        assert_eq!(
            pair_key(&upload),
            "APPLE/com.apple.curl→upload:https://ai.example.com/v1"
        );

        let nowhere = Alert {
            remote: None,
            remote_port: None,
            ..base
        };
        assert_eq!(pair_key(&nowhere), "APPLE/com.apple.curl→?:?");
    }

    /// And the route across the disk really carries: a remembered pair is
    /// still silent after a reload.
    ///
    /// The run above this sends an **empty** learner through JSON — that
    /// only proves that empty stays empty.
    #[test]
    fn a_remembered_pair_is_still_silent_after_a_reload() {
        let now = Utc::now();
        let mut l = Learner::new(0, now);
        l.confirm();
        let a = alert(1, "1.2.3.4", 1, now);
        assert!(l.remember(&a).is_some(), "das Paar muss lernbar sein");
        assert!(matches!(l.judge(&a, true, now), Decision::Drop));

        let json = serde_json::to_string(&l).expect("Lerner schreibt sich");
        // The key sits on disk as a field name -- a change of format shows
        // up here, not only at the next flood of alerts.
        assert!(
            json.contains("APPLE/com.apple.curl→1.2.3.0/24:443"),
            "{json}"
        );

        let mut back: Learner = serde_json::from_str(&json).expect("und liest sich wieder");
        assert_eq!(back.pair_count(), 1);
        let mut next = alert(2, "1.2.3.4", 1, now);
        next.id = 2;
        assert!(
            matches!(back.judge(&next, true, now), Decision::Drop),
            "nach dem Neuladen muss dasselbe Paar still bleiben"
        );
    }
}
