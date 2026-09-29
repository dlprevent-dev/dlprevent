//! Access counter for server agents and the NAS condensation: who reads
//! how many distinct files out of a protected folder? Decision of
//! 2026-09-06 (question 10): a fixed upper bound as an emergency brake from
//! day one plus a learned baseline per user and rule. Runs identically in
//! the agent (locally, so that the reaction works without the central
//! server too) and in the server (for syslog sources without an agent).
//!
//! Two views on the same stream:
//! - Window: distinct files in the last `window_secs` per (user, rule).
//!   Above `hard_max_files` → `HardLimit`.
//! - Days: distinct files per calendar day. After `learn_days` and with at
//!   least 3 days of observation, the day counts as a deviation if it
//!   exceeds four times the largest other day (and is at least
//!   `MIN_DEVIATION_FILES`, otherwise 1 → 5 would already be a deviation).

use crate::central::{AccessAlert, CountBucket, UserRef};
use chrono::{DateTime, Duration, NaiveDate, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

/// Below this daily total there is no deviation, no matter how small the
/// baseline is.
pub const MIN_DEVIATION_FILES: u32 = 20;
/// Factor as in learn.rs: four times the largest other day.
pub const DEVIATION_FACTOR: u32 = 4;
/// Days with data before a baseline counts.
pub const MIN_PROFILE_DAYS: usize = 3;
/// Days that stay in the profile.
const KEEP_DAYS: i64 = 60;
/// Upper bound per window, so that mass access does not blow up memory.
const MAX_WINDOW_ENTRIES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum AccessVerdict {
    /// Unremarkable.
    Ok,
    /// The rule's learning phase is still running; only the emergency
    /// brake takes effect.
    Learning,
    /// The user has no baseline yet (fewer than `MIN_PROFILE_DAYS` days).
    NoProfile,
    /// Emergency brake: more than `hard_max_files` distinct files in the window.
    HardLimit { files: u32, limit: u32 },
    /// Daily total above four times the baseline.
    Deviation { files: u32, baseline: u32 },
    /// Files have landed **in** the protected folder ([`crate::inbound`]).
    /// Not an access to the data and not measured against a baseline: an
    /// arrival is reported as a notice, from the first file on.
    Inbound { files: u32 },
}

impl AccessVerdict {
    pub fn is_alert(&self) -> bool {
        matches!(self, AccessVerdict::HardLimit { .. } | AccessVerdict::Deviation { .. })
    }
    pub fn label(&self) -> &'static str {
        match self {
            AccessVerdict::Ok => "ok",
            AccessVerdict::Learning => "learning",
            AccessVerdict::NoProfile => "no_profile",
            AccessVerdict::HardLimit { .. } => "hard_limit",
            AccessVerdict::Deviation { .. } => "deviation",
            AccessVerdict::Inbound { .. } => "inbound",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AccessParams {
    pub hard_max_files: u32,
    pub window_secs: u32,
    pub learn_days: u32,
}

impl Default for AccessParams {
    fn default() -> Self {
        Self { hard_max_files: 100, window_secs: 60, learn_days: 7 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Window {
    /// (time, file), ascending in time.
    entries: VecDeque<(DateTime<Utc>, String, u64)>,
    /// Start of the current exceedance; the key for carrying forward the
    /// same alert. Empty as soon as the window is back below the limit.
    exceeded_since: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Profile {
    first_seen: DateTime<Utc>,
    /// Distinct files per day (UTC calendar day).
    days: BTreeMap<NaiveDate, u32>,
    /// Files of the current day, in order to count "distinct".
    today: NaiveDate,
    today_files: HashSet<String>,
}

/// Result of one observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub verdict: AccessVerdict,
    /// Distinct files in the window.
    pub window_files: u32,
    pub window_bytes: u64,
    /// Distinct files today.
    pub day_files: u32,
    /// For carrying forward: start of the exceedance (HardLimit) or start
    /// of the day (Deviation). Same value = same alert.
    pub episode: Option<DateTime<Utc>>,
}

/// State per rule; serialisable, so that agents keep it across restarts
/// and the server can store it per source in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessMeter {
    started: DateTime<Utc>,
    windows: HashMap<String, Window>,
    profiles: HashMap<String, Profile>,
}

impl AccessMeter {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self { started: now, windows: HashMap::new(), profiles: HashMap::new() }
    }

    pub fn started(&self) -> DateTime<Utc> {
        self.started
    }

    /// The rule's learning phase: `learn_days` from the start of the counter.
    pub fn is_learning(&self, p: &AccessParams, now: DateTime<Utc>) -> bool {
        now < self.started + Duration::days(p.learn_days as i64)
    }

    /// One access by `user` to `file` (path relative or absolute, does not
    /// matter, only the same for the same file) with `bytes`.
    pub fn observe(&mut self, user_key: &str, file: &str, bytes: u64, p: &AccessParams, now: DateTime<Utc>) -> Observation {
        let window_len = Duration::seconds(p.window_secs.max(1) as i64);
        let learning = self.is_learning(p, now);
        let w = self.windows.entry(user_key.to_string()).or_default();
        while let Some((t, _, _)) = w.entries.front() {
            if *t + window_len <= now {
                w.entries.pop_front();
            } else {
                break;
            }
        }
        if w.entries.len() >= MAX_WINDOW_ENTRIES {
            w.entries.pop_front();
        }
        w.entries.push_back((now, file.to_string(), bytes));
        let window_files = w.entries.iter().map(|(_, f, _)| f.as_str()).collect::<HashSet<_>>().len() as u32;
        // Sum over the window, not over all time: otherwise it grows
        // without bound per user and the alert names a wrong amount.
        let window_bytes = w.entries.iter().fold(0u64, |s, (_, _, b)| s.saturating_add(*b));

        let day = now.date_naive();
        let prof = self.profiles.entry(user_key.to_string()).or_insert_with(|| Profile {
            first_seen: now,
            days: BTreeMap::new(),
            today: day,
            today_files: HashSet::new(),
        });
        if prof.today != day {
            prof.days.insert(prof.today, prof.today_files.len() as u32);
            prof.today = day;
            prof.today_files.clear();
            let cutoff = day - Duration::days(KEEP_DAYS);
            prof.days.retain(|d, _| *d >= cutoff);
        }
        prof.today_files.insert(file.to_string());
        let day_files = prof.today_files.len() as u32;

        // Emergency brake first: it always applies, even in the learning phase.
        if window_files > p.hard_max_files {
            let since = *w.exceeded_since.get_or_insert(now);
            return Observation {
                verdict: AccessVerdict::HardLimit { files: window_files, limit: p.hard_max_files },
                window_files,
                window_bytes,
                day_files,
                episode: Some(since),
            };
        }
        w.exceeded_since = None;

        let verdict = if learning {
            AccessVerdict::Learning
        } else if prof.days.len() < MIN_PROFILE_DAYS {
            AccessVerdict::NoProfile
        } else {
            let baseline = prof.days.values().copied().max().unwrap_or(0);
            if day_files >= MIN_DEVIATION_FILES && day_files > baseline.saturating_mul(DEVIATION_FACTOR) {
                AccessVerdict::Deviation { files: day_files, baseline }
            } else {
                AccessVerdict::Ok
            }
        };
        let episode = match verdict {
            AccessVerdict::Deviation { .. } => Some(day.and_hms_opt(0, 0, 0).unwrap().and_utc()),
            _ => None,
        };
        Observation { verdict, window_files, window_bytes, day_files, episode }
    }

    /// Remove windows without entries and profiles without data since
    /// `KEEP_DAYS`.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - Duration::days(KEEP_DAYS);
        self.windows.retain(|_, w| w.entries.back().map(|(t, _, _)| *t > now - Duration::hours(1)).unwrap_or(false));
        self.profiles.retain(|_, p| p.today.and_hms_opt(0, 0, 0).unwrap().and_utc() >= cutoff);
    }

    pub fn user_count(&self) -> usize {
        self.profiles.len()
    }

    /// Whether `user` already has state under the rule `rule_id` — so that
    /// a caller capping `user_count` still admits the users it follows.
    pub fn tracks(&self, rule_id: &str, user: &UserRef) -> bool {
        self.profiles.contains_key(&format!("{}|{}", rule_id, user.key()))
    }
}

/// An alert names at most this many sample files.
const SAMPLE_FILES: usize = 5;

/// A folder rule as the counter sees it. Both sides keep their rules
/// differently (the central server as `RuleRow` with `Uuid`, the agent as
/// `Rule` with `String`); here only what the counter really needs counts.
#[derive(Debug, Clone, Copy)]
pub struct RuleView<'a> {
    pub id: &'a str,
    pub path: &'a str,
    pub params: AccessParams,
}

/// Condensation of an access stream down to what goes outside: counts per
/// (rule, user, minute) and alerts on mass access. Raw events never leave
/// the aggregator.
///
/// Lives here because there are **two** streams that have to behave alike
/// (decision of 2026-09-06): the central server's syslog condensation and
/// the Windows file server agent. Before, this flow stood written out in
/// both — and had already drifted apart: the central server summed bytes
/// into the count, the agent did not.
///
/// The `AccessMeter` is owned by the caller and passed in: the central
/// server keeps one per source (stored in the database), the agent one per
/// rule (in its state file). That choice determines when the learning phase
/// starts, and therefore belongs where it is stored.
#[derive(Debug, Default)]
pub struct Aggregator {
    /// (rule path, user key, minute) → count.
    counts: HashMap<(String, String, DateTime<Utc>), CountBucket>,
    /// "{rule}|{user}" → most recently seen files, for the alert.
    samples: HashMap<String, VecDeque<String>>,
    /// "{rule}|{user}" → what has landed in the folder, see
    /// [`Aggregator::inbound`].
    arrivals: HashMap<String, Arrivals>,
}

/// Arrivals of one user in one folder within one episode.
#[derive(Debug, Clone)]
struct Arrivals {
    episode: DateTime<Utc>,
    count: u32,
    /// The most recent file names, at most [`SAMPLE_FILES`]. They go into
    /// the alert and at the same time keep the same file from counting
    /// twice when it is opened several times for writing.
    files: VecDeque<String>,
}

/// One arrival alert covers this much time; after that a new one starts.
/// An hour, not the window of the emergency brake: that one asks how fast
/// somebody reads, this one only says what came in.
const ARRIVAL_EPISODE_SECS: i64 = 3600;

/// Upper bound for the arrival bookkeeping, in the same spirit as
/// `MAX_WINDOW_ENTRIES`: a file server with many users must not let the
/// agent grow.
const MAX_ARRIVAL_KEYS: usize = 10_000;

impl Aggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// One read access on a rule. Counts it and returns an alert if the
    /// verdict is one. Carry-forwards of the same exceedance carry the same
    /// `external_id`.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        meter: &mut AccessMeter,
        rule: &RuleView<'_>,
        user: &UserRef,
        file: &str,
        bytes: u64,
        client_ip: Option<&str>,
        now: DateTime<Utc>,
    ) -> Option<AccessAlert> {
        let ukey = user.key();
        // To the minute: the central server does not need it finer, and
        // coarser would lose the course of a mass access.
        let bucket = now.with_second(0).unwrap_or(now).with_nanosecond(0).unwrap_or(now);
        let entry = self.counts.entry((rule.path.to_string(), ukey.clone(), bucket)).or_insert_with(|| CountBucket {
            rule_id: Some(rule.id.to_string()),
            path: rule.path.to_string(),
            user: user.clone(),
            bucket,
            files: 0,
            bytes: 0,
        });
        // The byte count can come from an untrusted syslog line: saturate,
        // an overflow killed the intake (debug) or wrapped (release).
        entry.files = entry.files.saturating_add(1);
        entry.bytes = entry.bytes.saturating_add(bytes);

        let skey = format!("{}|{}", rule.id, ukey);
        let s = self.samples.entry(skey.clone()).or_default();
        if !s.iter().any(|x| x == file) {
            s.push_back(file.to_string());
            while s.len() > SAMPLE_FILES {
                s.pop_front();
            }
        }

        let o = meter.observe(&skey, file, bytes, &rule.params, now);
        if !o.verdict.is_alert() {
            return None;
        }
        let episode = o.episode.unwrap_or(now);
        let (files, reason) = match o.verdict {
            AccessVerdict::HardLimit { files, limit } => (files, format!("{files} distinct files in {} s, limit {limit}", rule.params.window_secs)),
            AccessVerdict::Deviation { files, baseline } => (files, format!("{files} files today, at most {baseline} per day so far")),
            _ => (o.window_files, String::new()),
        };
        Some(AccessAlert {
            external_id: format!("access:{}:{}:{}", rule.id, ukey, episode.timestamp()),
            at: episode,
            last_at: Some(now),
            user: user.clone(),
            rule_id: Some(rule.id.to_string()),
            path: rule.path.to_string(),
            files,
            bytes: o.window_bytes,
            sample_files: self.samples.get(&skey).map(|s| s.iter().cloned().collect()).unwrap_or_default(),
            client_ip: client_ip.map(str::to_string),
            verdict: o.verdict,
            reason: Some(reason),
        })
    }

    /// A file that has just come into being in a protected folder.
    ///
    /// Deliberately past the meter and past the counts: an arrival is not
    /// an access, and the learned baseline (how many files does this user
    /// read per day) says nothing about it. One alert per user, folder and
    /// episode; further files count up in it.
    ///
    /// `None` means the file was already counted in this episode — a file
    /// is opened for writing more than once.
    pub fn inbound(&mut self, rule: &RuleView<'_>, user: &UserRef, file: &str, client_ip: Option<&str>, now: DateTime<Utc>) -> Option<AccessAlert> {
        let ukey = user.key();
        let skey = format!("{}|{}", rule.id, ukey);
        if self.arrivals.len() >= MAX_ARRIVAL_KEYS {
            self.arrivals.retain(|_, a| now - a.episode < Duration::seconds(ARRIVAL_EPISODE_SECS));
        }
        let a = self.arrivals.entry(skey).or_insert_with(|| Arrivals { episode: now, count: 0, files: VecDeque::new() });
        if now - a.episode >= Duration::seconds(ARRIVAL_EPISODE_SECS) {
            *a = Arrivals { episode: now, count: 0, files: VecDeque::new() };
        } else if a.files.iter().any(|f| f == file) {
            return None;
        }
        a.count += 1;
        a.files.push_back(file.to_string());
        while a.files.len() > SAMPLE_FILES {
            a.files.pop_front();
        }
        Some(AccessAlert {
            external_id: format!("inbound:{}:{}:{}", rule.id, ukey, a.episode.timestamp()),
            at: a.episode,
            last_at: Some(now),
            user: user.clone(),
            rule_id: Some(rule.id.to_string()),
            path: rule.path.to_string(),
            files: a.count,
            bytes: 0,
            sample_files: a.files.iter().cloned().collect(),
            client_ip: client_ip.map(str::to_string),
            verdict: AccessVerdict::Inbound { files: a.count },
            reason: Some(format!("{} file{} landed in {}", a.count, if a.count == 1 { "" } else { "s" }, rule.path)),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    /// Snapshot for a report; the counts stay standing until the central
    /// server has accepted them.
    pub fn counts(&self) -> Vec<CountBucket> {
        self.counts.values().cloned().collect()
    }

    /// Arrived — now it may go.
    pub fn clear_counts(&mut self) {
        self.counts.clear();
    }

    /// The counts and away with them, in one go (the central server writes
    /// them into its own database and needs no backlog).
    pub fn take_counts(&mut self) -> Vec<CountBucket> {
        self.counts.drain().map(|(_, v)| v).collect()
    }

    /// Put the backlog back from the state file (restart of the agent).
    pub fn restore_counts(&mut self, buckets: impl IntoIterator<Item = CountBucket>) {
        for b in buckets {
            self.counts.insert((b.path.clone(), b.user.key(), b.bucket), b);
        }
    }

    /// Caps the backlog at `max` counts and returns how many fell away.
    /// The newest counts for more than the oldest.
    pub fn trim_counts(&mut self, max: usize) -> usize {
        if self.counts.len() <= max {
            return 0;
        }
        let mut buckets: Vec<DateTime<Utc>> = self.counts.keys().map(|(_, _, b)| *b).collect();
        buckets.sort_unstable();
        let cut = buckets[self.counts.len() - max];
        let before = self.counts.len();
        self.counts.retain(|(_, _, b), _| *b >= cut);
        before - self.counts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn hard_limit_fires_and_continues_same_episode() {
        let p = AccessParams { hard_max_files: 3, window_secs: 60, learn_days: 7 };
        let mut m = AccessMeter::new(t("2026-09-06T10:00:00Z"));
        let base = t("2026-09-06T10:00:00Z");
        for i in 0..3 {
            let o = m.observe("srv\\hans", &format!("f{i}"), 10, &p, base + Duration::seconds(i));
            assert_eq!(o.verdict, AccessVerdict::Learning, "{i}");
        }
        let o = m.observe("srv\\hans", "f3", 10, &p, base + Duration::seconds(3));
        assert_eq!(o.verdict, AccessVerdict::HardLimit { files: 4, limit: 3 });
        let ep = o.episode.unwrap();
        let o2 = m.observe("srv\\hans", "f4", 10, &p, base + Duration::seconds(4));
        assert_eq!(o2.episode, Some(ep));
        assert_eq!(o2.window_files, 5);
        assert_eq!(o2.window_bytes, 50);
        // The same file again does not count as a new one.
        let o3 = m.observe("srv\\hans", "f4", 10, &p, base + Duration::seconds(5));
        assert_eq!(o3.window_files, 5);
        // Once the window has expired there is quiet and the episode is over.
        let o4 = m.observe("srv\\hans", "f9", 10, &p, base + Duration::seconds(120));
        assert_eq!(o4.verdict, AccessVerdict::Learning);
        assert_eq!(o4.window_files, 1);
        assert!(o4.episode.is_none());
        let o5 = m.observe("srv\\hans", "f10", 1, &p, base + Duration::seconds(121));
        let _ = o5;
        for i in 0..3 {
            m.observe("srv\\hans", &format!("g{i}"), 1, &p, base + Duration::seconds(122 + i));
        }
        let o6 = m.observe("srv\\hans", "g9", 1, &p, base + Duration::seconds(130));
        assert!(matches!(o6.verdict, AccessVerdict::HardLimit { .. }));
        assert_ne!(o6.episode, Some(ep));
    }

    #[test]
    fn window_bytes_expire_with_the_window() {
        let p = AccessParams { hard_max_files: 1000, window_secs: 60, learn_days: 7 };
        let mut m = AccessMeter::new(t("2026-09-06T10:00:00Z"));
        let base = t("2026-09-06T10:00:00Z");
        assert_eq!(m.observe("u", "a", 100, &p, base).window_bytes, 100);
        assert_eq!(m.observe("u", "b", 50, &p, base + Duration::seconds(30)).window_bytes, 150);
        // After 61 s the first entry is out, and its bytes with it.
        assert_eq!(m.observe("u", "c", 10, &p, base + Duration::seconds(61)).window_bytes, 60);
        assert_eq!(m.observe("u", "d", 1, &p, base + Duration::seconds(200)).window_bytes, 1);
    }

    #[test]
    fn users_are_independent() {
        let p = AccessParams { hard_max_files: 1, window_secs: 60, learn_days: 0 };
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        let now = t("2026-09-06T10:00:00Z");
        m.observe("a", "x", 0, &p, now);
        m.observe("a", "y", 0, &p, now);
        let o = m.observe("b", "x", 0, &p, now);
        assert_eq!(o.verdict, AccessVerdict::NoProfile);
    }

    #[test]
    fn deviation_needs_profile_and_factor() {
        let p = AccessParams { hard_max_files: 1000, window_secs: 60, learn_days: 0 };
        let mut m = AccessMeter::new(t("2026-08-01T00:00:00Z"));
        // Three days with 5 files each.
        for d in 1..=3 {
            for i in 0..5 {
                let o = m.observe("u", &format!("d{d}f{i}"), 0, &p, t(&format!("2026-09-0{d}T09:00:00Z")));
                assert!(matches!(o.verdict, AccessVerdict::NoProfile | AccessVerdict::Ok), "{:?}", o.verdict);
            }
        }
        // Day 4: 19 files are below MIN_DEVIATION_FILES, 21 are above 4×5.
        let mut last = None;
        for i in 0..21 {
            last = Some(m.observe("u", &format!("d4f{i}"), 0, &p, t("2026-09-04T09:00:00Z") + Duration::seconds(i)));
            if i < 19 {
                assert_eq!(last.as_ref().unwrap().verdict, AccessVerdict::Ok, "{i}");
            }
        }
        let o = last.unwrap();
        assert_eq!(o.verdict, AccessVerdict::Deviation { files: 21, baseline: 5 });
        assert_eq!(o.episode, Some(t("2026-09-04T00:00:00Z")));
    }

    #[test]
    fn learning_phase_then_no_profile() {
        let p = AccessParams { hard_max_files: 1000, window_secs: 60, learn_days: 7 };
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        assert_eq!(m.observe("u", "a", 0, &p, t("2026-09-03T00:00:00Z")).verdict, AccessVerdict::Learning);
        assert_eq!(m.observe("u", "a", 0, &p, t("2026-09-09T00:00:00Z")).verdict, AccessVerdict::NoProfile);
    }

    fn user(name: &str) -> UserRef {
        UserRef { source: "nas01".into(), name: name.into(), domain: None, sid: None }
    }

    fn rule(id: &str, hard_max_files: u32) -> RuleView<'_> {
        RuleView { id, path: "/volume1/GL", params: AccessParams { hard_max_files, window_secs: 60, learn_days: 0 } }
    }

    /// The contract shared by the central server (syslog) and the file
    /// server agent. Before, it stood written out in both, and the central
    /// server summed bytes into the count, the agent did not.
    #[test]
    fn counts_files_and_bytes_per_minute_and_user() {
        let mut a = Aggregator::new();
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        let r = rule("r1", 1000);
        let now = t("2026-09-06T10:00:30Z");
        assert!(a.observe(&mut m, &r, &user("hans"), "/volume1/GL/a.xlsx", 100, None, now).is_none());
        assert!(a.observe(&mut m, &r, &user("hans"), "/volume1/GL/b.xlsx", 50, None, now + Duration::seconds(5)).is_none());
        // A different minute, a different bucket; a different user likewise.
        a.observe(&mut m, &r, &user("hans"), "/volume1/GL/c.xlsx", 1, None, now + Duration::seconds(40));
        a.observe(&mut m, &r, &user("eva"), "/volume1/GL/a.xlsx", 7, None, now);
        let mut c = a.counts();
        c.sort_by_key(|b| (b.user.name.clone(), b.bucket));
        assert_eq!(c.len(), 3);
        assert_eq!((c[0].user.name.as_str(), c[0].files, c[0].bytes), ("eva", 1, 7));
        assert_eq!((c[1].files, c[1].bytes), (2, 150), "Bytes gehoeren in die Zaehlung");
        assert_eq!(c[1].bucket, t("2026-09-06T10:00:00Z"), "auf die Minute abgerundet");
        assert_eq!((c[2].files, c[2].bytes), (1, 1));
        assert_eq!(c[2].bucket, t("2026-09-06T10:01:00Z"));
        assert_eq!(c[0].rule_id.as_deref(), Some("r1"));
        // Without bytes (Windows security log) the file count remains.
        a.clear_counts();
        a.observe(&mut m, &r, &user("hans"), "/volume1/GL/d.xlsx", 0, None, now);
        assert_eq!((a.counts()[0].files, a.counts()[0].bytes), (1, 0));
    }

    /// Sizes can come from an untrusted syslog line: the sums saturate.
    #[test]
    fn byte_sums_saturate() {
        let mut a = Aggregator::new();
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        let r = rule("r1", 1);
        let now = t("2026-09-06T10:00:30Z");
        a.observe(&mut m, &r, &user("hans"), "/volume1/GL/a", u64::MAX, None, now);
        let alert = a.observe(&mut m, &r, &user("hans"), "/volume1/GL/b", u64::MAX, None, now).unwrap();
        assert_eq!(alert.bytes, u64::MAX);
        assert_eq!(a.counts()[0].bytes, u64::MAX);
    }

    /// An alert carries sample files and the same `external_id` for as
    /// long as the exceedance runs — that is how the central server
    /// recognises the carry-forward.
    #[test]
    fn alert_carries_samples_and_a_stable_id() {
        let mut a = Aggregator::new();
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        let r = rule("r1", 3);
        let base = t("2026-09-06T10:00:00Z");
        for i in 0..3 {
            assert!(a.observe(&mut m, &r, &user("hans"), &format!("f{i}"), 10, Some("10.0.0.5"), base + Duration::seconds(i)).is_none(), "{i}");
        }
        let first = a.observe(&mut m, &r, &user("hans"), "f3", 10, Some("10.0.0.5"), base + Duration::seconds(3)).expect("Notbremse");
        assert_eq!(first.verdict, AccessVerdict::HardLimit { files: 4, limit: 3 });
        assert_eq!(first.files, 4);
        assert_eq!(first.client_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(first.reason.as_deref(), Some("4 distinct files in 60 s, limit 3"));
        assert_eq!(first.sample_files, ["f0", "f1", "f2", "f3"]);
        let next = a.observe(&mut m, &r, &user("hans"), "f4", 10, Some("10.0.0.5"), base + Duration::seconds(4)).expect("laeuft weiter");
        assert_eq!(next.external_id, first.external_id, "Fortschreibung derselben Warnung");
        assert_eq!(next.at, first.at);
        // At most five samples, the oldest fall away.
        let later = a.observe(&mut m, &r, &user("hans"), "f5", 10, None, base + Duration::seconds(5)).unwrap();
        assert_eq!(later.sample_files, ["f1", "f2", "f3", "f4", "f5"]);
        // A different user, a different id.
        let eva = a.observe(&mut m, &r, &user("eva"), "f0", 0, None, base + Duration::seconds(5));
        assert!(eva.is_none(), "eva hat ihr eigenes Fenster");
    }

    #[test]
    fn backlog_survives_a_restart_and_gets_capped() {
        let mut a = Aggregator::new();
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        let r = rule("r1", 1000);
        let base = t("2026-09-06T10:00:00Z");
        for i in 0..5 {
            a.observe(&mut m, &r, &user("hans"), "f", 1, None, base + Duration::minutes(i));
        }
        // As on a restart: save the counts, read them back in.
        let saved = a.counts();
        let mut b = Aggregator::new();
        b.restore_counts(saved);
        assert_eq!(b.len(), 5);
        // Reading them in twice must not count twice.
        b.restore_counts(b.counts());
        assert_eq!(b.len(), 5);
        assert_eq!(b.trim_counts(2), 3, "die aeltesten fallen weg");
        let left: Vec<_> = b.counts().iter().map(|c| c.bucket).collect();
        assert!(left.iter().all(|t| *t >= base + Duration::minutes(3)), "{left:?}");
        assert_eq!(b.trim_counts(2), 0);
        assert!(!b.is_empty());
        b.clear_counts();
        assert!(b.is_empty());
    }

    #[test]
    fn state_roundtrip() {
        let p = AccessParams::default();
        let mut m = AccessMeter::new(t("2026-09-01T00:00:00Z"));
        m.observe("u", "a", 5, &p, t("2026-09-02T00:00:00Z"));
        let json = serde_json::to_string(&m).unwrap();
        let mut m2: AccessMeter = serde_json::from_str(&json).unwrap();
        let o = m2.observe("u", "b", 5, &p, t("2026-09-02T00:00:10Z"));
        assert_eq!(o.window_files, 2);
        assert_eq!(o.window_bytes, 10);
    }
}
