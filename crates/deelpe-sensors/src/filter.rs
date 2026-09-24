//! What the sensor passes on, and who recently read from a protected
//! folder.
//!
//! Pure bookkeeping, ahead of the first system call — the same split as in
//! [`crate::winpath`] and in `wfp::Cages` in the agent, and for the same
//! reason: the sensor only runs on Windows, but the decision about which
//! events come into being at all has to be testable where the build
//! happens. Before, all of this sat in `windows::etw`, a module `cargo
//! check` on a dev machine does not even read.

use std::collections::HashMap;
use deelpe_core::config::Guard;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

/// Pass on only file events below these folders. `None` turns the filter
/// off (everything), an empty list throws away all file events — the right
/// state as long as there is no rule.
static FILTER: LazyLock<RwLock<Option<Vec<String>>>> = LazyLock::new(|| RwLock::new(None));

/// The taint in the sensor has to hold at least as long as the one in the
/// correlator, otherwise the sensor is the narrower filter; see
/// [`deelpe_core::config::Config::sensor_taint_ttl`].
pub const DEFAULT_TAINT_TTL: Duration =
    Duration::from_secs(deelpe_core::config::DEFAULT_TOUCH_TTL_SECS + deelpe_core::config::SENSOR_TAINT_MARGIN_SECS);

static TAINT_TTL_SECS: AtomicU64 = AtomicU64::new(DEFAULT_TAINT_TTL.as_secs());

/// Events thrown away because the engine could not keep up. Goes to the
/// central server as sensor status: silent loss is worse than a red line.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Upper bound of the table of tainted processes.
const MAX_TAINTED: usize = 4_096;

pub fn taint_ttl() -> Duration {
    Duration::from_secs(TAINT_TTL_SECS.load(Ordering::Relaxed))
}

/// Set the filter. The paths are put into comparison form once, when the
/// filter is set, not on every event.
pub fn set_file_filter(paths: Option<Vec<String>>, taint_ttl: Duration) {
    TAINT_TTL_SECS.store(taint_ttl.as_secs(), Ordering::Relaxed);
    let normed = paths.map(|v: Vec<String>| v.iter().map(|p| deelpe_core::path::norm(p)).collect::<Vec<String>>());
    if let Ok(mut g) = FILTER.write() {
        *g = normed;
    }
}

/// Does the path match the filter? Without a filter: yes.
///
/// Compares via [`deelpe_core::path`] — the same place that also decides
/// about the protected folder and the folder rule. Before, there was a
/// version of its own here that normalized only the filter list and not the
/// incoming path.
pub fn wanted(path: &str) -> bool {
    let Ok(g) = FILTER.read() else { return true };
    matches(g.as_deref(), path)
}

/// The verdict itself, without the global list.
///
/// Kept separate so the tests can check it without setting the filter for
/// the whole process: `cargo test` runs in parallel, and two tests that
/// change the same `static` would otherwise check something different from
/// what they claim, depending on the order they run in.
fn matches(list: Option<&[String]>, path: &str) -> bool {
    let Some(list) = list else { return true };
    let p = deelpe_core::path::norm(path);
    list.iter().any(|b| deelpe_core::path::under_norm(&p, b))
}

/// Is there anything to watch at all?
///
/// An empty list means "no file events" — the state of every agent that
/// has not been enrolled yet and has no folder of its own. A sensor that
/// sees the whole machine can spare itself the entire resolution of an
/// event in that state, and that is not a micro-optimisation: without it,
/// a freshly installed agent resolves every open on the machine only to
/// throw it away at the end.
///
/// No filter at all (`None`) is not this state: that means "everything".
pub fn watches_nothing() -> bool {
    FILTER.read().map(|g| nothing(g.as_deref())).unwrap_or(false)
}

/// The verdict without the global list — same reason as [`matches`]: a test
/// that changed the `static` would decide what a parallel test sees.
fn nothing(list: Option<&[String]>) -> bool {
    list.is_some_and(<[String]>::is_empty)
}

/// How many events have been thrown away so far.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// One thrown away because the engine could not keep up.
pub fn note_dropped() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
}

/// Pass program starts on even outside the protected folders.
///
/// An agent's terminal command is joined on the command line of the shell
/// it started (`deelpe_core::agent`), and that shell starts from `/bin`, not
/// from a protected folder — the filter above would drop it. Switched on by
/// the Hermes sensor once it finds a session log, so a machine without an
/// agent keeps its starts filtered.
static PASS_EXECS: AtomicBool = AtomicBool::new(false);

pub fn pass_execs(on: bool) {
    PASS_EXECS.store(on, Ordering::Relaxed);
}

pub fn passes_execs() -> bool {
    PASS_EXECS.load(Ordering::Relaxed)
}

/// Folders whose opens are refused: the path in comparison form for the
/// verdict, and the guard as written, for the listener to mark — the
/// comparison form is lowercased and names no real folder on Linux.
static GUARDED: LazyLock<RwLock<Vec<(String, Guard)>>> = LazyLock::new(|| RwLock::new(Vec::new()));

pub fn set_guarded(guards: &[Guard]) {
    let normed = guards.iter().map(|g| (deelpe_core::path::norm(&g.path.to_string_lossy()), g.clone())).collect();
    if let Ok(mut g) = GUARDED.write() {
        *g = normed;
    }
}

/// The guarded folders as set, for the listener to mark.
pub fn guarded() -> Vec<Guard> {
    GUARDED.read().map(|g| g.iter().map(|(_, g)| g.clone()).collect()).unwrap_or_default()
}

/// Refuse this open? `chain` yields the command lines of the process and
/// its ancestors; it is only asked for a path under a guard that names
/// programs, because every call costs reads in `/proc`.
///
/// Fails open: a poisoned lock refuses nothing.
pub fn refuses(path: &str, chain: impl FnOnce() -> Vec<String>) -> bool {
    let Ok(g) = GUARDED.read() else { return false };
    refuse(&g, path, chain)
}

/// Is this path under any guard? The listener asks before it opens a file
/// itself: an open of its own in a guarded folder waits for an answer only
/// the listener could give.
pub fn is_guarded(path: &str) -> bool {
    GUARDED.read().map(|g| guard_of(&g, path).is_some()).unwrap_or(false)
}

/// The guard a path lies under. The longest decides, as for the strict
/// folders: a nested one may name other programs than the one around it.
fn guard_of<'a>(list: &'a [(String, Guard)], path: &str) -> Option<&'a Guard> {
    let p = deelpe_core::path::norm(path);
    list.iter().filter(|(n, _)| deelpe_core::path::under_norm(&p, n)).max_by_key(|(n, _)| n.len()).map(|(_, g)| g)
}

/// The verdict without the global list, for the tests.
fn refuse(list: &[(String, Guard)], path: &str, chain: impl FnOnce() -> Vec<String>) -> bool {
    let Some(g) = guard_of(list, path) else { return false };
    g.processes.is_empty() || chain().iter().any(|cmd| g.processes.iter().any(|w| !w.is_empty() && cmd.contains(w.as_str())))
}

/// Who recently read from a protected folder.
///
/// The table has an upper bound: flooding it with short-lived processes
/// must not eat the service's memory. What has expired goes first; if that
/// is not enough, everything goes — a forgotten taint costs detection, a
/// growing service costs the machine.
#[derive(Default)]
pub struct TaintTable {
    seen: HashMap<u32, Instant>,
}

impl TaintTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Has this process recently read from a protected folder? An expired
    /// entry is forgotten in the process.
    pub fn is_tainted(&mut self, pid: u32) -> bool {
        self.is_tainted_at(pid, Instant::now())
    }

    pub fn taint(&mut self, pid: u32) {
        self.taint_at(pid, Instant::now())
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Like [`Self::is_tainted`], but with the clock supplied — so a test
    /// can check expiry without waiting.
    fn is_tainted_at(&mut self, pid: u32, now: Instant) -> bool {
        let ttl = taint_ttl();
        match self.seen.get(&pid) {
            Some(t) if now.duration_since(*t) <= ttl => true,
            Some(_) => {
                self.seen.remove(&pid);
                false
            }
            None => false,
        }
    }

    fn taint_at(&mut self, pid: u32, now: Instant) {
        if self.seen.len() >= MAX_TAINTED {
            let ttl = taint_ttl();
            self.seen.retain(|_, t| now.duration_since(*t) <= ttl);
            if self.seen.len() >= MAX_TAINTED {
                self.seen.clear();
            }
        }
        self.seen.insert(pid, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter compares **both** sides normalized. A difference in
    /// casing or a different separator must not cause a protected folder to
    /// go unwatched.
    #[test]
    fn the_filter_compares_both_sides_normalised() {
        let list = [deelpe_core::path::norm(r"C:\Freigaben\GL")];
        assert!(matches(Some(&list), r"c:\freigaben\gl\Zahlen.xlsx"));
        assert!(matches(Some(&list), r"C:/Freigaben/GL/Zahlen.xlsx"));
        assert!(!matches(Some(&list), r"C:\Freigaben\HR\Lohn.xlsx"));
    }

    /// An empty list means "no file events at all", not "everything". The
    /// difference is the one between a quiet agent and one that reports the
    /// whole machine when there is no rule.
    #[test]
    fn an_empty_list_wants_nothing_but_no_filter_wants_everything() {
        assert!(!matches(Some(&[]), r"C:\Freigaben\GL\Zahlen.xlsx"));
        assert!(matches(None, r"C:\irgendwas"));
    }

    /// The three states are different, and a sensor acts differently on
    /// each: no filter means everything, an empty list means nothing, a
    /// filled one means these folders. Only the middle one lets a sensor
    /// skip the work entirely.
    #[test]
    fn watching_nothing_is_not_the_same_as_having_no_filter() {
        assert!(nothing(Some(&[])));
        assert!(!nothing(Some(&["/srv/gl".to_string()])));
        assert!(!nothing(None), "no filter means everything, not nothing");
    }

    #[test]
    fn a_touch_is_remembered_and_forgotten_when_it_expires() {
        let mut t = TaintTable::new();
        let now = Instant::now();
        t.taint_at(4242, now);
        assert!(t.is_tainted_at(4242, now));
        assert!(!t.is_tainted_at(4243, now));
        // Well past the deadline: the entry no longer counts and is gone.
        let later = now + taint_ttl() + Duration::from_secs(1);
        assert!(!t.is_tainted_at(4242, later));
        assert!(t.is_empty());
    }

    fn guards() -> Vec<(String, Guard)> {
        [("/root/.ssh", vec!["hermes".to_string()]), ("/srv/Vault", vec![])]
            .into_iter()
            .map(|(p, processes)| (deelpe_core::path::norm(p), Guard { path: p.into(), processes }))
            .collect()
    }

    #[test]
    fn a_guard_refuses_the_named_program_and_its_children() {
        let g = guards();
        let hermes = || vec!["cat /root/.ssh/id_ed25519".to_string(), "/usr/bin/python3 /opt/hermes/gateway.py".to_string()];
        assert!(refuse(&g, "/root/.ssh/id_ed25519", hermes));
        assert!(!refuse(&g, "/root/.ssh/id_ed25519", || vec!["ssh host".into(), "-bash".into()]), "the owner still reads");
        assert!(!refuse(&g, "/root/.sshx/a", || panic!("not guarded, no /proc reads")));
    }

    #[test]
    fn a_guard_without_programs_refuses_everyone() {
        assert!(refuse(&guards(), "/srv/vault/a.pdf", || panic!("nobody to ask about")));
        assert!(!refuse(&[], "/srv/vault/a.pdf", Vec::new));
    }

    /// Flooding the table must not make the service grow.
    #[test]
    fn the_table_stays_bounded_under_a_flood() {
        let mut t = TaintTable::new();
        let now = Instant::now();
        for pid in 0..(MAX_TAINTED as u32 + 500) {
            t.taint_at(pid, now);
        }
        assert!(t.len() <= MAX_TAINTED, "{} entries", t.len());
    }
}
