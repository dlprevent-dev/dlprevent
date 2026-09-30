//! The way from the correlator's result to the finished alert: judge,
//! intervene, give a reason.
//!
//! Until 2026-09-08 this stood written out twice — in the Mac service
//! (`deelpe/src/daemon.rs`) and in the Windows workstation agent
//! (`deelpe-winagent/src/client.rs`). Only the *decision* was shared
//! ([`crate::enforce::action_for`]); the wiring around it ran in two
//! transcriptions, and with it three promises that were written down
//! nowhere:
//!
//! 1. `is_new` has to be rescued **before** `into_alert()` — [`Outcome`]
//!    consumes itself in the process.
//! 2. The verdict of the learning phase has to come **before**
//!    `action_for`: the decision reads `verdict`, and without the step
//!    before it, `New` is still standing there. The intervention would
//!    silently fail to happen.
//! 3. A note about the intervention is appended to the reason, it does not
//!    replace it.
//!
//! Here they stand once, and the order is carried by the type: [`enforce`]
//! takes a [`Judged`], and that exists only out of [`judge`].

use crate::central::{LearnAction, LearnCommand};
use crate::config::Config;
use crate::correlate::{Alert, Outcome};
use crate::enforce::{action_for, Action};
use crate::identity::image_name;
use crate::learn::{Decision, Learner, Verdict};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

/// What an endpoint can actually use to stop a forbidden leak.
///
/// Two adapters: the Mac service can stop a process, no more; the Windows
/// workstation can additionally remove the copy. What is to be done is
/// decided by [`crate::enforce::action_for`] the same way for both.
/// `&self`, not `&mut self`: an intervention changes the world, not the
/// adapter. No production impl needs the mutability — it only stood there
/// because the test double keeps a record, and it can do that itself.
pub trait Enforcer {
    /// Remove the copy outside the protected folder.
    ///
    /// Returns the finished note instead of a result: what is possible here
    /// differs too much per platform for a common error type — the Mac
    /// service cannot do it at all and says exactly that.
    fn delete_copy(&self, alert: &Alert) -> String;
}

/// An alert whose verdict is settled.
///
/// It exists **only** out of [`judge`] — the field is private, and nobody
/// outside this module can build one. That makes promise 2 from the module
/// header no longer a request to the caller but a condition the compiler
/// checks: without a verdict you never even get as far as [`enforce`].
pub struct Judged(Alert);

impl Judged {
    pub fn alert(&self) -> &Alert {
        &self.0
    }

    /// Hand it out when the intervention is through and it is only stored.
    pub fn into_alert(self) -> Alert {
        self.0
    }
}

/// Apply the verdict of the learning phase to the correlator's result.
///
/// `None` means: known pair, unremarkable — no alert arises. Otherwise the
/// alert with its verdict set, plus `is_new` for the caller, who uses it to
/// decide whether to create or to carry forward.
///
/// `allow` is the hand-maintained allow list
/// ([`crate::learn::allowlist`]). It takes effect **before** the learning
/// phase: an allowed process should also not create pairs that turn up
/// later in the confirmation dialog.
pub fn judge(
    learner: &mut Learner,
    allow: &BTreeSet<String>,
    outcome: Outcome,
    now: DateTime<Utc>,
) -> Option<(Judged, bool)> {
    // Before `into_alert()`: after that, `outcome` is consumed.
    let is_new = outcome.is_new();
    let mut a = outcome.into_alert();
    // A forbidden destination outranks the list — otherwise the allowance
    // is not a filter but a hole: whoever enters `teams.exe` would thereby
    // have switched off the strict folder for `teams.exe`.
    if a.verdict != Verdict::Denied && allow.contains(&image_name(&a.identity.short())) {
        return None;
    }
    match learner.judge(&a, is_new, now) {
        Decision::Drop => None,
        Decision::Store { verdict, reason } => {
            a.verdict = verdict;
            a.reason = reason;
            Some((Judged(a), is_new))
        }
    }
}

/// Carry out the intervention and append the result to the reason.
///
/// Takes a [`Judged`], not just any alert: running after [`judge`] is
/// therefore no longer a rule in a comment but the signature.
pub fn enforce(cfg: &Config, j: &mut Judged, e: &dyn Enforcer) {
    let a = &mut j.0;
    match action_for(cfg, a) {
        Action::None => {}
        Action::DeleteCopy => {
            let n = e.delete_copy(a);
            note(a, n);
        }
    }
}

/// Append, do not replace: the reason from the correlator or the learning
/// phase stays standing, the intervention comes after it.
fn note(a: &mut Alert, s: String) {
    a.reason = Some(format!("{} — {s}", a.reason.take().unwrap_or_default()));
}

/// What one round of learning instructions achieved.
///
/// `done` are the ids the central server may tick off. Done does *not*
/// mean "took effect": an alert that has rolled out of the log, and an
/// unsigned process that is never learned, count as well — otherwise the
/// central server would send the same instruction forever.
///
/// `learned` carries the pairs that were actually learned, so that a caller
/// can write them into its own log. The Mac service does that; the
/// workstation agent does not.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Learned {
    pub done: Vec<i64>,
    pub learned: Vec<(LearnAction, String)>,
}

/// Carry out the central server's learning instructions.
///
/// Until 2026-09-10 this stood only in the Mac service. The workstation
/// agent got `resp.learn` in **every** answer and dropped it: a click on
/// "Remember" in the dashboard never took effect on a Windows endpoint,
/// and because nobody ticked anything off, the central server kept sending
/// the same instruction every 30 seconds. That is why it now stands here —
/// in the same place as [`judge`] and [`enforce`], for the same reason.
///
/// The alert id is the one of this device; the pair (process, destination
/// network) is held only at the agent. The caller therefore passes in the
/// alerts it still knows.
pub fn apply_learn(
    learner: &mut Learner,
    alerts: &[Alert],
    cmds: &[LearnCommand],
    already: &[i64],
) -> Learned {
    let mut out = Learned::default();
    for c in cmds {
        if already.contains(&c.id) || out.done.contains(&c.id) {
            continue;
        }
        match alerts.iter().find(|a| a.id == c.alert_id) {
            Some(a) => {
                let key = match c.action {
                    LearnAction::Remember => learner.remember(a),
                    LearnAction::Flag => learner.flag(a),
                };
                match key {
                    Some(k) => out.learned.push((c.action, k)),
                    None => {
                        tracing::info!("central: alert #{} is unsigned, never learned", c.alert_id)
                    }
                }
            }
            None => tracing::info!(
                "central: alert #{} no longer known, learn instruction dropped",
                c.alert_id
            ),
        }
        out.done.push(c.id);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Strict;
    use crate::identity::ProcessIdentity;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    /// Remembers what was asked of it.
    #[derive(Default)]
    struct Spy {
        copies: std::cell::Cell<usize>,
    }

    impl Enforcer for Spy {
        fn delete_copy(&self, _a: &Alert) -> String {
            self.copies.set(self.copies.get() + 1);
            "copy deleted".into()
        }
    }

    fn denied_alert() -> Alert {
        Alert {
            id: 1,
            at: Utc::now(),
            pid: 4242,
            identity: ProcessIdentity::Unknown {
                path: "/usr/bin/curl".into(),
            },
            files: vec![PathBuf::from("/GL/x.txt")],
            remote: Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
            remote_port: Some(443),
            bytes_out: 9000,
            via: None,
            last_at: None,
            verdict: Verdict::Denied,
            reason: Some("denied".into()),
            volume: None,
            copy_to: None,
            sender_read_directly: true,
            upload_url: None,
        }
    }

    fn strict_cfg(enforce: bool) -> Config {
        Config {
            strict: vec![Strict {
                path: PathBuf::from("/GL"),
                allow: vec![],
                enforce,
            }],
            ..Default::default()
        }
    }

    /// A drain to the network leaves the reason untouched: connector and
    /// cage work against that, not this seam. Until 2026-09-09 "sender
    /// stopped" stood here, and behind it a dead Explorer.
    #[test]
    fn a_flow_to_the_network_changes_nothing_here() {
        for enforce_on in [true, false] {
            let mut j = Judged(denied_alert());
            let spy = Spy::default();
            enforce(&strict_cfg(enforce_on), &mut j, &spy);
            assert_eq!(spy.copies.get(), 0);
            assert_eq!(
                j.alert().reason.as_deref(),
                Some("denied"),
                "enforce={enforce_on}"
            );
        }
    }

    /// A copy goes to the adapter.
    #[test]
    fn a_copy_goes_to_delete_not_to_stop() {
        let mut a = denied_alert();
        a.remote = None;
        a.remote_port = None;
        a.copy_to = Some(PathBuf::from("/Users/me/Desktop/x.txt"));
        let mut j = Judged(a);
        let spy = Spy::default();
        enforce(&strict_cfg(true), &mut j, &spy);
        assert_eq!(spy.copies.get(), 1);
        assert!(j.into_alert().reason.unwrap().contains("copy deleted"));
    }

    /// The promise from the module header: without [`judge`] the verdict
    /// still stands at `New`, and `action_for` does not take effect. The
    /// test records that the order carries the behaviour — not a comment.
    #[test]
    fn without_the_verdict_nothing_is_enforced() {
        // On the copy path, because that is the only one that still
        // intervenes at all: on the network the test would go green even if
        // the order broke.
        let mut a = denied_alert();
        a.remote = None;
        a.remote_port = None;
        a.copy_to = Some(PathBuf::from("/Users/me/Desktop/x.txt"));
        a.verdict = Verdict::New;
        // Buildable only in here: `Judged` has a private field, outside
        // the module there is no getting past `enforce` in the first place.
        let mut j = Judged(a);
        let spy = Spy::default();
        enforce(&strict_cfg(true), &mut j, &spy);
        assert_eq!(
            spy.copies.get(),
            0,
            "ohne Urteil darf kein Eingriff stattfinden"
        );
    }
    /// An allowed process produces no alert.
    #[test]
    fn a_listed_process_produces_no_alert() {
        let mut a = denied_alert();
        a.identity = ProcessIdentity::Signed {
            team_id: "Microsoft".into(),
            signing_id: "TEAMS.EXE.MUI".into(),
        };
        a.verdict = Verdict::New;
        let allow = crate::learn::parse_allowlist("# Kommentar\n\n  teams.exe  \n");
        let mut l = Learner::new(0, Utc::now());
        assert!(judge(&mut l, &allow, Outcome::New(a), Utc::now()).is_none());
        assert_eq!(
            l.pair_count(),
            0,
            "freigegeben heisst auch: kein Paar in der Lernphase"
        );
    }

    /// But a forbidden destination outranks the list: otherwise one entry
    /// switches off the strict folder for that process.
    #[test]
    fn the_list_does_not_silence_a_denied_target() {
        let mut a = denied_alert();
        a.identity = ProcessIdentity::Signed {
            team_id: "Microsoft".into(),
            signing_id: "teams.exe".into(),
        };
        let allow = crate::learn::parse_allowlist("teams.exe\n");
        let mut l = Learner::new(0, Utc::now());
        let (j, _) = judge(&mut l, &allow, Outcome::New(a), Utc::now())
            .expect("verbotenes Ziel bleibt eine Warnung");
        assert_eq!(j.alert().verdict, Verdict::Denied);
    }

    use crate::central::{LearnAction, LearnCommand};

    fn learn_alert(id: u64, signed: bool) -> Alert {
        let t: chrono::DateTime<chrono::Utc> = "2026-09-06T10:00:00Z".parse().unwrap();
        Alert {
            id,
            at: t,
            pid: 10,
            identity: if signed {
                ProcessIdentity::Signed {
                    signing_id: "com.example.app".into(),
                    team_id: "TEAM1".into(),
                }
            } else {
                ProcessIdentity::Unknown {
                    path: "/tmp/x".into(),
                }
            },
            files: vec![],
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

    fn cmd(id: i64, alert_id: u64, action: LearnAction) -> LearnCommand {
        LearnCommand {
            id,
            alert_id,
            action,
        }
    }

    /// After remembering, the same pair is silent — exactly what ends the
    /// flood of `new` at the central server.
    #[test]
    fn remember_from_central_silences_the_pair() {
        let now: chrono::DateTime<chrono::Utc> = "2026-09-06T10:00:00Z".parse().unwrap();
        let mut l = Learner::new(0, now);
        l.confirm();
        let a = learn_alert(1, true);
        assert!(matches!(
            l.judge(&a, true, now),
            crate::learn::Decision::Store {
                verdict: Verdict::New,
                ..
            }
        ));

        let out = apply_learn(&mut l, &[a], &[cmd(7, 1, LearnAction::Remember)], &[]);
        assert_eq!(out.done, vec![7]);
        assert_eq!(
            out.learned.len(),
            1,
            "ein gemerktes Paar gehoert ins Protokoll des Aufrufers"
        );

        let mut next = learn_alert(2, true);
        next.id = 2;
        assert!(
            matches!(l.judge(&next, true, now), crate::learn::Decision::Drop),
            "bekanntes Paar muss still sein"
        );
    }

    /// What cannot take effect still counts as done: otherwise the central
    /// server sends the same instruction again in every report.
    #[test]
    fn commands_are_never_repeated_forever() {
        let now: chrono::DateTime<chrono::Utc> = "2026-09-06T10:00:00Z".parse().unwrap();
        let mut l = Learner::new(0, now);
        l.confirm();
        // Alert has rolled out of the log.
        assert_eq!(
            apply_learn(&mut l, &[], &[cmd(1, 99, LearnAction::Remember)], &[]).done,
            vec![1]
        );
        // An unsigned process is never learned.
        assert_eq!(
            apply_learn(
                &mut l,
                &[learn_alert(2, false)],
                &[cmd(2, 2, LearnAction::Remember)],
                &[]
            )
            .done,
            vec![2]
        );
        // Ones already reported stay put, even if the central server
        // repeats them before it has processed the report.
        assert!(apply_learn(
            &mut l,
            &[learn_alert(3, true)],
            &[cmd(3, 3, LearnAction::Flag)],
            &[3]
        )
        .done
        .is_empty());
    }

    /// "Always report" stays loud, even if the pair were known.
    #[test]
    fn flag_from_central_keeps_reporting() {
        let now: chrono::DateTime<chrono::Utc> = "2026-09-06T10:00:00Z".parse().unwrap();
        let mut l = Learner::new(0, now);
        l.confirm();
        let a = learn_alert(1, true);
        assert_eq!(
            apply_learn(
                &mut l,
                std::slice::from_ref(&a),
                &[cmd(5, 1, LearnAction::Flag)],
                &[]
            )
            .done,
            vec![5]
        );
        let mut next = a;
        next.id = 2;
        assert!(matches!(
            l.judge(&next, true, now),
            crate::learn::Decision::Store {
                verdict: Verdict::Flagged,
                ..
            }
        ));
    }
}
