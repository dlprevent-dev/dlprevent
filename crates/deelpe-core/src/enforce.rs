//! What is to happen on a forbidden movement out of a strict folder — the
//! decision, not the execution.
//!
//! The decision is the same on every endpoint; each one may carry it out
//! differently. The Windows workstation removes the copy, the Mac service
//! cannot do that yet. Before, both answered the same question for
//! themselves — and arrived at different answers.
//!
//! **No process is stopped.** What takes effect on the network takes
//! effect earlier: the browser connector says no before a single byte
//! goes out, and the network cage takes the network away from a program
//! without killing it. Both hang off `Strict::enforce`, but they do not
//! run through this seam. See ADR 0002 and the addendum of 2026-09-09.
//!
//! Two adapters, one seam: here stands *what* is to be done, there *how*.

use crate::config::Config;
use crate::correlate::{Alert, Target};
use crate::learn::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Reporting is enough.
    None,
    /// Not a sender, but a copy onto a disk, a stick or a network drive:
    /// stopping the copier helps nobody — that is Explorer or Finder. What
    /// has to go instead of it is the copy.
    DeleteCopy,
}

/// The intervention for this alert.
///
/// What is asked for is the strict folder that forbids *this* flow — not
/// just any of the folders that were read: otherwise the service would
/// shoot because of folder B while the alert names folder A.
///
/// A drain to the network yields **no** intervention here any more.
/// Connector and cage work against that, and both take effect earlier;
/// what would still be possible here is to kill the sender after the bytes
/// are already out. On 2026-09-09 that cost the user's desktop twice and
/// prevented nothing.
pub fn action_for(cfg: &Config, a: &Alert) -> Action {
    if a.verdict != Verdict::Denied {
        return Action::None;
    }
    if !cfg.denies(&a.files, a.remote, a.remote_port).is_some_and(|s| s.enforce) {
        return Action::None;
    }
    // Before, two `is_none` questions stood here that together made the
    // same three-way decision — with a different precedence than the rest
    // of the program. Now the same derivation as everywhere else.
    match a.target() {
        Target::Volume(_) | Target::Copy(_) => Action::DeleteCopy,
        Target::Unknown | Target::Upload(_) | Target::Net { .. } => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Strict;
    use crate::identity::ProcessIdentity;
    use std::path::PathBuf;

    fn cfg(enforce: bool, allow: &[&str]) -> Config {
        Config {
            strict: vec![Strict { path: "/srv/GL".into(), allow: allow.iter().map(|s| s.to_string()).collect(), enforce }],
            ..Default::default()
        }
    }

    fn alert() -> Alert {
        Alert {
            id: 1,
            at: chrono::Utc::now(),
            pid: 4242,
            identity: ProcessIdentity::Unknown { path: "/usr/bin/curl".into() },
            files: vec![PathBuf::from("/srv/GL/a.xlsx")],
            remote: Some("203.0.113.9".parse().unwrap()),
            remote_port: Some(443),
            bytes_out: 9000,
            via: None,
            last_at: None,
            verdict: Verdict::Denied,
            reason: None,
            volume: None,
            copy_to: None,
            sender_read_directly: true,
            upload_url: None,
        }
    }

    /// A drain to the network is reported, nothing else. Until 2026-09-09
    /// the sending process was killed here; that hit the user's Explorer
    /// twice and never prevented anything, because by that point the bytes
    /// were already out.
    #[test]
    fn a_flow_to_the_network_is_only_reported() {
        for enforce in [true, false] {
            assert_eq!(action_for(&cfg(enforce, &[]), &alert()), Action::None, "enforce={enforce}");
        }
        // Not even when the sender read the file itself.
        let mut a = alert();
        a.sender_read_directly = false;
        assert_eq!(action_for(&cfg(true, &[]), &a), Action::None);
        // Destination on the allow list, a different verdict: all the less.
        assert_eq!(action_for(&cfg(true, &["203.0.113.9"]), &alert()), Action::None);
        a = alert();
        a.verdict = Verdict::New;
        assert_eq!(action_for(&cfg(true, &[]), &a), Action::None);
    }

    #[test]
    fn a_local_copy_gets_removed_instead_of_a_sender() {
        let mut a = alert();
        a.remote = None;
        a.remote_port = None;
        a.bytes_out = 0;
        a.copy_to = Some("/Users/eva/Desktop".into());
        assert_eq!(action_for(&cfg(true, &[]), &a), Action::DeleteCopy);
        // The same for an external volume.
        a.copy_to = None;
        a.volume = Some("/Volumes/Stick".into());
        assert_eq!(action_for(&cfg(true, &[]), &a), Action::DeleteCopy);
    }

    #[test]
    fn without_a_named_destination_nothing_is_stopped() {
        let mut a = alert();
        a.remote = None;
        a.remote_port = None;
        assert_eq!(action_for(&cfg(true, &[]), &a), Action::None, "kein Ziel, kein Kopierziel: melden reicht");
    }
}
