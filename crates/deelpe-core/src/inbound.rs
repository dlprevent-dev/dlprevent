//! "Something has landed in the protected folder" — the mirror image of
//! the question the rest of the program asks.
//!
//! Everything else here follows the data *out* of a protected folder:
//! read, copy, send. An arrival is the other direction, and it needs its
//! own answer on all three agents, because each of them sees something
//! different:
//!
//! * **Mac** (`eslogger`): `copyfile`, `clone`, `rename` and `link` name
//!   source *and* target. Source outside, target inside — that is an
//!   arrival, with no further question asked.
//! * **Windows workstation** (ETW `Kernel-File`): there is no copy event.
//!   The source is not even visible — the sensor's filter throws it away
//!   before the channel, because it lies outside the protected folders.
//!   What arrives is the write on the target, and nothing in it says
//!   whether a file is being created or an existing one saved.
//! * **Windows file server** (security log 5145/4663): the event names the
//!   user and the file, and the access mask says "was opened for writing"
//!   — again not whether the file is new.
//!
//! For the last two the file itself has to answer, and it can: a file that
//! has just come into being carries a creation time of just now, while a
//! document that gets saved over carries the one from the day it was first
//! written.
//!
//! **The ceiling of that answer**, and it is the honest one: a *move*
//! inside the same volume keeps the creation time. Whoever moves a file
//! into the share locally on the server, or on the workstation within the
//! same drive, is not reported by this path. Over SMB — the case this is
//! about — a new file comes into being on the server, and that one is
//! caught. On the Mac the rename event names the target, so a move is
//! caught there anyway.

use std::path::Path;
use std::time::{Duration, SystemTime};

/// How young a file has to be for a write to count as an arrival. Long
/// enough for a large copy over a slow line to still be counted as one
/// arrival, short enough that saving an old document does not become one.
pub const FRESH: Duration = Duration::from_secs(120);

/// Did this file come into being just now?
///
/// ponytail: the question is asked where the event is processed, so the
/// `stat` runs in the correlator's lock — on a workstation that means over
/// SMB, and a share that has just gone away stalls the loop until the
/// redirector gives up. Then the sensor's channel backs up and the dropped
/// events get counted and reported, so it is loud rather than silent.
/// Upgrade path if that ever bites: let the sensor answer it while it still
/// has the handle and carry the answer in the event.
///
/// No creation time (a file system that does not keep one, a file that is
/// already gone again, a Linux kernel without `statx`) means **no**: a
/// question that cannot be answered must not produce an alert.
pub fn just_created(path: &Path, now: SystemTime, max_age: Duration) -> bool {
    let Ok(created) = std::fs::metadata(path).and_then(|m| m.created()) else { return false };
    // A creation time in the future comes from a clock that ran backwards,
    // not from an old file.
    now.duration_since(created).map_or(true, |age| age <= max_age)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_written_just_now_is_new_and_an_old_one_is_not() {
        let dir = std::env::temp_dir().join(format!("deelpe-inbound-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.txt");
        std::fs::write(&f, b"x").unwrap();
        let now = SystemTime::now();
        assert!(just_created(&f, now, FRESH));
        // The same file, judged an hour later: no longer an arrival.
        assert!(!just_created(&f, now + Duration::from_secs(3600), FRESH));
        // What is not there answers nothing.
        assert!(!just_created(&dir.join("gone.txt"), now, FRESH));
        std::fs::remove_dir_all(&dir).ok();
    }
}
