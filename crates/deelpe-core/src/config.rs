use crate::identity::ProcessIdentity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Protected folders. Accesses below them make a process "touched".
    pub watched: Vec<PathBuf>,
    /// How long a process counts as touched after its last file access.
    pub touch_ttl_secs: u64,
    /// Network polling interval.
    pub net_poll_secs: u64,
    /// Below this amount sent (bytes) per interval no alert is raised.
    pub min_bytes_out: u64,
    /// How long a copy or a written file outside the protected folders
    /// counts as derived (copy tracking).
    pub derived_ttl_secs: u64,
    /// How long alerts stay on disk; 0 = unlimited.
    pub alert_retain_days: u32,
    /// Duration of the silent learning phase (M2), in days.
    pub learn_days: u32,
    /// Processes that are never reported. Rules: `TEAM/signing-id`,
    /// `TEAM/prefix.*`, `team:TEAM` or, without a team, just `signing-id`
    /// or `prefix.*` (weaker: any signature may call itself that).
    /// Default: system services that read every file and have network.
    pub ignored: Vec<String>,
    /// Strict folders ("block all"). See [`Strict`].
    pub strict: Vec<Strict>,
    /// Processes allowed by hand: no noise from the learning phase, no
    /// `new` and no `deviation` alert. Program name in comparison form
    /// ([`crate::identity::image_name`]).
    ///
    /// **Not** the same as [`Config::ignored`]: a forbidden destination in
    /// a strict folder stays an alert including the intervention. Whoever
    /// wants to take a process out of the correlator altogether takes
    /// `ignored`. Enforced in [`crate::pipeline::judge`]. Handed out by the
    /// central server.
    pub allow_processes: std::collections::BTreeSet<String>,
}

/// A folder out of which nothing may go outside, except to the
/// destinations in `allow`. A process that has read from it triggers an
/// immediate alert with verdict `denied` for every other destination —
/// without a minimum amount, without a learning phase, without silencing.
/// Handed out by the central server as a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Strict {
    pub path: PathBuf,
    /// Allowed destinations: IP or network, each with an optional port
    /// (`crate::allow`).
    pub allow: Vec<String>,
    /// In addition to the alert, stop the sending process. At the endpoint
    /// that is the only lever without a Network Extension: the bytes
    /// already sent are gone, the rest is not.
    pub enforce: bool,
}

/// Indexer, backup, cloud sync and virus scanner read everything and send
/// as well. Without this list the table before the learning phase (M2) is
/// full of noise. All bound to the team: `apple` are platform binaries
/// (eslogger.rs).
pub const DEFAULT_IGNORED: &[&str] = &[
    "apple/com.apple.metadata.mds",
    "apple/com.apple.metadata.mds_stores",
    "apple/com.apple.metadata.mdworker*",
    "apple/com.apple.mdworker_shared",
    "apple/com.apple.backupd",
    "apple/com.apple.bird",
    "apple/com.apple.cloudd",
    "apple/com.apple.fileproviderd",
    "apple/com.apple.syncdefaultsd",
    "apple/com.apple.Spotlight",
    "apple/com.apple.photoanalysisd",
    "apple/com.apple.mediaanalysisd",
    "apple/com.apple.XProtect*",
    "apple/com.apple.MRT",
    "GUNFMW623Y/com.bitdefender.*",
];

/// Minimum length of a prefix, so that `*` does not switch everything off.
const MIN_PREFIX: usize = 4;

/// Default touch expiry of the correlator.
///
/// Stands here as a `const` so that the sensor can **compute** its starting
/// value from it instead of recomputing it by hand: `etw.rs` briefly had a
/// 660 that had been formed by hand out of 600 + 60 — exactly the
/// duplication this value is meant to avoid.
pub const DEFAULT_TOUCH_TTL_SECS: u64 = 600;

/// Lead of the sensor over the correlator, see
/// [`Config::sensor_taint_ttl`].
pub const SENSOR_TAINT_MARGIN_SECS: u64 = 60;

impl Default for Config {
    fn default() -> Self {
        Self {
            watched: Vec::new(),
            touch_ttl_secs: DEFAULT_TOUCH_TTL_SECS,
            net_poll_secs: 3,
            min_bytes_out: 4096,
            derived_ttl_secs: 86_400,
            alert_retain_days: 365,
            learn_days: 7,
            ignored: DEFAULT_IGNORED.iter().map(|s| s.to_string()).collect(),
            strict: Vec::new(),
            allow_processes: Default::default(),
        }
    }
}

impl Config {
    /// How long a sensor has to let a touched process through.
    ///
    /// The sensor discards file events **outside** the protected folders
    /// before they go into the channel — except from a process that has
    /// just read from a protected folder. That is exactly how the
    /// correlator gets to see the copy on the desktop.
    ///
    /// So the sensor may never be the narrower filter: it has to keep
    /// letting the process through while the correlator still holds it as
    /// touched. Before, a `const` of 300 s stood here next to a
    /// `touch_ttl_secs` of 600 by default — and between the two the copy
    /// was lost. Hence derived instead of written down alongside.
    pub fn sensor_taint_ttl(&self) -> std::time::Duration {
        // The margin covers the offset: the correlator starts its expiry
        // at the read, the sensor at the event before it.
        std::time::Duration::from_secs(self.touch_ttl_secs.saturating_add(SENSOR_TAINT_MARGIN_SECS))
    }

    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Only root reads it: otherwise the list of protected folders and
        // exceptions tells an attacker what is watched and what is not.
        use std::io::Write;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        // Windows: the agent has its own configuration and does not use
        // this type; there the file is protected through the DACL.
        #[cfg(not(unix))]
        {
            let mut f = std::fs::File::create(path)?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
        }
        Ok(())
    }

    /// The configuration of an **endpoint**: its folders come from the
    /// central server, it has no file of its own.
    ///
    /// The remaining fields belong to the Mac service, which really keeps
    /// this file; here they stay at the default. That an endpoint drags
    /// them along is the price for the correlator and the service sharing
    /// one type — visible in exactly this place instead of at every caller.
    pub fn for_endpoint(watched: Vec<PathBuf>, strict: Vec<Strict>, learn_days: u32) -> Self {
        Self {
            watched,
            strict,
            learn_days: learn_days.max(1),
            // The default exception list names Apple signatures and
            // matches nothing on a Windows machine. A list of its own (say
            // `Microsoft Corporation/*`) belongs in the dashboard and is
            // not handed out yet — until then every program is reported.
            ignored: Vec::new(),
            ..Default::default()
        }
    }

    /// Adopt the central server's allow list, in comparison form.
    ///
    /// Takes raw lines, not the finished set: the central server sends what
    /// a human typed, and the comparison form belongs in exactly one place
    /// — see [`crate::identity::image_name`].
    pub fn with_allowed(mut self, names: &[String]) -> Self {
        self.allow_processes = names.iter().map(|n| crate::identity::image_name(n)).collect();
        self
    }

    /// Is the file inside a protected folder? Other routes to the same
    /// data (firmlink, Time Machine snapshot) count too, see `normalize`.
    pub fn is_watched(&self, file: &Path) -> bool {
        let file = normalize(file);
        self.watched.iter().any(|w| under(&file, w)) || self.strict.iter().any(|s| under(&file, &s.path))
    }

    /// The strict folder for this file; with nested ones the longest path,
    /// so that a subfolder can replace its parent folder's allow list
    /// instead of inheriting it.
    pub fn strict_for(&self, file: &Path) -> Option<&Strict> {
        let file = normalize(file);
        self.strict.iter().filter(|s| under(&file, &s.path)).max_by_key(|s| s.path.as_os_str().len())
    }

    /// The strict folder that forbids this flow: the first one among the
    /// files that were read whose allow list does not know the destination.
    ///
    /// **One** touched file from a strict folder is enough. Anyone checking
    /// only the first file here would let a process that has read from
    /// `/GL` (destination allowed) and `/HR` (nothing allowed) send at
    /// will — and which folder wins would hang on the order of reading.
    /// The machine itself is not a destination. A strict folder forbids
    /// data from **going away**; to `127.0.0.1` it goes nowhere. Without
    /// this line Firefox died in the lab on 2026-09-08: one byte to itself,
    /// an empty allow list, "block all" — and the intervention stopped the
    /// browser.
    ///
    /// The price is a forwarder on the same machine that takes the data in
    /// and carries it out. This layer then does not catch it; killing a
    /// browser because it is talking to itself is the more expensive
    /// mistake — the same trade-off as with a destination without a name.
    pub fn denies(&self, files: &[PathBuf], ip: Option<IpAddr>, port: Option<u16>) -> Option<&Strict> {
        if ip.is_some_and(|a| a.is_loopback()) {
            return None;
        }
        files.iter().filter_map(|f| self.strict_for(f)).find(|s| !crate::allow::allows(&s.allow, ip, port))
    }

    /// Does an entry of the exception list match this identity? Unsigned
    /// processes are never ignored (design: "is always reported").
    pub fn is_ignored(&self, id: &ProcessIdentity) -> bool {
        self.ignored.iter().any(|rule| rule_matches(rule, id))
    }

    /// A rule for exactly this identity, as app and CLI should create it.
    pub fn ignore_rule_for(id: &ProcessIdentity) -> Option<String> {
        match id {
            ProcessIdentity::Signed { team_id, signing_id } if !signing_id.is_empty() => Some(format!("{team_id}/{signing_id}")),
            _ => None,
        }
    }
}

/// Is `file` inside `base`? See [`crate::path::under`] — that is also
/// where it says why the comparison ignores upper and lower case.
fn under(file: &Path, base: &Path) -> bool {
    crate::path::under(&file.to_string_lossy(), &base.to_string_lossy())
}

/// Leads detours back to the actual path: `/System/Volumes/Data/Users/…`
/// is `/Users/…` via firmlink, and Time Machine snapshots
/// (`…/Backups.backupdb/<Mac>/<Zeit>/Data/Users/…`, locally under
/// `/Volumes/com.apple.TimeMachine.localsnapshots`, older form
/// `<Zeit>/Macintosh HD - Data/`) contain the same files. Otherwise an
/// attacker reads the copy in the snapshot without touching the folder.
pub fn normalize(path: &Path) -> PathBuf {
    if let Ok(rest) = path.strip_prefix("/System/Volumes/Data") {
        return Path::new("/").join(rest);
    }
    let comps: Vec<&std::ffi::OsStr> = path.iter().collect();
    if let Some(i) = comps.iter().position(|c| *c == "Backups.backupdb") {
        // Backups.backupdb / <Mac> / <Zeit> / <Volume> / rest
        if let Some(vol) = comps.get(i + 3) {
            let v = vol.to_string_lossy();
            if v == "Data" || v.ends_with("- Data") {
                let mut out = PathBuf::from("/");
                out.extend(&comps[i + 4..]);
                return out;
            }
        }
    }
    path.to_path_buf()
}

/// Checks a rule before it goes into the list. Rejects anything that would
/// switch off everything or all Apple programs.
pub fn validate_ignore_rule(rule: &str) -> Result<(), String> {
    let rule = rule.trim();
    if rule.is_empty() || rule.contains(char::is_whitespace) {
        return Err("a rule must not be empty or contain spaces".into());
    }
    if let Some(team) = rule.strip_prefix("team:") {
        return if team.is_empty() || team == "apple" {
            Err("team:apple would switch off every Apple program; name a signing id instead".into())
        } else {
            Ok(())
        };
    }
    let signing = rule.split_once('/').map_or(rule, |(_, s)| s);
    match signing.strip_suffix('*') {
        Some(prefix) if prefix.len() < MIN_PREFIX => Err(format!("the prefix before * needs at least {MIN_PREFIX} characters")),
        _ if signing.is_empty() => Err("signing id is missing".into()),
        _ => Ok(()),
    }
}

fn rule_matches(rule: &str, id: &ProcessIdentity) -> bool {
    let ProcessIdentity::Signed { team_id, signing_id } = id else { return false };
    if let Some(team) = rule.strip_prefix("team:") {
        return team_id == team;
    }
    let signing = match rule.split_once('/') {
        Some((team, signing)) => {
            if team_id != team {
                return false;
            }
            signing
        }
        None => rule,
    };
    match signing.strip_suffix('*') {
        Some(prefix) => signing_id.starts_with(prefix),
        None => signing_id == signing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed(team: &str, id: &str) -> ProcessIdentity {
        ProcessIdentity::Signed { team_id: team.into(), signing_id: id.into() }
    }

    #[test]
    fn ignore_rules() {
        let cfg = Config { ignored: vec!["com.apple.backupd".into(), "com.bitdefender.*".into(), "team:ABC".into()], ..Default::default() };
        assert!(cfg.is_ignored(&signed("apple", "com.apple.backupd")));
        assert!(!cfg.is_ignored(&signed("apple", "com.apple.backupd2")));
        assert!(cfg.is_ignored(&signed("X", "com.bitdefender.epsecurity")));
        assert!(cfg.is_ignored(&signed("ABC", "anything")));
        assert!(!cfg.is_ignored(&ProcessIdentity::Unknown { path: "/tmp/com.apple.backupd".into() }));
        assert!(!cfg.is_ignored(&ProcessIdentity::Hashed { path: "/x".into(), sha256: "team:ABC".into() }));
    }

    #[test]
    fn team_bound_rules_reject_impostors() {
        let cfg = Config::default();
        assert!(cfg.is_ignored(&signed("apple", "com.apple.backupd")));
        assert!(!cfg.is_ignored(&signed("EVIL1", "com.apple.backupd")), "fremde Signatur mit Apple-Namen");
        assert!(cfg.is_ignored(&signed("apple", "com.apple.metadata.mdworker_shared")));
        assert!(!cfg.is_ignored(&signed("EVIL1", "com.bitdefender.epsecurity")));
        assert!(cfg.is_ignored(&signed("GUNFMW623Y", "com.bitdefender.epsecurity")));
        assert_eq!(Config::ignore_rule_for(&signed("ABC", "com.x.y")).as_deref(), Some("ABC/com.x.y"));
        assert_eq!(Config::ignore_rule_for(&ProcessIdentity::Unknown { path: "/x".into() }), None);
    }

    #[test]
    fn rule_validation() {
        assert!(validate_ignore_rule("apple/com.apple.backupd").is_ok());
        assert!(validate_ignore_rule("com.example.*").is_ok());
        assert!(validate_ignore_rule("team:ABC").is_ok());
        assert!(validate_ignore_rule("*").is_err());
        assert!(validate_ignore_rule("co*").is_err());
        assert!(validate_ignore_rule("apple/*").is_err());
        assert!(validate_ignore_rule("team:apple").is_err());
        assert!(validate_ignore_rule("team:").is_err());
        assert!(validate_ignore_rule("").is_err());
        assert!(validate_ignore_rule("a b").is_err());
        assert!(validate_ignore_rule("ABC/").is_err());
    }

    #[test]
    fn old_config_without_new_keys_gets_defaults() {
        let cfg: Config = serde_json::from_str(r#"{"watched":["/a"]}"#).unwrap();
        assert_eq!(cfg.ignored, DEFAULT_IGNORED);
        assert_eq!(cfg.derived_ttl_secs, 86_400);
        assert_eq!(cfg.alert_retain_days, 365);
        assert!(cfg.strict.is_empty());
    }

    #[test]
    fn strict_folder_is_watched_and_the_longest_path_wins() {
        let cfg = Config {
            strict: vec![
                Strict { path: "/srv/GL".into(), allow: vec!["10.0.0.1".into()], enforce: false },
                Strict { path: "/srv/GL/Vertraege".into(), allow: vec![], enforce: true },
            ],
            ..Default::default()
        };
        assert!(cfg.is_watched(Path::new("/srv/GL/a.xlsx")));
        assert!(cfg.is_watched(Path::new("/System/Volumes/Data/srv/GL/a.xlsx")));
        assert!(!cfg.is_watched(Path::new("/srv/Other/a.xlsx")));
        assert_eq!(cfg.strict_for(Path::new("/srv/GL/a.xlsx")).unwrap().allow, ["10.0.0.1"]);
        assert!(cfg.strict_for(Path::new("/srv/GL/Vertraege/b.pdf")).unwrap().enforce);
        assert!(cfg.strict_for(Path::new("/srv/Other/a")).is_none());
    }

    #[test]
    fn any_strict_folder_in_the_flow_can_deny_it() {
        let cfg = Config {
            strict: vec![
                Strict { path: "/srv/GL".into(), allow: vec!["10.0.0.5".into()], enforce: false },
                Strict { path: "/srv/HR".into(), allow: vec![], enforce: true },
            ],
            ..Default::default()
        };
        let ip = Some("10.0.0.5".parse().unwrap());
        let gl: Vec<PathBuf> = vec!["/srv/GL/a.xlsx".into()];
        let both: Vec<PathBuf> = vec!["/srv/GL/a.xlsx".into(), "/srv/HR/b.xlsx".into()];
        assert!(cfg.denies(&gl, ip, Some(443)).is_none(), "GL erlaubt dieses Ziel");
        // HR allows nothing — the order of reading must not change that.
        let d = cfg.denies(&both, ip, Some(443)).expect("HR verbietet");
        assert_eq!(d.path, Path::new("/srv/HR"));
        assert!(d.enforce);
        let mut reversed = both.clone();
        reversed.reverse();
        assert_eq!(cfg.denies(&reversed, ip, Some(443)).unwrap().path, Path::new("/srv/HR"));
        assert!(cfg.denies(&[], ip, Some(443)).is_none());
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn normalize_maps_firmlink_and_snapshots_back() {
        assert_eq!(normalize(Path::new("/System/Volumes/Data/Users/me/Steuern/a.pdf")), PathBuf::from("/Users/me/Steuern/a.pdf"));
        assert_eq!(
            normalize(Path::new("/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/Mac/2026-09-05-101010/Data/Users/me/Steuern/a.pdf")),
            PathBuf::from("/Users/me/Steuern/a.pdf")
        );
        assert_eq!(
            normalize(Path::new("/Volumes/Backup/Backups.backupdb/Mac/2026-09-05-101010/Macintosh HD - Data/Users/me/Steuern/a.pdf")),
            PathBuf::from("/Users/me/Steuern/a.pdf")
        );
        // No snapshot pattern: unchanged.
        assert_eq!(normalize(Path::new("/Users/me/Backups.backupdb/x")), PathBuf::from("/Users/me/Backups.backupdb/x"));
        assert_eq!(normalize(Path::new("/tmp/x")), PathBuf::from("/tmp/x"));
    }

    #[test]
    fn paths_match_regardless_of_case_and_separator() {
        let c = Config { watched: vec![r"\\srv01\GL".into()], ..Default::default() };
        assert!(c.is_watched(Path::new(r"\\srv01\GL\zahlen.xlsx")));
        assert!(c.is_watched(Path::new(r"\\SRV01\gl\Zahlen.xlsx")), "Freigaben schreibt jeder anders");
        assert!(c.is_watched(Path::new(r"\\srv01\GL")));
        assert!(!c.is_watched(Path::new(r"\\srv01\GL2\a.txt")), "kein Treffer mitten im Namen");
        assert!(!c.is_watched(Path::new(r"\\srv01\Andere\a.txt")));
        // An empty rule path protects nothing rather than everything.
        let empty = Config { watched: vec!["".into()], ..Default::default() };
        assert!(!empty.is_watched(Path::new("/a/b")));
    }

    #[test]
    fn is_watched_sees_through_snapshots() {
        let c = Config { watched: vec!["/Users/me/Steuern".into()], ..Default::default() };
        assert!(c.is_watched(Path::new("/Users/me/Steuern/a")));
        assert!(c.is_watched(Path::new("/System/Volumes/Data/Users/me/Steuern/a")));
        assert!(c.is_watched(Path::new("/Volumes/com.apple.TimeMachine.localsnapshots/Backups.backupdb/Mac/2026-09-05-101010/Data/Users/me/Steuern/a")));
        assert!(!c.is_watched(Path::new("/Users/me/Other/a")));
    }

    /// The sensor's starting value (`etw::DEFAULT_TAINT_TTL`) is computed
    /// from exactly these two constants. If somebody changes the formula
    /// here without touching the sensor, it shows up here — on every
    /// platform, not only on Windows, where `etw.rs` compiles at all.
    #[test]
    fn the_sensors_starting_value_is_derived_not_retyped() {
        assert_eq!(
            Config::default().sensor_taint_ttl(),
            std::time::Duration::from_secs(DEFAULT_TOUCH_TTL_SECS + SENSOR_TAINT_MARGIN_SECS),
        );
    }

    /// The sensor may never be the narrower filter: otherwise it discards
    /// the copy the correlator is still waiting for. Until 2026-09-08 the
    /// ETW sensor had a `const` of 300 s against a default of 600 s.
    #[test]
    fn sensor_outlives_the_correlators_touch() {
        for secs in [0, 1, 10, 300, 600, 3600, u64::MAX] {
            let c = Config { touch_ttl_secs: secs, ..Default::default() };
            assert!(
                c.sensor_taint_ttl() >= std::time::Duration::from_secs(secs),
                "sensor ttl {:?} is shorter than touch_ttl_secs {secs}",
                c.sensor_taint_ttl(),
            );
        }
    }

    /// The machine itself is not a leak. On 2026-09-08 one byte to
    /// `127.0.0.1` killed Firefox in the lab: an empty allow list, "block
    /// all", and the intervention stopped the browser.
    #[test]
    fn the_machine_itself_is_never_a_forbidden_destination() {
        let c = Config { strict: vec![Strict { path: "/srv/GL".into(), allow: vec![], enforce: true }], ..Default::default() };
        let files = vec![PathBuf::from("/srv/GL/a.xlsx")];
        for local in ["127.0.0.1", "127.0.0.53", "::1"] {
            assert!(c.denies(&files, Some(local.parse().unwrap()), Some(443)).is_none(), "{local} verlaesst den Rechner nicht");
        }
        // Outbound it stays forbidden.
        assert!(c.denies(&files, Some("203.0.113.9".parse().unwrap()), Some(443)).is_some());
    }
}
