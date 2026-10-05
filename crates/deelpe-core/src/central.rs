//! Wire format between agents (Mac service, Windows server agent, later
//! the Windows client) and the central server (`deelpe-server`). Like the
//! socket format between the service and the app, this is a contract:
//! `tests/central_wire.rs` in the server checks the literals. Decision of
//! 2026-09-06.
//!
//! An agent sends a [`Report`] every `report_interval_secs` (status, new
//! alerts, counts) and gets its [`AgentConfig`] back as the answer. There
//! is deliberately no connection that the central server opens by itself:
//! everything it wants to tell the agent (rules, learning instructions)
//! hangs off the answer to that agent's report.

use crate::correlate::Alert;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Version of the wire format; the server rejects unknown versions.
pub const API_VERSION: u32 = 1;

/// Header on the agent program download: the release statement
/// (`deelpe_core::signing`), base64. Missing when the program was uploaded
/// without a signing key.
pub const RELEASE_HEADER: &str = "x-deelpe-release";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentKind {
    Mac,
    Linux,
    WindowsServer,
    WindowsClient,
}

/// Enrollment: the agent generates its key itself and sends only the CSR;
/// the private key never leaves the device. The token comes from the
/// dashboard and is burned after the enrollment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub api_version: u32,
    pub token: String,
    pub hostname: String,
    pub kind: AgentKind,
    pub version: String,
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub cert_pem: String,
    pub ca_pem: String,
    /// The token was one for machines reset to their image every night
    /// (terminal servers, VDI). Such a machine enrolls again on every boot
    /// and gets the same `agent_id` back; in return it keeps its state with
    /// the central server ([`Report::roaming`]), because the disk does not.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub non_persistent: bool,
    /// The state this agent last left with the central server, if it is
    /// `non_persistent` and has left one. Opaque to the central server: only
    /// the agent reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roaming: Option<serde_json::Value>,
}

/// Renewal of the agent certificate while the old one is still valid. No
/// token is needed: the connection already identifies the agent. Whoever
/// waits too long does not get through here any more — then only a fresh
/// enrollment is left.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewRequest {
    pub api_version: u32,
    pub csr_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewResponse {
    pub cert_pem: String,
    pub not_after: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SensorHealth {
    pub name: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// An SMB share of the file server. With it somebody can create a rule in
/// the dashboard without sitting down at the server and copying paths.
///
/// `path` is empty if the service account may not read the share table
/// (level 2 of `NetShareEnum` requires administrator rights). The name is
/// there anyway, and the path comes out of the events as soon as somebody
/// uses the share — that is the price for a service account without admin
/// rights, and a deliberate compromise.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remark: Option<String>,
    /// Where the path comes from: `enum` (share table) or `events`
    /// (learned from 5145). Visible in the dashboard, so nobody has to guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_from: Option<String>,
}

/// A group a customer puts users into. Only name and origin: a rule needs
/// no more, and with ten thousand groups we do not want to send more over
/// the line either.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInfo {
    /// Display name as a human knows it: `CORP\\Vorstand`.
    pub name: String,
    /// `domain` or `local`.
    pub kind: String,
}

/// Fingerprint of the running program: the first twelve hex digits of the
/// SHA-256 of its own file.
///
/// `version` stands at the same number on every agent and therefore says
/// nothing about who has already been swapped after a rollout —
/// `docs/INSTALL.md` itself points out that the column is "worth watching
/// when you update" but is no good as an answer. This one is: it is the
/// same value that `Get-FileHash` or `shasum -a 256` delivers on the
/// device, only shortened — comparable without any conversion.
///
/// Computed once per process: the program's own file is several megabytes
/// large. Empty if it cannot be read; then the dashboard shows nothing,
/// instead of a number that means nothing.
#[cfg(feature = "net")]
pub fn build_fingerprint() -> &'static str {
    static FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FP.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let Ok(exe) = std::env::current_exe() else {
            return String::new();
        };
        let Ok(data) = std::fs::read(&exe) else {
            return String::new();
        };
        Sha256::digest(data)
            .iter()
            .take(BUILD_FINGERPRINT_HEX / 2)
            .map(|b| format!("{b:02x}"))
            .collect()
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatus {
    pub version: String,
    /// Fingerprint of the running program, see [`build_fingerprint`].
    /// Older agents do not send the field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub build: String,
    pub hostname: String,
    /// Fully qualified name of the device, if it has one.
    ///
    /// `hostname` is the NetBIOS short name (`COMPUTERNAME`) and stays
    /// that: the UNC paths of the rules are built from it, and a rule with
    /// a long name would no longer match an access with a short one. The
    /// long name comes **alongside**, for the record: `\\fileserver\GL`
    /// does not say which machine in which domain that was, and a short
    /// name is resolved through mechanisms that can be forged.
    ///
    /// Empty on devices that do not keep one (the macOS service) and on
    /// older agents that do not send the field yet.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fqdn: String,
    pub started_at: DateTime<Utc>,
    pub sensors: Vec<SensorHealth>,
    /// Locally protected folders (including those handed out by the
    /// central server).
    pub watched: Vec<String>,
    pub learn_phase: String,
    /// Shares of the server. Empty on endpoint agents; older agents do not
    /// send the field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<ShareInfo>,
    /// The device's own IP addresses. Otherwise, behind a proxy, Docker or
    /// a tunnel, the server only records the address of the last hop.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
    /// Processor architecture in Debian's spelling (`amd64`, `arm64`), see
    /// [`arch`]. The central server picks the Linux program by it: one role,
    /// two files. Older agents do not send it and get no Linux update.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub arch: String,
    /// When the learning phase ran or runs out — the start of "review". Lets
    /// the dashboard say how long an agent has been waiting for a confirm.
    /// Empty on the file server agent (its baseline ends by itself) and on
    /// older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learn_until: Option<DateTime<Utc>>,
}

/// This program's architecture in Debian's spelling — the name the `.deb`
/// and the program files in the dashboard carry. Rust says `x86_64` and
/// `aarch64`.
pub fn arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

/// Who did the access. Identity as decided on 2026-09-06: not always AD.
/// `source` is the server/NAS that knows the name; with a `sid` the central
/// server merges across sources, without one it stays `Quelle\Name`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UserRef {
    pub source: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

impl UserRef {
    /// Key for counts and baselines: SID if present, otherwise
    /// `quelle\name` in lower case (SMB names are not case-sensitive).
    pub fn key(&self) -> String {
        match &self.sid {
            Some(s) if !s.is_empty() => format!("sid:{}", s),
            _ => format!(
                "{}\\{}",
                self.source.to_lowercase(),
                self.name.to_lowercase()
            ),
        }
    }
    pub fn display(&self) -> String {
        match &self.domain {
            Some(d) if !d.is_empty() => format!("{}\\{}", d, self.name),
            _ => self.name.clone(),
        }
    }
}

/// Condensed count: files and bytes per (user, rule, minute). Agents never
/// send raw events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CountBucket {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub path: String,
    pub user: UserRef,
    pub bucket: DateTime<Utc>,
    pub files: u32,
    pub bytes: u64,
}

/// Alert from a server agent or from the NAS condensation: mass access by
/// one user to a protected folder. Carry-forwards carry the same
/// `external_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessAlert {
    pub external_id: String,
    pub at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_at: Option<DateTime<Utc>>,
    pub user: UserRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub path: String,
    pub files: u32,
    pub bytes: u64,
    /// At most 5 samples.
    pub sample_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    pub verdict: crate::access::AccessVerdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One line from the agent's local log. Goes along with the report, so
/// that the dashboard shows *what* is going on at the device — not only
/// that it has not reported for an hour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogLine {
    pub at: DateTime<Utc>,
    /// `error`, `warn`, `info`, `debug` or `trace`.
    pub level: String,
    /// The module the line comes from.
    pub target: String,
    pub msg: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Missing on agents from before this version; the server only rejects
    /// versions that are explicitly foreign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
    /// The generation this agent is currently **running** — not the one it
    /// last received.
    ///
    /// If it matches the central server's, the central server leaves the
    /// rules out of the answer: the agent would discard them anyway, it
    /// only adopts its configuration when the generation has grown. The
    /// same consideration as with `groups`, only in the other direction —
    /// with ten thousand agents the same rule set otherwise goes over the
    /// line two thousand times a minute, and since a folder is handed out
    /// under its short name, its long name and its address, three times as
    /// large.
    ///
    /// `None` means "send them to me": an agent from before this version, a
    /// freshly enrolled one — and explicitly also one whose rule version
    /// did not survive. That one reports **nothing**, even though it knows
    /// a generation, because otherwise after a restart it would stand there
    /// without rules and nobody would see it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    /// Alerts from the endpoint correlator (Mac/Linux), new or carried forward.
    #[serde(default)]
    pub alerts: Vec<Alert>,
    #[serde(default)]
    pub access_alerts: Vec<AccessAlert>,
    #[serde(default)]
    pub counts: Vec<CountBucket>,
    /// Groups of the domain or of the server — **only if they have
    /// changed**, otherwise not at all.
    ///
    /// They deliberately do not belong in the status: that is written on
    /// every report, and an environment with tens of thousands of groups
    /// would keep the central server busy with the same list every 30
    /// seconds. Instead the agent compares a checksum and sends the list
    /// only when something has really changed. `None` means "unchanged", an
    /// empty list means "no groups".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<GroupInfo>>,
    /// Ids of the learning instructions this agent has carried out. With
    /// them the central server ticks them off and does not send them again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub learn_done: Vec<i64>,
    /// New lines of the local log, oldest first. The agent sends them
    /// again until the central server has accepted the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<LogLine>,
    /// A non-persistent machine's state (see
    /// [`EnrollResponse::non_persistent`]) — only when it has changed since
    /// the last report the central server accepted. The central server keeps
    /// the latest one and hands it back at the next enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roaming: Option<serde_json::Value>,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            api_version: Some(API_VERSION),
            generation: None,
            status: None,
            alerts: Vec::new(),
            access_alerts: Vec::new(),
            counts: Vec::new(),
            groups: None,
            learn_done: Vec::new(),
            log: Vec::new(),
            roaming: None,
        }
    }
}

/// Rule for a protected folder, handed out by the central server. On
/// endpoints only `path` counts (it becomes the protected folder); the
/// remaining fields steer server agents (Z2/Z3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub lockdown: bool,
    /// Strict folder ("block all"): allowed destinations as IP or network,
    /// each with an optional port. **An empty list does not mean
    /// "everything allowed"** — strict mode hangs off `strict`, not off the
    /// length of this list.
    #[serde(default)]
    pub allow_destinations: Vec<String>,
    /// Switches strict mode on for the folder: everything outbound is
    /// forbidden except `allow_destinations`.
    #[serde(default)]
    pub strict: bool,
    /// Switch the folder from reporting to acting (only with `strict`).
    /// No process is stopped: the levers are the network cage (every
    /// endpoint), the browser connector and deleting the copy (Windows
    /// workstation). See [`crate::config::Strict::enforce`].
    #[serde(default)]
    pub enforce: bool,
    pub hard_max_files: u32,
    pub window_secs: u32,
    #[serde(default)]
    pub ad_lock: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub api_version: u32,
    /// Rises on every change; the agent only adopts it when it grows.
    pub generation: i64,
    pub report_interval_secs: u32,
    pub learn_days: u32,
    pub rules: Vec<Rule>,
    /// Processes allowed by hand, see
    /// [`crate::config::Config::allow_processes`]. `default`: agents from
    /// before the field keep reporting everything, and an old agent can
    /// read a new answer. `skip_serializing_if`: an empty list leaves the
    /// answer byte for byte the way it was before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_processes: Vec<String>,
    /// The SHA-256 of the program the central server keeps ready for this
    /// agent — set only if it is a **different** one from the running one
    /// (see [`update_due`]) and the operator has switched distribution on.
    /// `None` means "stay as you are".
    ///
    /// The checksum stands here, not just a "yes": the agent downloads the
    /// program over the same connection and has to be able to check that it
    /// got exactly what the dashboard shows. Without it the central server
    /// would be a way to get any program at all onto the staff's machines,
    /// and nobody could recompute it.
    ///
    /// `default`/`skip_serializing_if`: an agent from before the field goes
    /// on reading a new answer, and without an update the answer looks byte
    /// for byte the way it did before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_to_sha256: Option<String>,
    /// End the learning phase now: what was learned counts as known, and
    /// from here on new and deviating traffic is reported — the same as
    /// "Confirm all" in the Mac app or `deelpe learn confirm`. Set while the
    /// operator's order stands and the agent does not yet report "active".
    ///
    /// Not tied to the generation, like `update_to_sha256`, and idempotent:
    /// an agent that is already active does nothing.
    ///
    /// `default`/`skip_serializing_if`: older agents keep reading the answer,
    /// and without an order it looks byte for byte as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub finish_learning: bool,
    /// Enrollment tokens that make Chrome and Edge honour the content-analysis
    /// connectors at all: without the browser being cloud-managed the policy
    /// shows up as `Error` in `chrome://policy` and nothing is blocked. The
    /// operator pastes the token from the Google (Chrome Browser Cloud
    /// Management) or Microsoft (Edge management service) console into the
    /// dashboard; the agent writes it to the browser's policy key at startup.
    /// `None`/empty means "do not enrol" (and the agent clears a stale one).
    ///
    /// `default`/`skip_serializing_if`: older agents keep reading the answer,
    /// and when unset the wire stays byte for byte as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chrome_enrollment_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge_enrollment_token: Option<String>,
}

/// What is to happen with the pair of an alert. Corresponds to the socket
/// commands `LearnRemember` and `LearnFlag` in the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearnAction {
    /// The pair counts as known: silent from now on, except on a deviation.
    Remember,
    /// The pair is always reported.
    Flag,
}

/// A learning instruction from the central server. Until now only the
/// human at the device decided which pair is known; without this route the
/// central server collects endless `new` alerts for every unknown pair,
/// because it can never silence it (decision of 2026-09-06).
///
/// `alert_id` is the alert id *of the agent* (in the central server the
/// `external_id`): only the agent knows the process identity and the
/// destination that make up the pair. The agent reports `id` back in
/// `learn_done`, so that the same instruction does not come back in every
/// report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnCommand {
    pub id: i64,
    pub alert_id: u64,
    pub action: LearnAction,
}

/// Is this rule version to be adopted?
///
/// It stood there twice, in two expressions: the workstation agent wrote
/// `resp.config.generation > st.generation || unconfigured`, the file
/// server agent `c.generation <= st.generation && !rules.is_empty()` — the
/// same question, once from the front and once from the back. The comment
/// next to it warned that both had to stay "the same expression"; that is
/// an agreement, not a check.
///
/// `configured` means "I really am running rules". The second leg is the
/// safety net underneath: if no usable version was on disk at startup,
/// even an equal generation gets adopted. Without that, an agent whose
/// central server does not answer at boot would protect nothing at all and
/// would never get the rules again, because it reports a generation it is
/// not running.
/// How many hex digits [`build_fingerprint`] delivers. Stands here because
/// this is where the comparison happens: if somebody shortens the
/// fingerprint without pulling this number along, the prefix matches more
/// than one file — and the agent would take somebody else's program for
/// its own.
pub const BUILD_FINGERPRINT_HEX: usize = 12;

/// Does the central server keep a different agent program ready from the
/// one this agent is currently running?
///
/// `available` is the full SHA-256 of the uploaded file, `running` the
/// fingerprint from the report — that is, **the beginning of the same
/// checksum** (see [`build_fingerprint`]). That way no version counting is
/// needed: the file itself is compared, and a rolled-back program is just
/// as much an update as a newer one.
///
/// `false` when in doubt. Whoever has nothing lying ready, or does not say
/// what they are running, gets no program sent — otherwise an agent whose
/// fingerprint is missing downloads the same four and a half megabytes on
/// every report.
pub fn update_due(available: &str, running: &str) -> bool {
    let available = available.trim().to_ascii_lowercase();
    let running = running.trim().to_ascii_lowercase();
    if available.len() != 64 || !available.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    if running.len() < BUILD_FINGERPRINT_HEX {
        return false;
    }
    !available.starts_with(&running)
}

pub fn adopt_generation(incoming: i64, current: i64, configured: bool) -> bool {
    incoming > current || !configured
}

/// The central server's answer.
///
/// **No `..` when taking it apart.** Every agent destructures it
/// completely; whoever adds a field to the wire format thereby breaks every
/// agent that does not handle it. That is exactly how `learn` got lost on
/// the workstation: the field arrived in every answer, and nobody read it —
/// silently, for weeks, while the central server repeated the instruction
/// every 30 seconds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    pub accepted_alerts: usize,
    pub accepted_access_alerts: usize,
    pub accepted_counts: usize,
    pub config: AgentConfig,
    /// Open learning instructions; empty in the normal case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub learn: Vec<LearnCommand>,
}

#[cfg(all(test, feature = "net"))]
mod build_tests {
    use super::*;

    /// The reported fingerprint has to be the same one a human gets on the
    /// device with `Get-FileHash` or `shasum -a 256` — otherwise the column
    /// in the dashboard is just a number again.
    #[test]
    fn the_fingerprint_is_the_first_twelve_hex_of_the_files_sha256() {
        use sha2::{Digest, Sha256};
        let exe = std::env::current_exe().expect("eigene Datei");
        let full: String = Sha256::digest(std::fs::read(&exe).unwrap())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let fp = build_fingerprint();
        assert_eq!(fp.len(), 12, "zwoelf Hexstellen: {fp}");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "nur Hex: {fp}");
        assert_eq!(
            fp,
            &full[..12],
            "muss der Anfang der echten Pruefsumme sein"
        );
        // Computed once, always the same answer.
        assert_eq!(fp, build_fingerprint());
    }

    /// Older agents do not send the field — the central server has to be
    /// able to read their report anyway.
    #[test]
    fn a_status_without_the_build_still_parses() {
        let old = r#"{"version":"0.1.0","hostname":"h","started_at":"2026-09-08T10:00:00Z",
                      "sensors":[],"watched":[],"learn_phase":"active"}"#;
        let st: AgentStatus = serde_json::from_str(old).expect("alter Bericht lesbar");
        assert!(st.build.is_empty());
        // And an empty fingerprint does not go into the wire format.
        let back = serde_json::to_string(&st).unwrap();
        assert!(
            !back.contains("build"),
            "leeres Feld gehoert nicht in den Bericht: {back}"
        );
    }
}

#[cfg(test)]
mod adopt_tests {
    use super::adopt_generation;

    /// The normal case: only a grown generation is adopted. Without that,
    /// every answer would rewrite the rules, and the agent would lose its
    /// counters on every report.
    #[test]
    fn only_a_newer_generation_is_adopted() {
        assert!(adopt_generation(5, 4, true));
        assert!(!adopt_generation(4, 4, true));
        assert!(!adopt_generation(3, 4, true));
    }

    /// The safety net underneath: whoever runs no rules also takes an
    /// equal or older generation. Otherwise an agent whose central server
    /// does not answer at boot protects nothing at all — and never gets the
    /// rules again, because it reports a generation it is not running.
    #[test]
    fn an_agent_without_rules_takes_whatever_it_gets() {
        assert!(adopt_generation(4, 4, false));
        assert!(adopt_generation(1, 9, false));
    }
}

#[cfg(test)]
mod update_tests {
    use super::{update_due, BUILD_FINGERPRINT_HEX};

    const SHA: &str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";

    /// The normal case: the central server keeps a different program ready
    /// from the one running here.
    #[test]
    fn a_different_binary_is_an_update() {
        assert!(update_due(SHA, "0123456789ab"));
    }

    /// The most frequent case of all — every report from an up-to-date
    /// agent. The fingerprint is the beginning of the checksum; if it
    /// matches, it is the same file and there is nothing to do.
    #[test]
    fn the_same_binary_is_no_update() {
        assert!(!update_due(SHA, &SHA[..BUILD_FINGERPRINT_HEX]));
    }

    /// Both sides write hex in lower case, but the checksum comes from the
    /// dashboard and the fingerprint from the device: an update that hangs
    /// only on the spelling would be an update on **every** report.
    #[test]
    fn case_does_not_decide() {
        assert!(!update_due(
            &SHA.to_uppercase(),
            &SHA[..BUILD_FINGERPRINT_HEX]
        ));
    }

    /// An agent from before the fingerprint does not send the field.
    /// Whoever does not say what they are running gets no program sent:
    /// otherwise every old agent downloads the same four and a half
    /// megabytes on every report.
    #[test]
    fn without_a_fingerprint_nothing_is_pushed() {
        assert!(!update_due(SHA, ""));
        assert!(!update_due(SHA, "aabb"));
    }

    /// And all the less without a program lying ready. Otherwise an empty
    /// prefix matches everything.
    #[test]
    fn without_a_binary_nothing_is_pushed() {
        assert!(!update_due("", "0123456789ab"));
        assert!(!update_due("nicht-hex", "0123456789ab"));
    }
}
