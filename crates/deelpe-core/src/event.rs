use crate::identity::ProcessIdentity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;

/// A process as a sensor saw it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRef {
    pub pid: u32,
    pub ppid: Option<u32>,
    /// macOS: PID of the responsible process (`responsible_audit_token`).
    /// XPC services such as the Safari network process hang off launchd but
    /// belong to an app; without this field the process chain breaks there.
    #[serde(default)]
    pub responsible: Option<u32>,
    pub path: PathBuf,
    pub identity: ProcessIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAction {
    /// Opened for reading.
    Open,
    /// Opened for writing: the process can write protected content here.
    Write,
    Exec,
    /// `path` copied to `target` (copyfile/clonefile).
    Copy,
    /// `path` renamed to `target`.
    Rename,
    /// Hard link `target` created on `path`: the same data under a new name.
    Link,
}

/// A process touched a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub at: DateTime<Utc>,
    pub process: ProcessRef,
    pub path: PathBuf,
    pub action: FileAction,
    /// Target for Copy, Rename and Link.
    #[serde(default)]
    pub target: Option<PathBuf>,
    /// (device, inode) of the file, if the sensor supplies it: detects hard links.
    #[serde(default)]
    pub inode: Option<(u64, u64)>,
    /// Number of hard links to the file; > 1 means there are further names.
    #[serde(default)]
    pub nlink: Option<u32>,
    /// Command line of the started program, for `Exec`, if the sensor can
    /// read it: the binary alone does not tell `rm -rf /data` from
    /// `rm /tmp/x`, and an agent's terminal command is joined on it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<String>,
}

/// A process sent data outward (delta since the last measurement).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetEvent {
    pub at: DateTime<Utc>,
    pub pid: u32,
    /// Parent process of the sender, if the sensor knows it.
    ///
    /// On a send, the correlator looks for the touch not only at the sender
    /// itself but also at its ancestors — but it knows the parent chain
    /// only from **file** events. A process that does nothing but send
    /// never shows up there, and the search ends immediately.
    ///
    /// That is exactly how an upload got through on 2026-09-08: the browser
    /// read the file from the share in PID 8112 and sent it out of PID 8952
    /// — a child of it that touched no file. The touch was on 8112, the
    /// question was asked about 8952, and the one edge in between was
    /// missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub process_name: String,
    pub remote: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

/// External volume mounted/removed (v2, the sensor already delivers it).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountEvent {
    pub at: DateTime<Utc>,
    pub mount_point: PathBuf,
    pub mounted: bool,
}

/// Process exited: forget the touch, the parent mapping and the identity,
/// so that a reused PID inherits nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitEvent {
    pub at: DateTime<Utc>,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    File(FileEvent),
    Net(NetEvent),
    /// A connection the network cage refused before its first byte (the
    /// macOS content filter). No sensor that counts bytes ever sees it.
    Refused(NetEvent),
    Mount(MountEvent),
    Exit(ExitEvent),
    /// An open the permission listener refused before the first byte
    /// (`FAN_OPEN_PERM` on Linux). `action` is `Open`.
    Blocked(FileEvent),
    /// What an AI agent (Hermes) asked a tool to do.
    Agent(AgentEvent),
    /// A verdict of the LLM guard (dlprevent-guard) on what went between an
    /// agent and its model: a prompt injection, secrets on their way out.
    Guard(GuardEvent),
}

/// One verdict line of the LLM guard. Metadata only, as the guard writes it:
/// rules and reasons, never the text they were found in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardEvent {
    pub at: DateTime<Utc>,
    /// `input` (the user's turn), `tool_result`, `tool_definition` (a tool
    /// the agent offers the model, by its description) or `output` (the
    /// model's answer and the tools it calls).
    pub direction: String,
    /// `flag`, `block` or `sanitize`, as the guard's engine judged it.
    pub verdict: String,
    /// Did the guard refuse the request? Only in its block mode.
    pub blocked: bool,
    pub model: Option<String>,
    /// The tool whose result or definition it was.
    pub origin: Option<String>,
    /// The rules that fired, strongest first as the guard lists them.
    pub rules: Vec<String>,
    /// The first rule's reason.
    pub reason: Option<String>,
}

/// One tool call of an AI agent, as its session log recorded it.
///
/// **Metadata only**: tool, command, path, query. Prompt and response stay
/// in the agent's own log — the DLP side must not become a second copy of
/// every conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEvent {
    /// The time the agent recorded, not the time the line was read.
    pub at: DateTime<Utc>,
    /// Session log name without its extension.
    pub session_id: String,
    /// `telegram`, `cli`, … — empty if the log does not say.
    pub platform: String,
    pub model: Option<String>,
    /// Who asked, labelled: `user <name> (<id>)` when the agent names the
    /// platform user (Hermes's database does), `account <name>` when only
    /// the home the log lies in is known — and a gateway serving many
    /// people runs under one account, so that is not the person.
    pub user: Option<String>,
    pub call_id: String,
    /// `function.name` of the call.
    pub tool: String,
    /// Shell command, for `terminal`.
    pub command: Option<String>,
    /// File or folder, for `read_file`, `write_file`, `patch`, `search_files`.
    pub path: Option<PathBuf>,
    /// Search text or URL, for `web_search`, `web_extract`.
    pub query: Option<String>,
}
