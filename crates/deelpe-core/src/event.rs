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
}
