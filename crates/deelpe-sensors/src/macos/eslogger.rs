//! File access via Apple's `eslogger` (Endpoint Security without an
//! entitlement of our own). Needs root and "Full Disk Access".

use crate::Sensor;
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use deelpe_core::event::{Event, ExitEvent, FileAction, FileEvent, MountEvent, ProcessRef};
use deelpe_core::identity::ProcessIdentity;
use serde_json::Value;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

pub struct EsLogger {
    pub events: Vec<&'static str>,
}

impl Default for EsLogger {
    fn default() -> Self {
        Self {
            events: vec![
                "open", "exec", "copyfile", "clone", "rename", "link", "exit", "mount", "unmount",
            ],
        }
    }
}

#[async_trait]
impl Sensor for EsLogger {
    fn name(&self) -> &'static str {
        "eslogger"
    }

    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> Result<()> {
        let mut child = Command::new("/usr/bin/eslogger")
            .args(&self.events)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("start eslogger (needs root plus Full Disk Access)")?;
        let stdout = child.stdout.take().context("eslogger stdout")?;
        let stderr = child.stderr.take().context("eslogger stderr")?;
        let err_task = tokio::spawn(async move {
            let mut buf = String::new();
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                tracing::debug!(target: "eslogger", "{l}");
                buf.push_str(&l);
                buf.push('\n');
            }
            buf
        });
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await? {
            match parse_line(&line) {
                Some(ev) => {
                    if tx.send(ev).await.is_err() {
                        break;
                    }
                }
                None => {
                    tracing::trace!(target: "eslogger", "ignoriert: {}", &line[..line.len().min(120)])
                }
            }
        }
        let status = child.wait().await?;
        let err = err_task.await.unwrap_or_default();
        let hint = if err.contains("NOT_PERMITTED") {
            "\nHint: the program that starts `deelpe daemon` (Terminal, iTerm or similar) is missing \
             \"Full Disk Access\" under System Settings > Privacy & Security. \
             Restart the terminal after granting it."
        } else if err.contains("NOT_PRIVILEGED") {
            "\nHint: `deelpe daemon` must run with sudo."
        } else {
            ""
        };
        bail!("eslogger beendet: {status}\n{}{hint}", err.trim_end())
    }
}

/// Translate one JSON line from eslogger into an event. Tolerant of
/// missing fields, because Apple extends the schema without warning.
pub fn parse_line(line: &str) -> Option<Event> {
    let v: Value = serde_json::from_str(line).ok()?;
    let event = v.get("event")?;
    let at = Utc::now();

    if let Some(m) = event.get("mount") {
        return Some(Event::Mount(MountEvent {
            at,
            mount_point: mount_point(m)?,
            mounted: true,
        }));
    }
    if let Some(m) = event.get("unmount") {
        return Some(Event::Mount(MountEvent {
            at,
            mount_point: mount_point(m)?,
            mounted: false,
        }));
    }

    let process = v.get("process")?;
    if event.get("exit").is_some() {
        let pid = process.get("audit_token")?.get("pid")?.as_u64()? as u32;
        return Some(Event::Exit(ExitEvent { at, pid }));
    }
    if let Some(e) = event.get("exec") {
        // `process` is the image from before the exec (the shell); the new
        // program's identity is in `target`. PID and PPID are the same.
        let target = e
            .get("target")
            .and_then(process_ref)
            .or_else(|| process_ref(process))?;
        let path = target.path.clone();
        return Some(Event::File(FileEvent {
            at,
            process: target,
            path,
            action: FileAction::Exec,
            target: None,
            inode: None,
            nlink: None,
            argv: None,
        }));
    }
    let process = process_ref(process)?;
    let (path, action, target, file) = if let Some(o) = event.get("open") {
        // A folder opened is a listing, not content: a file dialog opens
        // every one it shows.
        if o.get("file")
            .and_then(|f| f.get("stat"))
            .and_then(|s| s.get("st_mode"))
            .and_then(Value::as_u64)
            .is_some_and(|m| m & 0o170000 == 0o040000)
        {
            return None;
        }
        // fflag in FFLAGS format (sys/fcntl.h): FREAD 1, FWRITE 2.
        let writes = o
            .get("fflag")
            .and_then(Value::as_u64)
            .map_or(false, |f| f & 2 != 0);
        (
            str_at(o, &["file", "path"])?,
            if writes {
                FileAction::Write
            } else {
                FileAction::Open
            },
            None,
            o.get("file"),
        )
    } else if let Some(c) = event.get("copyfile").or_else(|| event.get("clone")) {
        (
            str_at(c, &["source", "path"])?,
            FileAction::Copy,
            copy_target(c),
            c.get("source"),
        )
    } else if let Some(r) = event.get("rename") {
        (
            str_at(r, &["source", "path"])?,
            FileAction::Rename,
            rename_target(r),
            r.get("source"),
        )
    } else if let Some(l) = event.get("link") {
        let target = Some(
            PathBuf::from(str_at(l, &["target_dir", "path"])?)
                .join(str_at(l, &["target_filename"])?),
        );
        (
            str_at(l, &["source", "path"])?,
            FileAction::Link,
            target,
            l.get("source"),
        )
    } else {
        return None;
    };
    let (inode, nlink) = file.map(stat_of).unwrap_or((None, None));
    Some(Event::File(FileEvent {
        at,
        process,
        path: PathBuf::from(path),
        action,
        target,
        inode,
        nlink,
        argv: None,
    }))
}

/// (device, inode) and link count from the `stat` of an es_file_t.
fn stat_of(file: &Value) -> (Option<(u64, u64)>, Option<u32>) {
    let st = match file.get("stat") {
        Some(s) => s,
        None => return (None, None),
    };
    let dev = st.get("st_dev").and_then(Value::as_u64);
    let ino = st.get("st_ino").and_then(Value::as_u64);
    let nlink = st.get("st_nlink").and_then(Value::as_u64).map(|n| n as u32);
    (dev.zip(ino), nlink)
}

/// copyfile/clone: `target_file` is set when the target already exists,
/// otherwise directory plus name.
fn copy_target(c: &Value) -> Option<PathBuf> {
    str_at(c, &["target_file", "path"])
        .map(PathBuf::from)
        .or_else(|| {
            Some(
                PathBuf::from(str_at(c, &["target_dir", "path"])?)
                    .join(str_at(c, &["target_name"])?),
            )
        })
}

fn rename_target(r: &Value) -> Option<PathBuf> {
    str_at(r, &["destination", "existing_file", "path"])
        .map(PathBuf::from)
        .or_else(|| {
            Some(
                PathBuf::from(str_at(r, &["destination", "new_path", "dir", "path"])?)
                    .join(str_at(r, &["destination", "new_path", "filename"])?),
            )
        })
}

fn mount_point(m: &Value) -> Option<PathBuf> {
    str_at(m, &["statfs", "f_mntonname"]).map(PathBuf::from)
}

fn process_ref(p: &Value) -> Option<ProcessRef> {
    let pid = p.get("audit_token")?.get("pid")?.as_u64()? as u32;
    let ppid = p.get("ppid").and_then(Value::as_u64).map(|x| x as u32);
    let responsible = p
        .get("responsible_audit_token")
        .and_then(|t| t.get("pid"))
        .and_then(Value::as_u64)
        .map(|x| x as u32);
    let path = str_at(p, &["executable", "path"])?;
    let signing_id = p
        .get("signing_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let team_id = p
        .get("team_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let platform = p
        .get("is_platform_binary")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let identity = if !signing_id.is_empty() && (!team_id.is_empty() || platform) {
        ProcessIdentity::Signed {
            team_id: if platform && team_id.is_empty() {
                "apple".into()
            } else {
                team_id
            },
            signing_id,
        }
    } else {
        ProcessIdentity::Unknown { path: path.clone() }
    };
    Some(ProcessRef {
        pid,
        ppid,
        responsible,
        path: PathBuf::from(path),
        identity,
    })
}

fn str_at(v: &Value, keys: &[&str]) -> Option<String> {
    let mut cur = v;
    for k in keys {
        cur = cur.get(k)?;
    }
    cur.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file dialog opens every folder it shows: those are names, not
    /// content, and listed as touched files they buried the one file that
    /// was picked (LibreWolf and Gemini, 2026-09-16).
    #[test]
    fn opening_a_directory_is_no_file_event() {
        let open = |mode: u32| {
            format!(
                r#"{{"event":{{"open":{{"fflag":1,"file":{{"path":"/Users/me/Steuern/x","stat":{{"st_mode":{mode},"st_dev":1,"st_ino":2,"st_nlink":1}}}}}}}},"process":{{"audit_token":{{"pid":42}},"ppid":1,"executable":{{"path":"/usr/bin/curl"}},"signing_id":"com.apple.curl","team_id":"","is_platform_binary":true}}}}"#
            )
        };
        assert!(parse_line(&open(0o040755)).is_none(), "a directory");
        assert!(
            matches!(parse_line(&open(0o100644)), Some(Event::File(_))),
            "a regular file"
        );
    }

    #[test]
    fn parses_open() {
        let line = r#"{"event":{"open":{"file":{"path":"/Users/me/Steuern/a.pdf"}}},"process":{"audit_token":{"pid":42},"ppid":1,"executable":{"path":"/usr/bin/curl"},"signing_id":"com.apple.curl","team_id":"","is_platform_binary":true}}"#;
        match parse_line(line) {
            Some(Event::File(f)) => {
                assert_eq!(f.process.pid, 42);
                assert_eq!(f.path, PathBuf::from("/Users/me/Steuern/a.pdf"));
                assert!(matches!(f.process.identity, ProcessIdentity::Signed { .. }));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unsigned_is_unknown() {
        let line = r#"{"event":{"open":{"file":{"path":"/x"}}},"process":{"audit_token":{"pid":1},"executable":{"path":"/tmp/evil"},"signing_id":"","team_id":""}}"#;
        match parse_line(line) {
            Some(Event::File(f)) => assert!(matches!(
                f.process.identity,
                ProcessIdentity::Unknown { .. }
            )),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn open_for_write_is_write() {
        let line = r#"{"event":{"open":{"fflag":3,"file":{"path":"/tmp/out.zip"}}},"process":{"audit_token":{"pid":42},"ppid":1,"executable":{"path":"/usr/bin/zip"},"signing_id":"com.apple.zip","team_id":"","is_platform_binary":true}}"#;
        match parse_line(line) {
            Some(Event::File(f)) => assert_eq!(f.action, FileAction::Write),
            other => panic!("{other:?}"),
        }
        let ro = r#"{"event":{"open":{"fflag":1,"file":{"path":"/tmp/out.zip"}}},"process":{"audit_token":{"pid":42},"ppid":1,"executable":{"path":"/usr/bin/zip"},"signing_id":"com.apple.zip","team_id":"","is_platform_binary":true}}"#;
        assert!(matches!(parse_line(ro), Some(Event::File(f)) if f.action == FileAction::Open));
    }

    #[test]
    fn exec_carries_target_identity() {
        let line = r#"{"event":{"exec":{"target":{"audit_token":{"pid":12},"ppid":10,"executable":{"path":"/usr/bin/curl"},"signing_id":"com.apple.curl","team_id":"","is_platform_binary":true}}},"process":{"audit_token":{"pid":12},"ppid":10,"executable":{"path":"/bin/zsh"},"signing_id":"com.apple.zsh","team_id":"","is_platform_binary":true}}"#;
        match parse_line(line) {
            Some(Event::File(f)) => {
                assert_eq!(f.action, FileAction::Exec);
                assert_eq!(f.process.pid, 12);
                assert_eq!(f.process.ppid, Some(10));
                assert_eq!(f.process.identity.short(), "com.apple.curl");
                assert_eq!(f.path, PathBuf::from("/usr/bin/curl"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn copyfile_and_clone_have_targets() {
        let existing = r#"{"event":{"copyfile":{"source":{"path":"/Users/me/Steuern/a.pdf"},"target_file":{"path":"/tmp/x.pdf"},"target_dir":{"path":"/tmp"},"target_name":"x.pdf"}},"process":{"audit_token":{"pid":5},"ppid":1,"executable":{"path":"/bin/cp"},"signing_id":"com.apple.cp","team_id":"","is_platform_binary":true}}"#;
        match parse_line(existing) {
            Some(Event::File(f)) => {
                assert_eq!(f.action, FileAction::Copy);
                assert_eq!(f.target, Some(PathBuf::from("/tmp/x.pdf")));
            }
            other => panic!("{other:?}"),
        }
        let fresh = r#"{"event":{"clone":{"source":{"path":"/Users/me/Steuern/a.pdf"},"target_dir":{"path":"/tmp"},"target_name":"y.pdf"}},"process":{"audit_token":{"pid":5},"ppid":1,"executable":{"path":"/bin/cp"},"signing_id":"com.apple.cp","team_id":"","is_platform_binary":true}}"#;
        assert!(
            matches!(parse_line(fresh), Some(Event::File(f)) if f.action == FileAction::Copy && f.target == Some(PathBuf::from("/tmp/y.pdf")))
        );
    }

    #[test]
    fn rename_targets_both_forms() {
        let new_path = r#"{"event":{"rename":{"source":{"path":"/tmp/x.pdf"},"destination_type":"new_path","destination":{"new_path":{"dir":{"path":"/tmp"},"filename":"harmless.txt"}}}},"process":{"audit_token":{"pid":5},"ppid":1,"executable":{"path":"/bin/mv"},"signing_id":"com.apple.mv","team_id":"","is_platform_binary":true}}"#;
        assert!(
            matches!(parse_line(new_path), Some(Event::File(f)) if f.action == FileAction::Rename && f.target == Some(PathBuf::from("/tmp/harmless.txt")))
        );
        let existing = r#"{"event":{"rename":{"source":{"path":"/tmp/x.pdf"},"destination_type":"existing_file","destination":{"existing_file":{"path":"/tmp/old.txt"}}}},"process":{"audit_token":{"pid":5},"ppid":1,"executable":{"path":"/bin/mv"},"signing_id":"com.apple.mv","team_id":"","is_platform_binary":true}}"#;
        assert!(
            matches!(parse_line(existing), Some(Event::File(f)) if f.target == Some(PathBuf::from("/tmp/old.txt")))
        );
    }

    #[test]
    fn responsible_process_is_read() {
        // Safari network process: parent is launchd, responsible is Safari (PID 500).
        let line = r#"{"event":{"open":{"fflag":1,"file":{"path":"/Users/me/Steuern/a.pdf"}}},"process":{"audit_token":{"pid":510},"ppid":1,"responsible_audit_token":{"pid":500},"executable":{"path":"/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking"},"signing_id":"com.apple.WebKit.Networking","team_id":"","is_platform_binary":true}}"#;
        match parse_line(line) {
            Some(Event::File(f)) => {
                assert_eq!(f.process.ppid, Some(1));
                assert_eq!(f.process.responsible, Some(500));
            }
            other => panic!("{other:?}"),
        }
        // Without the field (older message version): None, not an error.
        let line = r#"{"event":{"open":{"file":{"path":"/x"}}},"process":{"audit_token":{"pid":1},"ppid":1,"executable":{"path":"/tmp/evil"},"signing_id":"","team_id":""}}"#;
        assert!(
            matches!(parse_line(line), Some(Event::File(f)) if f.process.responsible.is_none())
        );
    }

    #[test]
    fn parses_link_and_stat() {
        let line = r#"{"event":{"link":{"source":{"path":"/Users/me/Steuern/a.pdf","stat":{"st_dev":16777234,"st_ino":4711,"st_nlink":2}},"target_dir":{"path":"/tmp"},"target_filename":"h"}},"process":{"audit_token":{"pid":5},"ppid":1,"executable":{"path":"/bin/ln"},"signing_id":"com.apple.ln","team_id":"","is_platform_binary":true}}"#;
        match parse_line(line) {
            Some(Event::File(f)) => {
                assert_eq!(f.action, FileAction::Link);
                assert_eq!(f.target, Some(PathBuf::from("/tmp/h")));
                assert_eq!(f.inode, Some((16777234, 4711)));
                assert_eq!(f.nlink, Some(2));
            }
            other => panic!("{other:?}"),
        }
        let open = r#"{"event":{"open":{"fflag":1,"file":{"path":"/tmp/h","stat":{"st_dev":16777234,"st_ino":4711,"st_nlink":2}}}},"process":{"audit_token":{"pid":6},"ppid":1,"executable":{"path":"/usr/bin/curl"},"signing_id":"com.apple.curl","team_id":"","is_platform_binary":true}}"#;
        assert!(
            matches!(parse_line(open), Some(Event::File(f)) if f.inode == Some((16777234, 4711)) && f.nlink == Some(2))
        );
    }

    #[test]
    fn parses_exit() {
        let line = r#"{"event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":77},"ppid":1,"executable":{"path":"/bin/cat"},"signing_id":"com.apple.cat","team_id":"","is_platform_binary":true}}"#;
        assert!(matches!(parse_line(line), Some(Event::Exit(e)) if e.pid == 77));
    }

    #[test]
    fn parses_mount() {
        let line = r#"{"event":{"mount":{"statfs":{"f_mntonname":"/Volumes/USB"}}},"process":{}}"#;
        assert!(matches!(parse_line(line), Some(Event::Mount(m)) if m.mounted));
    }
}
