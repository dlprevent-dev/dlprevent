//! Alerts survive a restart of the service: one JSON line per alert, read
//! back in at startup, old entries get pruned.

use chrono::{Duration, Utc};
use deelpe::alertlog::AlertLog;
use deelpe_core::correlate::Alert;
use deelpe_core::identity::ProcessIdentity;
use deelpe_core::learn::Verdict;
use std::os::unix::fs::PermissionsExt;

fn alert(id: u64, age_days: i64) -> Alert {
    Alert {
        id,
        at: Utc::now() - Duration::days(age_days),
        pid: 1,
        identity: ProcessIdentity::Unknown { path: "/tmp/x".into() },
        files: vec!["/Users/me/Steuern/a.pdf".into()],
        remote: Some("1.2.3.4".parse().unwrap()),
        remote_port: Some(443),
        bytes_out: 4096,
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

#[test]
fn appends_and_reloads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join("alerts.jsonl");
    {
        let mut log = AlertLog::open(&path, 365).unwrap();
        assert!(log.alerts().is_empty());
        assert_eq!(log.next_id(), 1);
        log.append(&alert(1, 0)).unwrap();
        log.append(&alert(2, 0)).unwrap();
    }
    let log = AlertLog::open(&path, 365).unwrap();
    assert_eq!(log.alerts().iter().map(|a| a.id).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(log.next_id(), 3);
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Dateinamen sind sensibel, nur Root liest das Protokoll");
}

#[test]
fn skips_broken_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    let good = serde_json::to_string(&alert(5, 0)).unwrap();
    std::fs::write(&path, format!("{good}\nkaputt\n\n{{\"id\":9}}\n")).unwrap();
    let log = AlertLog::open(&path, 365).unwrap();
    assert_eq!(log.alerts().len(), 1);
    assert_eq!(log.next_id(), 6);
    assert!(std::fs::read_to_string(&path).unwrap().contains("kaputt"), "unlesbare Zeilen bleiben erhalten");
}

#[test]
fn tightens_mode_of_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    AlertLog::open(&path, 365).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}


#[test]
fn zero_retention_keeps_everything() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    {
        let mut log = AlertLog::open(&path, 0).unwrap();
        log.append(&alert(1, 4000)).unwrap();
    }
    assert_eq!(AlertLog::open(&path, 0).unwrap().alerts().len(), 1);
}

#[test]
fn prunes_old_entries_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    {
        let mut log = AlertLog::open(&path, 30).unwrap();
        log.append(&alert(1, 40)).unwrap();
        log.append(&alert(2, 10)).unwrap();
    }
    let log = AlertLog::open(&path, 30).unwrap();
    assert_eq!(log.alerts().iter().map(|a| a.id).collect::<Vec<_>>(), vec![2]);
    // IDs keep counting up even when the highest entry was pruned.
    assert_eq!(log.next_id(), 3);
    let lines = std::fs::read_to_string(&path).unwrap().lines().count();
    assert_eq!(lines, 1, "Datei wird beim Stutzen neu geschrieben");
}

#[test]
fn update_replaces_by_id_and_compacts_on_reload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("alerts.jsonl");
    {
        let mut log = AlertLog::open(&path, 365).unwrap();
        log.append(&alert(1, 0)).unwrap();
        log.append(&alert(2, 0)).unwrap();
        let mut grown = alert(1, 0);
        grown.bytes_out = 99_000;
        log.update(&grown).unwrap();
        assert_eq!(log.alerts().len(), 2);
        assert_eq!(log.alerts()[0].bytes_out, 99_000, "an Ort und Stelle ersetzt");
    }
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3, "angehängt, nicht umgeschrieben");
    let log = AlertLog::open(&path, 365).unwrap();
    assert_eq!(log.alerts().iter().map(|a| (a.id, a.bytes_out)).collect::<Vec<_>>(), vec![(1, 99_000), (2, 4096)]);
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2, "beim Start kompaktiert");
}
