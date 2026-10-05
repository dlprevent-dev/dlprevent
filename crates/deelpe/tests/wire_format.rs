//! The JSON wire format between the service and its clients (CLI, menu bar
//! app) is a contract. These literals are the source of truth; the Swift
//! tests in apps/macos check the same strings.

use deelpe::ipc::{Request, Response, SensorState};
use deelpe_core::correlate::Alert;
use deelpe_core::identity::ProcessIdentity;
use deelpe_core::learn::Verdict;

#[test]
fn request_wire_format() {
    assert_eq!(
        serde_json::to_string(&Request::Alerts).unwrap(),
        r#""Alerts""#
    );
    assert_eq!(
        serde_json::to_string(&Request::AlertsAll).unwrap(),
        r#""AlertsAll""#
    );
    assert_eq!(
        serde_json::to_string(&Request::Status).unwrap(),
        r#""Status""#
    );
    assert_eq!(
        serde_json::to_string(&Request::WatchList).unwrap(),
        r#""WatchList""#
    );
    assert_eq!(
        serde_json::to_string(&Request::Show(7)).unwrap(),
        r#"{"Show":7}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::WatchAdd("/Users/me/Steuern".into())).unwrap(),
        r#"{"WatchAdd":"/Users/me/Steuern"}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::WatchRemove("/x".into())).unwrap(),
        r#"{"WatchRemove":"/x"}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::IgnoreAdd("com.apple.backupd".into())).unwrap(),
        r#"{"IgnoreAdd":"com.apple.backupd"}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::IgnoreRemove("team:ABC".into())).unwrap(),
        r#"{"IgnoreRemove":"team:ABC"}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::IgnoreList).unwrap(),
        r#""IgnoreList""#
    );
    assert_eq!(
        serde_json::to_string(&Request::LearnStatus).unwrap(),
        r#""LearnStatus""#
    );
    assert_eq!(
        serde_json::to_string(&Request::LearnConfirm).unwrap(),
        r#""LearnConfirm""#
    );
    assert_eq!(
        serde_json::to_string(&Request::LearnForget(
            "apple/com.apple.curl→1.2.3.0/24:443".into()
        ))
        .unwrap(),
        r#"{"LearnForget":"apple/com.apple.curl→1.2.3.0/24:443"}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::LearnRemember(7)).unwrap(),
        r#"{"LearnRemember":7}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::LearnFlag(7)).unwrap(),
        r#"{"LearnFlag":7}"#
    );
    assert_eq!(
        serde_json::to_string(&Request::LearnRestart).unwrap(),
        r#""LearnRestart""#
    );
    assert_eq!(
        serde_json::to_string(&Request::CentralStatus).unwrap(),
        r#""CentralStatus""#
    );
}

#[test]
fn central_wire_format() {
    use deelpe::central::CentralInfo;
    assert_eq!(
        serde_json::to_string(&Response::Central(None)).unwrap(),
        r#"{"Central":null}"#
    );
    let t0: chrono::DateTime<chrono::Utc> = "2026-09-06T10:00:00Z".parse().unwrap();
    let info = CentralInfo {
        url: "https://z:8444".into(),
        agent_id: "a1".into(),
        enrolled_at: Some(t0),
        last_ok: Some(t0),
        last_error: Some("Verbindung".into()),
        last_error_at: None,
        reports: 3,
        generation: 2,
        managed: vec!["/Users/me/GL".into()],
    };
    assert_eq!(
        serde_json::to_string(&Response::Central(Some(info))).unwrap(),
        r#"{"Central":{"url":"https://z:8444","agent_id":"a1","enrolled_at":"2026-09-06T10:00:00Z","last_ok":"2026-09-06T10:00:00Z","last_error":"Verbindung","last_error_at":null,"reports":3,"generation":2,"managed":["/Users/me/GL"]}}"#
    );
}

#[test]
fn learn_wire_format() {
    use deelpe_core::learn::{Learner, Verdict};
    let t0: chrono::DateTime<chrono::Utc> = "2026-09-05T15:44:45Z".parse().unwrap();
    let mut l = Learner::new(7, t0);
    let a = Alert {
        id: 1,
        at: t0,
        pid: 1,
        identity: ProcessIdentity::Signed {
            team_id: "apple".into(),
            signing_id: "com.apple.curl".into(),
        },
        files: vec![],
        remote: Some("100.59.99.192".parse().unwrap()),
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
        user: None,
    };
    l.judge(&a, true, t0);
    let json = serde_json::to_string(&Response::Learn(l.status(t0))).unwrap();
    let head = r#"{"Learn":{"phase":"learning","until":"2026-09-12T15:44:45Z","pairs":[{"key":"apple/com.apple.curl→100.59.99.0/24:443","process":"com.apple.curl","identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.curl"}},"destination":"100.59.99.0/24","port":443,"state":"candidate","count":1,"bytes_max":4096,"prev_max":0,"last_id":1,"first_seen":"2026-09-05T15:44:45Z","last_seen":"2026-09-05T15:44:45Z","hours":["#;
    assert!(json.starts_with(head), "{json}");
    l.confirm();
    assert!(serde_json::to_string(&Response::Learn(l.status(t0)))
        .unwrap()
        .starts_with(r#"{"Learn":{"phase":"active","until":null,"#));
}

#[test]
fn response_wire_format() {
    let alert = Alert {
        id: 1,
        at: "2026-09-05T15:44:45.179509Z".parse().unwrap(),
        pid: 39416,
        identity: ProcessIdentity::Signed {
            team_id: "apple".into(),
            signing_id: "com.apple.curl".into(),
        },
        files: vec!["/Users/me/Steuern/deelpe-test.bin".into()],
        remote: Some("100.59.99.192".parse().unwrap()),
        remote_port: Some(443),
        bytes_out: 201438,
        via: None,
        last_at: None,
        verdict: Verdict::New,
        reason: None,
        volume: None,
        copy_to: None,
        sender_read_directly: false,
        upload_url: None,
        user: None,
    };
    assert_eq!(
        serde_json::to_string(&Response::Alerts(vec![alert])).unwrap(),
        r#"{"Alerts":[{"id":1,"at":"2026-09-05T15:44:45.179509Z","pid":39416,"identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.curl"}},"files":["/Users/me/Steuern/deelpe-test.bin"],"remote":"100.59.99.192","remote_port":443,"bytes_out":201438,"verdict":"new"}]}"#
    );
    assert_eq!(
        serde_json::to_string(&Response::Status {
            touched: 5,
            alerts: 1,
            watched: 1,
            uptime_secs: 87,
            sensors: vec![
                SensorState {
                    name: "eslogger".into(),
                    error: Some("ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED".into())
                },
                SensorState {
                    name: "nettop".into(),
                    error: None
                },
            ],
            warnings: vec!["config.json changed outside the service".into()],
        })
        .unwrap(),
        r#"{"Status":{"touched":5,"alerts":1,"watched":1,"uptime_secs":87,"sensors":[{"name":"eslogger","error":"ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"},{"name":"nettop","error":null}],"warnings":["config.json changed outside the service"]}}"#
    );
    assert_eq!(
        serde_json::to_string(&Response::Watched(vec!["/Users/me/Steuern".into()])).unwrap(),
        r#"{"Watched":["/Users/me/Steuern"]}"#
    );
    assert_eq!(
        serde_json::to_string(&Response::Ok("x".into())).unwrap(),
        r#"{"Ok":"x"}"#
    );
    assert_eq!(
        serde_json::to_string(&Response::Alert(None)).unwrap(),
        r#"{"Alert":null}"#
    );
    assert_eq!(
        serde_json::to_string(&Response::Err("kaputt".into())).unwrap(),
        r#"{"Err":"kaputt"}"#
    );
    let unknown = Alert {
        id: 2,
        at: "2026-09-05T15:44:45Z".parse().unwrap(),
        pid: 1,
        identity: ProcessIdentity::Unknown {
            path: "/tmp/evil".into(),
        },
        files: vec![],
        remote: None,
        remote_port: None,
        bytes_out: 5,
        via: Some("read by com.apple.cat (PID 11), via copy /tmp/x".into()),
        last_at: None,
        verdict: Verdict::New,
        reason: None,
        volume: None,
        copy_to: None,
        sender_read_directly: false,
        upload_url: None,
        user: None,
    };
    // `via` is absent when it has no value (older log lines and clients stay valid).
    // A continued alert: `last_at` and the total in `bytes_out`.
    let updated = Alert {
        id: 3,
        last_at: Some("2026-09-05T15:50:00Z".parse().unwrap()),
        bytes_out: 9000,
        ..unknown.clone()
    };
    assert!(serde_json::to_string(&updated).unwrap().ends_with(r#""bytes_out":9000,"via":"read by com.apple.cat (PID 11), via copy /tmp/x","last_at":"2026-09-05T15:50:00Z","verdict":"new"}"#));
    assert_eq!(
        serde_json::to_string(&Response::Alerts(vec![unknown.clone()])).unwrap(),
        r#"{"Alerts":[{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5,"via":"read by com.apple.cat (PID 11), via copy /tmp/x","verdict":"new"}]}"#
    );
    assert_eq!(
        serde_json::to_string(&Response::Ignored(vec!["com.apple.backupd".into()])).unwrap(),
        r#"{"Ignored":["com.apple.backupd"]}"#
    );
    let old: Alert = serde_json::from_str(r#"{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5}"#).unwrap();
    assert_eq!(old.via, None);
    assert_eq!(old.last_at, None);
    // A volume as the target instead of the network.
    let usb = Alert {
        volume: Some("/Volumes/USB".into()),
        remote: None,
        remote_port: None,
        bytes_out: 0,
        via: Some("2 files written to volume /Volumes/USB, last /Volumes/USB/b.pdf".into()),
        ..unknown.clone()
    };
    assert!(serde_json::to_string(&usb)
        .unwrap()
        .ends_with(r#""verdict":"new","volume":"/Volumes/USB"}"#));
    let cp = Alert {
        copy_to: Some("/Users/me/Desktop".into()),
        remote: None,
        remote_port: None,
        bytes_out: 0,
        ..unknown.clone()
    };
    assert!(serde_json::to_string(&cp)
        .unwrap()
        .ends_with(r#""verdict":"new","copy_to":"/Users/me/Desktop"}"#));
    assert_eq!(old.verdict, Verdict::New);
    // Learning phase: verdict and reasoning.
    let dev = Alert {
        verdict: Verdict::Deviation,
        reason: Some("amount 5.0 MB is over 4× the usual maximum of 1.0 MB".into()),
        ..old.clone()
    };
    assert!(serde_json::to_string(&dev).unwrap().ends_with(
        r#""verdict":"deviation","reason":"amount 5.0 MB is over 4× the usual maximum of 1.0 MB"}"#
    ));
    let learning: Alert = serde_json::from_str(r#"{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5,"verdict":"learning"}"#).unwrap();
    assert_eq!(learning.verdict, Verdict::Learning);
}
