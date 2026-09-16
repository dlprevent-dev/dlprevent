//! The wire format between agent and central server is a contract (like
//! tests/wire_format.rs in the service). These literals are the source of
//! truth for every agent, including the later Windows agent.

use deelpe_core::access::AccessVerdict;
use deelpe_core::central::*;

#[test]
fn enroll_wire_format() {
    let r = EnrollRequest { api_version: 1, token: "abc".into(), hostname: "mac-1".into(), kind: AgentKind::Mac, version: "0.1.0".into(), csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n".into() };
    assert_eq!(
        serde_json::to_string(&r).unwrap(),
        r#"{"api_version":1,"token":"abc","hostname":"mac-1","kind":"mac","version":"0.1.0","csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n"}"#
    );
    for (k, s) in [(AgentKind::Mac, "\"mac\""), (AgentKind::Linux, "\"linux\""), (AgentKind::WindowsServer, "\"windows_server\""), (AgentKind::WindowsClient, "\"windows_client\"")] {
        assert_eq!(serde_json::to_string(&k).unwrap(), s);
    }
    let resp: EnrollResponse = serde_json::from_str(r#"{"agent_id":"6a0f","cert_pem":"c","ca_pem":"a"}"#).unwrap();
    assert_eq!(resp.agent_id, "6a0f");
}

/// Renewal: the agent sends only a CSR, its identity sits in the client
/// certificate of the connection. The answer is the new certificate together
/// with its expiry, so the agent knows when its turn comes round again.
#[test]
fn renew_wire_format() {
    let r = RenewRequest { api_version: 1, csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n".into() };
    assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"api_version":1,"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n"}"#);
    let resp: RenewResponse =
        serde_json::from_str(r#"{"cert_pem":"c","not_after":"2028-09-06T10:00:00Z"}"#).unwrap();
    assert_eq!(resp.cert_pem, "c");
    assert_eq!(resp.not_after.to_rfc3339(), "2028-09-06T10:00:00+00:00");
}

#[test]
fn user_ref_keys() {
    let u = UserRef { source: "NAS01".into(), name: "Hans".into(), domain: None, sid: None };
    assert_eq!(u.key(), "nas01\\hans");
    assert_eq!(u.display(), "Hans");
    assert_eq!(serde_json::to_string(&u).unwrap(), r#"{"source":"NAS01","name":"Hans"}"#);
    let u = UserRef { source: "srv".into(), name: "hans".into(), domain: Some("DOM".into()), sid: Some("S-1-5-21-1".into()) };
    assert_eq!(u.key(), "sid:S-1-5-21-1");
    assert_eq!(u.display(), "DOM\\hans");
}

#[test]
fn report_wire_format() {
    let t0: chrono::DateTime<chrono::Utc> = "2026-09-06T10:00:00Z".parse().unwrap();
    let r = Report {
        api_version: Some(1),
        generation: None,
        status: None,
        alerts: vec![],
        access_alerts: vec![AccessAlert {
            external_id: "access:r1:nas01\\hans:1757152800".into(),
            at: t0,
            last_at: None,
            user: UserRef { source: "nas01".into(), name: "hans".into(), domain: None, sid: None },
            rule_id: Some("r1".into()),
            path: "GL".into(),
            files: 101,
            bytes: 2048,
            sample_files: vec!["/volume1/GL/a.docx".into()],
            client_ip: Some("10.0.0.5".into()),
            verdict: AccessVerdict::HardLimit { files: 101, limit: 100 },
            reason: None,
        }],
        counts: vec![CountBucket { rule_id: None, path: "GL".into(), user: UserRef { source: "nas01".into(), name: "hans".into(), domain: None, sid: None }, bucket: t0, files: 3, bytes: 10 }],
                groups: None,
        learn_done: vec![],
        log: vec![],
    };
    assert_eq!(
        serde_json::to_string(&r).unwrap(),
        r#"{"api_version":1,"alerts":[],"access_alerts":[{"external_id":"access:r1:nas01\\hans:1757152800","at":"2026-09-06T10:00:00Z","user":{"source":"nas01","name":"hans"},"rule_id":"r1","path":"GL","files":101,"bytes":2048,"sample_files":["/volume1/GL/a.docx"],"client_ip":"10.0.0.5","verdict":{"kind":"hard_limit","files":101,"limit":100}}],"counts":[{"path":"GL","user":{"source":"nas01","name":"hans"},"bucket":"2026-09-06T10:00:00Z","files":3,"bytes":10}]}"#
    );
    // An empty report is valid (a pure sign of life), even without a version:
    // older agents should be allowed to keep reporting.
    let empty: Report = serde_json::from_str("{}").unwrap();
    assert!(empty.alerts.is_empty() && empty.status.is_none() && empty.api_version.is_none());
    // And without `generation` — that is exactly what "send me the rules"
    // means. An agent of an older build may know nothing about it and still
    // has to get its rules.
    assert_eq!(empty.generation, None);

    // If it does report one, it goes over the wire as a plain number.
    let r = Report { generation: Some(57), ..Default::default() };
    assert_eq!(
        serde_json::to_string(&r).unwrap(),
        r#"{"api_version":1,"generation":57,"alerts":[],"access_alerts":[],"counts":[]}"#
    );
    assert_eq!(serde_json::from_str::<Report>(r#"{"generation":57}"#).unwrap().generation, Some(57));
}

#[test]
fn config_wire_format() {
    let c = AgentConfig {
        api_version: 1,
        generation: 4,
        report_interval_secs: 30,
        learn_days: 7,
        rules: vec![Rule { id: "r1".into(), name: "GL".into(), path: "/Volumes/GL".into(), allowed_groups: vec!["GL-Mitglieder".into()], lockdown: false, allow_destinations: vec!["10.0.0.7:443".into()], strict: true, enforce: true, hard_max_files: 100, window_secs: 60, ad_lock: false, enabled: true }],
        allow_processes: Vec::new(),
        update_to_sha256: None,
        finish_learning: false,
    };
    assert_eq!(
        serde_json::to_string(&c).unwrap(),
        r#"{"api_version":1,"generation":4,"report_interval_secs":30,"learn_days":7,"rules":[{"id":"r1","name":"GL","path":"/Volumes/GL","allowed_groups":["GL-Mitglieder"],"lockdown":false,"allow_destinations":["10.0.0.7:443"],"strict":true,"enforce":true,"hard_max_files":100,"window_secs":60,"ad_lock":false,"enabled":true}]}"#
    );
    // An empty allowlist does not appear in the answer: the line above still
    // holds byte for byte, and an agent from before the field can read it.
    let with_allow = AgentConfig { allow_processes: vec!["teams.exe".into()], ..c.clone() };
    assert!(serde_json::to_string(&with_allow).unwrap().contains(r#""allow_processes":["teams.exe"]"#));

    // The same for the update order: without it the answer looks as it did
    // before (the line above), with it the checksum is in there. An agent from
    // before the field reads both.
    let with_update = AgentConfig { update_to_sha256: Some("ab".repeat(32)), ..c };
    assert!(serde_json::to_string(&with_update).unwrap().contains(&format!(r#""update_to_sha256":"{}""#, "ab".repeat(32))));
    let old: AgentConfig = serde_json::from_str(
        r#"{"api_version":1,"generation":1,"report_interval_secs":30,"learn_days":7,"rules":[]}"#,
    )
    .unwrap();
    assert_eq!(old.update_to_sha256, None, "an answer without the field orders no update");
    // The learning order: absent unless set, and an answer without it ends
    // no learning phase.
    let finish = AgentConfig { finish_learning: true, ..old.clone() };
    assert!(serde_json::to_string(&finish).unwrap().contains(r#""finish_learning":true"#));
    assert!(!old.finish_learning);

    let r: Rule = serde_json::from_str(r#"{"id":"x","name":"n","path":"/p","hard_max_files":5,"window_secs":10}"#).unwrap();
    assert!(r.enabled && !r.lockdown && r.allowed_groups.is_empty());
    // Older central servers do not know the strict folder: no strict, no
    // allowlist, no intervention.
    assert!(!r.strict && !r.enforce && r.allow_destinations.is_empty());
    for (v, s) in [
        (AccessVerdict::Ok, r#"{"kind":"ok"}"#),
        (AccessVerdict::Learning, r#"{"kind":"learning"}"#),
        (AccessVerdict::NoProfile, r#"{"kind":"no_profile"}"#),
        (AccessVerdict::Deviation { files: 40, baseline: 5 }, r#"{"kind":"deviation","files":40,"baseline":5}"#),
    ] {
        assert_eq!(serde_json::to_string(&v).unwrap(), s);
    }
}

/// Learning instructions: the central server silences a pair without anybody
/// sitting at the device. Both directions are additional fields with defaults
/// — an agent from before still talks along, it just learns nothing new.
#[test]
fn learn_wire_format() {
    let c = LearnCommand { id: 7, alert_id: 42, action: LearnAction::Remember };
    assert_eq!(serde_json::to_string(&c).unwrap(), r#"{"id":7,"alert_id":42,"action":"remember"}"#);
    assert_eq!(serde_json::to_string(&LearnAction::Flag).unwrap(), r#""flag""#);

    // An answer without instructions looks the way it always did.
    let resp: ReportResponse = serde_json::from_str(
        r#"{"accepted_alerts":0,"accepted_access_alerts":0,"accepted_counts":0,"config":{"api_version":1,"generation":1,"report_interval_secs":30,"learn_days":7,"rules":[]}}"#,
    )
    .unwrap();
    assert!(resp.learn.is_empty());

    // The agent ticks off what it has carried out; with no open instruction
    // the field is missing from the report entirely.
    let r = Report { learn_done: vec![7, 8], ..Default::default() };
    assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"api_version":1,"alerts":[],"access_alerts":[],"counts":[],"learn_done":[7,8]}"#);
    assert!(!serde_json::to_string(&Report::default()).unwrap().contains("learn_done"));
}

/// Log lines are part of the contract: the agent writes them, the central
/// server shows them in the dashboard. A report without lines does not carry
/// the field at all — older agents do not send it, and an empty field in every
/// report would be pure noise on the wire.
#[test]
fn log_lines_wire_format() {
    let t0: chrono::DateTime<chrono::Utc> = "2026-09-08T10:00:00Z".parse().unwrap();
    let r = Report {
        log: vec![LogLine { at: t0, level: "warn".into(), target: "deelpe_winagent::client".into(), msg: "report not accepted".into() }],
        ..Default::default()
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(
        json.contains(r#""log":[{"at":"2026-09-08T10:00:00Z","level":"warn","target":"deelpe_winagent::client","msg":"report not accepted"}]"#),
        "{json}"
    );
    assert!(!serde_json::to_string(&Report::default()).unwrap().contains("log"), "leeres Protokoll gehoert nicht in den Bericht");
    // An agent on an old build does not send the field; that must not make
    // the report fail.
    let old: Report = serde_json::from_str(r#"{"api_version":1}"#).unwrap();
    assert!(old.log.is_empty());
}
