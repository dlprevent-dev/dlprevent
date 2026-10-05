//! Enrollment and reporting against a running central server, mTLS
//! included. Only runs when DEELPE_TEST_CENTRAL_URL, _TOKEN and _CA are set
//! (see docs/SERVER.md, section Entwicklung); otherwise silently skipped.

use deelpe::central::{enroll, Client};
use deelpe_core::central::Report;
use deelpe_core::correlate::Alert;
use deelpe_core::identity::ProcessIdentity;

#[tokio::test]
async fn enroll_and_report() {
    let (Ok(url), Ok(token), Ok(ca)) = (
        std::env::var("DEELPE_TEST_CENTRAL_URL"),
        std::env::var("DEELPE_TEST_CENTRAL_TOKEN"),
        std::env::var("DEELPE_TEST_CENTRAL_CA"),
    ) else {
        eprintln!("übersprungen: DEELPE_TEST_CENTRAL_* nicht gesetzt");
        return;
    };
    // Wrong fingerprint: nothing happens.
    let bad = enroll(&url, &token, &"0".repeat(64), "test-host", "0.0.0").await;
    assert!(bad.unwrap_err().to_string().contains("Fingerabdruck"));

    let cfg = enroll(&url, &token, &ca, "test-host", "0.0.0")
        .await
        .expect("Aufnahme");
    assert!(cfg.cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(cfg.key_pem.contains("PRIVATE KEY"));

    // The token is burned.
    let again = enroll(&url, &token, &ca, "test-host-2", "0.0.0").await;
    let msg = again.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(msg.contains("verwendet"), "{msg}");

    let client = Client::new(&cfg.credentials()).expect("Client");
    let now = chrono::Utc::now();
    let a = Alert {
        id: 4242,
        at: now,
        pid: 7,
        identity: ProcessIdentity::Signed {
            team_id: "apple".into(),
            signing_id: "com.apple.curl".into(),
        },
        files: vec!["/Users/test/GL/Budget.xlsx".into()],
        remote: Some("203.0.113.9".parse().unwrap()),
        remote_port: Some(443),
        bytes_out: 123_456,
        via: None,
        last_at: None,
        verdict: deelpe_core::learn::Verdict::New,
        reason: None,
        volume: None,
        copy_to: None,
        sender_read_directly: false,
        upload_url: None,
        user: None,
    };
    let resp = client
        .report(&Report {
            api_version: Some(1),
            generation: None,
            status: None,
            alerts: vec![a.clone()],
            access_alerts: vec![],
            counts: vec![],
            groups: None,
            learn_done: vec![],
            log: vec![],
            roaming: None,
        })
        .await
        .expect("Bericht");
    assert_eq!(resp.accepted_alerts, 1);
    assert!(resp.config.generation >= 1);
    assert!(
        resp.config.rules.iter().any(|r| r.path == "GL"),
        "Regel GL aus dem Dashboard erwartet"
    );
    // Continuation of the same alert.
    let mut a2 = a;
    a2.bytes_out = 999_999;
    a2.last_at = Some(now);
    let resp = client
        .report(&Report {
            api_version: Some(1),
            generation: None,
            status: None,
            alerts: vec![a2],
            access_alerts: vec![],
            counts: vec![],
            groups: None,
            learn_done: vec![],
            log: vec![],
            roaming: None,
        })
        .await
        .unwrap();
    assert_eq!(resp.accepted_alerts, 1);

    // Renewal: a new certificate over the existing connection, without a
    // token. Afterwards both the new one and — during the grace period —
    // the old one must still be able to report; the latter is the way back
    // for an agent whose save went wrong.
    let (cert_pem, key_pem, not_after) = client.renew("test-host").await.expect("Erneuerung");
    assert!(cert_pem.contains("BEGIN CERTIFICATE"));
    assert!(key_pem.contains("PRIVATE KEY"));
    assert!(
        not_after > chrono::Utc::now(),
        "neues Zertifikat läuft schon ab: {not_after}"
    );
    assert_ne!(cert_pem, cfg.cert_pem, "Zertifikat unverändert");

    let renewed = deelpe_core::net::Credentials {
        cert_pem,
        key_pem,
        ..cfg.credentials()
    };
    let fresh = Client::new(&renewed).expect("Client mit neuem Zertifikat");
    fresh
        .report(&Report::default())
        .await
        .expect("Bericht mit neuem Zertifikat");
    client
        .report(&Report::default())
        .await
        .expect("altes Zertifikat gilt in der Gnadenfrist weiter");

    eprintln!("ok: Agent {}", cfg.agent_id);
}

/// The service's state file (`central.json`) lives on disk. Since
/// 2026-09-08 the four report counters are a shared `Tally`, but `flatten`
/// has to keep the file byte-for-byte the same — otherwise an updated
/// service reports in as "never heard from" and the central server sees it
/// as mute.
#[test]
fn the_state_file_keeps_its_shape_across_the_tally() {
    use deelpe::central::CentralState;

    let old = r#"{"generation":3,"managed":[],"sent":{},"reports":17,
                  "last_ok":"2026-09-08T10:00:00Z","last_error":"boom",
                  "last_error_at":"2026-09-08T09:00:00Z","learn_done":[]}"#;
    let st: CentralState = serde_json::from_str(old).expect("alte central.json lesbar");
    assert_eq!(st.generation, 3);
    assert_eq!(st.tally.reports, 17);
    assert_eq!(st.tally.last_error.as_deref(), Some("boom"));

    let back: serde_json::Value = serde_json::to_value(&st).unwrap();
    for k in [
        "generation",
        "reports",
        "last_ok",
        "last_error",
        "last_error_at",
    ] {
        assert!(
            back.get(k).is_some(),
            "{k} fehlt auf oberster Ebene: {back}"
        );
    }
    assert!(
        back.get("tally").is_none(),
        "die Zahlen duerfen nicht verschachtelt werden: {back}"
    );
}
