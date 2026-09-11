//! CSV and JSON for `deelpe export`. The menu bar app produces the same
//! CSV columns, see AlertExport in Swift.

use deelpe::export;
use deelpe_core::correlate::Alert;
use deelpe_core::identity::ProcessIdentity;
use deelpe_core::learn::Verdict;

fn alerts() -> Vec<Alert> {
    vec![
        Alert {
            id: 1,
            at: "2026-09-05T15:44:45.179509Z".parse().unwrap(),
            pid: 39416,
            identity: ProcessIdentity::Signed { team_id: "apple".into(), signing_id: "com.apple.curl".into() },
            files: vec!["/Users/me/Steuern/a, \"b\".pdf".into(), "/Users/me/Steuern/c.txt".into()],
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
        },
        Alert {
            id: 2,
            at: "2026-09-05T15:44:45Z".parse().unwrap(),
            pid: 1,
            identity: ProcessIdentity::Unknown { path: "/tmp/evil\nx".into() },
            files: vec![],
            remote: None,
            remote_port: None,
            bytes_out: 5,
            via: Some("read by com.apple.cat (PID 11)".into()),
            last_at: None,
            verdict: Verdict::Deviation,
            reason: Some("amount 5 B is over 4× the usual maximum of 1 B".into()),
            volume: None,
            copy_to: None,
            sender_read_directly: false,
            upload_url: None,
        },
    ]
}

#[test]
fn csv_has_header_and_escapes() {
    let out = export::csv(&alerts());
    let mut lines = out.lines();
    assert_eq!(lines.next().unwrap(), export::CSV_HEADER);
    assert_eq!(
        lines.next().unwrap(),
        r#"1,2026-09-05T15:44:45.179509Z,com.apple.curl,com.apple.curl (Team apple),39416,100.59.99.192,443,201438,"/Users/me/Steuern/a, ""b"".pdf; /Users/me/Steuern/c.txt",,new,"#
    );
    // A line break in the path stays inside the quoted field, the row does
    // not break.
    let rest: Vec<&str> = lines.collect();
    assert_eq!(rest.join("\n"), "2,2026-09-05T15:44:45Z,\"evil\nx\",\"/tmp/evil\nx [unsigned]\",1,,,5,,read by com.apple.cat (PID 11),deviation,amount 5 B is over 4× the usual maximum of 1 B");
    assert!(out.ends_with('\n'));
}

#[test]
fn csv_empty_is_header_only() {
    assert_eq!(export::csv(&[]), format!("{}\n", export::CSV_HEADER));
}

#[test]
fn json_is_pretty_array_in_wire_format() {
    let out = export::json(&alerts()).unwrap();
    let back: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back[0]["identity"]["Signed"]["signing_id"], "com.apple.curl");
    assert_eq!(back[1]["remote"], serde_json::Value::Null);
    assert!(out.contains('\n'), "lesbar formatiert");
}
