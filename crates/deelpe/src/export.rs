//! Export of the alerts as CSV or JSON (`deelpe export`). The menu bar app
//! writes the same CSV columns.

use anyhow::Result;
use deelpe_core::correlate::Alert;

pub const CSV_HEADER: &str = "id,time,process,identity,pid,destination,port,bytes_out,files,via,verdict,reason";

pub fn csv(alerts: &[Alert]) -> String {
    let mut out = String::from(CSV_HEADER);
    out.push('\n');
    for a in alerts {
        let fields = [
            a.id.to_string(),
            a.at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
            a.identity.short(),
            a.identity.to_string(),
            a.pid.to_string(),
            a.remote.map(|r| r.to_string()).unwrap_or_default(),
            a.remote_port.map(|p| p.to_string()).unwrap_or_default(),
            a.bytes_out.to_string(),
            a.files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>().join("; "),
            a.via.clone().unwrap_or_default(),
            serde_json::to_value(a.verdict).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default(),
            a.reason.clone().unwrap_or_default(),
        ];
        out.push_str(&fields.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// RFC 4180: fields containing a comma, a quote or a line break get
/// quoted, and inner quotes get doubled.
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn json(alerts: &[Alert]) -> Result<String> {
    Ok(serde_json::to_string_pretty(alerts)?)
}
