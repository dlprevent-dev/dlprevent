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
/// quoted, and inner quotes get doubled. A `;` or TAB is quoted too.
///
/// Quoting does not stop a spreadsheet from evaluating a cell that starts
/// with `=`, `+`, `-`, `@`, TAB or CR, and file names are attacker input. Such
/// a cell gets a leading `'`, which every spreadsheet reads as "text". A BOM,
/// zero-width character or space in front does not hide the trigger (an
/// import may trim spaces).
///
/// The same holds after every `;`, TAB and line break inside the value: a
/// spreadsheet set to `;` (the default list separator in a Swiss or German
/// locale) or TAB splits the row there, and it only honours a quote at the
/// start of a field, so our quotes around a later cell do not hold it
/// together. What follows the split is a new cell and gets the same check.
fn csv_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 1);
    let mut mark = Some(0);
    for c in s.chars() {
        if let Some(m) = mark.filter(|_| !matches!(c, '\u{feff}' | '\u{200b}' | '\u{200c}' | '\u{200d}' | ' ')) {
            if matches!(c, '=' | '+' | '-' | '@' | '\t' | '\r') {
                out.insert(m, '\'');
            }
            mark = None;
        }
        out.push(c);
        if matches!(c, ';' | '\t' | '\n' | '\r') {
            mark = Some(out.len());
        }
    }
    let s = out;
    if s.contains([',', '"', '\n', '\r', ';', '\t']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn json(alerts: &[Alert]) -> Result<String> {
    Ok(serde_json::to_string_pretty(alerts)?)
}
