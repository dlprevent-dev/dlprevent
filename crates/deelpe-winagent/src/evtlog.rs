//! Reading the security log through the Windows Event Log API.
//!
//! Two events, cross-checked on the real machine (2026-09-06, Windows Server
//! 2025) — the planning was off on two counts here:
//!
//! * **5145** carries the work on SMB. It sits in the subcategory
//!   **"Detailed File Share"**, not in "File Share" (which yields 5140, once
//!   per share connection). It names the user with SID, the **client IP**,
//!   the local path of the share (`ShareLocalPath`), the file relative to it
//!   and the access mask — all in one event. Joining over the logon ID is
//!   therefore unnecessary.
//! * **4663** covers local access on the server (console, RDP). On SMB it
//!   **never** carries `FILE_READ_DATA`, only attribute accesses (`0x80`,
//!   `0x8`, `0x20000`) — whoever filters on that sees nothing.
//!
//! Counting carries on over the `EventRecordID`, not over time: no time
//! zones, no clock drift, no accesses counted twice.

use anyhow::{bail, Context, Result};

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RawEvent {
    pub event_id: u32,
    pub record_id: u64,
    pub data: HashMap<String, String>,
}

impl RawEvent {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.data.get(k).map(|s| s.as_str()).filter(|s| !s.is_empty() && *s != "-")
    }
}

/// Elsewhere there is no security log. The parser on top of it is checked
/// all the same; only the reading itself needs Windows.
#[cfg(not(windows))]
pub fn read_since(_after: u64, _limit: usize) -> Result<Vec<RawEvent>> {
    Ok(Vec::new())
}

/// Fetches up to `limit` events with `EventRecordID > after`.
#[cfg(windows)]
pub fn read_since(after: u64, limit: usize) -> Result<Vec<RawEvent>> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        EvtClose, EvtNext, EvtQuery, EvtQueryChannelPath, EvtQueryForwardDirection, EvtRender, EvtRenderEventXml, EVT_HANDLE,
    };

    let query = format!("*[System[(EventID=4663 or EventID=5145) and (EventRecordID>{after})]]");
    let channel = HSTRING::from("Security");
    let q = HSTRING::from(query.as_str());
    let flags = EvtQueryChannelPath.0 | EvtQueryForwardDirection.0;
    let h = unsafe { EvtQuery(None, PCWSTR(channel.as_ptr()), PCWSTR(q.as_ptr()), flags) }
        .context("query the security event log (account needs \"Event Log Readers\" or administrator)")?;

    let mut out = Vec::new();
    let mut buf = vec![0u16; 64 * 1024];
    loop {
        let mut events: [isize; 32] = [0; 32];
        let mut got: u32 = 0;
        let more = unsafe { EvtNext(h, &mut events, 2000, 0, &mut got) };
        if more.is_err() || got == 0 {
            break;
        }
        for raw in events.iter().take(got as usize) {
            let e = EVT_HANDLE(*raw);
            let mut used: u32 = 0;
            let mut props: u32 = 0;
            let r = unsafe {
                EvtRender(
                    None,
                    e,
                    EvtRenderEventXml.0,
                    (buf.len() * 2) as u32,
                    Some(buf.as_mut_ptr() as *mut _),
                    &mut used,
                    &mut props,
                )
            };
            if r.is_ok() {
                let n = (used as usize / 2).saturating_sub(1).min(buf.len());
                let xml = String::from_utf16_lossy(&buf[..n]);
                match parse_event(&xml) {
                    Ok(ev) => out.push(ev),
                    Err(e) => tracing::debug!("event not understood: {e:#}"),
                }
            }
            unsafe { let _ = EvtClose(e); }
        }
        if out.len() >= limit {
            break;
        }
    }
    unsafe { let _ = EvtClose(h); }
    out.sort_by_key(|e| e.record_id);
    Ok(out)
}

/// Windows event XML: `System` carries EventID and EventRecordID,
/// `EventData` a list of `<Data Name="…">value</Data>`.
pub fn parse_event(xml: &str) -> Result<RawEvent> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut r = Reader::from_str(xml);
    r.config_mut().trim_text(true);
    let mut event_id = 0u32;
    let mut record_id = 0u64;
    let mut data = HashMap::new();
    let mut cur: Option<String> = None;
    let mut in_system_field: Option<&'static str> = None;

    loop {
        match r.read_event().context("XML")? {
            Event::Start(t) => match t.name().as_ref() {
                "EventID" => in_system_field = Some("EventID"),
                "EventRecordID" => in_system_field = Some("EventRecordID"),
                "Data" => {
                    cur = t
                        .attributes()
                        .flatten()
                        .find(|a| a.key.as_ref() == "Name")
                        .map(|a| a.value.to_string());
                }
                _ => {}
            },
            Event::Text(t) => {
                let v = quick_xml::escape::unescape(&t.xml10_content()).context("XML entities")?.into_owned();
                match in_system_field.take() {
                    Some("EventID") => event_id = v.trim().parse().unwrap_or(0),
                    Some("EventRecordID") => record_id = v.trim().parse().unwrap_or(0),
                    _ => {
                        if let Some(name) = cur.take() {
                            data.insert(name, v);
                        }
                    }
                }
            }
            Event::End(t) => {
                if t.name().as_ref() == "Data" {
                    // An empty <Data Name="x"/> would otherwise leave the name behind.
                    if let Some(name) = cur.take() {
                        data.entry(name).or_default();
                    }
                }
                in_system_field = None;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if event_id == 0 {
        bail!("no EventID");
    }
    Ok(RawEvent { event_id, record_id, data })
}

/// Access mask from the log (`0x1`, `0x20089`, occasionally decimal).
pub fn parse_mask(s: &str) -> u32 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(h, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// `FILE_READ_DATA`. Reading is what the access counter counts — as in the
/// NAS path of the central.
pub const FILE_READ_DATA: u32 = 0x0001;
/// `FILE_WRITE_DATA` and `FILE_APPEND_DATA`. Writing says nothing about
/// mass access; it is the only sign the server gets that something is
/// landing in the folder. Whether the file is *new* is a question only the
/// file itself answers, see [`deelpe_core::inbound`].
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;

/// Removes an alternate data stream (`datei.dat:AFP_AfpInfo`).
///
/// macOS clients put metadata down as a stream next to the file over SMB.
/// Without this every file counts twice and the folder itself counts as an
/// additional "file" — the emergency brake then trips too early, and the
/// alert carries names nobody recognises as a file.
///
/// The colon of the drive letter stays untouched: the search happens only in
/// the last path component.
pub fn strip_stream(path: &str) -> &str {
    let cut = path.rfind('\\').map(|i| i + 1).unwrap_or(0);
    // If there is no backslash in front of it, the first colon is the drive
    // letter and not a data stream.
    let b = path.as_bytes();
    let skip = usize::from(cut == 0 && b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic()) * 2;
    match path[cut + skip..].find(':') {
        // Stream on the folder itself: what is meant is the folder.
        Some(0) if cut > 0 => path[..cut - 1].trim_end_matches('\\'),
        Some(i) => &path[..cut + skip + i],
        None => path,
    }
}

/// Full local path out of a 5145: `ShareLocalPath` carries the NT prefix
/// `\??\`, `RelativeTargetName` the rest.
pub fn share_path(share_local: &str, relative: &str) -> String {
    let base = share_local.trim_start_matches(r"\??\").trim_end_matches('\\');
    let rel = relative.trim_start_matches('\\');
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{base}\\{rel}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const E4663: &str = r#"<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4663</EventID><EventRecordID>4711</EventRecordID></System>
<EventData>
<Data Name="SubjectUserSid">S-1-5-21-1-2-3-1108</Data>
<Data Name="SubjectUserName">dl-anna</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x3e7abc</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Freigaben\GL\Zahlen\Zahlen-001.dat</Data>
<Data Name="AccessMask">0x1</Data>
<Data Name="ProcessName">System</Data>
</EventData></Event>"#;

    #[test]
    fn reads_system_fields_and_data() {
        let e = parse_event(E4663).unwrap();
        assert_eq!(e.event_id, 4663);
        assert_eq!(e.record_id, 4711);
        assert_eq!(e.get("SubjectUserName"), Some("dl-anna"));
        assert_eq!(e.get("ObjectName"), Some(r"C:\Freigaben\GL\Zahlen\Zahlen-001.dat"));
        assert_eq!(parse_mask(e.get("AccessMask").unwrap()) & FILE_READ_DATA, FILE_READ_DATA);
    }

    #[test]
    fn dash_counts_as_absent() {
        let xml = E4663.replace("<Data Name=\"SubjectDomainName\">CORP</Data>", "<Data Name=\"SubjectDomainName\">-</Data>");
        assert_eq!(parse_event(&xml).unwrap().get("SubjectDomainName"), None);
    }

    #[test]
    fn strips_alternate_data_streams() {
        assert_eq!(strip_stream(r"C:\Freigaben\GL\Zahlen\a.dat:AFP_AfpInfo"), r"C:\Freigaben\GL\Zahlen\a.dat");
        assert_eq!(strip_stream(r"C:\Freigaben\GL\a.dat:Zone.Identifier:$DATA"), r"C:\Freigaben\GL\a.dat");
        // Stream on the folder itself — observed with macOS clients.
        assert_eq!(strip_stream(r"C:\Freigaben\GL\:AFP_AfpInfo"), r"C:\Freigaben\GL");
        // The drive colon must not count as a data stream.
        assert_eq!(strip_stream(r"C:\Freigaben\GL"), r"C:\Freigaben\GL");
        assert_eq!(strip_stream("C:"), "C:");
    }

    #[test]
    fn composes_local_path_from_share_event() {
        assert_eq!(
            share_path(r"\??\C:\Freigaben\GL", r"Protokolle\Protokolle-030.dat"),
            r"C:\Freigaben\GL\Protokolle\Protokolle-030.dat"
        );
        // Access to the share root itself.
        assert_eq!(share_path(r"\??\C:\Freigaben\GL", ""), r"C:\Freigaben\GL");
        // Without the NT prefix (happens with some kinds of share).
        assert_eq!(share_path(r"D:\Daten", r"a\b.txt"), r"D:\Daten\a\b.txt");
    }

    /// Observed on the real machine: on SMB a 4663 never says 0x1.
    #[test]
    fn smb_attribute_masks_are_not_reads() {
        for m in ["0x80", "0x8", "0x20000"] {
            assert_eq!(parse_mask(m) & FILE_READ_DATA, 0, "{m}");
        }
        // The mask from a real 5145, on the other hand, does.
        assert_eq!(parse_mask("0x120089") & FILE_READ_DATA, FILE_READ_DATA);
    }

    /// The mask of a 5145 for writing. Whoever filters on
    /// `FILE_READ_DATA` alone sees a file being put into the share and
    /// discards the event.
    #[test]
    fn a_write_mask_is_recognised_next_to_the_read_mask() {
        let m = parse_mask("0x120116");
        assert_eq!(m & FILE_READ_DATA, 0);
        assert_ne!(m & (FILE_WRITE_DATA | FILE_APPEND_DATA), 0);
        // Read and write at once — Word opens a document that way.
        let rw = parse_mask("0x12019f");
        assert_ne!(rw & FILE_READ_DATA, 0);
        assert_ne!(rw & FILE_WRITE_DATA, 0);
    }

    #[test]
    fn masks_in_both_notations() {
        assert_eq!(parse_mask("0x20089") & FILE_READ_DATA, 1);
        assert_eq!(parse_mask("2") & FILE_READ_DATA, 0);
    }
}
