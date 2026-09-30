//! The browser asks **before** it sends.
//!
//! Firefox (from 137 on) and Chrome speak the same protocol: Google's Content
//! Analysis SDK. Before an upload, a paste from the clipboard or a print job
//! the browser sends a request to a named pipe and **waits for the verdict**
//! before it carries the action out.
//!
//! This is the only intervention in this program where there is no race.
//! Everything else reports after the bytes are gone: event tracing delivers a
//! touch a median of 1.5 s after the read, and the browser's connection to the
//! destination has been up since the tab loaded anyway. See ADR 0002.
//!
//! **Why the pipe lives under `ProtectedPrefix\Administrators\`.** The SDK
//! knows two forms: `\\.\pipe\<name>.<SID>` for a per-user agent, and
//! `\\.\pipe\ProtectedPrefix\Administrators\<name>` for one with
//! administrator rights. Only an administrator may create anything there —
//! that is the protection against some arbitrary user process passing itself
//! off as the DLP agent and waving everything through. We are a service
//! running as LocalSystem, so the second form applies, and for that Firefox
//! needs `IsPerUser: false` in the `ContentAnalysis` policy.

use anyhow::Result;
// `Context` is used only by the named pipe, and that exists only on Windows.
#[cfg(windows)]
use anyhow::Context;
use chrono::{DateTime, Utc};
use deelpe_core::config::Config;
use deelpe_core::correlate::Alert;
use deelpe_core::identity::ProcessIdentity;
use deelpe_core::learn::Verdict;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Name of the pipe the browser policy has to point at. It lives here so
/// that service and policy can never drift apart.
pub const PIPE_NAME: &str = "deelpe";

/// `TriggeredRule.Action`
const ACTION_BLOCK: u64 = 3;
/// `Result.Status`
const STATUS_SUCCESS: u64 = 1;

/// This is how much a single message takes. On a paste the whole text is in
/// it, not just a path — hence generous. The pipe runs in message mode: what
/// does not fit into the buffer does not arrive half, it does not arrive at
/// all, and that would be a silent failure.
const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// This is how long the destination URL may get. It comes out of a browser's
/// address bar, so from outside, and it ends up in an alert, in the central
/// and in a table cell of the dashboard. A destination nobody can read any
/// more is not a better report — and the message may be four megabytes large.
/// 2048 is the limit browsers and servers keep to as well; the hostname is at
/// the front and stays in.
const MAX_URL: usize = 2048;

// ---------------------------------------------------------------------------
// Protobuf, only as much as needed
// ---------------------------------------------------------------------------
//
// Deliberately without a library. There are five fields to read and three
// nested messages to write; a code generator in the mingw cross build costs
// more friction than it carries here. The field numbers come from the SDK's
// `proto/content_analysis/sdk/analysis.proto` and are noted at every access,
// so they can be followed without that file at hand.

/// A step counter over a protobuf message. Returns `None` as soon as
/// something no longer adds up — truncated, overlong, unknown wire type. A
/// browser is a trust boundary here like any other.
struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, i: 0 }
    }

    fn done(&self) -> bool {
        self.i >= self.b.len()
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.b.get(self.i)?;
            self.i += 1;
            v |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.varint()?).ok()?;
        let end = self.i.checked_add(len)?;
        let out = self.b.get(self.i..end)?;
        self.i = end;
        Some(out)
    }

    /// Next field as (number, wire type). Skips nothing — the caller does
    /// that via [`Reader::skip`].
    fn key(&mut self) -> Option<(u64, u64)> {
        let k = self.varint()?;
        Some((k >> 3, k & 7))
    }

    /// Pass over a field whose number does not interest us.
    fn skip(&mut self, wire: u64) -> Option<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            1 => self.i = self.i.checked_add(8).filter(|e| *e <= self.b.len())?,
            2 => {
                self.bytes()?;
            }
            5 => self.i = self.i.checked_add(4).filter(|e| *e <= self.b.len())?,
            // 3 and 4 are the abolished groups, 6 and 7 do not exist.
            _ => return None,
        }
        Some(())
    }
}

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn put_len_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    put_varint(out, (field << 3) | 2);
    put_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn put_varint_field(out: &mut Vec<u8>, field: u64, v: u64) {
    put_varint(out, (field << 3) | 0);
    put_varint(out, v);
}

/// What the browser asks us.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Request {
    /// Passed through raw: the answer has to carry the same token, otherwise
    /// the browser does not match it up.
    pub token: Vec<u8>,
    /// `AnalysisConnector`: attach, paste, print …
    pub connector: u64,
    /// Destination URL out of `ContentMetaData`.
    pub url: Option<String>,
    /// On an upload the path of the file; empty on a paste.
    pub file_path: Option<PathBuf>,
    /// On a paste the content itself is in the request. We only remember
    /// **that** it was text — keeping the text would mean storing the user's
    /// clipboard contents.
    pub has_text: bool,
}

/// What arrives on the pipe.
///
/// The browser does **not** send the bare `ContentAnalysisRequest` but the
/// envelope `ChromeToAgent` — and inside it acknowledgements and
/// cancellations too, not just questions. Leave the envelope out and every
/// message reads as empty and gets answered with an empty token; the browser
/// then matches the answer to no question and waits until the timeout. That
/// is exactly how it sat in the lab on 2026-09-08.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// A question. This is the only thing that gets an answer.
    Ask(Request),
    /// Acknowledgement or cancellation. Noted, no answer.
    Note,
}

/// Read `ChromeToAgent`. `None` means: not readable.
pub fn parse_message(buf: &[u8]) -> Option<Incoming> {
    let mut r = Reader::new(buf);
    let mut out = None;
    while !r.done() {
        let (field, wire) = r.key()?;
        match (field, wire) {
            // ChromeToAgent.request = 1
            (1, 2) => out = Some(Incoming::Ask(parse_request(r.bytes()?)?)),
            // ack = 2, cancel = 3
            (2, 2) | (3, 2) => {
                r.bytes()?;
                out = out.or(Some(Incoming::Note));
            }
            _ => r.skip(wire)?,
        }
    }
    out
}

/// Read the inner `ContentAnalysisRequest`.
fn parse_request(buf: &[u8]) -> Option<Request> {
    let mut r = Reader::new(buf);
    let mut req = Request::default();
    while !r.done() {
        let (field, wire) = r.key()?;
        match (field, wire) {
            // request_token = 5
            (5, 2) => req.token = r.bytes()?.to_vec(),
            // analysis_connector = 9
            (9, 0) => req.connector = r.varint()?,
            // request_data = 10 (ContentMetaData), url = 1 inside it
            (10, 2) => {
                let mut inner = Reader::new(r.bytes()?);
                while !inner.done() {
                    let (f, w) = inner.key()?;
                    match (f, w) {
                        (1, 2) => {
                            let mut url = String::from_utf8_lossy(inner.bytes()?).into_owned();
                            url.truncate(
                                url.char_indices()
                                    .nth(MAX_URL)
                                    .map_or(url.len(), |(i, _)| i),
                            );
                            req.url = Some(url);
                        }
                        _ => inner.skip(w)?,
                    }
                }
            }
            // content_data is a oneof: text_content = 13, file_path = 14
            (13, 2) => {
                r.bytes()?;
                req.has_text = true;
            }
            (14, 2) => {
                req.file_path = Some(PathBuf::from(
                    String::from_utf8_lossy(r.bytes()?).into_owned(),
                ))
            }
            _ => r.skip(wire)?,
        }
    }
    Some(req)
}

/// Build the `ContentAnalysisResponse`.
///
/// Allowing means: a result with status `SUCCESS` and **no** triggered rule.
/// An empty `results` would not be a yes but an answer without a statement —
/// depending on the setting the browser treats it as an error.
pub fn response(token: &[u8], block: Option<&str>) -> Vec<u8> {
    let mut result = Vec::new();
    // Result.tag = 1 — the name the browser shows the rule under.
    put_len_field(&mut result, 1, b"dlp");
    // Result.status = 2
    put_varint_field(&mut result, 2, STATUS_SUCCESS);
    if let Some(rule) = block {
        let mut triggered = Vec::new();
        // TriggeredRule.action = 1
        put_varint_field(&mut triggered, 1, ACTION_BLOCK);
        // TriggeredRule.rule_name = 2 — shown in the browser's notice window.
        put_len_field(&mut triggered, 2, rule.as_bytes());
        // Result.triggered_rules = 3
        put_len_field(&mut result, 3, &triggered);
    }

    let mut resp = Vec::new();
    // ContentAnalysisResponse.request_token = 1
    put_len_field(&mut resp, 1, token);
    // ContentAnalysisResponse.results = 4
    put_len_field(&mut resp, 4, &result);

    // And the envelope around it: AgentToChrome.response = 1.
    let mut out = Vec::new();
    put_len_field(&mut out, 1, &resp);
    out
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// A drive letter is not a different place — here for the second time.
///
/// The sensor converts kernel paths (`deelpe_sensors::winpath`); the browser
/// on the other hand names the path to us the way the user sees it:
/// `G:\Zahlen\Zahlen-004.dat`. At the endpoint the rule reads
/// `\\fs-01\GL`, and the letter does not match that. On 2026-09-08
/// that let through every upload picked via the mapped drive instead of via
/// the UNC path — and that is the normal case, because handing out the
/// letters is exactly what the group policy is for.
///
/// The mapping lives in `HKU\<SID>\Network\<letter>\RemotePath`, and **the
/// SID belongs to the browser, not to us**: network drives hang off the logon
/// session, the service runs as LocalSystem and has no `G:` of its own. So we
/// take the SID of the asking process — known, because its PID is looked up
/// at the pipe anyway.
fn splice(remote: &str, rest: &str) -> PathBuf {
    let mut s = remote.trim_end_matches('\\').to_string();
    s.push_str(rest);
    PathBuf::from(s)
}

/// Splits `G:\rest` into letter and remainder. `None` if there is no drive
/// letter there.
fn drive_of(path: &Path) -> Option<(char, String)> {
    let s = path.to_string_lossy();
    let mut it = s.chars();
    let letter = it.next()?;
    if !letter.is_ascii_alphabetic() || it.next()? != ':' {
        return None;
    }
    Some((letter.to_ascii_uppercase(), s[2..].to_string()))
}

/// Trace the answer of `QueryDosDeviceW` back to a share.
///
/// Two forms occur, depending on the Windows version:
///
/// | answer | means |
/// |---|---|
/// | `\Device\LanmanRedirector\;G:0000…\srv\GL` | `\\srv\GL` |
/// | `\??\UNC\srv\GL` | `\\srv\GL` |
///
/// [`deelpe_sensors::winpath::to_user_path`] already knows the first one — it
/// throws away the `;G:…` sections, which belong to the mapping and not to
/// the place. The second one is here because it comes out of this query and
/// not out of event tracing.
///
/// `None` means: no network drive. Then the browser's path stays as it is —
/// with a local drive it is the right one already anyway.
fn nt_to_share(nt: &str) -> Option<String> {
    let trimmed = nt.trim_end_matches('\0');
    for p in [r"\??\UNC\", r"\\?\UNC\"] {
        if let Some(rest) = trimmed.strip_prefix(p) {
            return Some(format!(r"\\{rest}"));
        }
    }
    let user = deelpe_sensors::winpath::to_user_path(trimmed, &std::collections::HashMap::new());
    user.starts_with(r"\\").then_some(user)
}

/// Trace the browser's path back to the share, if it came via a network
/// drive.
///
/// **Why this is necessary.** The sensor converts kernel paths; the browser
/// names the path to us the way the user sees it: `G:\Zahlen\a.dat`. At the
/// endpoint the rule reads `\\fs-01\GL`, and the letter does not match
/// that. On 2026-09-08 that let through every upload picked via the mapped
/// drive — so the normal case, because handing out the letters is exactly
/// what the group policy is for.
///
/// **Why via the browser's session and not out of the registry.** Tried
/// first: `HKU\<SID>\Network\<letter>\RemotePath`. On the test client there
/// is **nothing** there — the group policy's mappings do not end up in the
/// registry, and the resolution would silently never have taken hold. A drive
/// letter belongs to the logon session, not to the machine: the service runs
/// as LocalSystem and has no `G:` of its own.
///
/// [`ImpersonateNamedPipeClient`] lends us the user at the other end of the
/// pipe for two calls — device table included. `QueryDosDeviceW` then answers
/// with the kernel form, and that one
/// [`deelpe_sensors::winpath::to_user_path`] already knows: it throws away the
/// `;G:…` sections, which belong to the mapping and not to the place.
///
/// Between impersonating and reverting there must be **no `await`** — the
/// task could switch threads and take the identity along. Hence synchronous
/// and in one piece.
#[cfg(windows)]
fn on_the_share(pipe: &tokio::net::windows::named_pipe::NamedPipeServer, path: &Path) -> PathBuf {
    use std::os::windows::io::AsRawHandle;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::RevertToSelf;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows::Win32::System::Pipes::ImpersonateNamedPipeClient;

    let Some((letter, rest)) = drive_of(path) else {
        return path.to_path_buf();
    };
    let drive = HSTRING::from(format!("{letter}:"));
    let mut buf = [0u16; 1024];
    let n = unsafe {
        if ImpersonateNamedPipeClient(HANDLE(pipe.as_raw_handle())).is_err() {
            return path.to_path_buf();
        }
        let n = QueryDosDeviceW(PCWSTR(drive.as_ptr()), Some(&mut buf));
        let _ = RevertToSelf();
        n
    };
    if n == 0 {
        return path.to_path_buf();
    }
    let nt = String::from_utf16_lossy(&buf[..n as usize]);
    let Some(base) = nt_to_share(&nt) else {
        return path.to_path_buf();
    };
    let full = splice(&base, &rest);
    tracing::debug!("content analysis: {} is {}", path.display(), full.display());
    full
}

/// Forbidden? And if so, with what reason for the notice window.
///
/// Two questions, in this order: does the file lie in a strict folder that
/// enforces — and is the destination on that folder's allow list?
///
/// **Only** this layer can ask the second one. On the network path there is
/// just an IP, and the service resolves no names; here the browser supplies
/// the destination URL along with it. So here the name counts, and that is
/// why `chatgpt.com` may stand next to `10.0.0.7` in the dashboard — see
/// [`deelpe_core::allow`]. That keeps an AI service the operator trusts
/// usable while everything else is shut.
pub fn verdict(cfg: &Config, req: &Request) -> Option<String> {
    let file = req.file_path.as_ref()?;
    let strict = cfg.strict_for(file)?;
    if !strict.enforce {
        return None;
    }
    if req
        .url
        .as_deref()
        .is_some_and(|u| deelpe_core::allow::allows_host(&strict.allow, u))
    {
        return None;
    }
    Some(format!(
        "{} may not leave {}",
        file.display(),
        strict.path.display()
    ))
}

// ---------------------------------------------------------------------------
// The report to the central
// ---------------------------------------------------------------------------

/// A block, the way the central is meant to learn of it.
///
/// Until 2026-09-08 a block wrote only a log line. **Nothing** of it was to
/// be seen in the dashboard — of all things from the one intervention that
/// takes effect before the bytes are gone. Whoever only looks at the
/// dashboard saw a silent agent and took it for idle.
#[derive(Debug, Clone)]
pub struct Blocked {
    pub at: DateTime<Utc>,
    pub pid: u32,
    pub identity: ProcessIdentity,
    /// The file in the strict folder, already traced back to the share.
    pub file: PathBuf,
    /// Destination URL, if the browser sent one along.
    pub url: Option<String>,
    /// The SDK's `AnalysisConnector` — which action was intercepted.
    pub connector: u64,
    /// Reason out of [`verdict`], word for word the one in the notice window.
    /// When letting through, this says **why** nothing was blocked.
    pub reason: String,
    /// Was the action refused? `false` means: seen and let through. An upload
    /// out of a watched folder is worth a line even then — otherwise "never
    /// asked" looks like "asked and allowed" in the dashboard, and whoever
    /// has set no block sees nothing at all of their outflows.
    pub blocked: bool,
}

/// `AnalysisConnector` out of `analysis.proto`, for humans.
fn connector_name(c: u64) -> &'static str {
    match c {
        1 => "download",
        2 => "upload",
        3 => "paste",
        4 => "print",
        5 => "file transfer",
        _ => "browser action",
    }
}

/// Build the alert that goes to the central out of a block.
///
/// `Denied`, like every violation of a strict folder: never learned, never
/// silenced. No destination in the network sense — there is no IP but the
/// name the browser supplies (ADR 0002), and that goes in `upload_url`. And
/// `sender_read_directly` stays false: the browser asked and got a no, so
/// killing it afterwards prevents nothing.
pub fn alert_for(b: &Blocked, id: u64) -> Alert {
    Alert {
        id,
        at: b.at,
        pid: b.pid,
        identity: b.identity.clone(),
        files: vec![b.file.clone()],
        remote: None,
        remote_port: None,
        bytes_out: 0,
        via: None,
        last_at: None,
        // Let through is not an alert: `New` appears in the table and in the
        // dashboard but sets off no mail (see `mail::ALARM_VERDICTS`).
        verdict: if b.blocked {
            Verdict::Denied
        } else {
            Verdict::New
        },
        reason: Some(if b.blocked {
            format!(
                "{} blocked before sending: {}",
                connector_name(b.connector),
                b.reason
            )
        } else {
            format!("{} allowed: {}", connector_name(b.connector), b.reason)
        }),
        volume: None,
        copy_to: None,
        sender_read_directly: false,
        upload_url: b.url.clone(),
    }
}

/// The same action as already reported? A browser that asks again after the
/// no should not flood the list — then `last_at` grows instead of the table.
/// The same promise as in the correlator: one alert per sender, destination
/// and touch.
pub fn same_action(a: &Alert, b: &Blocked) -> bool {
    a.pid == b.pid && a.upload_url == b.url && a.files.first().is_some_and(|f| f == &b.file)
}

// ---------------------------------------------------------------------------
// The pipe
// ---------------------------------------------------------------------------

/// Full pipe name for an agent with administrator rights.
///
/// Matches `BuildPipeName(kPipePrefixForAgent, base, /*user_specific=*/false)`
/// out of the SDK's `common/utils_win.cc`.
pub fn pipe_path(base: &str) -> String {
    format!(r"\\.\pipe\ProtectedPrefix\Administrators\{base}")
}

/// Access list of the pipe, word for word the SDK's `kDaclEveryone`: full
/// access for creator and administrators, read and write for everyone.
///
/// "Everyone" sounds wide and is not: under
/// `ProtectedPrefix\Administrators\` only an administrator may create, and
/// that is exactly the protection. Read and write **has** to be allowed for
/// everyone — the browser runs as an ordinary user and would otherwise not
/// get at its own watchdog.
const PIPE_DACL: &str = "D:(A;OICI;GA;;;CO)(A;OICI;GA;;;BA)(A;OICI;GRGW;;;WD)";

/// Elsewhere there is no named pipe a browser reports to. The protocol and
/// the verdict over it -- [`verdict`], [`alert_for`] -- are checked on every
/// platform; only the listening needs Windows.
#[cfg(not(windows))]
pub async fn serve(
    _base: &str,
    _cfg: Arc<RwLock<Config>>,
    _blocked: tokio::sync::mpsc::Sender<Blocked>,
) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub async fn serve(
    base: &str,
    cfg: Arc<RwLock<Config>>,
    blocked: tokio::sync::mpsc::Sender<Blocked>,
) -> Result<()> {
    let path = pipe_path(base);
    tracing::info!(pipe = %path, "content analysis: listening for browsers");
    let mut first = true;
    loop {
        // The security descriptor is a raw pointer and must not live across
        // any `await`, otherwise the task is no longer `Send`. So it comes
        // into being and passes away inside this synchronous function, once
        // per pipe instance — one SDDL conversion per connection, which does
        // not show next to a browser dialog.
        let server = create_pipe(&path, first)?;
        first = false;
        server
            .connect()
            .await
            .with_context(|| format!("accept on {path}"))?;
        let cfg = cfg.clone();
        let blocked = blocked.clone();
        tokio::spawn(async move {
            if let Err(e) = talk(server, cfg, blocked).await {
                // A browser that throws the connection away is not a fault
                // of the service — but we want to see it when it piles up.
                tracing::debug!("content analysis: connection ended: {e:#}");
            }
        });
    }
}

/// Create one pipe instance with the SDK's access list.
///
/// `first` sets `FILE_FLAG_FIRST_PIPE_INSTANCE`: if somebody is already
/// listening under this name, creation fails. That is exactly how it should
/// be — a second listener would be either a service started twice or someone
/// passing themselves off as the watchdog.
#[cfg(windows)]
fn create_pipe(
    path: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let sddl = HSTRING::from(PIPE_DACL);
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
        .context("DACL for the content-analysis pipe")?;
    }
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .pipe_mode(PipeMode::Message)
            .reject_remote_clients(true)
            .in_buffer_size(MAX_MESSAGE as u32)
            .out_buffer_size(MAX_MESSAGE as u32)
            .create_with_security_attributes_raw(path, &mut sa as *mut _ as *mut std::ffi::c_void)
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0)));
    }
    server.with_context(|| format!("create {path}"))
}

/// Programs that have ever reported at the pipe — by **image path**, not by
/// PID.
///
/// A PID is the wrong question when it comes to the network cage: on
/// 2026-09-09 `firefox.exe` was caged and lost seven open connections
/// because *this* PID had not asked yet. But a browser asks as a program,
/// not as a process — and whoever has asked once asks on the next start too.
fn asking_images() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static I: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    I.get_or_init(Default::default)
}

/// Browsers whose content-analysis connector may speak for their program:
/// publisher from the signature, original file name from the version
/// resource. Nothing else earns the exemption.
const CONNECTOR_BROWSERS: &[(&str, &str)] = &[
    ("Google LLC", "chrome.exe"),
    ("Microsoft Corporation", "msedge.exe"),
    ("Mozilla Corporation", "firefox.exe"),
];

/// May a process with this identity exempt its program from the network
/// cage by connecting to the pipe?
///
/// Pentest 8840/0003: the pipe has to be open to everyone (browsers run as
/// ordinary users), and every client's image was remembered on connect,
/// before a single message. Any tool of the monitored user connected once
/// and was never caged again. A signature from a browser vendor under that
/// browser's own name cannot be had by renaming a file — and a vendor name
/// alone is not enough either: Microsoft signs `curl.exe` too.
pub fn may_exempt_its_image(id: &ProcessIdentity) -> bool {
    match id {
        ProcessIdentity::Signed {
            team_id,
            signing_id,
        } => {
            let name = deelpe_core::identity::image_name(signing_id);
            CONNECTOR_BROWSERS
                .iter()
                .any(|(p, n)| team_id == p && name == *n)
        }
        _ => false,
    }
}

/// Remember that this program asks. Without an expiry: a program does not
/// unlearn that, and the set stays as large as the number of browsers on the
/// machine. Only for a client [`may_exempt_its_image`] lets through.
pub fn note_image(exe: &str) {
    if exe.is_empty() {
        return;
    }
    if let Ok(mut i) = asking_images().lock() {
        i.insert(exe.to_lowercase());
    }
}

/// Does this **program** ask before it sends? The network cage's question:
/// it hangs off the EXE, so the exception has to hang off the EXE too.
pub fn image_asks_before_sending(exe: &str) -> bool {
    asking_images()
        .lock()
        .is_ok_and(|i| i.contains(&exe.to_lowercase()))
}

/// Who is hanging on the other end? Without that, the log says only that
/// somebody asked — and the first question in an incident is always
/// **which** browser it was.
#[cfg(windows)]
fn client_of(pipe: &tokio::net::windows::named_pipe::NamedPipeServer) -> Option<u32> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
    let mut pid = 0u32;
    unsafe { GetNamedPipeClientProcessId(HANDLE(pipe.as_raw_handle()), &mut pid) }.ok()?;
    Some(pid)
}

/// Who is the browser? The same identification as everywhere else in the
/// agent: valid signature including issuer, otherwise the path. Asked once
/// per connection — the check is expensive, and a process does not swap its
/// EXE.
#[cfg(windows)]
fn identity_of_pid(pid: u32) -> ProcessIdentity {
    deelpe_sensors::windows::signature::SignatureCache::default().identity(&image_of(pid))
}

/// Image path of a PID; empty if it cannot be determined.
#[cfg(windows)]
fn image_of(pid: u32) -> String {
    deelpe_sensors::windows::procinfo::image_path(pid).unwrap_or_default()
}

/// One connection: read requests, judge, answer — until the browser leaves.
#[cfg(windows)]
async fn talk(
    mut pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    cfg: Arc<RwLock<Config>>,
    blocked: tokio::sync::mpsc::Sender<Blocked>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let client = client_of(&pipe);
    // Who the browser is, is otherwise only needed once something really
    // gets blocked: the signature check is the most expensive step here.
    let mut identity: Option<ProcessIdentity> = None;
    // Remember the image path **right away**, not only when blocking: the
    // network cage's exception hangs off it, and it has to be in place before
    // the browser touches a protected folder for the first time. But only for
    // a real browser — once per program, the set remembers it after that.
    if let Some(pid) = client {
        let exe = image_of(pid);
        if !image_asks_before_sending(&exe) {
            let id = identity_of_pid(pid);
            if may_exempt_its_image(&id) {
                note_image(&exe);
            } else {
                tracing::warn!(pid, exe = %exe, "content analysis: a program that is not a known browser connected; it stays subject to the network cage");
            }
            identity = Some(id);
        }
    }
    tracing::info!(
        pid = client.unwrap_or(0),
        "content analysis: browser connected"
    );
    let mut buf = vec![0u8; MAX_MESSAGE];
    loop {
        let n = pipe.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let msg = match parse_message(&buf[..n]) {
            Some(Incoming::Ask(req)) => req,
            // Acknowledgement or cancellation: noted, no answer. Whoever
            // answers here sends the browser an answer to something it never
            // asked.
            Some(Incoming::Note) => continue,
            None => {
                // Unreadable. Nothing to answer that the browser could
                // match up — the token is in the request, after all.
                tracing::warn!("content analysis: unreadable message ({n} bytes)");
                continue;
            }
        };
        let mut req = msg;
        // The letter becomes the share before any rule is asked.
        if let Some(p) = req.file_path.as_deref() {
            req.file_path = Some(on_the_share(&pipe, p));
        }
        // Verdict and "does this concern anybody at all" in one grab: the
        // folder decides both, and locking twice would be waiting twice.
        let (block, watched) = {
            let c = cfg.read().await;
            (
                verdict(&c, &req),
                req.file_path.as_deref().is_some_and(|f| c.is_watched(f)),
            )
        };
        // Allowing belongs in the log too. Without this line "never asked"
        // and "asked and let through" look the same, and that is exactly what
        // cost half an hour of guessing on 2026-09-08.
        match &block {
            Some(reason) => {
                tracing::warn!(
                    pid = client.unwrap_or(0),
                    url = req.url.as_deref().unwrap_or("-"),
                    connector = req.connector,
                    "BLOCKED: {reason}"
                );
                // The central learns of it, not just the log. Without
                // `await`-free sending the browser would hang on our backlog:
                // a full mailbox costs the report, never the no. `try_send`
                // is the fail-open direction here that ADR 0002 lays down for
                // this whole building block.
                let who = identity
                    .get_or_insert_with(|| {
                        client
                            .map(identity_of_pid)
                            .unwrap_or(ProcessIdentity::Unknown {
                                path: String::new(),
                            })
                    })
                    .clone();
                let note = Blocked {
                    at: Utc::now(),
                    pid: client.unwrap_or(0),
                    identity: who,
                    file: req.file_path.clone().unwrap_or_default(),
                    url: req.url.clone(),
                    connector: req.connector,
                    reason: reason.clone(),
                    blocked: true,
                };
                if let Err(e) = blocked.try_send(note) {
                    tracing::warn!("block not reported to the central: {e}");
                }
            }
            None => {
                tracing::info!(
                    pid = client.unwrap_or(0),
                    url = req.url.as_deref().unwrap_or("-"),
                    connector = req.connector,
                    file = %req.file_path.as_deref().unwrap_or(std::path::Path::new("-")).display(),
                    "content analysis: allowed"
                );
                // Out of a watched folder, allowing is worth a line too. On
                // 2026-09-09 somebody uploaded six files out of
                // `\\fs-01\Engineering\Doku` to Gemini; the folder had
                // set no enforcement, and the dashboard said nothing — only
                // six INFO lines in the workstation's log that nobody reads.
                // Whoever blocks nothing still wants to see.
                if watched {
                    let who = identity
                        .get_or_insert_with(|| {
                            client
                                .map(identity_of_pid)
                                .unwrap_or(ProcessIdentity::Unknown {
                                    path: String::new(),
                                })
                        })
                        .clone();
                    let note = Blocked {
                        at: Utc::now(),
                        pid: client.unwrap_or(0),
                        identity: who,
                        file: req.file_path.clone().unwrap_or_default(),
                        url: req.url.clone(),
                        connector: req.connector,
                        reason: "watched folder, no rule forbids this destination".to_string(),
                        blocked: false,
                    };
                    if let Err(e) = blocked.try_send(note) {
                        tracing::warn!("upload not reported to the central: {e}");
                    }
                }
            }
        }
        let out = response(&req.token, block.as_deref());
        pipe.write_all(&out).await?;
        pipe.flush().await?;
    }
}

// ---------------------------------------------------------------------------
// The policy that tells the browser we exist
// ---------------------------------------------------------------------------
//
// Without it no browser asks, and the connector has no effect — it listens
// at a pipe nobody knows about. So it belongs to the agent's installation and
// not into a manual: a protection that still has to be switched on by hand
// after the rollout is off on half the machines.

/// The key Firefox reads its enterprise policies under.
const POLICY_KEY: &str = r"SOFTWARE\Policies\Mozilla\Firefox\ContentAnalysis";

/// One entry of the policy: subkey, name, value.
#[derive(Debug, PartialEq, Eq)]
enum Value {
    Dword(u32),
    Text(&'static str),
}

/// What has to be in the policy so that Firefox asks us.
///
/// The values live here and not in a manual so that they cannot drift apart:
/// `PipePathName` **has** to be the same name the service listens at, and
/// `IsPerUser` **has** to be false, because our pipe lies under
/// `ProtectedPrefix\Administrators\` and not per user. A test pins both down.
///
/// All five interception points are on. On 2026-09-08 `DragAndDrop` and
/// `Clipboard` stood at false in the lab — "just for the first test" — and
/// whoever dragged the file into the window was never asked. A hole nobody
/// sees, because nothing happens.
///
/// `DefaultResult` and `TimeoutResult` on *allow*: no agent, no standstill.
/// That is the fail-open decision out of ADR 0002 — a DLP building block that
/// cripples the browser when it fails itself is worse than the leak it is up
/// against.
fn policy() -> Vec<(&'static str, &'static str, Value)> {
    let mut v = vec![
        ("", "Enabled", Value::Dword(1)),
        ("", "PipePathName", Value::Text(PIPE_NAME)),
        ("", "IsPerUser", Value::Dword(0)),
        ("", "AgentName", Value::Text("DLPrevent")),
        ("", "AgentTimeout", Value::Dword(30)),
        ("", "DefaultResult", Value::Dword(2)),
        ("", "TimeoutResult", Value::Dword(2)),
        ("", "ShowBlockedResult", Value::Dword(1)),
    ];
    for p in [
        r"InterceptionPoints\FileUpload",
        r"InterceptionPoints\DragAndDrop",
        r"InterceptionPoints\Clipboard",
        r"InterceptionPoints\Print",
        r"InterceptionPoints\Download",
    ] {
        v.push((p, "Enabled", Value::Dword(1)));
    }
    // Otherwise Firefox sees only `text/plain` on paste and drag — but a
    // file carries other formats, and we are meant to get those too.
    v.push((
        r"InterceptionPoints\Clipboard",
        "PlainTextOnly",
        Value::Dword(0),
    ));
    v.push((
        r"InterceptionPoints\DragAndDrop",
        "PlainTextOnly",
        Value::Dword(0),
    ));
    v
}

/// Write the policy. Belongs to `service install`.
#[cfg(windows)]
pub fn install_policy() -> anyhow::Result<()> {
    use anyhow::Context;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_WRITE,
        REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    for (sub, name, value) in policy() {
        let path = if sub.is_empty() {
            POLICY_KEY.to_string()
        } else {
            format!(r"{POLICY_KEY}\{sub}")
        };
        let wide = HSTRING::from(path.as_str());
        let mut key = HKEY::default();
        unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(wide.as_ptr()),
                None,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
            .ok()
            .with_context(|| format!("create HKLM\\{path}"))?;
        }
        let n = HSTRING::from(name);
        let r = unsafe {
            match value {
                Value::Dword(d) => RegSetValueExW(
                    key,
                    PCWSTR(n.as_ptr()),
                    None,
                    REG_DWORD,
                    Some(&d.to_le_bytes()),
                ),
                Value::Text(t) => {
                    // REG_SZ wants UTF-16 with a trailing zero, as bytes.
                    let bytes: Vec<u8> = t
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .flat_map(|c| c.to_le_bytes())
                        .collect();
                    RegSetValueExW(key, PCWSTR(n.as_ptr()), None, REG_SZ, Some(&bytes))
                }
            }
        };
        unsafe {
            let _ = RegCloseKey(key);
        }
        r.ok()
            .with_context(|| format!("set {name} under HKLM\\{path}"))?;
    }
    println!("Firefox content-analysis policy written (pipe '{PIPE_NAME}').");
    println!("Firefox reads it at startup — a running browser has to be restarted once.");
    Ok(())
}

/// Remove the policy again. Belongs to `service uninstall`: a browser that
/// after the uninstall keeps asking for an agent that is no longer there
/// waits for the timeout on every upload.
#[cfg(windows)]
pub fn remove_policy() -> anyhow::Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::Registry::{RegDeleteTreeW, HKEY_LOCAL_MACHINE};

    let wide = HSTRING::from(POLICY_KEY);
    // If it is gone already that is no error — uninstalling is meant to work.
    unsafe {
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(wide.as_ptr()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deelpe_core::config::Strict;

    fn cfg(enforce: bool) -> Config {
        cfg_allowing(enforce, vec![])
    }

    fn cfg_allowing(enforce: bool, allow: Vec<&str>) -> Config {
        let allow = allow.into_iter().map(String::from).collect();
        Config {
            strict: vec![Strict {
                path: r"\\srv\GL".into(),
                allow,
                enforce,
            }],
            ..Default::default()
        }
    }

    fn blocked() -> Blocked {
        Blocked {
            at: Utc::now(),
            pid: 4242,
            identity: ProcessIdentity::Unknown {
                path: r"C:\Program Files\Mozilla Firefox\firefox.exe".into(),
            },
            file: PathBuf::from(r"\\srv\GL\Zahlen.xlsx"),
            url: Some("https://chatgpt.com/c/1".into()),
            connector: 2,
            reason: r"\\srv\GL\Zahlen.xlsx may not leave \\srv\GL".into(),
            blocked: true,
        }
    }

    /// An upload no rule forbids is still worth a line — but not an alert:
    /// `New` appears in the dashboard and sets off no mail. On 2026-09-09 six
    /// files went out of a watched folder to Gemini, and there was nothing of
    /// it to see.
    /// Pentest 8840/0003: connecting to the pipe once must not exempt just
    /// any program from the network cage.
    #[test]
    fn only_a_signed_browser_exempts_its_program_from_the_cage() {
        let signed = |p: &str, n: &str| ProcessIdentity::Signed {
            team_id: p.into(),
            signing_id: n.into(),
        };
        assert!(may_exempt_its_image(&signed("Google LLC", "chrome.exe")));
        assert!(may_exempt_its_image(&signed(
            "Microsoft Corporation",
            "msedge.exe"
        )));
        assert!(
            may_exempt_its_image(&signed("Mozilla Corporation", "FIREFOX.EXE.MUI")),
            "the name in any spelling Windows hands out"
        );
        assert!(
            !may_exempt_its_image(&ProcessIdentity::Unknown {
                path: r"C:\Users\me\chrome.exe".into()
            }),
            "a renamed tool is unsigned"
        );
        assert!(
            !may_exempt_its_image(&signed("Microsoft Corporation", "curl.exe")),
            "the vendor alone is not enough"
        );
        assert!(
            !may_exempt_its_image(&signed("Evil LLC", "chrome.exe")),
            "the name alone is not enough"
        );
    }

    #[test]
    fn an_allowed_upload_is_visible_but_is_not_an_alarm() {
        let allowed = Blocked {
            blocked: false,
            reason: "watched folder, no rule forbids this destination".into(),
            ..blocked()
        };
        let a = alert_for(&allowed, 8);
        assert_eq!(a.verdict, Verdict::New, "durchgelassen ist kein Alarm");
        assert_ne!(a.verdict, Verdict::Denied, "sonst kommt dafuer Mail");
        assert!(
            a.reason.as_deref().unwrap().starts_with("upload allowed:"),
            "{:?}",
            a.reason
        );
        assert_eq!(a.files, vec![PathBuf::from(r"\\srv\GL\Zahlen.xlsx")]);
        assert_eq!(a.upload_url.as_deref(), Some("https://chatgpt.com/c/1"));
    }

    /// The block becomes an alert, and that one carries the destination —
    /// otherwise the dashboard shows a line without the place it was about.
    #[test]
    fn a_block_becomes_an_alert_the_dashboard_can_show() {
        use deelpe_core::correlate::Target;
        let a = alert_for(&blocked(), 7);
        assert_eq!(a.id, 7);
        assert_eq!(a.identity.short(), "firefox.exe");
        assert_eq!(a.files, vec![PathBuf::from(r"\\srv\GL\Zahlen.xlsx")]);
        assert_eq!(
            a.verdict,
            Verdict::Denied,
            "ein strenger Ordner wird nie gelernt"
        );
        assert_eq!(a.target(), Target::Upload("https://chatgpt.com/c/1"));
        assert!(a
            .reason
            .as_deref()
            .unwrap()
            .starts_with("upload blocked before sending:"));
        // The browser asked and waited — it does not get killed.
        assert!(!a.sender_read_directly);
        assert_eq!(a.bytes_out, 0, "es ging kein Byte hinaus");
    }

    /// The browser is a trust boundary: an address bar with a megabyte in it
    /// must not end up as a destination in the alert list.
    #[test]
    fn an_absurdly_long_url_is_cut_but_keeps_its_host() {
        let long = format!("https://chatgpt.com/{}", "a".repeat(1_000_000));
        let req = asked(&upload(b"t", r"\\srv\GL\a.dat", &long));
        let url = req.url.unwrap();
        assert_eq!(url.len(), MAX_URL);
        assert!(url.starts_with("https://chatgpt.com/"));
        // And the allow list judges by it unchanged afterwards.
        assert!(deelpe_core::allow::allows_host(
            &["chatgpt.com".to_string()],
            &url
        ));
    }

    /// The same action twice is one alert, not two.
    #[test]
    fn the_same_action_twice_is_one_alert() {
        let b = blocked();
        let a = alert_for(&b, 7);
        assert!(same_action(&a, &b));
        let mut other = b.clone();
        other.url = Some("https://gemini.google.com/".into());
        assert!(!same_action(&a, &other));
        let mut elsewhere = b.clone();
        elsewhere.file = PathBuf::from(r"\\srv\GL\Andere.xlsx");
        assert!(!same_action(&a, &elsewhere));
    }

    /// The bare `ContentAnalysisRequest` — the way it does **not** come over
    /// the pipe.
    fn inner_upload(token: &[u8], path: &str, url: &str) -> Vec<u8> {
        let mut meta = Vec::new();
        put_len_field(&mut meta, 1, url.as_bytes()); // ContentMetaData.url
        let mut out = Vec::new();
        put_len_field(&mut out, 5, token); // request_token
        put_varint_field(&mut out, 9, 2); // analysis_connector = FILE_ATTACHED
        put_len_field(&mut out, 10, &meta); // request_data
        put_len_field(&mut out, 14, path.as_bytes()); // file_path
        out
    }

    /// A request the way Firefox really sends it: in the envelope
    /// `ChromeToAgent`, field 1.
    fn upload(token: &[u8], path: &str, url: &str) -> Vec<u8> {
        let mut out = Vec::new();
        put_len_field(&mut out, 1, &inner_upload(token, path, url));
        out
    }

    /// Fetch the question out of a message; anything else is a test failure.
    fn asked(raw: &[u8]) -> Request {
        match parse_message(raw) {
            Some(Incoming::Ask(r)) => r,
            other => panic!("keine Frage: {other:?}"),
        }
    }

    #[test]
    fn an_upload_request_is_read_field_by_field() {
        let raw = upload(
            b"tok-1",
            r"\\srv\GL\Zahlen.xlsx",
            "https://gemini.google.com/app",
        );
        let req = asked(&raw);
        assert_eq!(req.token, b"tok-1");
        assert_eq!(req.connector, 2, "FILE_ATTACHED");
        assert_eq!(req.url.as_deref(), Some("https://gemini.google.com/app"));
        assert_eq!(req.file_path, Some(PathBuf::from(r"\\srv\GL\Zahlen.xlsx")));
        assert!(!req.has_text);
    }

    /// The reader has to pass over unknown fields: even today the SDK
    /// carries `tags`, `client_metadata`, `user_action_id` along, and more
    /// will come. A reader that trips over them fails on the next browser
    /// version — and silently at that.
    #[test]
    fn unknown_fields_are_skipped() {
        let mut inner = inner_upload(b"t", r"\\srv\GL\a.dat", "https://x.test/");
        put_varint_field(&mut inner, 17, 42); // user_action_requests_count
        put_len_field(&mut inner, 11, b"dlp"); // tags
        put_varint_field(&mut inner, 15, 1_700_000_000); // expires_at
        let mut raw = Vec::new();
        put_len_field(&mut raw, 1, &inner);
        put_varint_field(&mut raw, 9, 7); // unknown field of the envelope
        let req = asked(&raw);
        assert_eq!(req.file_path, Some(PathBuf::from(r"\\srv\GL\a.dat")));
        assert_eq!(req.token, b"t");
    }

    /// The browser is a trust boundary. Something truncated may yield `None`,
    /// but never panic.
    #[test]
    fn a_truncated_request_is_refused_not_fatal() {
        let raw = upload(b"tok", r"\\srv\GL\a.dat", "https://x.test/");
        for cut in 1..raw.len() {
            let _ = parse_message(&raw[..cut]);
        }
        // A length that points past the end.
        assert_eq!(parse_message(&[(1 << 3) | 2, 200, b'a']), None);
        // A wire type that does not exist.
        assert_eq!(parse_message(&[(1 << 3) | 6]), None);
    }

    #[test]
    fn a_file_from_a_strict_folder_is_blocked_whatever_the_destination() {
        let c = cfg(true);
        let req = asked(&upload(
            b"t",
            r"\\srv\GL\Zahlen.xlsx",
            "https://gemini.google.com/app",
        ));
        assert!(
            verdict(&c, &req).is_some(),
            "Upload aus dem strengen Ordner"
        );

        // Without enforcement it is only reported, not blocked.
        assert_eq!(verdict(&cfg(false), &req), None);

        // File outside: concerns nobody.
        let other = asked(&upload(
            b"t",
            r"C:\Users\eva\Bilder\urlaub.jpg",
            "https://gemini.google.com/app",
        ));
        assert_eq!(verdict(&c, &other), None);
    }

    /// The operator enters an AI service in the dashboard that he trusts.
    /// The file may go there, nowhere else — the case the customer cared
    /// about on 2026-09-08.
    #[test]
    fn a_whitelisted_destination_may_receive_the_file() {
        let c = cfg_allowing(true, vec!["ethical-ai.example"]);
        let ok = asked(&upload(
            b"t",
            r"\\srv\GL\Zahlen.xlsx",
            "https://chat.ethical-ai.example/upload",
        ));
        assert_eq!(verdict(&c, &ok), None, "freigegebenes Ziel");

        let nope = asked(&upload(
            b"t",
            r"\\srv\GL\Zahlen.xlsx",
            "https://gemini.google.com/app",
        ));
        assert!(verdict(&c, &nope).is_some(), "alles andere bleibt zu");

        // An IP in the list allows no name.
        let ip_only = cfg_allowing(true, vec!["10.0.0.7"]);
        assert!(
            verdict(&ip_only, &ok).is_some(),
            "IP-Eintrag deckt keinen Hostnamen"
        );
    }

    /// A paste from the clipboard carries no path. Today we pass no verdict
    /// on it — but the request has to stay readable, otherwise the browser
    /// gets no answer and waits until the timeout.
    #[test]
    fn a_paste_carries_text_and_no_path() {
        let mut inner = Vec::new();
        put_len_field(&mut inner, 5, b"tok-paste");
        put_varint_field(&mut inner, 9, 3); // BULK_DATA_ENTRY
        put_len_field(&mut inner, 13, b"streng geheime Zahlen");
        let mut raw = Vec::new();
        put_len_field(&mut raw, 1, &inner);
        let req = asked(&raw);
        assert!(req.has_text);
        assert_eq!(req.file_path, None);
        assert_eq!(verdict(&cfg(true), &req), None);
    }

    /// Fetch one field out of a message, length-limited. For tests that
    /// really read the answer instead of poking around at byte offsets — that
    /// is exactly how the missing envelope slipped through on 2026-09-08.
    fn field(buf: &[u8], want: u64) -> Option<Vec<u8>> {
        let mut r = Reader::new(buf);
        while !r.done() {
            let (f, w) = r.key()?;
            if w == 2 {
                let d = r.bytes()?;
                if f == want {
                    return Some(d.to_vec());
                }
            } else {
                r.skip(w)?;
            }
        }
        None
    }

    /// The answer sits in the envelope `AgentToChrome` and carries the same
    /// token as the question. Without the envelope the browser matches it to
    /// no question and waits until the timeout — in the lab that looked like
    /// "the upload just does not work".
    #[test]
    fn the_answer_is_wrapped_and_carries_the_token_and_the_verdict() {
        for (block, expect_rule) in [(None, false), (Some("kein Abfluss aus GL"), true)] {
            let msg = response(b"tok-1", block);
            // AgentToChrome.response = 1
            let resp = field(&msg, 1).expect("Huelle AgentToChrome fehlt");
            // ContentAnalysisResponse.request_token = 1
            assert_eq!(
                field(&resp, 1).as_deref(),
                Some(&b"tok-1"[..]),
                "Zeichen fehlt"
            );
            // results = 4
            let result = field(&resp, 4).expect("results fehlt");
            assert_eq!(field(&result, 1).as_deref(), Some(&b"dlp"[..]), "tag");
            // triggered_rules = 3 only exists on a block
            let rules = field(&result, 3);
            assert_eq!(
                rules.is_some(),
                expect_rule,
                "triggered_rules bei block={block:?}"
            );
            if let Some(tr) = rules {
                assert_eq!(
                    field(&tr, 2).as_deref(),
                    Some("kein Abfluss aus GL".as_bytes()),
                    "Regelname"
                );
            }
        }
    }

    /// The letter has to become the share, otherwise no rule matches. On
    /// 2026-09-08 every upload picked via `G:` instead of via the UNC path
    /// went through -- and the normal case runs over the letter, since that
    /// is what the group policy hands it out for.
    #[test]
    fn a_drive_letter_is_taken_apart_and_put_back_on_the_share() {
        assert_eq!(
            drive_of(Path::new(r"G:\Zahlen\Zahlen-004.dat")),
            Some(('G', r"\Zahlen\Zahlen-004.dat".to_string()))
        );
        assert_eq!(
            drive_of(Path::new(r"g:\a")),
            Some(('G', r"\a".to_string())),
            "kleiner Buchstabe zaehlt auch"
        );
        // No letter: UNC paths and nonsense stay as they are.
        assert_eq!(drive_of(Path::new(r"\\srv\GL\a.dat")), None);
        assert_eq!(drive_of(Path::new("/tmp/a")), None);
        assert_eq!(drive_of(Path::new("")), None);

        assert_eq!(
            splice(r"\\fs-01\GL", r"\Zahlen\Zahlen-004.dat"),
            PathBuf::from(r"\\fs-01\GL\Zahlen\Zahlen-004.dat")
        );
        // A trailing separator in the registry must not double up.
        assert_eq!(
            splice(r"\\fs-01\GL\", r"\Zahlen\a.dat"),
            PathBuf::from(r"\\fs-01\GL\Zahlen\a.dat")
        );
    }

    /// Both forms `QueryDosDevice` delivers for a network drive have to lead
    /// to the same share. The second one turns up on newer Windows versions
    /// and was the reason not to trust `winpath` blindly here.
    #[test]
    fn both_forms_of_a_mapped_drive_lead_to_the_share() {
        assert_eq!(
            nt_to_share(r"\??\UNC\fs-01\GL").as_deref(),
            Some(r"\\fs-01\GL")
        );
        assert_eq!(
            nt_to_share(r"\Device\LanmanRedirector\;G:0000000000123456\fs-01\GL").as_deref(),
            Some(r"\\fs-01\GL")
        );
        assert_eq!(
            nt_to_share("\\??\\UNC\\srv\\GL\0\0").as_deref(),
            Some(r"\\srv\GL"),
            "Nullbytes am Ende stoeren nicht"
        );
        // A local drive is no share.
        assert_eq!(nt_to_share(r"\Device\HarddiskVolume3"), None);
    }

    /// The policy has to match what the service really does. If the two
    /// drift apart, the agent listens at a pipe no browser asks for — and
    /// nobody notices anything, because nothing happens.
    #[test]
    fn the_policy_matches_the_pipe_the_service_opens() {
        let p = policy();
        let get = |sub: &str, name: &str| {
            p.iter()
                .find(|(s, n, _)| *s == sub && *n == name)
                .map(|(_, _, v)| v)
        };

        assert_eq!(
            get("", "PipePathName"),
            Some(&Value::Text(PIPE_NAME)),
            "Richtlinie und Pipe muessen denselben Namen nennen"
        );
        assert_eq!(
            get("", "IsPerUser"),
            Some(&Value::Dword(0)),
            "unsere Pipe liegt unter ProtectedPrefix\\Administrators, nicht je Benutzer"
        );
        assert_eq!(get("", "Enabled"), Some(&Value::Dword(1)));

        // All five interception points. On 2026-09-08 two of them were off,
        // and whoever dragged the file into the window was never asked.
        for point in [
            "FileUpload",
            "DragAndDrop",
            "Clipboard",
            "Print",
            "Download",
        ] {
            let sub = format!("InterceptionPoints\\{point}");
            assert_eq!(
                get(&sub, "Enabled"),
                Some(&Value::Dword(1)),
                "{point} muss an sein"
            );
        }

        // Fail-open, see ADR 0002: no agent, no standstill.
        assert_eq!(get("", "DefaultResult"), Some(&Value::Dword(2)));
        assert_eq!(get("", "TimeoutResult"), Some(&Value::Dword(2)));
    }

    /// An acknowledgement is not a question. Whoever answers it sends the
    /// browser an answer to something it never asked.
    #[test]
    fn an_acknowledgement_is_noted_and_not_answered() {
        let mut ack = Vec::new();
        put_len_field(&mut ack, 1, b"tok-1"); // request_token
        put_varint_field(&mut ack, 2, 1); // status = SUCCESS
        let mut raw = Vec::new();
        put_len_field(&mut raw, 2, &ack); // ChromeToAgent.ack = 2
        assert_eq!(parse_message(&raw), Some(Incoming::Note));

        let mut cancel = Vec::new();
        put_len_field(&mut cancel, 1, b"aktion-7");
        let mut raw = Vec::new();
        put_len_field(&mut raw, 3, &cancel); // ChromeToAgent.cancel = 3
        assert_eq!(parse_message(&raw), Some(Incoming::Note));
    }

    /// The bare request without its envelope must **not** pass as a question.
    /// That is exactly how it was built, and exactly how every message came
    /// in empty on 2026-09-08: `url=- connector=0 file=-`, and everything was
    /// let through.
    #[test]
    fn a_request_without_its_envelope_is_not_a_question() {
        let bare = inner_upload(
            b"t",
            r"\\srv\GL\Zahlen.xlsx",
            "https://gemini.google.com/app",
        );
        assert!(
            !matches!(parse_message(&bare), Some(Incoming::Ask(_))),
            "ohne Huelle ist es keine Frage"
        );
    }

    #[test]
    fn the_pipe_lies_where_only_an_administrator_may_create_it() {
        assert_eq!(
            pipe_path("deelpe"),
            r"\\.\pipe\ProtectedPrefix\Administrators\deelpe"
        );
        // The browser has to be allowed to read and write, otherwise it does
        // not reach its own watchdog.
        assert!(PIPE_DACL.contains("GRGW;;;WD"));
    }
}
