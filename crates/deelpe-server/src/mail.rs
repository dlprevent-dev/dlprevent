//! Notification by e-mail (SMTP).
//!
//! The server sits in a browser, and whoever does not look sees nothing.
//! Three things are worth nudging somebody about:
//!
//! - **Alerts** with a verdict worth reporting — the case "somebody is
//!   carting off the GL folder".
//! - **An agent that stops reporting.** A silent agent looks like a quiet
//!   day on the dashboard; that is the most dangerous state the whole
//!   installation can be in.
//! - **A destination with a bad reputation** (AbuseIPDB), even when the
//!   flow itself stayed below the threshold.
//!
//! Not one mail per event: the worker collects what has piled up since the
//! last message and sends **one** summary per digest window
//! (`notify_digest_mins`). A bulk copy that produces two hundred alerts
//! therefore costs one mail, not two hundred.
//!
//! The state is remembered in the database, not in memory
//! (`alerts.notified_at`, `agents.down_notified_at`): a restart of the
//! server must neither swallow a notification nor repeat one. The flag is
//! set **after** a successful send — if the SMTP server does not pick up the
//! phone, the next pass tries again.
//!
//! The server itself is arbitrary (Proton Bridge on `127.0.0.1:1025`,
//! `smtp.protonmail.ch:587`, an in-house relay without a login): address,
//! port, transport security and credentials live in the dashboard.

use crate::abuseipdb;
use crate::db;
use crate::state::Shared;
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// The worker looks every minute; whether it also sends is decided by the
/// digest window.
const SWEEP_SECS: u64 = 60;

/// How long to wait for the SMTP server. A hanging relay must not hold the
/// worker up forever.
const SMTP_TIMEOUT: Duration = Duration::from_secs(20);

/// This many unjudged alerts are fetched by one pass. After a longer outage
/// of the server there is more waiting than belongs in one mail; the rest
/// comes in the next pass.
const BATCH: i64 = 2000;

/// This long an alert stays open whose destination address has never been
/// looked up. The reputation lives in a table that the worker in
/// `abuseipdb` fills — and that one runs at its own pace. Without this
/// deadline a fresh alert would be ticked off before AbuseIPDB has
/// answered, and the reputation trigger would only fire for addresses that
/// happen to be in the cache already from an older alert. After the
/// deadline it is ticked off anyway: the cache may never fill (service off,
/// budget spent, error pause), and it must not stay open.
const REPUTATION_GRACE_SECS: i64 = 15 * 60;

/// This many alerts are listed individually in the mail. What goes beyond
/// that is counted — nobody reads a mail with two thousand lines.
const MAX_LISTED: usize = 50;

/// This many recipients the server accepts. A distribution list belongs on
/// the mail server, not in a text field.
pub const MAX_RECIPIENTS: usize = 20;

/// Verdicts worth a mail — the same ones the dashboard counts as an alarm
/// (`api::alerts::IS_ALERT`).
/// When the last message went out. Lives in `settings`, because the digest
/// window has to survive a restart.
const LAST_SENT_KEY: &str = "notify_last_sent_at";

pub const ALARM_VERDICTS: &[&str] = &["denied", "hard_limit", "deviation"];

// ---------- Setup ----------

/// How the connection to the SMTP server is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Plain text, without encryption. Only for a relay on the same machine
    /// (Proton Bridge, Postfix on localhost).
    None,
    /// A plain-text connection that is encrypted with `STARTTLS`. The
    /// usual case on port 587.
    StartTls,
    /// TLS from the first second on (SMTPS), usual on port 465.
    Tls,
}

impl Security {
    /// From the settings. Anything unknown becomes `StartTls`: that is the
    /// default and the safe one of the three answers.
    pub fn parse(s: &str) -> Self {
        match s {
            "none" => Security::None,
            "tls" => Security::Tls,
            _ => Security::StartTls,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Security::None => "none",
            Security::StartTls => "starttls",
            Security::Tls => "tls",
        }
    }
}

/// Time zone from the settings. Anything that cannot be read becomes `UTC`:
/// a mail with an unclear time is worse than one with an inconvenient time,
/// and it is checked on save anyway.
pub async fn timezone(pool: &PgPool) -> Result<Tz> {
    Ok(db::setting_str(pool, "report_timezone")
        .await?
        .and_then(|s| s.parse().ok())
        .unwrap_or(Tz::UTC))
}

/// What the server needs in order to send, plus the question of what about.
#[derive(Debug, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub security: Security,
    pub user: String,
    pub pass: String,
    pub from: String,
    pub to: Vec<String>,
    /// Address of the dashboard for the links in the mail. Empty means: no
    /// links — the server does not know its own public address.
    pub base_url: String,
    pub on_alerts: bool,
    pub on_agent_down: bool,
    pub on_abuse: bool,
    pub abuse_min_score: i64,
    pub digest_mins: i64,
    /// This long an agent may stay silent before it counts as down. This
    /// used to be `report_interval_secs * 3` — 90 seconds, in which a Wi-Fi
    /// switch or a standby was enough for a down/up pair. The cadence of
    /// the reports and the patience of the notification are two different
    /// questions.
    pub agent_down_mins: i64,
    /// Time zone of the timestamps in the mail. The dashboard converts to
    /// the browser's; a mail has no browser, and the server does not know
    /// where the recipient sits. Default `UTC` — the one that is never
    /// wrong, only inconvenient.
    pub tz: Tz,
}

/// Recipients from one text field: comma, semicolon, newline or whitespace
/// separate them. Anything empty drops out.
pub fn recipients(s: &str) -> Vec<String> {
    s.split([',', ';', '\n', '\r', ' ', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// An address the way a mail server accepts it. Checked on save, so that a
/// typo shows up there and not only when things are on fire.
pub fn valid_address(s: &str) -> bool {
    s.parse::<Mailbox>().is_ok()
}

/// The setup from the settings. `None` means: off or incomplete — then
/// nobody asks and nobody sends anything. Whoever needs the reason takes
/// `configured`.
pub async fn config(pool: &PgPool) -> Result<Option<Config>> {
    Ok(configured(pool).await?.ok())
}

/// Like `config`, but it names **why** nothing is sent. The worker simply
/// stays quiet; at the test button the reason is everything. "Off or
/// incomplete (server, sender and at least one recipient)" listed three
/// fields and kept quiet about the most common one: the master switch.
/// Whoever has filled in all three then goes and adds SMTP credentials —
/// and gets the same message again.
pub async fn configured(pool: &PgPool) -> Result<std::result::Result<Config, String>> {
    if !db::setting_bool(pool, "smtp_enabled", false).await? {
        return Ok(Err(
            r#"email is switched off - turn on "Send email" at the top of this tab, then save"#
                .into(),
        ));
    }
    let host = db::setting_str(pool, "smtp_host")
        .await?
        .unwrap_or_default();
    let from = db::setting_str(pool, "smtp_from")
        .await?
        .unwrap_or_default();
    let to = recipients(&db::setting_str(pool, "smtp_to").await?.unwrap_or_default());
    let missing: Vec<&str> = [
        ("SMTP server", host.is_empty()),
        ("sender", from.is_empty()),
        ("at least one recipient", to.is_empty()),
    ]
    .into_iter()
    .filter_map(|(name, empty)| empty.then_some(name))
    .collect();
    if !missing.is_empty() {
        return Ok(Err(format!("still missing: {}", missing.join(", "))));
    }
    Ok(Ok(Config {
        host,
        port: db::setting_i64(pool, "smtp_port", 587)
            .await?
            .clamp(1, 65535) as u16,
        security: Security::parse(
            &db::setting_str(pool, "smtp_security")
                .await?
                .unwrap_or_default(),
        ),
        user: db::setting_str(pool, "smtp_user")
            .await?
            .unwrap_or_default(),
        pass: db::setting_str(pool, "smtp_pass")
            .await?
            .unwrap_or_default(),
        from,
        to,
        base_url: db::setting_str(pool, "notify_base_url")
            .await?
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_string(),
        on_alerts: db::setting_bool(pool, "notify_alerts", true).await?,
        on_agent_down: db::setting_bool(pool, "notify_agent_down", true).await?,
        on_abuse: db::setting_bool(pool, "notify_abuse_ip", false).await?,
        abuse_min_score: db::setting_i64(pool, "notify_abuse_min_score", 50).await?,
        digest_mins: db::setting_i64(pool, "notify_digest_mins", 5)
            .await?
            .clamp(1, 1440),
        agent_down_mins: db::setting_i64(pool, "notify_agent_down_mins", 10)
            .await?
            .clamp(1, 1440),
        tz: timezone(pool).await?,
    }))
}

/// What the dashboard shows about sending. In memory: it describes the
/// running process, not the setup — as with AbuseIPDB.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Status {
    /// Mails since the server started.
    pub sent: u64,
    pub last_sent_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

// ---------- Sending ----------

fn transport(cfg: &Config) -> Result<AsyncSmtpTransport<Tokio1Executor>> {
    let b = match cfg.security {
        Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)?,
        Security::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)?,
        Security::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host),
    };
    let mut b = b.port(cfg.port).timeout(Some(SMTP_TIMEOUT));
    // An in-house relay on your own network often accepts without a login;
    // then the field stays empty and `AUTH` is not spoken at all.
    if !cfg.user.is_empty() {
        b = b.credentials(Credentials::new(cfg.user.clone(), cfg.pass.clone()));
    }
    Ok(b.build())
}

/// One mail to all recipients, as text **and** as HTML. Whoever reads in a
/// client without HTML gets the same message.
pub async fn send(cfg: &Config, subject: &str, text: &str, html: &str) -> Result<()> {
    let mut m = Message::builder()
        .from(
            cfg.from
                .parse::<Mailbox>()
                .map_err(|e| anyhow!("sender address {:?}: {e}", cfg.from))?,
        )
        .subject(subject);
    for r in &cfg.to {
        m = m.to(r
            .parse::<Mailbox>()
            .map_err(|e| anyhow!("recipient {r:?}: {e}"))?);
    }
    let msg = m.multipart(MultiPart::alternative_plain_html(
        text.to_string(),
        html.to_string(),
    ))?;
    transport(cfg)?.send(msg).await?;
    Ok(())
}

// ---------- Events ----------

/// An alert, trimmed down to the way it stands in a mail.
#[derive(Debug, Clone, FromRow)]
pub struct AlertLine {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub origin_name: String,
    pub verdict: String,
    pub reason: Option<String>,
    pub user_display: Option<String>,
    pub process: Option<String>,
    pub path: Option<String>,
    pub file_count: i32,
    pub bytes: i64,
    pub remote: Option<String>,
    /// When the server last took it in. Decides how long to wait for a
    /// reputation that is still missing.
    pub received_at: DateTime<Utc>,
    /// Reputation of the destination, filled in from the server's cache —
    /// not from the query: `remote` also carries `1.2.3.4:443` and
    /// `volume /Volumes/Stick`.
    #[sqlx(default)]
    pub score: Option<i32>,
    #[sqlx(default)]
    pub country_code: Option<String>,
}

const ALERT_LINE_COLS: &str = "id, at, origin_name, verdict, reason, user_display, process, path, file_count, bytes, remote, received_at";

/// An agent that stopped reporting — or is back.
#[derive(Debug, Clone, FromRow)]
pub struct AgentLine {
    pub name: String,
    pub last_seen: Option<DateTime<Utc>>,
}

/// What belongs in a mail. Empty means: nothing to report.
#[derive(Debug, Default)]
pub struct Digest {
    pub down: Vec<AgentLine>,
    pub up: Vec<AgentLine>,
    pub alerts: Vec<AlertLine>,
}

impl Digest {
    pub fn is_empty(&self) -> bool {
        self.down.is_empty() && self.up.is_empty() && self.alerts.is_empty()
    }
}

// ---------- Presentation ----------

/// Bytes the way a human reads them. The same scale as in the dashboard.
fn human_bytes(n: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// What is allowed into HTML. Paths, process names and reasons come from a
/// watched machine: they are data, not markup.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A timestamp in the configured zone, with the abbreviation behind it.
/// Without the abbreviation you cannot tell what a bare time means — and a
/// record that is two hours off is worthless.
fn fmt_time(t: DateTime<Utc>, tz: Tz) -> String {
    t.with_timezone(&tz).format("%Y-%m-%d %H:%M %Z").to_string()
}

/// The destination's reputation as an addition behind the address — only
/// if one is known.
fn reputation_note(a: &AlertLine) -> String {
    match a.score {
        Some(s) => match &a.country_code {
            Some(c) => format!(" (AbuseIPDB {s}/100, {c})"),
            None => format!(" (AbuseIPDB {s}/100)"),
        },
        None => String::new(),
    }
}

/// Who or what triggered the flow: for access alerts the user, for
/// endpoint alerts the process.
fn who(a: &AlertLine) -> &str {
    a.user_display
        .as_deref()
        .or(a.process.as_deref())
        .unwrap_or("—")
}

/// One line of the mail. The same file, the same process, the same verdict
/// — but every destination that was spoken to along the way.
///
/// A browser somebody has touched speaks to a dozen CDN addresses in ten
/// minutes, and each one is a flow of its own and therefore an alert of its
/// own. Correct in substance, but as a mail it is the same event seven
/// times over: on 2026-09-09 one message held seven lines for
/// `Zahlen-014.dat` that differed only in the destination. Every alert is
/// still counted, one line is what gets read.
pub struct Group<'a> {
    /// The first alert of the group — it supplies time, origin and path.
    pub head: &'a AlertLine,
    /// Destinations without repetition. The order is made by
    /// [`Group::destination`]: the upload first, then the worst reputation.
    pub dests: Vec<Dest>,
    /// Sum over the group: what went out in total.
    pub bytes: i64,
    /// How many alerts were folded together.
    pub count: usize,
    /// The worst reputation among the destinations — the line is coloured
    /// by it.
    pub worst_score: Option<i32>,
}

/// Fold alerts into lines. The key is what a human reads as *one* event:
/// origin, originator, verdict and path. The order stays that of the first
/// alert per group.
pub fn group(alerts: &[AlertLine]) -> Vec<Group<'_>> {
    let mut out: Vec<Group<'_>> = Vec::new();
    let mut seen: std::collections::HashMap<(String, String, String, String), usize> =
        std::collections::HashMap::new();
    for a in alerts {
        let key = (
            a.origin_name.clone(),
            who(a).to_string(),
            a.verdict.clone(),
            a.path.clone().unwrap_or_default(),
        );
        let dest = Dest {
            text: format!(
                "{}{}",
                a.remote.as_deref().unwrap_or("—"),
                reputation_note(a)
            ),
            score: a.score,
            upload: urgent(a),
        };
        match seen.get(&key) {
            Some(&i) => {
                let g: &mut Group<'_> = &mut out[i];
                if !g.dests.iter().any(|d| d.text == dest.text) {
                    g.dests.push(dest);
                }
                g.bytes = g.bytes.saturating_add(a.bytes);
                g.count += 1;
                g.worst_score = g.worst_score.max(a.score);
            }
            None => {
                seen.insert(key, out.len());
                out.push(Group {
                    head: a,
                    dests: vec![dest],
                    bytes: a.bytes,
                    count: 1,
                    worst_score: a.score,
                });
            }
        }
    }
    out
}

/// One destination of the group, together with what it is sorted by.
pub struct Dest {
    pub text: String,
    pub score: Option<i32>,
    /// An upload is the event itself, not a side connection.
    pub upload: bool,
}

/// This many destinations are listed individually in the line; the rest is
/// counted.
const MAX_DESTS: usize = 3;

impl Group<'_> {
    /// The destination column: a single destination stands there the way
    /// it always did.
    ///
    /// With several of them it is **not** the order of appearance that
    /// decides which three stay visible. On 2026-09-09 a line with ten
    /// destinations held an address with AbuseIPDB 94/100 — it stayed in
    /// the visible part only by chance, and in the line above it the same
    /// number would have vanished among the six that were cut. What stays
    /// visible is what counts: the upload (the event itself), then the
    /// worst reputation.
    fn destination(&self) -> String {
        let mut d: Vec<&Dest> = self.dests.iter().collect();
        d.sort_by_key(|x| (!x.upload, std::cmp::Reverse(x.score.unwrap_or(-1))));
        match d.len() {
            0 => "—".to_string(),
            1 => d[0].text.clone(),
            n => {
                let head = d
                    .iter()
                    .take(MAX_DESTS)
                    .map(|x| x.text.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                if n > MAX_DESTS {
                    format!("{n} destinations: {head}, … (+{})", n - MAX_DESTS)
                } else {
                    format!("{n} destinations: {head}")
                }
            }
        }
    }
}

/// Subject, text body and HTML body. Testable without a network and
/// without a database. `bad_from` is the threshold from the settings
/// (`notify_abuse_min_score`): what the trigger calls bad has to look bad
/// in the mail too.
pub fn render(
    d: &Digest,
    base_url: &str,
    bad_from: i64,
    now: DateTime<Utc>,
    tz: Tz,
) -> (String, String, String) {
    let mut parts = Vec::new();
    // The upload comes first: it is the reason this message did not wait
    // until the end of the digest window (see `urgent`). Whoever reads only
    // the subject line should see that.
    let uploads = d.alerts.iter().filter(|a| urgent(a)).count();
    if uploads > 0 {
        parts.push(format!(
            "{uploads} upload attempt{}",
            if uploads == 1 { "" } else { "s" }
        ));
    }
    if !d.alerts.is_empty() {
        parts.push(format!(
            "{} alert{}",
            d.alerts.len(),
            if d.alerts.len() == 1 { "" } else { "s" }
        ));
    }
    if !d.down.is_empty() {
        parts.push(format!(
            "{} agent{} offline",
            d.down.len(),
            if d.down.len() == 1 { "" } else { "s" }
        ));
    }
    if !d.up.is_empty() {
        parts.push(format!("{} back online", d.up.len()));
    }
    let subject = format!("[DLPrevent] {}", parts.join(", "));

    let link = |path: &str| (!base_url.is_empty()).then(|| format!("{base_url}{path}"));
    let mut text = format!("DLPrevent — {}\n", fmt_time(now, tz));
    let mut html = format!(
        "<div style=\"font:14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a1a1a\">\
         <p style=\"color:#666;margin:0 0 18px\">DLPrevent — {}</p>",
        esc(&fmt_time(now, tz))
    );

    if !d.down.is_empty() {
        text.push_str(&format!("\nAGENTS OFFLINE ({})\n", d.down.len()));
        html.push_str(&format!("<h2 style=\"font-size:15px;margin:18px 0 6px\">Agents offline ({})</h2><ul style=\"margin:0;padding-left:20px\">", d.down.len()));
        for a in &d.down {
            let last = a
                .last_seen
                .map(|t| fmt_time(t, tz))
                .unwrap_or_else(|| "never reported".into());
            text.push_str(&format!("  {} — last report {last}\n", a.name));
            html.push_str(&format!(
                "<li><strong>{}</strong> — last report {}</li>",
                esc(&a.name),
                esc(&last)
            ));
        }
        html.push_str("</ul>");
    }

    if !d.up.is_empty() {
        text.push_str(&format!("\nBACK ONLINE ({})\n", d.up.len()));
        html.push_str(&format!("<h2 style=\"font-size:15px;margin:18px 0 6px\">Back online ({})</h2><ul style=\"margin:0;padding-left:20px\">", d.up.len()));
        for a in &d.up {
            text.push_str(&format!("  {}\n", a.name));
            html.push_str(&format!("<li><strong>{}</strong></li>", esc(&a.name)));
        }
        html.push_str("</ul>");
    }

    if !d.alerts.is_empty() {
        // Folding happens only here: the number in the subject stays that
        // of the alerts, what gets read are the lines.
        let groups = group(&d.alerts);
        let folded = if groups.len() < d.alerts.len() {
            format!(
                " in {} line{}",
                groups.len(),
                if groups.len() == 1 { "" } else { "s" }
            )
        } else {
            String::new()
        };
        text.push_str(&format!("\nALERTS ({}{folded})\n", d.alerts.len()));
        html.push_str(&format!(
            "<h2 style=\"font-size:15px;margin:18px 0 6px\">Alerts ({})</h2>\
             <table style=\"border-collapse:collapse;font-size:13px\"><tr style=\"text-align:left;color:#666\">\
             <th style=\"padding:4px 10px 4px 0\">When</th><th style=\"padding:4px 10px 4px 0\">Verdict</th>\
             <th style=\"padding:4px 10px 4px 0\">Origin</th><th style=\"padding:4px 10px 4px 0\">Who</th>\
             <th style=\"padding:4px 10px 4px 0\">What</th><th style=\"padding:4px 10px 4px 0\">Destination</th></tr>",
            d.alerts.len()
        ));
        for g in groups.iter().take(MAX_LISTED) {
            let a = g.head;
            // An amount only if one flowed. The connector blocks before
            // the first byte goes — "0 B" in every upload line is a column
            // full of zeroes and says nothing.
            let what = match g.bytes {
                0 => format!(
                    "{} — {} file(s)",
                    a.path.as_deref().unwrap_or("—"),
                    a.file_count
                ),
                b => format!(
                    "{} — {} file(s), {}",
                    a.path.as_deref().unwrap_or("—"),
                    a.file_count,
                    human_bytes(b)
                ),
            };
            let dest = g.destination();
            text.push_str(&format!(
                "  {} · {} · {} · {}\n    {what} -> {dest}\n",
                fmt_time(a.at, tz),
                a.verdict,
                a.origin_name,
                who(a)
            ));
            if let Some(r) = a.reason.as_deref().filter(|r| !r.is_empty()) {
                text.push_str(&format!("    reason: {r}\n"));
            }
            let deep = link(&format!("/alerts?alert={}", a.id));
            if let Some(u) = &deep {
                text.push_str(&format!("    {u}\n"));
            }
            // A bad reputation catches the eye without reading the number.
            let bad = g.worst_score.is_some_and(|s| s as i64 >= bad_from);
            // The time column is the handle on the line: one click and the
            // alert stands open on the screen — without having to find it
            // again in a list of a thousand. Without a dashboard address it
            // stays at the bare timestamp; a dead link would be worse.
            //
            // The link points at the head of the group. If the line is
            // folded, its numbers are the sum over all destinations, while
            // those of the destination at the end of the link are only its
            // own share of that. That is the price of a link hitting **one**
            // line: the folding goes over origin, originator, verdict and
            // path, and of those the list can only filter the origin.
            // Whoever wants to see the whole group takes the origin filter
            // in the opened alert.
            let when = match &deep {
                Some(u) => format!(
                    "<a href=\"{}\" style=\"color:#0b57d0\">{}</a>",
                    esc(u),
                    esc(&fmt_time(a.at, tz))
                ),
                None => esc(&fmt_time(a.at, tz)),
            };
            html.push_str(&format!(
                "<tr style=\"border-top:1px solid #eee\"><td style=\"padding:6px 10px 6px 0;white-space:nowrap\">{}</td>\
                 <td style=\"padding:6px 10px 6px 0\"><strong>{}</strong></td><td style=\"padding:6px 10px 6px 0\">{}</td>\
                 <td style=\"padding:6px 10px 6px 0\">{}</td><td style=\"padding:6px 10px 6px 0\">{}</td>\
                 <td style=\"padding:6px 10px 6px 0{}\">{}</td></tr>",
                when,
                esc(&a.verdict),
                esc(&a.origin_name),
                esc(who(a)),
                esc(&what),
                if bad { ";color:#b00020" } else { "" },
                esc(&dest),
            ));
        }
        html.push_str("</table>");
        if groups.len() > MAX_LISTED {
            let more = groups.len() - MAX_LISTED;
            text.push_str(&format!("  … and {more} more\n"));
            html.push_str(&format!("<p style=\"color:#666\">… and {more} more</p>"));
        }
    }

    if let Some(u) = link("/alerts") {
        text.push_str(&format!("\n{u}\n"));
        html.push_str(&format!(
            "<p style=\"margin-top:18px\"><a href=\"{0}\">{0}</a></p>",
            esc(&u)
        ));
    }
    html.push_str("</div>");
    (subject, text, html)
}

/// The test message of the "Send test email" button.
pub fn test_message(cfg: &Config, now: DateTime<Utc>) -> (String, String, String) {
    let tz = cfg.tz;
    let text = format!(
        "DLPrevent — {}\n\nThis is a test. Notifications are set up correctly.\n\nServer: {}:{} ({})\nFrom:   {}\nTo:     {}\n",
        fmt_time(now, tz),
        cfg.host,
        cfg.port,
        cfg.security.label(),
        cfg.from,
        cfg.to.join(", "),
    );
    let html = format!(
        "<div style=\"font:14px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#1a1a1a\">\
         <p style=\"color:#666;margin:0 0 18px\">DLPrevent — {}</p>\
         <p>This is a test. Notifications are set up correctly.</p>\
         <p style=\"color:#666;font-size:13px\">{}:{} ({})<br>from {}<br>to {}</p></div>",
        esc(&fmt_time(now, tz)),
        esc(&cfg.host),
        cfg.port,
        cfg.security.label(),
        esc(&cfg.from),
        esc(&cfg.to.join(", ")),
    );
    ("[DLPrevent] Test message".to_string(), text, html)
}

// ---------- Worker ----------

/// Collects and sends. A task of its own like `retention` and `abuseipdb`:
/// none of them may hold up an agent's report.
pub async fn run(state: Shared, stop: CancellationToken) -> Result<()> {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(SWEEP_SECS)) => {}
            _ = stop.cancelled() => return Ok(()),
        }
        if let Err(e) = sweep(&state).await {
            warn!("notifications: {e:#}");
            state.mail.lock().unwrap().last_error = Some(e.to_string());
        }
    }
}

async fn sweep(state: &Shared) -> Result<()> {
    let pool = &state.pool;
    let Some(cfg) = config(pool).await? else {
        // Off: set the flag anyway. Otherwise the partial index collects
        // every alert of the whole retention period — and switching on
        // would kick off messages years old.
        sqlx::query("UPDATE alerts SET notified_at = now() WHERE notified_at IS NULL")
            .execute(pool)
            .await?;
        return Ok(());
    };
    let (alerts, seen) = pending_alerts(pool, &cfg).await?;

    // Digest window: rather wait than send two hundred mails. What is left
    // lying keeps its flag and comes in the next message.
    //
    // The state is in the database, not only in memory: otherwise every
    // restart of the server lifts the window, and whoever restarts often
    // gets mail by the minute despite an hour-long window.
    //
    // An attempted upload does **not** wait. It is the one case where
    // nobody wants an hour to pass between "seen" and "read": the file is
    // on its way to a foreign service. Everything else keeps collecting —
    // and the urgent message takes it along instead of sending a second one
    // shortly after.
    //
    // This does not get expensive: the worker only looks every minute
    // anyway, so a bulk upload of two hundred files costs one mail, not two
    // hundred.
    if !alerts.iter().any(urgent) {
        let in_memory = state.mail.lock().unwrap().last_sent_at;
        if let Some(last) = last_sent_at(pool, in_memory).await? {
            if Utc::now() - last < chrono::Duration::minutes(cfg.digest_mins) {
                return Ok(());
            }
        }
    }

    let (down, up) = if cfg.on_agent_down {
        agent_changes(pool, cfg.agent_down_mins * 60).await?
    } else {
        (Vec::new(), Vec::new())
    };
    let digest = Digest { down, up, alerts };

    if digest.is_empty() {
        // Nothing to report, but looked at: otherwise the same rows would
        // come through the reputation lookup again every minute.
        mark_alerts(pool, &seen).await?;
        return Ok(());
    }
    let (subject, text, html) = render(
        &digest,
        &cfg.base_url,
        cfg.abuse_min_score,
        Utc::now(),
        cfg.tz,
    );
    send(&cfg, &subject, &text, &html).await?;

    // Only now tick them off. A relay that does not accept therefore costs
    // one repeat — never a swallowed notification.
    mark_alerts(pool, &seen).await?;
    let down_names: Vec<String> = digest.down.iter().map(|a| a.name.clone()).collect();
    let up_names: Vec<String> = digest.up.iter().map(|a| a.name.clone()).collect();
    if !down_names.is_empty() {
        sqlx::query("UPDATE agents SET down_notified_at = now() WHERE name = ANY($1) AND down_notified_at IS NULL").bind(&down_names).execute(pool).await?;
    }
    if !up_names.is_empty() {
        sqlx::query("UPDATE agents SET down_notified_at = NULL WHERE name = ANY($1)")
            .bind(&up_names)
            .execute(pool)
            .await?;
    }
    let now = Utc::now();
    db::set_setting(pool, LAST_SENT_KEY, serde_json::json!(now.to_rfc3339())).await?;
    {
        let mut s = state.mail.lock().unwrap();
        s.sent += 1;
        s.last_sent_at = Some(now);
        s.last_error = None;
    }
    info!(
        alerts = digest.alerts.len(),
        down = down_names.len(),
        up = up_names.len(),
        "notification sent"
    );
    Ok(())
}

/// When the last send happened. Memory is the fast way, the database the
/// surviving one: after a restart what the mutex forgot is still there.
async fn last_sent_at(
    pool: &PgPool,
    in_memory: Option<DateTime<Utc>>,
) -> Result<Option<DateTime<Utc>>> {
    if in_memory.is_some() {
        return Ok(in_memory);
    }
    let Some(s) = db::setting_str(pool, LAST_SENT_KEY).await? else {
        return Ok(None);
    };
    Ok(DateTime::parse_from_rfc3339(&s)
        .ok()
        .map(|t| t.with_timezone(&Utc)))
}

/// What must not wait until the end of the digest window: an upload that
/// was attempted — refused or let through.
///
/// It is recognised by the destination, not by the verdict:
/// `Target::Upload` writes itself into the column as `upload to <URL>`, and
/// only the browser connector knows that form. An ordinary connection to
/// the outside stands there as address and port and keeps collecting.
fn urgent(a: &AlertLine) -> bool {
    a.remote
        .as_deref()
        .is_some_and(|r| r.starts_with("upload to "))
}

/// Tick off every alert in the array — including those not worth a mail.
async fn mark_alerts(pool: &PgPool, ids: &[i64]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query("UPDATE alerts SET notified_at = now() WHERE id = ANY($1)")
        .bind(ids)
        .execute(pool)
        .await?;
    Ok(())
}

/// What gets reported, and what the pass looked at in total. The second is
/// always at least as long as the first: a learning alert is ticked off
/// without anybody reading it.
async fn pending_alerts(pool: &PgPool, cfg: &Config) -> Result<(Vec<AlertLine>, Vec<i64>)> {
    if !cfg.on_alerts && !cfg.on_abuse {
        // Neither of the two triggers: do not even fetch, but tick them
        // off anyway so the partial index stays small.
        let ids: Vec<(i64,)> = sqlx::query_as(
            "SELECT id FROM alerts WHERE notified_at IS NULL ORDER BY received_at LIMIT $1",
        )
        .bind(BATCH)
        .fetch_all(pool)
        .await?;
        return Ok((Vec::new(), ids.into_iter().map(|(i,)| i).collect()));
    }
    let mut rows: Vec<AlertLine> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {ALERT_LINE_COLS} FROM alerts WHERE notified_at IS NULL ORDER BY received_at LIMIT $1"
    )))
    .bind(BATCH)
    .fetch_all(pool)
    .await?;

    // Fill in the destinations' reputation from the cache. Read only: a
    // mail must not trigger a lookup to the outside — the worker in
    // `abuseipdb` is there for that.
    let ips: Vec<String> = rows
        .iter()
        .filter_map(|a| a.remote.as_deref())
        .filter_map(abuseipdb::ip_of)
        .map(|ip| ip.to_string())
        .collect();
    if !ips.is_empty() {
        let known: std::collections::HashMap<String, abuseipdb::Reputation> =
            abuseipdb::cached(pool, &ips)
                .await?
                .into_iter()
                .map(|r| (r.ip.clone(), r))
                .collect();
        for a in &mut rows {
            if let Some(r) = a
                .remote
                .as_deref()
                .and_then(abuseipdb::ip_of)
                .and_then(|ip| known.get(&ip.to_string()))
            {
                a.score = Some(r.score);
                a.country_code = r.country_code.clone();
            }
        }
    }
    let notable = |a: &AlertLine| {
        (cfg.on_alerts && ALARM_VERDICTS.contains(&a.verdict.as_str()))
            || (cfg.on_abuse && a.score.is_some_and(|s| s as i64 >= cfg.abuse_min_score))
    };
    // A public address with no entry in the cache: the reputation may
    // still arrive (see `REPUTATION_GRACE_SECS`). Until then the row stays
    // open — but only if it is not going into this mail anyway. Otherwise
    // it would stand in the next one a second time.
    let waiting_for_reputation = |a: &AlertLine| {
        cfg.on_abuse
            && a.score.is_none()
            && a.received_at > Utc::now() - chrono::Duration::seconds(REPUTATION_GRACE_SECS)
            && a.remote
                .as_deref()
                .and_then(abuseipdb::ip_of)
                .is_some_and(abuseipdb::is_public)
    };
    let seen = rows
        .iter()
        .filter(|a| notable(a) || !waiting_for_reputation(a))
        .map(|a| a.id)
        .collect();
    rows.retain(notable);
    Ok((rows, seen))
}

/// Agents that went down or came back since the last message. "Down" here
/// means: no report for `notify_agent_down_mins`. The dashboard colours
/// earlier (three missed reports) — it may do so, because a colour wakes
/// nobody and a mail does.
///
/// A freshly enrolled agent that has never reported counts from its
/// enrollment — otherwise the down notification would arrive before it
/// could start for the first time.
async fn agent_changes(pool: &PgPool, grace_secs: i64) -> Result<(Vec<AgentLine>, Vec<AgentLine>)> {
    let down: Vec<AgentLine> = sqlx::query_as(
        "SELECT name, last_seen FROM agents \
         WHERE revoked_at IS NULL AND down_notified_at IS NULL \
           AND COALESCE(last_seen, enrolled_at) < now() - ($1::bigint * interval '1 second') \
         ORDER BY name",
    )
    .bind(grace_secs)
    .fetch_all(pool)
    .await?;
    let up: Vec<AgentLine> = sqlx::query_as(
        "SELECT name, last_seen FROM agents \
         WHERE revoked_at IS NULL AND down_notified_at IS NOT NULL \
           AND last_seen > now() - ($1::bigint * interval '1 second') \
         ORDER BY name",
    )
    .bind(grace_secs)
    .fetch_all(pool)
    .await?;
    Ok((down, up))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(verdict: &str, score: Option<i32>) -> AlertLine {
        AlertLine {
            id: 7,
            at: "2026-09-08T12:00:00Z".parse().unwrap(),
            origin_name: "srv01".into(),
            verdict: verdict.into(),
            reason: Some("destination not allowed".into()),
            user_display: Some("dl-anna".into()),
            process: None,
            path: Some("G:\\GL\\Q3".into()),
            file_count: 412,
            bytes: 1_288_490_188,
            remote: Some("203.0.113.9:443".into()),
            received_at: "2026-09-08T12:00:00Z".parse().unwrap(),
            score,
            country_code: score.map(|_| "RU".into()),
        }
    }

    #[test]
    fn recipients_come_from_one_field_however_it_is_typed() {
        assert_eq!(
            recipients("a@x.ch, b@x.ch;c@x.ch\n d@x.ch"),
            ["a@x.ch", "b@x.ch", "c@x.ch", "d@x.ch"]
        );
        assert!(recipients("  ,; \n ").is_empty());
        assert!(valid_address("a@x.ch"));
        assert!(valid_address("Nachtdienst <a@x.ch>"));
        assert!(!valid_address("kein-mail"));
        assert!(!valid_address(""));
    }

    #[test]
    fn transport_security_falls_back_to_the_safe_answer() {
        assert_eq!(Security::parse("none"), Security::None);
        assert_eq!(Security::parse("tls"), Security::Tls);
        assert_eq!(Security::parse("starttls"), Security::StartTls);
        assert_eq!(
            Security::parse(""),
            Security::StartTls,
            "leer darf nicht Klartext heissen"
        );
        assert_eq!(Security::parse("plaintext-please"), Security::StartTls);
    }

    /// The subject says in one line what is going on — it is the only
    /// thing that arrives on a lock screen.
    #[test]
    fn the_subject_names_every_section() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let d = Digest {
            down: vec![AgentLine {
                name: "srv01".into(),
                last_seen: None,
            }],
            up: vec![AgentLine {
                name: "ws-anna".into(),
                last_seen: Some(now),
            }],
            alerts: vec![alert("denied", None)],
        };
        let (subject, _, _) = render(&d, "", 50, now, Tz::UTC);
        assert_eq!(
            subject,
            "[DLPrevent] 1 alert, 1 agent offline, 1 back online"
        );

        let only_alerts = Digest {
            alerts: vec![alert("denied", None), alert("hard_limit", None)],
            ..Default::default()
        };
        assert_eq!(
            render(&only_alerts, "", 50, now, Tz::UTC).0,
            "[DLPrevent] 2 alerts"
        );
    }

    /// Paths, process names and reasons come from a watched machine. In
    /// the HTML part they are data, never markup.
    #[test]
    fn content_from_a_watched_machine_cannot_become_markup() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let mut a = alert("denied", None);
        a.path = Some("C:\\<script>alert(1)</script>\\x".into());
        a.origin_name = "a\"b".into();
        let d = Digest {
            alerts: vec![a],
            ..Default::default()
        };
        let (_, text, html) = render(&d, "", 50, now, Tz::UTC);
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(html.contains("a&quot;b"), "{html}");
        // The text part stays text: there is nothing to defuse there.
        assert!(text.contains("<script>"));
    }

    #[test]
    fn a_bad_destination_is_named_with_its_score() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let d = Digest {
            alerts: vec![alert("new", Some(91))],
            ..Default::default()
        };
        let (_, text, html) = render(&d, "https://dlp.example/", 50, now, Tz::UTC);
        assert!(
            text.contains("203.0.113.9:443 (AbuseIPDB 91/100, RU)"),
            "{text}"
        );
        assert!(html.contains("AbuseIPDB 91/100, RU"), "{html}");
        assert!(
            html.contains("#b00020"),
            "ein schlechter Ruf faellt ins Auge: {html}"
        );
        // Whoever raises the threshold no longer wants to see 91 in red:
        // the colour has to follow the same number as the trigger.
        assert!(
            !render(&d, "", 95, now, Tz::UTC).2.contains("#b00020"),
            "die Farbe haengt an der Einstellung"
        );
        // Without a reputation only the address stands there, no empty
        // pair of brackets.
        let plain = Digest {
            alerts: vec![alert("denied", None)],
            ..Default::default()
        };
        assert!(
            render(&plain, "", 50, now, Tz::UTC)
                .1
                .contains("203.0.113.9:443\n"),
            "{:?}",
            render(&plain, "", 50, now, Tz::UTC).1
        );
    }

    /// Without a dashboard address there is no link in the mail — a dead
    /// link is worse than none.
    #[test]
    fn links_appear_only_with_a_dashboard_address() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let d = Digest {
            alerts: vec![alert("denied", None)],
            ..Default::default()
        };
        let (_, text, html) = render(&d, "", 50, now, Tz::UTC);
        assert!(!text.contains("http"), "{text}");
        assert!(!html.contains("href"), "{html}");
        // The trailing slash is trimmed on load, here stands the already
        // shortened form.
        let (_, text, html) = render(&d, "https://dlp.example", 50, now, Tz::UTC);
        assert!(text.contains("https://dlp.example/alerts\n"), "{text}");
        assert!(
            text.contains("https://dlp.example/alerts?alert=7"),
            "{text}"
        );
        assert!(
            html.contains("href=\"https://dlp.example/alerts\""),
            "{html}"
        );
        // The per-line link belongs in **both** parts. Whoever reads HTML —
        // that is nearly everybody — had only the collective link at the
        // foot until 2026-09-11 and got to look for the alert themselves.
        assert!(
            html.contains("href=\"https://dlp.example/alerts?alert=7\""),
            "{html}"
        );
    }

    /// An attempted upload does not wait for the end of the digest window —
    /// and takes along whatever else is open. Everything else keeps
    /// collecting.
    #[sqlx::test(migrations = "./migrations")]
    async fn an_upload_does_not_wait_for_the_window(pool: PgPool) {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        for (k, v) in [
            ("smtp_enabled", serde_json::json!(true)),
            ("smtp_host", serde_json::json!("127.0.0.1")),
            // Nothing listens here: if the pass gets as far as sending, it
            // fails — and that is exactly how the test sees that it got
            // that far at all.
            ("smtp_port", serde_json::json!(1)),
            ("smtp_security", serde_json::json!("none")),
            ("smtp_from", serde_json::json!("dlp@x.ch")),
            ("smtp_to", serde_json::json!("ops@x.ch")),
            ("notify_digest_mins", serde_json::json!(60)),
        ] {
            db::set_setting(&pool, k, v).await.unwrap();
        }
        let dir = std::env::temp_dir().join(format!("deelpe-mail-test-{}", uuid::Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let state: Shared = std::sync::Arc::new(crate::state::AppState::new(
            pool.clone(),
            std::sync::Arc::new(pki),
            false,
            8444,
            false,
            dir,
        ));
        state.mail.lock().unwrap().last_sent_at = Some(Utc::now());

        // An ordinary alert inside the window: nothing happens.
        add_alert(&pool, "a1", "denied", Some("203.0.113.9:443")).await;
        sweep(&state).await.expect("im Fenster wird nicht gewaehlt");

        // Now an upload — the pass runs all the way through to sending and
        // only fails at the relay.
        add_alert(
            &pool,
            "a2",
            "denied",
            Some("upload to https://gemini.google.com/app"),
        )
        .await;
        let err = sweep(&state)
            .await
            .expect_err("der Upload treibt den Durchgang bis zum Relay");
        assert!(
            format!("{err:#}").to_lowercase().contains("connect"),
            "{err:#}"
        );

        // Nothing ticked off, because nothing went out.
        let (open,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM alerts WHERE notified_at IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(open, 2, "der Versand schlug fehl, also bleibt beides offen");
    }

    /// The subject says first why the message did not wait.
    #[test]
    fn the_subject_leads_with_the_upload() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let mut up = alert("denied", None);
        up.remote = Some("upload to https://gemini.google.com/app".into());
        let d = Digest {
            alerts: vec![up, alert("denied", None)],
            ..Default::default()
        };
        let (subject, _, _) = render(&d, "", 50, now, Tz::UTC);
        assert_eq!(
            subject, "[DLPrevent] 1 upload attempt, 2 alerts",
            "{subject}"
        );
    }

    /// A browser somebody has touched speaks to many addresses; the file is
    /// the same. Seven alerts are seven alerts, but one line.
    #[test]
    fn one_file_to_many_destinations_is_one_line() {
        let mut rows = Vec::new();
        for ip in [
            "34.107.243.93:443",
            "172.217.208.132:443",
            "151.101.1.91:443",
            "151.101.129.91:443",
            "34.54.185.247:443",
        ] {
            let mut a = alert("denied", None);
            a.path = Some(r"\\srv\GL\Zahlen-014.dat".into());
            a.process = Some("firefox.exe".into());
            a.remote = Some(ip.to_string());
            a.bytes = 10;
            rows.push(a);
        }
        // The same address twice counts as an alert, not as a destination.
        let mut again = rows[0].clone();
        again.id = 99;
        rows.push(again);

        let g = group(&rows);
        assert_eq!(g.len(), 1, "eine Datei, ein Prozess, ein Urteil");
        assert_eq!(g[0].count, 6, "alle Warnungen bleiben gezaehlt");
        assert_eq!(g[0].dests.len(), 5, "jede Adresse einmal");
        assert_eq!(g[0].bytes, 60, "die Mengen werden summiert");
        // Without a reputation and without an upload the order of
        // appearance stays.
        let d = g[0].destination();
        assert!(
            d.starts_with(
                "5 destinations: 34.107.243.93:443, 172.217.208.132:443, 151.101.1.91:443, … (+2)"
            ),
            "{d}"
        );

        // A different file stays a line of its own.
        let mut other = rows[0].clone();
        other.path = Some(r"\\srv\GL\Loehne.dat".into());
        rows.push(other);
        assert_eq!(group(&rows).len(), 2);
    }

    /// What gets cut off is not decided by the order of appearance. On
    /// 2026-09-09 an address with AbuseIPDB 94/100 was still in the visible
    /// part of a line with ten destinations only by chance.
    #[test]
    fn the_worst_destination_never_falls_off_the_end() {
        let mut rows = Vec::new();
        // Eight harmless ones first, then the bad one, then the upload: in
        // the order of appearance both would be invisible.
        for i in 0..8 {
            let mut a = alert("denied", Some(0));
            a.remote = Some(format!("10.0.0.{i}:443"));
            rows.push(a);
        }
        let mut bad = alert("denied", Some(94));
        bad.remote = Some("34.107.243.93:443".into());
        rows.push(bad);
        let mut up = alert("denied", None);
        up.remote = Some("upload to https://gemini.google.com/app".into());
        rows.push(up);

        let g = group(&rows);
        assert_eq!(g.len(), 1);
        let d = g[0].destination();
        assert!(
            d.starts_with(
                "10 destinations: upload to https://gemini.google.com/app, 34.107.243.93:443"
            ),
            "{d}"
        );
        assert!(d.ends_with("… (+7)"), "{d}");
    }

    /// The connector blocks before a byte goes. A column full of zeroes
    /// says nothing — the amount only stands there if one flowed.
    #[test]
    fn a_blocked_upload_shows_no_byte_count() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let mut up = alert("denied", None);
        up.remote = Some("upload to https://gemini.google.com/app".into());
        up.path = Some(r"\\srv\GL\Zahlen.dat".into());
        up.bytes = 0;
        up.file_count = 1;
        let (_, text, _) = render(
            &Digest {
                alerts: vec![up.clone()],
                ..Default::default()
            },
            "",
            50,
            now,
            Tz::UTC,
        );
        assert!(
            text.contains(r"\\srv\GL\Zahlen.dat — 1 file(s) ->"),
            "{text}"
        );
        assert!(!text.contains("0 B"), "{text}");

        // If something flowed, it still stands there.
        let flowed = AlertLine { bytes: 4096, ..up };
        let (_, text, _) = render(
            &Digest {
                alerts: vec![flowed],
                ..Default::default()
            },
            "",
            50,
            now,
            Tz::UTC,
        );
        assert!(text.contains("1 file(s), 4.0 KB"), "{text}");
    }

    /// A single destination stands there the way it always did — no count
    /// that nobody needs.
    #[test]
    fn a_single_destination_reads_as_before() {
        let mut a = alert("denied", None);
        a.remote = Some("1.2.3.4:443".into());
        let g = group(std::slice::from_ref(&a));
        assert_eq!(g[0].destination(), "1.2.3.4:443");
        assert_eq!(g[0].count, 1);
    }

    /// The cut is made by **lines**, not by alerts: that is what the reader
    /// scrolls. Hence one file of its own per alert.
    #[test]
    fn long_digests_are_cut_and_counted() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let alerts = (0..MAX_LISTED + 3)
            .map(|i| {
                let mut a = alert("denied", None);
                a.path = Some(format!(r"G:\GL\Q3\datei-{i}.dat"));
                a
            })
            .collect();
        let d = Digest {
            alerts,
            ..Default::default()
        };
        let (subject, text, html) = render(&d, "", 50, now, Tz::UTC);
        assert!(
            subject.contains(&format!("{} alerts", MAX_LISTED + 3)),
            "{subject}"
        );
        assert!(text.contains("… and 3 more"), "{text}");
        assert!(html.contains("… and 3 more"), "{html}");
    }

    /// The same operation, reported a hundred times over, is one line — and
    /// the subject still says how many alerts stand behind it.
    #[test]
    fn the_subject_counts_alerts_the_body_counts_lines() {
        let now = "2026-09-08T12:05:00Z".parse().unwrap();
        let d = Digest {
            alerts: (0..MAX_LISTED + 3).map(|_| alert("denied", None)).collect(),
            ..Default::default()
        };
        let (subject, text, _) = render(&d, "", 50, now, Tz::UTC);
        assert!(
            subject.contains(&format!("{} alerts", MAX_LISTED + 3)),
            "{subject}"
        );
        assert!(
            text.contains(&format!("ALERTS ({} in 1 line)", MAX_LISTED + 3)),
            "{text}"
        );
        assert!(
            !text.contains("more"),
            "nichts abgeschnitten, es ist ja eine Zeile: {text}"
        );
    }

    /// The mail converts into the configured zone and writes the
    /// abbreviation with it. Summer and winter time differ, and that is
    /// exactly where a fixed offset fails.
    #[test]
    fn the_email_speaks_the_local_time_including_its_name() {
        let zurich: Tz = "Europe/Zurich".parse().unwrap();
        let sommer = "2026-09-09T14:01:00Z".parse().unwrap();
        assert_eq!(fmt_time(sommer, zurich), "2026-09-09 16:01 CEST");
        let winter = "2026-01-15T14:01:00Z".parse().unwrap();
        assert_eq!(
            fmt_time(winter, zurich),
            "2026-01-15 15:01 CET",
            "im Winter eine Stunde weniger"
        );
        assert_eq!(fmt_time(sommer, Tz::UTC), "2026-09-09 14:01 UTC");

        // And the time really does stand that way in the message.
        let d = Digest {
            alerts: vec![alert("denied", None)],
            ..Default::default()
        };
        let (_, text, _) = render(&d, "", 50, sommer, zurich);
        assert!(text.contains("DLPrevent — 2026-09-09 16:01 CEST"), "{text}");
    }

    #[test]
    fn bytes_read_like_the_dashboard() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1_288_490_188), "1.2 GB");
    }

    // ---------- Against the database ----------
    //
    // What can go wrong here is not the formatting but the bookkeeping: a
    // notification twice, one swallowed, or a flag that never gets set and
    // lets the partial index fill up. Needs `DATABASE_URL` pointing at a
    // development database, see docs/SERVER.md.

    fn cfg(on_alerts: bool, on_abuse: bool) -> Config {
        Config {
            host: "localhost".into(),
            port: 587,
            security: Security::StartTls,
            user: String::new(),
            pass: String::new(),
            from: "dlp@x.ch".into(),
            to: vec!["ops@x.ch".into()],
            base_url: String::new(),
            on_alerts,
            on_agent_down: true,
            on_abuse,
            abuse_min_score: 50,
            digest_mins: 5,
            agent_down_mins: 10,
            tz: Tz::UTC,
        }
    }

    fn reputation(ip: &str, score: i32) -> abuseipdb::Reputation {
        abuseipdb::Reputation {
            ip: ip.into(),
            score,
            country_code: Some("RU".into()),
            isp: None,
            domain: None,
            usage_type: None,
            total_reports: 42,
            is_tor: false,
            is_whitelisted: false,
            checked_at: Utc::now(),
        }
    }

    async fn add_alert(
        pool: &PgPool,
        external_id: &str,
        verdict: &str,
        remote: Option<&str>,
    ) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO alerts (kind, origin_name, external_id, at, verdict, remote, detail) \
             VALUES ('access', 'srv01', $1, now(), $2, $3, '{}') RETURNING id",
        )
        .bind(external_id)
        .bind(verdict)
        .bind(remote)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn add_agent(pool: &PgPool, name: &str, last_seen_mins_ago: Option<i64>) {
        sqlx::query(
            "INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after, enrolled_at, last_seen) \
             VALUES (gen_random_uuid(), $1, 'windows', '0.1.0', $1, now() + interval '1 day', \
                     now() - interval '1 day', CASE WHEN $2::bigint IS NULL THEN NULL ELSE now() - ($2 * interval '1 minute') END)",
        )
        .bind(name)
        .bind(last_seen_mins_ago)
        .execute(pool)
        .await
        .unwrap();
    }

    /// What gets reported is whatever has a verdict or a bad destination —
    /// ticked off is **everything** the pass looked at. Otherwise the
    /// partial index fills up with every learning alert and the reputation
    /// lookup repeats itself every minute.
    #[sqlx::test(migrations = "./migrations")]
    async fn only_alarms_are_mailed_but_everything_seen_is_ticked_off(pool: PgPool) {
        let denied = add_alert(&pool, "a1", "denied", Some("203.0.113.9:443")).await;
        let learning = add_alert(&pool, "a2", "learning", None).await;
        let known_bad = add_alert(&pool, "a3", "known", Some("198.51.100.7")).await;
        abuseipdb::store(&pool, &reputation("198.51.100.7", 91))
            .await
            .unwrap();

        // Alerts only: the bad destination under "known" is left lying.
        let (mailed, seen) = pending_alerts(&pool, &cfg(true, false)).await.unwrap();
        assert_eq!(mailed.iter().map(|a| a.id).collect::<Vec<_>>(), [denied]);
        assert_eq!(seen.len(), 3, "abgehakt wird alles: {seen:?}");

        // With the reputation trigger it joins in — score and country and all.
        let (mailed, _) = pending_alerts(&pool, &cfg(true, true)).await.unwrap();
        assert_eq!(
            mailed.iter().map(|a| a.id).collect::<Vec<_>>(),
            [denied, known_bad]
        );
        let bad = mailed.iter().find(|a| a.id == known_bad).unwrap();
        assert_eq!(
            (bad.score, bad.country_code.as_deref()),
            (Some(91), Some("RU"))
        );
        // The address with a port does not find its reputation in the cache
        // — there it stands bare. No hit is correct, a wrong one would be
        // bad.
        assert_eq!(mailed.iter().find(|a| a.id == denied).unwrap().score, None);

        // Both triggers off: nothing to report, but everything ticked off
        // anyway.
        let (mailed, seen) = pending_alerts(&pool, &cfg(false, false)).await.unwrap();
        assert!(mailed.is_empty());
        assert_eq!(seen.len(), 3);

        mark_alerts(&pool, &seen).await.unwrap();
        let (mailed, seen) = pending_alerts(&pool, &cfg(true, true)).await.unwrap();
        assert!(
            mailed.is_empty() && seen.is_empty(),
            "abgehakt heisst: kein zweites Mal"
        );
        let _ = learning;
    }

    /// The reputation trigger hangs off a table that another worker fills.
    /// If a fresh alert is ticked off right away, it is closed before
    /// AbuseIPDB has answered — and the trigger would only fire for
    /// addresses that happen to be in the cache already from an older
    /// alert. Exactly the case the requirement asks for ("or is an abuse
    /// IP") would then quietly come to nothing.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_fresh_alert_waits_for_its_reputation_before_it_is_ticked_off(pool: PgPool) {
        let fresh = add_alert(&pool, "a1", "known", Some("8.8.8.8")).await;
        add_alert(&pool, "a2", "known", Some("10.0.0.5")).await; // private: never looked up
        add_alert(&pool, "a3", "known", Some("volume /Volumes/Stick")).await; // no address
        let alarm = add_alert(&pool, "a4", "denied", Some("1.2.3.4")).await;

        // Nothing in the cache yet: only the public address is held back.
        let (mailed, seen) = pending_alerts(&pool, &cfg(true, true)).await.unwrap();
        assert_eq!(mailed.iter().map(|a| a.id).collect::<Vec<_>>(), [alarm]);
        assert!(
            !seen.contains(&fresh),
            "auf den Ruf wird gewartet: {seen:?}"
        );
        assert_eq!(seen.len(), 3, "alles andere wird abgehakt: {seen:?}");
        // The held-back row too, if it is reported anyway — otherwise it
        // would stand in the next mail a second time.
        assert!(seen.contains(&alarm));

        // Without the reputation trigger nothing waits: then the cache
        // plays no part.
        assert_eq!(
            pending_alerts(&pool, &cfg(true, false))
                .await
                .unwrap()
                .1
                .len(),
            4
        );

        // The worker answers — now it is reported and ticked off.
        abuseipdb::store(&pool, &reputation("8.8.8.8", 91))
            .await
            .unwrap();
        let (mailed, seen) = pending_alerts(&pool, &cfg(true, true)).await.unwrap();
        assert!(mailed.iter().any(|a| a.id == fresh), "{mailed:?}");
        assert!(seen.contains(&fresh));

        // And if it never answers, the row does not stay open forever.
        sqlx::query("UPDATE alerts SET received_at = now() - ($1::bigint * interval '1 second') WHERE id = $2")
            .bind(REPUTATION_GRACE_SECS + 60)
            .bind(fresh)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM ip_reputations")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            pending_alerts(&pool, &cfg(true, true))
                .await
                .unwrap()
                .1
                .contains(&fresh),
            "nach der Frist wird abgehakt"
        );
    }

    /// One notification per outage, one per return — not one per minute
    /// for as long as the machine stays off.
    #[sqlx::test(migrations = "./migrations")]
    async fn an_agent_is_reported_down_once_and_up_once(pool: PgPool) {
        let grace = 10 * 60; // `notify_agent_down_mins`, default ten minutes
        add_agent(&pool, "srv01", Some(30)).await; // silent for 30 min
        add_agent(&pool, "ws-anna", Some(0)).await; // reporting right now
                                                    // Freshly enrolled, never reported: `enrolled_at` lies a day back,
                                                    // so that one counts as down too.
        add_agent(&pool, "neu", None).await;

        let (down, up) = agent_changes(&pool, grace).await.unwrap();
        assert_eq!(
            down.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["neu", "srv01"]
        );
        assert!(up.is_empty());

        let names: Vec<String> = down.iter().map(|a| a.name.clone()).collect();
        sqlx::query("UPDATE agents SET down_notified_at = now() WHERE name = ANY($1)")
            .bind(&names)
            .execute(&pool)
            .await
            .unwrap();
        let (down, up) = agent_changes(&pool, grace).await.unwrap();
        assert!(down.is_empty(), "einmal gemeldet reicht: {down:?}");
        assert!(up.is_empty());

        // srv01 reports back.
        sqlx::query("UPDATE agents SET last_seen = now() WHERE name = 'srv01'")
            .execute(&pool)
            .await
            .unwrap();
        let (_, up) = agent_changes(&pool, grace).await.unwrap();
        assert_eq!(
            up.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            ["srv01"]
        );
        sqlx::query("UPDATE agents SET down_notified_at = NULL WHERE name = 'srv01'")
            .execute(&pool)
            .await
            .unwrap();
        let (down, up) = agent_changes(&pool, grace).await.unwrap();
        assert!(
            down.is_empty() && up.is_empty(),
            "danach ist Ruhe: {down:?} {up:?}"
        );

        // A revoked agent never reports again; that is not worth a
        // message.
        sqlx::query(
            "UPDATE agents SET revoked_at = now(), down_notified_at = NULL WHERE name = 'neu'",
        )
        .execute(&pool)
        .await
        .unwrap();
        assert!(agent_changes(&pool, grace).await.unwrap().0.is_empty());
    }

    /// The test button has to say **what** is missing. "Off or incomplete
    /// (server, sender and at least one recipient)" did not name the master
    /// switch — and whoever has filled in the three fields it does name
    /// then goes and adds SMTP credentials and sees the same message again
    /// (as happened on 2026-09-09, for seven saves in a row).
    #[sqlx::test(migrations = "./migrations")]
    async fn the_reason_names_the_master_switch_before_it_names_a_field(pool: PgPool) {
        let reason = |r: std::result::Result<Config, String>| r.err().unwrap_or_default();

        // Everything filled in, only the switch off: exactly the user's case.
        for (k, v) in [
            ("smtp_host", "smtp.example.com"),
            ("smtp_from", "a@x.ch"),
            ("smtp_to", "b@x.ch"),
        ] {
            db::set_setting(&pool, k, serde_json::json!(v))
                .await
                .unwrap();
        }
        let off = reason(configured(&pool).await.unwrap());
        assert!(
            off.contains("switched off") && off.contains("Send email"),
            "{off}"
        );

        // Switch on, sender and recipient missing: both are named.
        db::set_setting(&pool, "smtp_enabled", serde_json::json!(true))
            .await
            .unwrap();
        db::set_setting(&pool, "smtp_from", serde_json::json!(""))
            .await
            .unwrap();
        db::set_setting(&pool, "smtp_to", serde_json::json!(" , ; "))
            .await
            .unwrap();
        assert_eq!(
            reason(configured(&pool).await.unwrap()),
            "still missing: sender, at least one recipient"
        );

        // Complete: no reason left, and `config` sees the same setup.
        db::set_setting(&pool, "smtp_from", serde_json::json!("a@x.ch"))
            .await
            .unwrap();
        db::set_setting(&pool, "smtp_to", serde_json::json!("b@x.ch"))
            .await
            .unwrap();
        assert_eq!(configured(&pool).await.unwrap().unwrap().to, ["b@x.ch"]);
        assert!(config(&pool).await.unwrap().is_some());
    }

    /// Master switch off: no mail goes out, but the flag is set anyway.
    /// Otherwise switching on would kick off messages months old — and
    /// until then the partial index carries the whole retention period.
    #[sqlx::test(migrations = "./migrations")]
    async fn switched_off_still_ticks_the_alerts_off(pool: PgPool) {
        add_alert(&pool, "a1", "denied", None).await;
        // As in main(): a working build can have more than one TLS provider
        // in it, and `Pki` builds rustls configurations.
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let dir = std::env::temp_dir().join(format!("deelpe-mail-test-{}", uuid::Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let state: Shared = std::sync::Arc::new(crate::state::AppState::new(
            pool.clone(),
            std::sync::Arc::new(pki),
            false,
            8444,
            false,
            dir,
        ));

        assert!(config(&pool).await.unwrap().is_none(), "ab Werk aus");
        sweep(&state).await.unwrap();
        let (open,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM alerts WHERE notified_at IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(open, 0, "abgehakt, obwohl niemand eine Mail bekommen hat");
        assert_eq!(state.mail.lock().unwrap().sent, 0);
    }

    /// The digest window is the only way a notification is left lying. It
    /// has to stay **open** while it does: if the pass ticked it off and
    /// then did not send, it would be swallowed forever.
    #[sqlx::test(migrations = "./migrations")]
    async fn inside_the_digest_window_nothing_is_sent_and_nothing_is_lost(pool: PgPool) {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        add_alert(&pool, "a1", "denied", None).await;
        for (k, v) in [
            ("smtp_enabled", serde_json::json!(true)),
            ("smtp_host", serde_json::json!("127.0.0.1")),
            // A port nothing listens on: if the pass got as far as
            // sending, it would fail — and the test would see it.
            ("smtp_port", serde_json::json!(1)),
            ("smtp_security", serde_json::json!("none")),
            ("smtp_from", serde_json::json!("dlp@x.ch")),
            ("smtp_to", serde_json::json!("ops@x.ch")),
            ("notify_digest_mins", serde_json::json!(60)),
        ] {
            db::set_setting(&pool, k, v).await.unwrap();
        }
        let dir = std::env::temp_dir().join(format!("deelpe-mail-test-{}", uuid::Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let state: Shared = std::sync::Arc::new(crate::state::AppState::new(
            pool.clone(),
            std::sync::Arc::new(pki),
            false,
            8444,
            false,
            dir,
        ));
        state.mail.lock().unwrap().last_sent_at = Some(Utc::now());

        sweep(&state)
            .await
            .expect("im Fenster wird gar nicht erst gewaehlt");
        let (open,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM alerts WHERE notified_at IS NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(open, 1, "was nicht verschickt wurde, bleibt offen");
        assert_eq!(state.mail.lock().unwrap().sent, 0);
    }

    /// A restart of the server must not lift the digest window. Before, the
    /// state stood only in the mutex: whoever restarted often got mail by
    /// the minute despite an hour-long window.
    #[sqlx::test(migrations = "./migrations")]
    async fn the_digest_window_survives_a_restart(pool: PgPool) {
        assert!(
            last_sent_at(&pool, None).await.unwrap().is_none(),
            "ohne Eintrag ist nichts bekannt"
        );

        let sent = Utc::now() - chrono::Duration::minutes(3);
        db::set_setting(&pool, LAST_SENT_KEY, serde_json::json!(sent.to_rfc3339()))
            .await
            .unwrap();

        // Fresh process, empty mutex: the state comes from the database.
        let from_db = last_sent_at(&pool, None)
            .await
            .unwrap()
            .expect("aus der Datenbank");
        assert!(
            (from_db - sent).num_seconds().abs() < 2,
            "{from_db} != {sent}"
        );

        // Memory stays the fast way when it knows something.
        let newer = Utc::now();
        assert_eq!(last_sent_at(&pool, Some(newer)).await.unwrap(), Some(newer));
    }
}
