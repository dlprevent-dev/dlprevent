//! AI assistance: explain a single alert in plain language.
//!
//! The occasion is not automation but legwork. Whoever wants to judge an
//! alert sees one line today — and gathers the rest by hand: the rule that
//! matched; the reputation of the destination address; what the same user
//! did otherwise this week; whether the process stands out on other devices
//! too; and what stood in the agent's log around that minute. [`dossier`]
//! makes these five queries, and out of them the model writes three
//! paragraphs. Nothing is decided: no verdict changes, no alert is closed,
//! no agent gets an instruction.
//!
//! **One provider in the code, two in practice.** Ollama and Infomaniak
//! both speak the OpenAI shape; that makes the provider not a case in the
//! code but a base URL in the settings:
//!
//! - Ollama in your own network: `http://10.0.0.5:11434/v1`, no key.
//!   Nothing leaves the house.
//! - Infomaniak AI Tools: `https://api.infomaniak.com/2/ai/<product_id>/openai/v1`
//!   with a key. The data stays in Switzerland and, according to the
//!   provider, is not used for training — but it does leave the network.
//!
//! Which of the two situations applies is decided by the address an
//! administrator enters, and by nothing else. That is why the dossier that
//! went out is kept word for word in `alert_insights.prompt`: in a tool
//! against data loss the question "what exactly went out there?" must not
//! be unanswerable.
//!
//! Unlike the IP reputation, **no worker runs in the background** here.
//! What gets explained is what somebody clicks. That keeps the cost visible
//! and prevents alert data from flowing outwards on its own and unnoticed.

use crate::abuseipdb;
use crate::db::{self, AlertRow, RuleRow, ALERT_COLS, RULE_COLS};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use std::fmt::Write as _;
use std::time::Duration;
use uuid::Uuid;

/// What gets appended to the base URL. The same line for Ollama as for
/// Infomaniak — that is the whole reason there is one setting instead of a
/// provider list.
const PATH: &str = "/chat/completions";

/// A model on an office machine without a graphics card easily takes a
/// minute for this answer. Three are generous and still finite.
const TIMEOUT: Duration = Duration::from_secs(180);

/// Length of the answer. Three short paragraphs, no more — whoever wants
/// an essay reads the raw data.
const MAX_TOKENS: u32 = 700;

/// Upper limit of the dossier in characters. A small local model often has
/// only 4k or 8k tokens of context; if it overruns it does not answer with
/// an error but with nonsense about the beginning of the text. Better to
/// cut off up front what sits at the end, and to write that down with it.
const MAX_PROMPT: usize = 12_000;

/// This many file names the dossier lists. A mass access has thousands; the
/// first twenty say what it is about, the rest only costs context.
const MAX_FILES: usize = 20;

/// Log lines of the agent around the event.
const MAX_LOG_LINES: i64 = 60;
const LOG_WINDOW_MINS: i64 = 10;

/// How far back the user's history reaches.
const USER_HISTORY_DAYS: i64 = 7;
/// And that of the process across the whole fleet.
const PROCESS_HISTORY_DAYS: i64 = 30;

/// What the three paragraphs should contain — and what not. The last
/// sentence is the most important one: a model that is not allowed to
/// invent is usable as groundwork; one that guesses is worse than none.
const SYSTEM: &str = "You are assisting a data-loss-prevention administrator. You are given a dossier that a monitoring server assembled about one alert. \
Write a short briefing in English with exactly these three parts, each on its own line and prefixed with its heading:\n\
What happened: two or three sentences in plain language.\n\
Why it was flagged: one or two sentences naming the rule or threshold that applies.\n\
What to check next: at most three short bullet points starting with \"- \".\n\n\
Rules: use only facts from the dossier. Never invent a file name, address, user, rule or number. \
If the dossier does not answer something that matters, say so instead of guessing. \
Do not decide whether this is an incident and do not recommend closing or escalating the alert - the administrator decides that. \
No preamble, no closing remark, no markdown headings.";

// ---------- Setup ----------

#[derive(Debug, Clone)]
pub struct Config {
    /// Without a trailing slash; `PATH` appends itself.
    pub base_url: String,
    pub model: String,
    /// Empty means: no `Authorization` header. Ollama does not want one.
    pub key: String,
    pub daily_limit: i64,
}

impl Config {
    pub fn endpoint(&self) -> String {
        format!("{}{PATH}", self.base_url)
    }

    /// Is the server talking to a service outside this network? The
    /// dashboard writes it next to the switch, so that nobody has to read
    /// the question "do our alerts leave the house?" off a URL.
    pub fn external(&self) -> bool {
        let host = host_of(&self.base_url);
        let host = host.as_str();
        match abuseipdb::ip_of(host) {
            // An address answers the question by itself: public means
            // outside, everything else is our own network.
            Some(ip) => abuseipdb::is_public(ip),
            // A name does not — except this one, which every Ollama
            // carries. When in doubt "outside": the more cautious of the two
            // answers. A host name is independent of its spelling, and the
            // dot at the end ("localhost.") is the absolute form of the same
            // name; neither of them may recolour the badge.
            None => !host.trim_end_matches('.').eq_ignore_ascii_case("localhost"),
        }
    }
}

/// The host the client will really connect to, parsed the way `reqwest`
/// parses it. A hand-rolled split once read `https://[a.example]@b.example`
/// as `a.example` while the request went to `b.example`. IPv6 comes without
/// brackets; an address that does not parse has no host (and counts as
/// outside).
pub fn host_of(base: &str) -> String {
    reqwest::Url::parse(base).ok().and_then(|u| u.host_str().map(|h| h.trim_start_matches('[').trim_end_matches(']').to_string())).unwrap_or_default()
}

/// Would the stored key go to the same place? Scheme, host and port: a key
/// for `https://x` must not follow a switch to `http://x` either.
pub fn same_origin(a: &str, b: &str) -> bool {
    matches!((reqwest::Url::parse(a), reqwest::Url::parse(b)), (Ok(a), Ok(b)) if a.origin() == b.origin())
}

/// Setup from the settings. `None` means: off, or incomplete — then the
/// server asks nothing.
pub async fn config(pool: &PgPool) -> Result<Option<Config>> {
    if !db::setting_bool(pool, "assist_enabled", false).await? {
        return Ok(None);
    }
    let base_url = db::setting_str(pool, "assist_base_url").await?.unwrap_or_default().trim().trim_end_matches('/').to_string();
    let model = db::setting_str(pool, "assist_model").await?.unwrap_or_default().trim().to_string();
    if base_url.is_empty() || model.is_empty() {
        return Ok(None);
    }
    Ok(Some(Config {
        base_url,
        model,
        key: db::setting_str(pool, "assist_key").await?.unwrap_or_default(),
        daily_limit: db::setting_i64(pool, "assist_daily_limit", 50).await?,
    }))
}

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder().timeout(TIMEOUT).build()?)
}

// ---------- Errors ----------

#[derive(Debug, PartialEq)]
pub enum Error {
    /// 401/403: key missing, wrong, or valid for a different product.
    Unauthorized,
    /// 404: with Ollama almost always a model name that does not exist
    /// there; with Infomaniak a wrong `product_id` in the base URL.
    NotFound(String),
    /// 429: too many requests at the provider.
    RateLimited,
    Http(u16, String),
    Malformed,
    /// Valid answer, but without any text. Happens when a model has only
    /// thought and said nothing.
    Empty,
    Network(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unauthorized => write!(f, "AI service: API key missing, wrong, or not valid for this endpoint."),
            Error::NotFound(m) if m.is_empty() => write!(f, "AI service: endpoint or model not found - check the base URL and the model name."),
            Error::NotFound(m) => write!(f, "AI service: not found - {m}"),
            Error::RateLimited => write!(f, "AI service: too many requests, try again shortly."),
            Error::Http(code, m) if m.is_empty() => write!(f, "AI service: HTTP {code}"),
            Error::Http(code, m) => write!(f, "AI service: HTTP {code} {m}"),
            Error::Malformed => write!(f, "AI service: unexpected response (is this an OpenAI-compatible endpoint?)"),
            Error::Empty => write!(f, "AI service: the model returned no text."),
            Error::Network(m) => write!(f, "AI service: {m}"),
        }
    }
}

impl std::error::Error for Error {}

// ---------- Wire format ----------

#[derive(serde::Serialize)]
struct Request<'a> {
    model: &'a str,
    messages: [Message<'a>; 2],
    temperature: f32,
    max_tokens: u32,
    stream: bool,
}

#[derive(serde::Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(serde::Deserialize)]
struct Envelope {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(serde::Deserialize)]
struct Choice {
    #[serde(default)]
    message: Option<Content>,
}

#[derive(serde::Deserialize)]
struct Content {
    #[serde(default)]
    content: Option<String>,
}

/// Error body in the OpenAI shape. For some errors Infomaniak puts a
/// `description` next to it; both are taken, whichever is there first.
#[derive(serde::Deserialize)]
struct ErrorEnvelope {
    #[serde(default)]
    error: Option<ErrorItem>,
    #[serde(default)]
    description: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ErrorItem {
    Msg { message: String },
    Text(String),
}

/// Status code and body into text or an error. Kept apart from [`ask`] so
/// that it can be checked without a network and without a model.
pub fn parse(status: u16, body: &[u8]) -> Result<String, Error> {
    if status == 200 {
        let env: Envelope = serde_json::from_slice(body).map_err(|_| Error::Malformed)?;
        let text = env.choices.into_iter().next().and_then(|c| c.message).and_then(|m| m.content).unwrap_or_default();
        let text = strip_thoughts(&text);
        return if text.is_empty() { Err(Error::Empty) } else { Ok(text) };
    }
    let detail = serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .and_then(|e| match e.error {
            Some(ErrorItem::Msg { message }) => Some(message),
            Some(ErrorItem::Text(t)) => Some(t),
            None => e.description,
        })
        .unwrap_or_default();
    match status {
        401 | 403 => Err(Error::Unauthorized),
        404 => Err(Error::NotFound(detail)),
        429 => Err(Error::RateLimited),
        code => Err(Error::Http(code, detail)),
    }
}

/// `reqwest` writes only the outermost layer — "error sending request for
/// url (…)". The reason sits below it: "connection refused", "dns error",
/// "invalid peer certificate". For somebody who is just typing in an
/// address, that is precisely the information, and without it the message
/// is worth nothing.
fn why(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    let mut src = std::error::Error::source(e);
    // The chain is short; the limit is against an error that points at
    // itself, not against length.
    for _ in 0..5 {
        let Some(s) = src else { break };
        let _ = write!(out, ": {s}");
        src = s.source();
    }
    out
}

/// Thinking models (qwen3 and relatives) put their reasoning up front as
/// `<think>…</think>`. That does not belong in a statement someone pins to
/// an alert as evidence. An unclosed block means: the length limit came
/// before the end of the thinking — then nothing is left over, and the
/// caller sees `Empty` instead of a soliloquy.
fn strip_thoughts(text: &str) -> String {
    let mut rest = text.trim();
    while let Some(open) = rest.find("<think>") {
        match rest[open..].find("</think>") {
            Some(close) => {
                let after = open + close + "</think>".len();
                rest = rest[after..].trim_start();
            }
            None => return rest[..open].trim().to_string(),
        }
    }
    rest.trim().to_string()
}

/// One question to the model. The provider's error is passed on unchanged:
/// "model 'lama3' not found" says more than any wording of our own.
pub async fn ask(client: &reqwest::Client, cfg: &Config, prompt: &str) -> Result<String, Error> {
    let body = Request {
        model: &cfg.model,
        messages: [Message { role: "system", content: SYSTEM }, Message { role: "user", content: prompt }],
        // Low, not zero: this is about a summary of facts, not about
        // ideas.
        temperature: 0.2,
        max_tokens: MAX_TOKENS,
        stream: false,
    };
    let mut req = client.post(cfg.endpoint()).json(&body);
    if !cfg.key.is_empty() {
        req = req.bearer_auth(&cfg.key);
    }
    let resp = req.send().await.map_err(|e| Error::Network(why(&e)))?;
    let status = resp.status().as_u16();
    let body = resp.bytes().await.map_err(|e| Error::Network(why(&e)))?;
    parse(status, &body)
}

/// "Test connection": the cheapest question there is. Checks address, key
/// and model name in one go, without an alert leaving the house.
pub async fn probe(client: &reqwest::Client, cfg: &Config) -> Result<String, Error> {
    ask(client, cfg, "This is a connection test. Reply with the single word: ready").await
}

// ---------- Dossier ----------

/// What the administrator would otherwise have to gather by hand, as one
/// text. `None` if the alert does not (any longer) exist.
pub async fn dossier(pool: &PgPool, alert_id: i64) -> Result<Option<String>> {
    let Some(a) = alert(pool, alert_id).await? else {
        return Ok(None);
    };
    let mut d = String::new();

    // ---- the alert itself ----
    let _ = writeln!(d, "ALERT #{}", a.id);
    let _ = writeln!(d, "  first seen: {}", a.at.format("%Y-%m-%d %H:%M:%S UTC"));
    if let Some(last) = a.last_at.filter(|l| *l != a.at) {
        let _ = writeln!(d, "  last seen:  {}", last.format("%Y-%m-%d %H:%M:%S UTC"));
    }
    let _ = writeln!(d, "  source: {} ({})", a.origin_name, if a.kind == "access" { "file server access log" } else { "endpoint agent" });
    let _ = writeln!(d, "  user: {}", a.user_display.as_deref().unwrap_or("unknown"));
    let _ = writeln!(d, "  process: {}", a.process.as_deref().unwrap_or("unknown"));
    let _ = writeln!(d, "  protected folder: {}", a.path.as_deref().unwrap_or("unknown"));
    let _ = writeln!(d, "  destination: {}", a.remote.as_deref().unwrap_or("none recorded"));
    let _ = writeln!(d, "  volume: {} in {} file(s)", bytes(a.bytes), a.file_count);
    let _ = writeln!(d, "  verdict: {}{}", a.verdict, a.reason.as_deref().map(|r| format!(" - {r}")).unwrap_or_default());
    if let Some(files) = a.files.as_array().filter(|f| !f.is_empty()) {
        let names: Vec<&str> = files.iter().filter_map(|f| f.as_str()).take(MAX_FILES).collect();
        let _ = writeln!(d, "  files: {}{}", names.join(", "), if files.len() > names.len() { format!(" (+{} more)", files.len() - names.len()) } else { String::new() });
    }

    // ---- the rule that matched ----
    if let Some(r) = rule(pool, a.rule_id).await? {
        let _ = writeln!(d, "\nRULE \"{}\"", r.name);
        let _ = writeln!(d, "  path: {}", r.path);
        let _ = writeln!(d, "  strict folder (nothing may leave except to allowed destinations): {}", yes(r.strict));
        if r.strict {
            let allowed = if r.allow_destinations.is_empty() { "none - every destination is forbidden".to_string() } else { r.allow_destinations.join(", ") };
            let _ = writeln!(d, "  allowed destinations: {allowed}");
        }
        let _ = writeln!(d, "  agent removes copies that left the folder (enforce): {}", yes(r.enforce));
        if r.hard_max_files > 0 {
            let _ = writeln!(d, "  hard limit: more than {} files within {} s", r.hard_max_files, r.window_secs);
        }
    } else {
        let _ = writeln!(d, "\nRULE: none recorded for this alert.");
    }

    // ---- the reputation of the destination address ----
    if let Some(ip) = a.remote.as_deref().and_then(abuseipdb::ip_of) {
        let _ = writeln!(d, "\nDESTINATION REPUTATION (AbuseIPDB)");
        match abuseipdb::cached(pool, &[ip.to_string()]).await?.into_iter().next() {
            Some(r) => {
                let _ = writeln!(d, "  {}: {}% abuse confidence, {} reports in 90 days{}{}", r.ip, r.score, r.total_reports,
                    if r.is_tor { ", Tor exit node" } else { "" },
                    if r.is_whitelisted { ", whitelisted" } else { "" });
                let who: Vec<&str> = [r.country_code.as_deref(), r.isp.as_deref(), r.domain.as_deref(), r.usage_type.as_deref()].into_iter().flatten().collect();
                if !who.is_empty() {
                    let _ = writeln!(d, "  {}", who.join(" / "));
                }
            }
            None if !abuseipdb::is_public(ip) => {
                let _ = writeln!(d, "  {ip} is a private or reserved address - inside this network, not on the internet.");
            }
            None => {
                let _ = writeln!(d, "  {ip} has not been checked. Do not assume it is either good or bad.");
            }
        }
    }

    // ---- what the same user did otherwise ----
    if let Some(user) = a.user_key.as_deref().filter(|u| !u.is_empty()) {
        let _ = writeln!(d, "\nSAME USER, LAST {USER_HISTORY_DAYS} DAYS (this alert excluded)");
        let verdicts = top(pool, "verdict", "user_key = $1", user, a.id, USER_HISTORY_DAYS).await?;
        if verdicts.is_empty() {
            let _ = writeln!(d, "  no other alerts.");
        } else {
            let _ = writeln!(d, "  verdicts: {}", counted(&verdicts));
            let _ = writeln!(d, "  processes: {}", counted(&top(pool, "coalesce(process, '(none)')", "user_key = $1", user, a.id, USER_HISTORY_DAYS).await?));
            let _ = writeln!(d, "  folders: {}", counted(&top(pool, "coalesce(path, '(none)')", "user_key = $1", user, a.id, USER_HISTORY_DAYS).await?));
        }
    }

    // ---- and the same process on all devices ----
    if let Some(p) = a.process.as_deref().filter(|p| !p.is_empty()) {
        let (n, devices, first): (i64, i64, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT count(*), count(DISTINCT origin_name), min(at) FROM alerts \
             WHERE process = $1 AND id <> $2 AND at > now() - ($3::bigint * interval '1 day')",
        )
        .bind(p).bind(a.id).bind(PROCESS_HISTORY_DAYS).fetch_one(pool).await?;
        let _ = writeln!(d, "\nSAME PROCESS ACROSS THE FLEET, LAST {PROCESS_HISTORY_DAYS} DAYS");
        match first {
            Some(f) => {
                let _ = writeln!(d, "  {p}: {n} other alert(s) on {devices} device(s), earliest {}", f.format("%Y-%m-%d"));
            }
            None => {
                let _ = writeln!(d, "  {p}: no other alerts. This is the first time it turns up.");
            }
        }
    }

    // ---- the agent's log around the event ----
    if let Some(agent) = a.agent_id {
        let from = a.at - chrono::Duration::minutes(LOG_WINDOW_MINS);
        let to = a.last_at.unwrap_or(a.at) + chrono::Duration::minutes(LOG_WINDOW_MINS);
        let lines: Vec<(DateTime<Utc>, String, String, String)> = sqlx::query_as(
            "SELECT at, level, target, msg FROM agent_log WHERE agent_id = $1 AND at BETWEEN $2 AND $3 ORDER BY at DESC, id DESC LIMIT $4",
        )
        .bind(agent).bind(from).bind(to).bind(MAX_LOG_LINES).fetch_all(pool).await?;
        // The heading names the times, not "ten minutes": for an alert
        // that keeps being written on, the window runs from `at` to
        // `last_at` and is hours long. A model that has been told "use only
        // facts from the dossier" must not find a false fact at the head of
        // the list.
        let _ = writeln!(d, "\nAGENT LOG, {} to {} (newest {MAX_LOG_LINES} lines at most)", from.format("%Y-%m-%d %H:%M:%S UTC"), to.format("%H:%M:%S UTC"));
        if lines.is_empty() {
            let _ = writeln!(d, "  nothing logged in that window.");
        }
        // The query fetches the newest first (that is what the index is
        // for), reading goes from front to back.
        for (at, level, target, msg) in lines.into_iter().rev() {
            let _ = writeln!(d, "  {} {:<5} {target}: {}", at.format("%H:%M:%S"), level.to_uppercase(), clamp(msg.trim(), 300));
        }
    }

    Ok(Some(clamp(&d, MAX_PROMPT)))
}

async fn alert(pool: &PgPool, id: i64) -> Result<Option<AlertRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {ALERT_COLS} FROM alerts WHERE id = $1"))).bind(id).fetch_optional(pool).await?)
}

async fn rule(pool: &PgPool, id: Option<Uuid>) -> Result<Option<RuleRow>> {
    let Some(id) = id else { return Ok(None) };
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {RULE_COLS} FROM rules WHERE id = $1"))).bind(id).fetch_optional(pool).await?)
}

/// The most frequent values of an expression among related alerts. `expr`
/// and `filter` are fixed strings from this module — only `key` comes from
/// the request, and it is bound.
async fn top(pool: &PgPool, expr: &str, filter: &str, key: &str, id: i64, days: i64) -> Result<Vec<(String, i64)>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {expr}, count(*) FROM alerts \
         WHERE {filter} AND id <> $2 AND at > now() - ($3::bigint * interval '1 day') \
         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 5"
    )))
    .bind(key)
    .bind(id)
    .bind(days)
    .fetch_all(pool)
    .await?)
}

fn counted(rows: &[(String, i64)]) -> String {
    if rows.is_empty() {
        return "none".into();
    }
    rows.iter().map(|(k, n)| format!("{k} ({n})")).collect::<Vec<_>>().join(", ")
}

fn yes(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

/// Bytes, the way the dashboard writes them.
fn bytes(b: i64) -> String {
    if b < 1024 {
        return format!("{b} B");
    }
    let (mut v, mut i) = (b as f64 / 1024.0, 0usize);
    let units = ["KB", "MB", "GB", "TB"];
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v < 10.0 {
        format!("{v:.1} {}", units[i])
    } else {
        format!("{} {}", v.round() as i64, units[i])
    }
}

/// Truncates on characters, not on bytes: a path with an umlaut must not
/// break off in the middle of a character, otherwise the text is no longer
/// UTF-8. That it was truncated is stated with it — a model that does not
/// see the end should not believe it has seen everything.
fn clamp(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    const NOTE: &str = "\n[truncated]";
    let keep = max.saturating_sub(NOTE.chars().count());
    let mut out: String = s.chars().take(keep).collect();
    out.push_str(NOTE);
    out
}

// ---------- Storage ----------

/// The stored explanation for an alert. At once a row of the table and the
/// dashboard's response type.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Insight {
    pub alert_id: i64,
    pub model: String,
    pub endpoint: String,
    /// Exactly what went to the model.
    pub prompt: String,
    pub summary: String,
    pub created_at: DateTime<Utc>,
    pub created_by_name: String,
}

pub const INSIGHT_COLS: &str = "alert_id, model, endpoint, prompt, summary, created_at, created_by_name";

pub async fn cached(pool: &PgPool, alert_id: i64) -> Result<Option<Insight>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {INSIGHT_COLS} FROM alert_insights WHERE alert_id = $1")))
        .bind(alert_id)
        .fetch_optional(pool)
        .await?)
}

pub async fn store(pool: &PgPool, alert_id: i64, cfg: &Config, prompt: &str, summary: &str, by: (Uuid, &str)) -> Result<Insight> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO alert_insights (alert_id, model, endpoint, prompt, summary, created_by, created_by_name) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (alert_id) DO UPDATE SET model = EXCLUDED.model, endpoint = EXCLUDED.endpoint, prompt = EXCLUDED.prompt, \
           summary = EXCLUDED.summary, created_at = now(), created_by = EXCLUDED.created_by, created_by_name = EXCLUDED.created_by_name \
         RETURNING {INSIGHT_COLS}"
    )))
    .bind(alert_id)
    .bind(&cfg.model)
    .bind(cfg.endpoint())
    .bind(prompt)
    .bind(summary)
    .bind(by.0)
    .bind(by.1)
    .fetch_one(pool)
    .await?)
}

/// Under these names the two questions to the model appear in the audit
/// log — and the daily budget is counted from it at the same time. The
/// connection test is among them: it is short, but with a paid service it
/// costs something too.
pub const AUDIT_ACTION: &str = "alert_explain";
pub const AUDIT_TEST: &str = "assist_test";

/// How many explanations were asked for today (UTC). Counted out of the
/// database as with the IP reputation, so that a restart of the server does
/// not set the budget back to zero.
///
/// The counting happens in the **audit log**, not in `alert_insights`:
/// there is only one row per alert there, and explaining the same one a
/// second time would overwrite it. The table would stay the same size, the
/// budget would notice nothing — and whoever leans on "Explain again" with
/// a paid service would pay without a brake. The audit log forgets nothing
/// and is never cleaned up.
pub async fn used_today(pool: &PgPool) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log WHERE action = ANY($1) AND at >= date_trunc('day', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'")
        .bind(&[AUDIT_ACTION, AUDIT_TEST][..])
        .fetch_one(pool)
        .await?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_become_the_errors_the_dashboard_shows() {
        let ok = br#"{"choices":[{"message":{"role":"assistant","content":"What happened: a thing."}}]}"#;
        assert_eq!(parse(200, ok).unwrap(), "What happened: a thing.");

        assert_eq!(parse(401, b"").unwrap_err(), Error::Unauthorized);
        assert_eq!(parse(403, b"").unwrap_err(), Error::Unauthorized);
        assert_eq!(parse(429, b"").unwrap_err(), Error::RateLimited);
        // Ollama: a model name that does not exist there.
        assert_eq!(
            parse(404, br#"{"error":{"message":"model 'lama3' not found"}}"#).unwrap_err(),
            Error::NotFound("model 'lama3' not found".into())
        );
        // Some services send `error` as plain text.
        assert_eq!(parse(400, br#"{"error":"bad request"}"#).unwrap_err(), Error::Http(400, "bad request".into()));
        assert_eq!(parse(500, b"<html>gateway</html>").unwrap_err(), Error::Http(500, String::new()));
        // An answer that is not an OpenAI answer: the most common
        // consequence of a base URL without `/v1`.
        assert_eq!(parse(200, b"<html>hello</html>").unwrap_err(), Error::Malformed);
        assert_eq!(parse(200, br#"{"choices":[]}"#).unwrap_err(), Error::Empty);
    }

    #[test]
    fn a_thinking_model_keeps_its_thoughts_to_itself() {
        assert_eq!(strip_thoughts("<think>hmm, the user...</think>\n\nWhat happened: x"), "What happened: x");
        assert_eq!(strip_thoughts("  plain answer  "), "plain answer");
        // Cut off in the middle of the thinking: nothing is left, and the
        // caller reports `Empty` instead of half a soliloquy.
        assert_eq!(strip_thoughts("<think>hmm, and then"), "");
        assert_eq!(parse(200, br#"{"choices":[{"message":{"content":"<think>a</think>b"}}]}"#).unwrap(), "b");
    }

    #[test]
    fn the_dossier_never_grows_past_the_context_of_a_small_model() {
        let long = "a".repeat(MAX_PROMPT * 2);
        let cut = clamp(&long, MAX_PROMPT);
        assert_eq!(cut.chars().count(), MAX_PROMPT);
        assert!(cut.ends_with("[truncated]"));
        // On characters, not on bytes: otherwise this here would no longer be UTF-8.
        let umlauts = "ä".repeat(100);
        assert_eq!(clamp(&umlauts, 20).chars().count(), 20);
        assert_eq!(clamp("short", 20), "short");
    }

    /// The real value of the whole thing is not the model but this query:
    /// the five pieces of information an administrator would otherwise
    /// gather by hand, in one text. If one of them silently drops out,
    /// nobody notices — the model's answer still looks right, after all.
    #[sqlx::test(migrations = "./migrations")]
    async fn the_dossier_carries_what_the_admin_would_look_up_by_hand(pool: PgPool) {
        let agent: Uuid = sqlx::query_scalar(
            "INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after) \
             VALUES (gen_random_uuid(), 'DESKTOP-EXAMPLE', 'windows', '0.1.0', 'fp', now() + interval '1 day') RETURNING id",
        )
        .fetch_one(&pool).await.unwrap();
        let rule: Uuid = sqlx::query_scalar(
            "INSERT INTO rules (name, path, strict, allow_destinations, enforce, hard_max_files, window_secs) \
             VALUES ('GL strict', 'G:\\', true, ARRAY['10.0.0.0/8'], true, 50, 300) RETURNING id",
        )
        .fetch_one(&pool).await.unwrap();

        let at: DateTime<Utc> = "2026-09-08T12:00:00Z".parse().unwrap();
        let add = |ext: &'static str, user: &'static str, process: &'static str, verdict: &'static str, remote: Option<&'static str>, ago_days: i64| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, i64>(
                    "INSERT INTO alerts (kind, agent_id, origin_name, external_id, at, user_key, user_display, rule_id, path, process, files, file_count, bytes, remote, verdict, reason, detail) \
                     VALUES ('endpoint', $1, 'DESKTOP-EXAMPLE', $2, now() - ($8::bigint * interval '1 day'), $3, $3, $4, 'G:\\Vertraege', $5, '[\"a.pdf\",\"b.pdf\"]', 2, 4194304, $6, $7, 'destination not allowed', '{}') RETURNING id",
                )
                .bind(agent).bind(ext).bind(user).bind(rule).bind(process).bind(remote).bind(verdict).bind(ago_days)
                .fetch_one(&pool).await.unwrap()
            }
        };
        let id = add("e1", "CORP\\dl-anna", "firefox.exe", "denied", Some("203.0.113.9:443"), 0).await;
        // History: the same user this week, the same process on another
        // device.
        add("e2", "CORP\\dl-anna", "explorer.exe", "new", None, 2).await;
        add("e3", "CORP\\dl-bruno", "firefox.exe", "hard_limit", None, 3).await;
        // And a row that is too old to still belong.
        add("e4", "CORP\\dl-anna", "curl.exe", "denied", None, 90).await;

        // The time of the alert is fixed; the log has to lie around it so
        // that the window hits it.
        sqlx::query("UPDATE alerts SET at = $1, last_at = $1 WHERE id = $2").bind(at).bind(id).execute(&pool).await.unwrap();
        for (offset_secs, level, msg) in [(-120i64, "info", "watching G:\\Vertraege"), (5, "warn", "strict folder: destination 203.0.113.9 not in allow list"), (3600, "info", "zu spaet, gehoert nicht mehr dazu")] {
            sqlx::query("INSERT INTO agent_log (agent_id, at, level, target, msg) VALUES ($1, $2, $3, 'deelpe::pipeline', $4)")
                .bind(agent).bind(at + chrono::Duration::seconds(offset_secs)).bind(level).bind(msg)
                .execute(&pool).await.unwrap();
        }
        abuseipdb::store(&pool, &abuseipdb::Reputation {
            ip: "203.0.113.9".into(), score: 91, country_code: Some("RU".into()), isp: Some("Acme".into()),
            domain: None, usage_type: None, total_reports: 42, is_tor: true, is_whitelisted: false, checked_at: Utc::now(),
        }).await.unwrap();

        let d = dossier(&pool, id).await.unwrap().expect("die Warnung gibt es");

        // 1. the alert itself
        assert!(d.contains("ALERT #"), "{d}");
        assert!(d.contains("CORP\\dl-anna") && d.contains("firefox.exe") && d.contains("a.pdf"), "{d}");
        assert!(d.contains("4.0 MB in 2 file(s)"), "{d}");
        // 2. the rule, including allow list and threshold
        assert!(d.contains("RULE \"GL strict\"") && d.contains("10.0.0.0/8") && d.contains("more than 50 files within 300 s"), "{d}");
        // 3. the reputation of the destination
        assert!(d.contains("91% abuse confidence") && d.contains("Tor exit node"), "{d}");
        // 4. the history — and only what is inside the window
        assert!(d.contains("explorer.exe (1)"), "{d}");
        assert!(!d.contains("curl.exe"), "90 Tage alt, gehoert nicht in die Wochenschau: {d}");
        assert!(d.contains("firefox.exe: 1 other alert(s) on 1 device(s)"), "{d}");
        // 5. the log around the event, in reading order
        assert!(d.contains("AGENT LOG, 2026-09-08 11:50:00 UTC to 12:10:00 UTC"), "die Ueberschrift nennt das Fenster, das wirklich gilt: {d}");
        assert!(d.contains("watching G:\\Vertraege"), "{d}");
        assert!(d.contains("not in allow list"), "{d}");
        assert!(!d.contains("zu spaet"), "eine Stunde spaeter gehoert nicht mehr dazu: {d}");
        assert!(d.find("watching") < d.find("not in allow list"), "aelteste Zeile zuerst: {d}");

        assert!(dossier(&pool, id + 9999).await.unwrap().is_none(), "eine Warnung, die es nicht gibt");
    }

    #[test]
    fn the_base_url_alone_says_whether_data_leaves_the_house() {
        let cfg = |u: &str| Config { base_url: u.into(), model: "m".into(), key: String::new(), daily_limit: 50 };
        for local in ["http://localhost:11434/v1", "http://LOCALHOST:11434/v1", "http://localhost./v1", "http://127.0.0.1:11434/v1", "http://10.0.0.5:11434/v1", "http://192.168.1.9:11434/v1", "http://[::1]:11434/v1"] {
            assert!(!cfg(local).external(), "{local} liegt im eigenen Netz");
        }
        for out in ["https://api.infomaniak.com/2/ai/123/openai/v1", "https://api.openai.com/v1", "http://8.8.8.8/v1"] {
            assert!(cfg(out).external(), "{out} liegt draussen");
        }
        assert_eq!(cfg("http://localhost:11434/v1").endpoint(), "http://localhost:11434/v1/chat/completions");
        // What looks local in the user-info part is not where the request goes.
        assert!(cfg("http://[10.0.0.5]@evil.example/v1").external());
    }

    /// The stored key follows only to the same scheme, host and port.
    #[test]
    fn the_key_stays_only_where_it_was_meant_for() {
        let home = "https://api.infomaniak.com/2/ai/1/openai/v1";
        assert!(same_origin(home, "https://API.infomaniak.com/2/ai/2/openai/v1"));
        assert!(!same_origin(home, "https://[api.infomaniak.com]@evil.example/v1"), "user-info trick");
        assert!(!same_origin(home, "http://api.infomaniak.com/2/ai/1/openai/v1"), "downgrade to http");
        assert!(!same_origin(home, "https://api.infomaniak.com:8443/v1"), "other port");
        assert!(!same_origin(home, "not a url"));
    }
}
