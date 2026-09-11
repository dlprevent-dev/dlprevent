//! The central server's settings.

use super::*;
use crate::mail;

// ---------- Settings, audit log ----------

#[derive(Serialize, Deserialize)]
pub(super) struct Settings {
    learn_days: i64,
    report_interval_secs: i64,
    alert_retain_days: i64,
    count_retain_days: i64,
    /// May the central server tell an agent to remember a pair? That is the
    /// only way in which the central server changes a device's behaviour;
    /// whoever does not need it leaves it shut.
    #[serde(default)]
    learn_push_enabled: bool,
    /// May the central server roll out a new agent program? Off means: the
    /// dashboard only says who is out of date — nothing gets fetched. Off
    /// out of the box; whoever flips it swaps the program on every machine.
    #[serde(default)]
    agent_update_enabled: bool,
    /// Where new agent versions come from — `besitzer/name` (GitHub) or the
    /// full API URL of your own Gitea. Empty means: not at all.
    #[serde(default)]
    release_repo: String,
    /// Does the central server check on its own? Nothing is ever fetched by it.
    #[serde(default)]
    release_check_enabled: bool,
    /// The public key (ed25519, base64) a release's signature is checked
    /// against. If one is baked into the program, that one applies and this
    /// one here is not read.
    #[serde(default)]
    release_pubkey: String,
    /// Credentials for a private repo. In only, never out — like the
    /// AbuseIPDB key. Empty means "unchanged", a single hyphen means
    /// "delete".
    #[serde(default, skip_serializing)]
    release_token: String,
    #[serde(default, skip_deserializing)]
    release_token_set: bool,
    /// Is the key baked into the program? Then the field above is moot, and
    /// the dashboard should not offer it for typing into. Out only, never
    /// in.
    #[serde(default, skip_deserializing)]
    release_pubkey_built_in: bool,
    /// Syslog receiver (UDP and TCP). Off means: the port is not bound.
    #[serde(default = "dtrue")]
    syslog_enabled: bool,
    /// Master switch for third-party access via API key. Off means: no key
    /// is valid, no matter how many have been created — only signing in
    /// through the browser still gets at the API. Off out of the box.
    #[serde(default)]
    api_keys_enabled: bool,
    /// Second factor mandatory, per role. An account without one only gets
    /// as far as its own account page after signing in, until it has one
    /// (auth.rs, extractor `User`).
    #[serde(default)]
    require_2fa_admin: bool,
    #[serde(default)]
    require_2fa_viewer: bool,
    /// IP reputation via AbuseIPDB. Off means: the central server asks
    /// nothing of the outside world, even if a key is on file.
    #[serde(default)]
    abuseipdb_enabled: bool,
    /// The key itself. In only, never out: `skip_serializing` keeps it out of
    /// the answer **and** out of the audit log (`settings_update`). Empty
    /// means „unchanged", a single hyphen means „delete".
    #[serde(default, skip_serializing)]
    abuseipdb_key: String,
    /// Is a key set? Computed, not the secret itself.
    #[serde(default)]
    abuseipdb_key_set: bool,
    /// Lookups per day. The free plan gives 1000.
    #[serde(default = "d1000")]
    abuseipdb_daily_limit: i64,
    // ---------- AI assistance ----------
    /// Master switch. Off means: the central server talks to no model, no
    /// matter what is below. Off out of the box.
    #[serde(default)]
    assist_enabled: bool,
    /// Base URL of an OpenAI-compatible service, without
    /// `/chat/completions`. Ollama on your own network or Infomaniak — which
    /// of the two it is, this line alone decides.
    #[serde(default)]
    assist_base_url: String,
    #[serde(default)]
    assist_model: String,
    /// Like the AbuseIPDB key: in only, never out. Empty means "unchanged",
    /// a single hyphen means "delete". Ollama needs none.
    #[serde(default, skip_serializing)]
    assist_key: String,
    #[serde(default)]
    assist_key_set: bool,
    /// Explanations per day. A brake against the twitchy finger and, with a
    /// paid service, against the bill.
    #[serde(default = "d50c")]
    assist_daily_limit: i64,
    // ---------- Email notification ----------
    /// Master switch. Off means: the central server opens no SMTP
    /// connection, no matter what is below.
    #[serde(default)]
    smtp_enabled: bool,
    #[serde(default)]
    smtp_host: String,
    #[serde(default = "d587")]
    smtp_port: i64,
    /// `starttls` (the default), `tls` or `none` — see `mail::Security`.
    #[serde(default)]
    smtp_security: String,
    #[serde(default)]
    smtp_user: String,
    /// Like the AbuseIPDB key: in only, never out. Empty means „unchanged",
    /// a single hyphen means „delete".
    #[serde(default, skip_serializing)]
    smtp_pass: String,
    #[serde(default)]
    smtp_pass_set: bool,
    #[serde(default)]
    smtp_from: String,
    /// Recipients, separated by comma or semicolon.
    #[serde(default)]
    smtp_to: String,
    /// The dashboard's URL for the links in the email. Empty means: no
    /// links — the central server does not know its own public address.
    #[serde(default)]
    notify_base_url: String,
    #[serde(default = "dtrue")]
    notify_alerts: bool,
    #[serde(default = "dtrue")]
    notify_agent_down: bool,
    #[serde(default)]
    notify_abuse_ip: bool,
    #[serde(default = "d50")]
    notify_abuse_min_score: i64,
    /// Digest window in minutes: at most one email per window.
    #[serde(default = "d5")]
    notify_digest_mins: i64,
    /// This long an agent may stay silent before a down notice goes out.
    #[serde(default = "d10")]
    notify_agent_down_mins: i64,
    /// Time zone for the times in the email, as an IANA name
    /// („Europe/Zurich"). The dashboard takes the browser's; an email has no
    /// browser.
    #[serde(default = "dutc")]
    report_timezone: String,
    /// Processes that raise no learning-phase alert — one name per line, as
    /// typed into the field. A forbidden destination in a strict folder is
    /// untouched by this; that is the difference from `ignored`.
    #[serde(default)]
    allow_processes: String,
    #[serde(default)]
    config_generation: i64,
}

/// The usual submission port with STARTTLS.
fn d587() -> i64 {
    587
}

/// From here on an address counts as having a bad reputation — the middle of
/// the AbuseIPDB scale, see `notify_abuse_min_score`.
fn d50() -> i64 {
    50
}

/// Digest window in minutes, see `notify_digest_mins`.
fn d5() -> i64 {
    5
}

/// Without a value everything is computed in UTC: never wrong, only inconvenient.
fn dutc() -> String {
    "UTC".to_string()
}

/// Patience before the down notice, see `notify_agent_down_mins`.
fn d10() -> i64 {
    10
}

/// Default for the daily budget, see `abuseipdb_daily_limit`.
fn d1000() -> i64 {
    1000
}

/// Default for the explanations' daily budget, see `assist_daily_limit`.
fn d50c() -> i64 {
    50
}

/// A single hyphen in a secret field deletes the secret — AbuseIPDB key and
/// SMTP password alike. An empty field leaves it standing: the UI never gets
/// to see it and would otherwise delete it on every save.
const CLEAR_SECRET: &str = "-";

/// Upper bound on the allow list. It goes out to every agent in every
/// answer; a list without a limit would be a way to bloat the reports.
const MAX_ALLOW_PROCESSES: usize = 200;

/// Every setting named exactly once: the key stands next to the field that
/// carries it, and both are read and written from the same list. Before, the
/// names stood as bare strings once in the reading and once in the writing —
/// a typo in either of the two compiled cleanly and got silently lost.
const KEYS: [&str; 40] = [
    "learn_days",
    "report_interval_secs",
    "alert_retain_days",
    "count_retain_days",
    "learn_push_enabled",
    "agent_update_enabled",
    "release_repo",
    "release_check_enabled",
    "release_pubkey",
    "release_token",
    "syslog_enabled",
    "api_keys_enabled",
    "require_2fa_admin",
    "require_2fa_viewer",
    "abuseipdb_enabled",
    "abuseipdb_key",
    "abuseipdb_daily_limit",
    "assist_enabled",
    "assist_base_url",
    "assist_model",
    "assist_key",
    "assist_daily_limit",
    "smtp_enabled",
    "smtp_host",
    "smtp_port",
    "smtp_security",
    "smtp_user",
    "smtp_pass",
    "smtp_from",
    "smtp_to",
    "notify_base_url",
    "notify_alerts",
    "notify_agent_down",
    "notify_abuse_ip",
    "notify_abuse_min_score",
    "notify_digest_mins",
    "notify_agent_down_mins",
    "report_timezone",
    "allow_processes",
    "config_generation",
];

pub(super) async fn settings(State(st): State<Shared>, _u: Admin) -> R<Settings> {
    let m = db::settings_map(&st.pool, &KEYS).await?;
    // The defaults are the same as before, when each was queried on its own.
    let i64_of = |k: &str, d: i64| m.get(k).and_then(serde_json::Value::as_i64).unwrap_or(d);
    let bool_of = |k: &str, d: bool| m.get(k).and_then(serde_json::Value::as_bool).unwrap_or(d);
    let str_of = |k: &str| m.get(k).and_then(serde_json::Value::as_str).unwrap_or_default().to_string();
    Ok(Json(Settings {
        learn_days: i64_of("learn_days", 7),
        report_interval_secs: i64_of("report_interval_secs", 30),
        alert_retain_days: i64_of("alert_retain_days", 730),
        count_retain_days: i64_of("count_retain_days", 30),
        learn_push_enabled: bool_of("learn_push_enabled", false),
        agent_update_enabled: bool_of("agent_update_enabled", false),
        release_repo: str_of("release_repo"),
        release_check_enabled: bool_of("release_check_enabled", false),
        release_pubkey: str_of("release_pubkey"),
        release_token: String::new(),
        release_token_set: !str_of("release_token").is_empty(),
        release_pubkey_built_in: crate::release::BUILT_IN_PUBKEY.map(str::trim).is_some_and(|k| !k.is_empty()),
        syslog_enabled: bool_of("syslog_enabled", true),
        api_keys_enabled: bool_of("api_keys_enabled", false),
        require_2fa_admin: bool_of("require_2fa_admin", false),
        require_2fa_viewer: bool_of("require_2fa_viewer", false),
        abuseipdb_enabled: bool_of("abuseipdb_enabled", false),
        abuseipdb_key: String::new(),
        abuseipdb_key_set: !str_of("abuseipdb_key").is_empty(),
        abuseipdb_daily_limit: i64_of("abuseipdb_daily_limit", 1000),
        assist_enabled: bool_of("assist_enabled", false),
        assist_base_url: str_of("assist_base_url"),
        assist_model: str_of("assist_model"),
        assist_key: String::new(),
        assist_key_set: !str_of("assist_key").is_empty(),
        assist_daily_limit: i64_of("assist_daily_limit", 50),
        smtp_enabled: bool_of("smtp_enabled", false),
        smtp_host: str_of("smtp_host"),
        smtp_port: i64_of("smtp_port", 587),
        smtp_security: m.get("smtp_security").and_then(serde_json::Value::as_str).unwrap_or("starttls").to_string(),
        smtp_user: str_of("smtp_user"),
        smtp_pass: String::new(),
        smtp_pass_set: !str_of("smtp_pass").is_empty(),
        smtp_from: str_of("smtp_from"),
        smtp_to: str_of("smtp_to"),
        notify_base_url: str_of("notify_base_url"),
        notify_alerts: bool_of("notify_alerts", true),
        notify_agent_down: bool_of("notify_agent_down", true),
        notify_abuse_ip: bool_of("notify_abuse_ip", false),
        notify_abuse_min_score: i64_of("notify_abuse_min_score", 50),
        notify_digest_mins: i64_of("notify_digest_mins", 5),
        notify_agent_down_mins: i64_of("notify_agent_down_mins", 10),
        report_timezone: match m.get("report_timezone").and_then(serde_json::Value::as_str) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => dutc(),
        },
        allow_processes: str_of("allow_processes"),
        config_generation: i64_of("config_generation", 1),
    }))
}

pub(super) async fn update_settings(State(st): State<Shared>, Admin(user): Admin, Json(b): Json<Settings>) -> R<Settings> {
    if !(0..=90).contains(&b.learn_days) {
        return Err(bad("learning days: 0 to 90"));
    }
    if !(10..=3600).contains(&b.report_interval_secs) {
        return Err(bad("report interval: 10 to 3600 seconds"));
    }
    if !(30..=3650).contains(&b.alert_retain_days) {
        return Err(bad("alerts: 30 to 3650 days"));
    }
    if !(1..=365).contains(&b.count_retain_days) {
        return Err(bad("counts: 1 to 365 days"));
    }
    if !(1..=100_000).contains(&b.abuseipdb_daily_limit) {
        return Err(bad("AbuseIPDB lookups per day: 1 to 100000"));
    }
    if !(1..=10_000).contains(&b.assist_daily_limit) {
        return Err(bad("explanations per day: 1 to 10000"));
    }
    // A base URL without a scheme is one `reqwest` could not resolve, and the
    // error would only turn up at the first explanation. Same as with
    // `notify_base_url`.
    let assist_base = b.assist_base_url.trim().trim_end_matches('/');
    if !assist_base.is_empty() && !(assist_base.starts_with("https://") || assist_base.starts_with("http://")) {
        return Err(bad("AI base URL: start with https:// or http://"));
    }
    if b.assist_enabled && (assist_base.is_empty() || b.assist_model.trim().is_empty()) {
        return Err(bad("AI assistance: enter a base URL and a model name"));
    }
    // The most common typo with both providers: the URL entered all the way
    // to `/chat/completions`. The central server appends that itself.
    if assist_base.ends_with("/chat/completions") {
        return Err(bad("AI base URL: leave off /chat/completions - the server appends it"));
    }
    // If the base URL points at a different machine, the stored key is
    // dropped. Otherwise the Infomaniak token would go to the newly entered
    // address as `Authorization: Bearer …` at the next explanation — and the
    // form would still say only „A key is stored". A new key sent along
    // naturally applies; it is meant for the new machine after all.
    let assist_host_changed = {
        let old = db::setting_str(&st.pool, "assist_base_url").await?.unwrap_or_default();
        !old.is_empty() && !crate::assist::host_of(&old).eq_ignore_ascii_case(crate::assist::host_of(assist_base))
    };
    // Mail: only check what is actually used. A half-filled form with the
    // master switch off has to be saveable.
    if !(1..=65535).contains(&b.smtp_port) {
        return Err(bad("SMTP port: 1 to 65535"));
    }
    if !(1..=1440).contains(&b.notify_digest_mins) {
        return Err(bad("collect for: 1 to 1440 minutes"));
    }
    if !(1..=1440).contains(&b.notify_agent_down_mins) {
        return Err(bad("agent counts as down after: 1 to 1440 minutes"));
    }
    // A typo shows up here and not only in the email, which would then
    // quietly compute in UTC.
    if b.report_timezone.trim().parse::<chrono_tz::Tz>().is_err() {
        return Err(bad("time zone: not an IANA name such as Europe/Zurich"));
    }
    if !(0..=100).contains(&b.notify_abuse_min_score) {
        return Err(bad("AbuseIPDB score: 0 to 100"));
    }
    let to = mail::recipients(&b.smtp_to);
    if b.smtp_enabled {
        if b.smtp_host.trim().is_empty() {
            return Err(bad("SMTP server: enter a host name"));
        }
        if !mail::valid_address(b.smtp_from.trim()) {
            return Err(bad("sender: not an email address"));
        }
        if to.is_empty() {
            return Err(bad("recipients: enter at least one email address"));
        }
    }
    if to.len() > mail::MAX_RECIPIENTS {
        return Err(bad(format!("recipients: at most {} (use a distribution list)", mail::MAX_RECIPIENTS)));
    }
    if let Some(r) = to.iter().find(|r| !mail::valid_address(r)) {
        return Err(bad(format!("recipient {r:?}: not an email address")));
    }
    // A link into nothing is worse than no link.
    let base = b.notify_base_url.trim();
    if !base.is_empty() && !(base.starts_with("https://") || base.starts_with("http://")) {
        return Err(bad("dashboard address: start with https:// or http://"));
    }
    if b.require_2fa_admin {
        // Otherwise the administrator locks himself out of administration by
        // saving — and would not be able to reach this page any more.
        let (has,): (bool,) = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {} FROM users u WHERE u.id = $1", auth::HAS_SECOND_FACTOR)))
            .bind(user.id).fetch_one(&st.pool).await?;
        if !has {
            return Err(bad("set up your own second factor first (Account), then require it for administrators"));
        }
    }
    // Only the lines that actually mean something — and the same splitting as
    // in the agent. What arrives here stands in the field afterwards exactly
    // as it is.
    let allow: Vec<String> = deelpe_core::learn::parse_allowlist(&b.allow_processes).into_iter().collect();
    if allow.len() > MAX_ALLOW_PROCESSES {
        return Err(bad(format!("allowed processes: at most {MAX_ALLOW_PROCESSES}")));
    }
    // Everything in **one** statement. Before, thirty-five writes stood here
    // one after another and without a transaction: if the connection broke in
    // the middle, the central server was half configured, and nothing in the
    // dashboard looked like it.
    // A mistyped key would otherwise report "on file", the dashboard would
    // offer the button, and the error would only be found after the whole
    // program had been downloaded. The same check as in `release::verify`.
    let relkey = b.release_pubkey.trim();
    if !relkey.is_empty() {
        if let Err(e) = crate::release::check_pubkey(relkey) {
            return Err(bad(format!("release signing key: {e:#}")));
        }
    }
    let mut pairs: Vec<(&str, serde_json::Value)> = vec![
        ("allow_processes", json!(allow.join("\n"))),
        ("learn_days", json!(b.learn_days)),
        ("report_interval_secs", json!(b.report_interval_secs)),
        ("alert_retain_days", json!(b.alert_retain_days)),
        ("count_retain_days", json!(b.count_retain_days)),
        ("learn_push_enabled", json!(b.learn_push_enabled)),
        ("agent_update_enabled", json!(b.agent_update_enabled)),
        ("release_repo", json!(b.release_repo.trim())),
        ("release_check_enabled", json!(b.release_check_enabled)),
        ("release_pubkey", json!(relkey)),
        ("syslog_enabled", json!(b.syslog_enabled)),
        ("api_keys_enabled", json!(b.api_keys_enabled)),
        ("require_2fa_admin", json!(b.require_2fa_admin)),
        ("require_2fa_viewer", json!(b.require_2fa_viewer)),
        ("abuseipdb_enabled", json!(b.abuseipdb_enabled)),
        ("abuseipdb_daily_limit", json!(b.abuseipdb_daily_limit)),
        ("assist_enabled", json!(b.assist_enabled)),
        ("assist_base_url", json!(assist_base)),
        ("assist_model", json!(b.assist_model.trim())),
        ("assist_daily_limit", json!(b.assist_daily_limit)),
        ("smtp_enabled", json!(b.smtp_enabled)),
        ("smtp_host", json!(b.smtp_host.trim())),
        ("smtp_port", json!(b.smtp_port)),
        ("smtp_security", json!(mail::Security::parse(&b.smtp_security).label())),
        ("smtp_user", json!(b.smtp_user.trim())),
        ("smtp_from", json!(b.smtp_from.trim())),
        ("smtp_to", json!(to.join(", "))),
        ("notify_base_url", json!(base.trim_end_matches('/'))),
        ("notify_alerts", json!(b.notify_alerts)),
        ("notify_agent_down", json!(b.notify_agent_down)),
        ("notify_abuse_ip", json!(b.notify_abuse_ip)),
        ("notify_abuse_min_score", json!(b.notify_abuse_min_score)),
        ("notify_digest_mins", json!(b.notify_digest_mins)),
        ("notify_agent_down_mins", json!(b.notify_agent_down_mins)),
        ("report_timezone", json!(b.report_timezone.trim())),
    ];
    // Secrets only when something really arrived: empty means „unchanged", a
    // single hyphen means „delete".
    let pass = b.smtp_pass.trim();
    if !pass.is_empty() {
        pairs.push(("smtp_pass", json!(if pass == CLEAR_SECRET { "" } else { pass })));
    }
    let key = b.abuseipdb_key.trim();
    if !key.is_empty() {
        pairs.push(("abuseipdb_key", json!(if key == CLEAR_SECRET { "" } else { key })));
    }
    let rel_tok = b.release_token.trim();
    if !rel_tok.is_empty() {
        pairs.push(("release_token", json!(if rel_tok == CLEAR_SECRET { "" } else { rel_tok })));
    }
    let ai_key = b.assist_key.trim();
    if !ai_key.is_empty() {
        pairs.push(("assist_key", json!(if ai_key == CLEAR_SECRET { "" } else { ai_key })));
    } else if assist_host_changed {
        pairs.push(("assist_key", json!("")));
    }
    db::set_settings(&st.pool, &pairs).await?;
    if !key.is_empty() || b.abuseipdb_enabled {
        // A new key (or switching it on again) lifts the pause: otherwise,
        // after a wrong key, the central server would stay silent for an hour
        // even though the right one has long been on file.
        let mut s = st.abuse.lock().unwrap();
        s.paused_until = None;
        s.last_error = None;
    }
    // Same as with the AbuseIPDB key: whoever puts the configuration right
    // has dealt with the old error. Without this the red dot on the tab would
    // stay until the next email happened to fall due.
    st.mail.lock().unwrap().last_error = None;
    db::bump_generation(&st.pool).await?;
    db::audit(&st.pool, (&user).into(), "settings_update", serde_json::to_value(&b).unwrap_or_default()).await;
    settings(State(st), Admin(user)).await
}
