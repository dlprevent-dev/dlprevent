//! Database access. Every query at runtime (no `query!`), so the build gets
//! by without a running database.

use crate::auth;
use anyhow::Result;
use chrono::{DateTime, Utc};
use deelpe_core::central::{AccessAlert, CountBucket, LearnAction, LearnCommand, LogLine, Rule, ShareInfo};
use deelpe_core::correlate::{Alert, Target};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// How many connections the server keeps open.
///
/// Fifty, not ten: one agent report makes about a dozen queries one after
/// another, and with ten thousand agents on a half-minute cycle hundreds of
/// reports are pending at the same time. With ten connections most of them
/// wait in the queue and drop out after `acquire_timeout` — that does not
/// look like slowness, it looks like database errors.
///
/// The ceiling comes from Postgres: the default is `max_connections =
/// 100`, and what stands here applies per server process. Fifty leaves room
/// for `psql`, backups and a second instance during an update.
pub const MAX_DB_CONNECTIONS: u32 = 50;

pub async fn connect(url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new().max_connections(MAX_DB_CONNECTIONS).acquire_timeout(std::time::Duration::from_secs(10)).connect(url).await?)
}

/// On the first start: user `admin` with a random password. Returns the
/// password exactly once (for the log).
pub async fn ensure_admin(pool: &PgPool) -> Result<Option<String>> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users").fetch_one(pool).await?;
    if n > 0 {
        return Ok(None);
    }
    let pw: String = auth::random_token()[..20].to_string();
    sqlx::query("INSERT INTO users (name, pw_hash, role) VALUES ('admin', $1, 'admin')")
        .bind(auth::hash_password(&pw)?)
        .execute(pool)
        .await?;
    Ok(Some(pw))
}

pub async fn setting_i64(pool: &PgPool, key: &str, default: i64) -> Result<i64> {
    let v: Option<(serde_json::Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1").bind(key).fetch_optional(pool).await?;
    Ok(v.and_then(|(v,)| v.as_i64()).unwrap_or(default))
}

/// A switch from the settings. If the key is missing, `default` applies —
/// a server that has never saved anything behaves as it did before.
pub async fn setting_bool(pool: &PgPool, key: &str, default: bool) -> Result<bool> {
    let v: Option<(serde_json::Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1").bind(key).fetch_optional(pool).await?;
    Ok(v.and_then(|(v,)| v.as_bool()).unwrap_or(default))
}

/// A string from the settings. For secrets such as the AbuseIPDB key:
/// those live in `settings` but never leave through the API again (see
/// `api::settings`).
pub async fn setting_str(pool: &PgPool, key: &str) -> Result<Option<String>> {
    let v: Option<(serde_json::Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1").bind(key).fetch_optional(pool).await?;
    Ok(v.and_then(|(v,)| v.as_str().map(str::to_string)))
}

/// Read several settings in **one** query.
///
/// The same argument as for [`agent_settings`], one place further along:
/// the settings page read its thirty-six values one by one, so thirty-six
/// round trips in sequence for one page. That only a human opens it does
/// not make the queries cheaper, it only makes them rarer.
///
/// A missing key is the normal case, not the error case — the caller
/// decides the default.
pub async fn settings_map(pool: &PgPool, keys: &[&str]) -> Result<std::collections::HashMap<String, serde_json::Value>> {
    let rows: Vec<(String, serde_json::Value)> =
        sqlx::query_as("SELECT key, value FROM settings WHERE key = ANY($1)").bind(keys).fetch_all(pool).await?;
    Ok(rows.into_iter().collect())
}

/// Write several settings in **one** step.
///
/// One statement, not thirty-five in a row: if the connection breaks after
/// the twentieth, the server used to stand there half configured — half new
/// rules, half old ones, and nobody saw it. A single `INSERT` over `UNNEST`
/// is atomic in itself; either all values are there, or none.
pub async fn set_settings(pool: &PgPool, pairs: &[(&str, serde_json::Value)]) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
    let values: Vec<serde_json::Value> = pairs.iter().map(|(_, v)| v.clone()).collect();
    sqlx::query(
        "INSERT INTO settings (key, value) SELECT * FROM UNNEST($1::text[], $2::jsonb[]) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(&keys)
    .bind(&values)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_setting(pool: &PgPool, key: &str, value: serde_json::Value) -> Result<()> {
    sqlx::query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await?;
    Ok(())
}

/// Everything that goes from `settings` into the answer to an agent.
///
/// In **one** query, not in five: `agent::report` read these values one by
/// one, and with ten thousand agents on a half-minute cycle that is over a
/// thousand queries per second for five rows that almost never change. How
/// long the answer may be held is not decided by this module but by
/// `state::AppState::agent_settings`.
#[derive(Debug, Clone)]
pub struct AgentSettings {
    pub generation: i64,
    pub report_interval_secs: i64,
    pub learn_days: i64,
    pub learn_push_enabled: bool,
    pub allow_processes: String,
    /// May the server tell an agent to fetch the program staged here and
    /// replace itself with it?
    /// Off by default: whoever switches this on swaps the program on every
    /// machine in the company.
    pub agent_update_enabled: bool,
}

pub async fn agent_settings(pool: &PgPool) -> Result<AgentSettings> {
    const KEYS: [&str; 6] = ["config_generation", "report_interval_secs", "learn_days", "learn_push_enabled", "allow_processes", "agent_update_enabled"];
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as("SELECT key, value FROM settings WHERE key = ANY($1)").bind(&KEYS[..]).fetch_all(pool).await?;
    // A missing key is the normal case, not the error case: an installation
    // where nobody has ever saved anything does not have most of them. The
    // defaults are the same as in the single queries.
    let get = |k: &str| rows.iter().find(|(n, _)| n == k).map(|(_, v)| v);
    Ok(AgentSettings {
        generation: get("config_generation").and_then(serde_json::Value::as_i64).unwrap_or(1),
        report_interval_secs: get("report_interval_secs").and_then(serde_json::Value::as_i64).unwrap_or(30),
        learn_days: get("learn_days").and_then(serde_json::Value::as_i64).unwrap_or(7),
        learn_push_enabled: get("learn_push_enabled").and_then(serde_json::Value::as_bool).unwrap_or(false),
        allow_processes: get("allow_processes").and_then(serde_json::Value::as_str).unwrap_or_default().to_string(),
        agent_update_enabled: get("agent_update_enabled").and_then(serde_json::Value::as_bool).unwrap_or(false),
    })
}

/// Every change to a rule or a setting raises the generation; agents only
/// take over their configuration when it has grown.
pub async fn bump_generation(pool: &PgPool) -> Result<i64> {
    let g = setting_i64(pool, "config_generation", 1).await? + 1;
    set_setting(pool, "config_generation", serde_json::json!(g)).await?;
    Ok(g)
}

/// Raise the generation when a different server build is running than at
/// the last start. Returns the new generation if it was raised.
///
/// An agent only takes over its configuration when the generation has
/// grown — and otherwise that only grows when somebody saves a rule or a
/// setting. A new server build can however *translate the same rules
/// differently*: when `endpoint_rules` started to deliver every folder
/// under the file server's address as well, not one line in `rules`
/// changed — and every agent kept its old version until somebody nudged it
/// by hand. Happened twice in a row on 2026-09-10.
///
/// Not at every start: a restart of the same build changes nothing, and
/// every nudge costs every agent a re-application of its policy — arming
/// the sensors again, setting the SACLs again. So what is compared is the
/// server file itself, not `version`: that has stood at the same number
/// since forever and says nothing about what is running right now.
///
/// If the own file cannot be read, `build` is empty and the generation is
/// raised. Better once too often than a fleet on an old state.
pub async fn bump_generation_on_new_build(pool: &PgPool, build: &str) -> Result<Option<i64>> {
    if !build.is_empty() && setting_str(pool, "server_build").await?.as_deref() == Some(build) {
        return Ok(None);
    }
    let g = bump_generation(pool).await?;
    set_setting(pool, "server_build", serde_json::json!(build)).await?;
    Ok(Some(g))
}

/// Who triggered a change.
///
/// Id and name only — an audit entry carries no more. `auth::User` used to
/// stand here, the extractor of the HTTP side; that hung this module on
/// `state` and on axum by way of `auth`, even though four of the twenty-one
/// callers have no HTTP session at all (mTLS agent path, syslog, failed
/// login) and always passed `None`.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    pub id: Option<Uuid>,
    pub name: &'a str,
}

impl Actor<'_> {
    /// No logged-in user: the service itself acted.
    pub const SYSTEM: Actor<'static> = Actor { id: None, name: "system" };
}

pub async fn audit(pool: &PgPool, actor: Actor<'_>, action: &str, detail: serde_json::Value) {
    let r = sqlx::query("INSERT INTO audit_log (user_id, user_name, action, detail) VALUES ($1, $2, $3, $4)")
        .bind(actor.id)
        .bind(actor.name)
        .bind(action)
        .bind(detail)
        .execute(pool)
        .await;
    if let Err(e) = r {
        tracing::error!("audit: {e}");
    }
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct RuleRow {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub scope: String,
    pub agent_id: Option<Uuid>,
    pub source_id: Option<Uuid>,
    pub allowed_groups: Vec<String>,
    pub lockdown: bool,
    pub strict: bool,
    pub allow_destinations: Vec<String>,
    pub enforce: bool,
    pub hard_max_files: i32,
    pub window_secs: i32,
    pub ad_lock: bool,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RuleRow {
    pub fn to_wire(&self) -> Rule {
        Rule {
            id: self.id.to_string(),
            name: self.name.clone(),
            path: self.path.clone(),
            allowed_groups: self.allowed_groups.clone(),
            lockdown: self.lockdown,
            allow_destinations: self.allow_destinations.clone(),
            strict: self.strict,
            enforce: self.enforce,
            hard_max_files: self.hard_max_files.max(1) as u32,
            window_secs: self.window_secs.max(1) as u32,
            ad_lock: self.ad_lock,
            enabled: self.enabled,
        }
    }
}

pub const RULE_COLS: &str =
    "id, name, path, scope, agent_id, source_id, allowed_groups, lockdown, strict, allow_destinations, enforce, hard_max_files, window_secs, ad_lock, enabled, created_at, updated_at";

pub async fn all_rules(pool: &PgPool) -> Result<Vec<RuleRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {RULE_COLS} FROM rules ORDER BY name"))).fetch_all(pool).await?)
}

pub async fn rules_for_agent(pool: &PgPool, agent: Uuid) -> Result<Vec<RuleRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {RULE_COLS} FROM rules WHERE enabled AND (scope = 'all' OR (scope = 'agent' AND agent_id = $1)) ORDER BY path"
    )))
    .bind(agent)
    .fetch_all(pool)
    .await?)
}

/// Rules for an **endpoint**: its own, the general ones — and those of
/// every file server.
///
/// A folder on a file server is a shared thing: whoever protects it there
/// means it on every workstation that can reach it. That was exactly the
/// gap — the strict rule hung off the file server, the workstation never
/// got to see it and guarded nothing (lab 2026-09-08). The path is
/// translated afterwards in [`deelpe_core::rules::endpoint_rule_path`].
///
/// Rules that hang off *another workstation* stay there: a local folder is
/// not a shared thing.
pub async fn rules_for_endpoint(pool: &PgPool, agent: Uuid) -> Result<Vec<RuleRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {RULE_COLS} FROM rules WHERE enabled AND (scope = 'all' OR (scope = 'agent' AND (agent_id = $1 \
         OR agent_id IN (SELECT id FROM agents WHERE kind = 'windows_server' AND revoked_at IS NULL)))) ORDER BY path"
    )))
    .bind(agent)
    .fetch_all(pool)
    .await?)
}

/// A file server agent with the share table it last reported. Translating
/// a rule needs no more than that.
pub struct FileServer {
    pub id: Uuid,
    pub name: String,
    pub shares: Vec<ShareInfo>,
    /// Addresses under which the same server is reachable — from the
    /// agent's status, not from `last_addr`: behind Docker, a proxy or a
    /// tunnel the server only carries the last hop there
    /// (`deelpe_core::netaddr`).
    pub addrs: Vec<String>,
    /// Fully qualified name, empty for a server without a domain or for an
    /// agent that does not send the field yet.
    pub fqdn: String,
}

impl FileServer {
    /// The names under which the same server can show up on a workstation:
    /// its computer name, then its addresses.
    ///
    /// For each of them the rule goes over the wire once. That is the same
    /// trade as with two servers holding a share of the same name — more
    /// rows in the answer, but in exchange the rule also catches whoever
    /// types `\\192.0.2.201\GL` into the address bar instead of taking
    /// the mapped drive.
    ///
    /// Strictly speaking the long name is dispensable — the comparison
    /// shortens it itself anyway (`deelpe_core::path`). It stands here all
    /// the same, because "the rule covers it" and "the rule names it" are
    /// not the same thing: what the agent reports as a guarded folder is
    /// what the dashboard shows, and there the fully qualified name should
    /// be visible.
    ///
    /// If the server carries no long name, the entry drops out; if it is
    /// the same as the short name, the duplicate path falls out again in
    /// `endpoint_rules`.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        std::iter::once(self.name.as_str())
            .chain(Some(self.fqdn.as_str()).filter(|f| !f.is_empty()))
            .chain(self.addrs.iter().map(String::as_str))
    }
}

/// What may go into a UNC path the server builds for somebody else.
///
/// `FileServer::hosts` and `deelpe_core::rules::endpoint_rule_path` turn the
/// name, the fqdn and the addresses of a `windows_server` agent into
/// `\\<host>\<share>` — and all three come out of that agent's own report.
/// Every `windows_server` in this list is folded into **every** endpoint's
/// rule set (`rules_for_endpoint`), so an unvalidated host here is an
/// unvalidated folder name in another agent's policy.
///
/// A host component of a UNC path is a NetBIOS name, a fully qualified name
/// or an IPv4 literal: dot-separated labels of letters, digits, `-` and `_`
/// (Windows lets a computer name carry one). Anything else — empty,
/// carrying a path separator, a wildcard or a space, only dots — is dropped
/// rather than sanitised: a host that cannot be spelled is a host that
/// cannot be matched, and a rule matching nothing is better than one
/// matching an attacker's server.
fn valid_unc_host(h: &str) -> bool {
    h.len() <= 253
        && h.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63 && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// The share table of a file server, as far as the rule delivery may use it.
///
/// The same question one level down: `ShareInfo::path` is matched against a
/// rule's path to decide *which* share of this server the rule means, and
/// `ShareInfo::name` becomes the share component of the UNC path. A name
/// that is not a single path component, or a `path` carrying a UNC prefix of
/// its own, would let one server claim a folder on a *different* machine. An
/// entry that fails is dropped and the rest of the table still works: a
/// server with one odd share is still the right answer for the others.
fn usable_shares(shares: Vec<ShareInfo>) -> Vec<ShareInfo> {
    shares
        .into_iter()
        .filter(|s| {
            let name = s.name.trim();
            let name_ok = !name.is_empty()
                && name.len() <= 80
                && !name.chars().all(|c| c == '.')
                && !name.contains(|c: char| c.is_control() || r#"\/*?"<>|:"#.contains(c));
            let path_ok = s
                .path
                .as_deref()
                .map(|p| {
                    let p = p.trim();
                    // A UNC path of its own (`\\other\share`) would let a
                    // server claim a folder on a *different* machine.
                    !p.is_empty() && !p.starts_with("\\\\") && !p.contains('\0')
                })
                .unwrap_or(true);
            name_ok && path_ok
        })
        .collect()
}

pub async fn file_servers(pool: &PgPool) -> Result<Vec<FileServer>> {
    let rows: Vec<(Uuid, String, Option<serde_json::Value>)> =
        sqlx::query_as("SELECT id, name, status FROM agents WHERE kind = 'windows_server' AND revoked_at IS NULL ORDER BY name")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, status)| FileServer {
            id,
            // The name is the host in every `\\<host>\<share>` this server
            // contributes. An empty or unspellable one yields no rule path
            // at all rather than a malformed one.
            name: Some(name.trim()).filter(|n| valid_unc_host(n)).unwrap_or_default().to_string(),
            // A server that has never reported has no table — then there
            // is nothing to translate for its rules, and they stay out
            // instead of pointing at a guessed place.
            shares: usable_shares(status
                .as_ref()
                .and_then(|v| v.get("shares").cloned())
                .and_then(|v| serde_json::from_value(v).ok())
                .unwrap_or_default()),
            // IPv4 only: an IPv6 address does not stand in a UNC path as
            // itself but in the literal form
            // (`2001-db8--1.ipv6-literal.net`). Delivering it raw would
            // yield a rule path that no event ever hits — and that is worse
            // than none, because in the dashboard it looks like protection.
            fqdn: status
                .as_ref()
                .and_then(|v| v.get("fqdn"))
                .and_then(|v| v.as_str())
                .filter(|f| valid_unc_host(f))
                .unwrap_or_default()
                .to_string(),
            addrs: status
                .as_ref()
                .and_then(|v| v.get("addrs").cloned())
                .and_then(|v| serde_json::from_value::<Vec<String>>(v).ok())
                .unwrap_or_default()
                .into_iter()
                .filter(|a| a.parse::<std::net::Ipv4Addr>().is_ok())
                .collect(),
        })
        .collect())
}

pub async fn rules_for_source(pool: &PgPool, source: Uuid) -> Result<Vec<RuleRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {RULE_COLS} FROM rules WHERE enabled AND (scope = 'all' OR (scope = 'source' AND source_id = $1)) ORDER BY path"
    )))
    .bind(source)
    .fetch_all(pool)
    .await?)
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AgentRow {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub version: String,
    pub cert_fingerprint: String,
    pub cert_not_after: DateTime<Utc>,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub last_addr: Option<String>,
    pub status: Option<serde_json::Value>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// An open update order for **this** agent, independent of the master
    /// switch. See migration 0013; `agent::report` clears it away as soon
    /// as the agent runs the staged program.
    pub update_requested: Option<DateTime<Utc>>,
    /// An open order to finish the learning phase. See migration 0016;
    /// `agent::report` clears it once the agent reports "active".
    pub learn_confirm_requested: Option<DateTime<Utc>>,
}

pub const AGENT_COLS: &str =
    "id, name, kind, version, cert_fingerprint, cert_not_after, enrolled_at, last_seen, last_addr, status, revoked_at, update_requested, learn_confirm_requested";

/// The agent for a client certificate. The previous fingerprint counts as
/// long as `prev_cert_until` lies in the future: otherwise an agent locks
/// itself out when it crashes between the answer and the store during a
/// renewal. How long that deadline is, is decided where it is set —
/// `agent::RENEW_GRACE_HOURS`.
pub async fn agent_by_fingerprint(pool: &PgPool, fp: &str) -> Result<Option<AgentRow>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {AGENT_COLS} FROM agents WHERE cert_fingerprint = $1 OR (prev_cert_fingerprint = $1 AND prev_cert_until > now())"
    )))
    .bind(fp)
    .fetch_optional(pool)
    .await?)
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SourceRow {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub address: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub lines: i64,
    pub unparsed: i64,
    /// Lines of an unconfirmed source are counted, nothing more: no access
    /// counts, no alerts (syslog is unauthenticated).
    pub confirmed: bool,
}

pub const SOURCE_COLS: &str = "id, name, kind, address, first_seen, last_seen, lines, unparsed, confirmed";

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AlertRow {
    pub id: i64,
    pub kind: String,
    pub agent_id: Option<Uuid>,
    pub source_id: Option<Uuid>,
    pub origin_name: String,
    pub external_id: String,
    pub at: DateTime<Utc>,
    pub last_at: Option<DateTime<Utc>>,
    pub user_key: Option<String>,
    pub user_display: Option<String>,
    pub rule_id: Option<Uuid>,
    pub path: Option<String>,
    pub process: Option<String>,
    pub files: serde_json::Value,
    pub file_count: i32,
    pub bytes: i64,
    pub remote: Option<String>,
    pub verdict: String,
    pub reason: Option<String>,
    pub detail: serde_json::Value,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledged_by: Option<Uuid>,
    pub received_at: DateTime<Utc>,
}

pub const ALERT_COLS: &str = "id, kind, agent_id, source_id, origin_name, external_id, at, last_at, user_key, user_display, rule_id, path, process, files, file_count, bytes, remote, verdict, reason, detail, acknowledged_at, acknowledged_by, received_at";

#[derive(Debug, Clone, Copy)]
pub enum Origin {
    Agent(Uuid),
    Source(Uuid),
}

impl Origin {
    fn cols(&self) -> (Option<Uuid>, Option<Uuid>) {
        match self {
            Origin::Agent(u) => (Some(*u), None),
            Origin::Source(u) => (None, Some(*u)),
        }
    }
}

/// `$20` says whether the alert comes in already settled: by design,
/// learning-phase alerts are stored but not reported, and would have no
/// business in the list of open ones. When updating, an `acknowledged_at`
/// that is set stays set — whoever closed an alert does not want to see it
/// open again at the next report — but a learning alert that came in
/// silently opens up if it later gets a verdict worth reporting. The one
/// exception to "stays set": an alert re-judged `denied` opens again even if
/// someone acknowledged it while it was something milder — a denied alarm is
/// never silenced.
const ALERT_UPSERT: &str = "INSERT INTO alerts (kind, agent_id, source_id, origin_name, external_id, at, last_at, user_key, user_display, rule_id, path, process, files, file_count, bytes, remote, verdict, reason, detail, acknowledged_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, CASE WHEN $20 THEN now() ELSE NULL END) \
     ON CONFLICT (COALESCE(agent_id, source_id), external_id) DO UPDATE SET \
       last_at = EXCLUDED.last_at, files = EXCLUDED.files, file_count = EXCLUDED.file_count, bytes = EXCLUDED.bytes, \
       verdict = EXCLUDED.verdict, reason = EXCLUDED.reason, detail = EXCLUDED.detail, received_at = now(), \
       acknowledged_at = CASE WHEN alerts.acknowledged_by IS NULL AND NOT $20 THEN NULL \
                              WHEN EXCLUDED.verdict = 'denied' AND alerts.verdict <> 'denied' THEN NULL \
                              ELSE alerts.acknowledged_at END, \
       acknowledged_by = CASE WHEN EXCLUDED.verdict = 'denied' AND alerts.verdict <> 'denied' THEN NULL ELSE alerts.acknowledged_by END \
     RETURNING (xmax = 0) AS inserted";

/// Verdicts that are meant for the table only and should not occupy
/// anybody.
fn silent_verdict(verdict: &str) -> bool {
    verdict == "learning"
}

/// An alert from the endpoint correlator (Mac/Linux). Returns true if new.
pub async fn upsert_endpoint_alert(pool: &PgPool, origin: Origin, origin_name: &str, a: &Alert) -> Result<bool> {
    let (agent_id, source_id) = origin.cols();
    // The same derivation as in the correlator and in the CLI; only the
    // presentation is that of a column: no destination means NULL, not "?".
    let remote = match a.target() {
        Target::Volume(v) => Some(format!("volume {}", v.display())),
        Target::Copy(c) => Some(format!("copy to {}", c.display())),
        Target::Net { ip, port: Some(p), .. } => Some(format!("{ip}:{p}")),
        Target::Net { ip, port: None, .. } => Some(ip.to_string()),
        Target::Upload(u) => Some(format!("upload to {u}")),
        Target::Unknown => None,
    };
    let verdict = serde_json::to_value(a.verdict)?.as_str().unwrap_or("new").to_string();
    let files: Vec<String> = a.files.iter().map(|p| p.display().to_string()).collect();
    let (inserted,): (bool,) = sqlx::query_as(ALERT_UPSERT)
        .bind("endpoint")
        .bind(agent_id)
        .bind(source_id)
        .bind(origin_name)
        .bind(a.id.to_string())
        .bind(a.at)
        .bind(a.last_at)
        .bind(Option::<String>::None)
        .bind(Option::<String>::None)
        .bind(Option::<Uuid>::None)
        .bind(files.first().cloned())
        .bind(a.identity.short())
        .bind(serde_json::to_value(&files)?)
        .bind(files.len() as i32)
        .bind(a.bytes_out as i64)
        .bind(remote)
        .bind(&verdict)
        .bind(a.reason.clone())
        .bind(serde_json::to_value(a)?)
        .bind(silent_verdict(&verdict))
        .fetch_one(pool)
        .await?;
    Ok(inserted)
}

pub async fn upsert_access_alert(pool: &PgPool, origin: Origin, origin_name: &str, a: &AccessAlert) -> Result<bool> {
    let (agent_id, source_id) = origin.cols();
    let rule_id = a.rule_id.as_deref().and_then(|s| Uuid::parse_str(s).ok());
    let (inserted,): (bool,) = sqlx::query_as(ALERT_UPSERT)
        .bind("access")
        .bind(agent_id)
        .bind(source_id)
        .bind(origin_name)
        .bind(&a.external_id)
        .bind(a.at)
        .bind(a.last_at)
        .bind(a.user.key())
        .bind(a.user.display())
        .bind(rule_id)
        .bind(&a.path)
        .bind(Option::<String>::None)
        .bind(serde_json::to_value(&a.sample_files)?)
        .bind(a.files as i32)
        .bind(i64::try_from(a.bytes).unwrap_or(i64::MAX))
        .bind(a.client_ip.clone())
        .bind(a.verdict.label())
        .bind(a.reason.clone())
        .bind(serde_json::to_value(a)?)
        .bind(silent_verdict(a.verdict.label()))
        .fetch_one(pool)
        .await?;
    Ok(inserted)
}

/// A count as it stands in the table — minute already truncated.
#[derive(Debug, Clone, PartialEq)]
pub struct CountRow {
    pub rule_id: Option<Uuid>,
    pub path: String,
    pub user_key: String,
    pub user_display: String,
    pub bucket: DateTime<Utc>,
    pub files: i32,
    pub bytes: i64,
}

/// Merge the counts of one report down to what the table distinguishes:
/// path, user and minute.
///
/// Has to happen before the write, ever since they all go in with **one**
/// statement: `ON CONFLICT DO UPDATE` must not hit the same row twice in
/// the same statement — otherwise Postgres does not abort that one count
/// but the whole report. Merging follows exactly the rule the statement
/// applies too: the larger value wins, a rule id replaces a missing one,
/// and the display name stays the one reported first — the statement does
/// not rewrite it on a hit either.
///
/// `BTreeMap`, not `HashMap`: that fixes the order of the rows, and two
/// identical reports produce the same statement.
fn merge_counts(counts: &[CountBucket]) -> Vec<CountRow> {
    use chrono::Timelike;
    let mut merged: std::collections::BTreeMap<(String, String, DateTime<Utc>), CountRow> = std::collections::BTreeMap::new();
    for c in counts {
        // The same minute as `date_trunc('minute', ...)` in the statement;
        // whoever truncates differently here merges what the table keeps
        // apart (or the other way round).
        let bucket = c.bucket.with_second(0).and_then(|t| t.with_nanosecond(0)).unwrap_or(c.bucket);
        let rule_id = c.rule_id.as_deref().and_then(|s| Uuid::parse_str(s).ok());
        // Clamped, not cast: a saturated u64 became -1 in the table.
        let (files, bytes) = (i32::try_from(c.files).unwrap_or(i32::MAX), i64::try_from(c.bytes).unwrap_or(i64::MAX));
        match merged.entry((c.path.clone(), c.user.key(), bucket)) {
            std::collections::btree_map::Entry::Occupied(mut e) => {
                let row = e.get_mut();
                row.files = row.files.max(files);
                row.bytes = row.bytes.max(bytes);
                row.rule_id = rule_id.or(row.rule_id);
            }
            std::collections::btree_map::Entry::Vacant(e) => {
                e.insert(CountRow { rule_id, path: c.path.clone(), user_key: c.user.key(), user_display: c.user.display(), bucket, files, bytes });
            }
        }
    }
    merged.into_values().collect()
}

/// Write the counts of one report.
///
/// One statement for all of them, not one per row: a file server easily
/// reports dozens of counts, and sending each one on its own cost a trip to
/// the database each time. The pattern is the same as in `insert_agent_log`.
///
/// What comes back is how many counts the report brought along — not how
/// many rows came out of them: the agent reads the number as "accepted",
/// and accepted are all of them, the merged ones included.
pub async fn upsert_counts(pool: &PgPool, origin: Uuid, counts: &[CountBucket]) -> Result<usize> {
    let rows = merge_counts(counts);
    if rows.is_empty() {
        return Ok(0);
    }
    let rule_ids: Vec<Option<Uuid>> = rows.iter().map(|r| r.rule_id).collect();
    let paths: Vec<&str> = rows.iter().map(|r| r.path.as_str()).collect();
    let user_keys: Vec<&str> = rows.iter().map(|r| r.user_key.as_str()).collect();
    let user_displays: Vec<&str> = rows.iter().map(|r| r.user_display.as_str()).collect();
    let buckets: Vec<DateTime<Utc>> = rows.iter().map(|r| r.bucket).collect();
    let files: Vec<i32> = rows.iter().map(|r| r.files).collect();
    let bytes: Vec<i64> = rows.iter().map(|r| r.bytes).collect();
    sqlx::query(
        "INSERT INTO access_counts (origin, rule_id, path, user_key, user_display, bucket, files, bytes) \
         SELECT $1, r, p, uk, ud, date_trunc('minute', b), f, y \
         FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[], $6::timestamptz[], $7::int[], $8::bigint[]) AS x(r, p, uk, ud, b, f, y) \
         ON CONFLICT (origin, path, user_key, bucket) DO UPDATE SET files = GREATEST(access_counts.files, EXCLUDED.files), bytes = GREATEST(access_counts.bytes, EXCLUDED.bytes), rule_id = COALESCE(EXCLUDED.rule_id, access_counts.rule_id)",
    )
    .bind(origin)
    .bind(&rule_ids)
    .bind(&paths)
    .bind(&user_keys)
    .bind(&user_displays)
    .bind(&buckets)
    .bind(&files)
    .bind(&bytes)
    .execute(pool)
    .await?;
    Ok(counts.len())
}

/// Replace an agent's groups completely. An agent reports them only when
/// they change, and then as a whole list — so delete and write anew rather
/// than reconcile: with ten thousand rows that is faster and cannot drift
/// apart.
pub async fn replace_agent_groups(pool: &PgPool, agent_id: Uuid, groups: &[deelpe_core::central::GroupInfo]) -> Result<usize> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM agent_groups WHERE agent_id = $1").bind(agent_id).execute(&mut *tx).await?;
    if !groups.is_empty() {
        let names: Vec<String> = groups.iter().map(|g| g.name.clone()).collect();
        let kinds: Vec<String> = groups.iter().map(|g| g.kind.clone()).collect();
        sqlx::query(
            "INSERT INTO agent_groups (agent_id, name, kind) \
             SELECT $1, n, k FROM unnest($2::text[], $3::text[]) AS t(n, k) \
             ON CONFLICT (agent_id, name) DO NOTHING",
        )
        .bind(agent_id)
        .bind(&names)
        .bind(&kinds)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(groups.len())
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct GroupRow {
    pub name: String,
    pub kind: String,
    pub agent_id: Uuid,
    pub agent_name: String,
}

/// Search groups. Always with a limit: in a customer environment there are
/// tens of thousands, and neither the wire nor the browser wants them all.
pub async fn search_groups(pool: &PgPool, q: Option<&str>, agent: Option<Uuid>, limit: i64) -> Result<Vec<GroupRow>> {
    let pattern = format!("%{}%", q.unwrap_or("").trim().to_lowercase());
    Ok(sqlx::query_as(
        "SELECT g.name, g.kind, g.agent_id, a.name AS agent_name \
         FROM agent_groups g JOIN agents a ON a.id = g.agent_id \
         WHERE ($1::uuid IS NULL OR g.agent_id = $1) AND lower(g.name) LIKE $2 \
         ORDER BY g.name LIMIT $3",
    )
    .bind(agent)
    .bind(pattern)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

// ---------- Agent log ----------

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct LogRow {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub level: String,
    pub target: String,
    pub msg: String,
}

/// Write away the lines of one report. One statement for all of them: at
/// 200 lines every 30 seconds per agent, one row per insert costs too much.
pub async fn insert_agent_log(pool: &PgPool, agent_id: Uuid, lines: &[LogLine]) -> Result<usize> {
    if lines.is_empty() {
        return Ok(0);
    }
    let ats: Vec<DateTime<Utc>> = lines.iter().map(|l| l.at).collect();
    let levels: Vec<String> = lines.iter().map(|l| l.level.clone()).collect();
    let targets: Vec<String> = lines.iter().map(|l| l.target.clone()).collect();
    // A line can be arbitrarily long (an error text with paths); the table
    // is no place to park megabytes. Null bytes are thrown out: Postgres
    // does not accept them in `text`, and a single such line would otherwise
    // make every further report from this agent unstorable.
    let msgs: Vec<String> = lines.iter().map(|l| l.msg.chars().filter(|c| *c != '\0').take(2000).collect()).collect();
    // `DO NOTHING`: if the server accepts the report and the answer gets
    // lost, the agent sends the same lines again — as with alerts and
    // counts, that must not duplicate anything.
    sqlx::query(
        "INSERT INTO agent_log (agent_id, at, level, target, msg) \
         SELECT $1, a, l, t, m FROM unnest($2::timestamptz[], $3::text[], $4::text[], $5::text[]) AS x(a, l, t, m) \
         ON CONFLICT DO NOTHING",
    )
    .bind(agent_id)
    .bind(&ats)
    .bind(&levels)
    .bind(&targets)
    .bind(&msgs)
    .execute(pool)
    .await?;
    Ok(lines.len())
}

/// The last lines of an agent, newest first. `level` filters on exactly
/// that level (`info` shows infos only), `q` searches the text.
pub async fn agent_log(pool: &PgPool, agent_id: Uuid, level: Option<&str>, q: Option<&str>, limit: i64) -> Result<Vec<LogRow>> {
    Ok(sqlx::query_as(
        "SELECT id, at, level, target, msg FROM agent_log \
         WHERE agent_id = $1 AND ($2::text IS NULL OR level = $2) \
         AND ($3::text IS NULL OR msg ILIKE $3 OR target ILIKE $3) \
         ORDER BY at DESC, id DESC LIMIT $4",
    )
    .bind(agent_id)
    .bind(level)
    // Check first, then wrap: `%a%` is three characters long and would
    // otherwise get through every length check.
    .bind(q.map(str::trim).filter(|q| q.chars().count() > 2).map(|q| format!("%{q}%")))
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

// ---------- Learning instructions ----------

/// Open instructions for an agent. They stay open until the agent ticks
/// them off in its next report; a lost report therefore costs only one
/// repeat.
pub async fn pending_learn(pool: &PgPool, agent_id: Uuid) -> Result<Vec<LearnCommand>> {
    let rows: Vec<(i64, i64, String)> =
        sqlx::query_as("SELECT id, alert_id, action FROM learn_commands WHERE agent_id = $1 AND applied_at IS NULL ORDER BY id LIMIT 100")
            .bind(agent_id)
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|(id, alert_id, action)| LearnCommand {
            id,
            alert_id: alert_id.max(0) as u64,
            action: if action == "flag" { LearnAction::Flag } else { LearnAction::Remember },
        })
        .collect())
}

/// Tick off what the agent reported. Only its own rows: the id comes from
/// an answer to exactly this agent.
pub async fn mark_learn_applied(pool: &PgPool, agent_id: Uuid, ids: &[i64]) -> Result<u64> {
    if ids.is_empty() {
        return Ok(0);
    }
    Ok(sqlx::query("UPDATE learn_commands SET applied_at = now() WHERE agent_id = $1 AND applied_at IS NULL AND id = ANY($2)")
        .bind(agent_id)
        .bind(ids)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Queue an instruction. If the same one is already open, the old one stays.
pub async fn queue_learn(pool: &PgPool, agent_id: Uuid, alert_id: i64, action: &str, by: Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO learn_commands (agent_id, alert_id, action, created_by) VALUES ($1, $2, $3, $4) \
         ON CONFLICT DO NOTHING",
    )
    .bind(agent_id)
    .bind(alert_id)
    .bind(action)
    .bind(by)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deelpe_core::central::UserRef;

    fn count(path: &str, user: &str, at: &str, files: u32, bytes: u64, rule: Option<&str>) -> CountBucket {
        CountBucket {
            rule_id: rule.map(str::to_string),
            path: path.into(),
            user: UserRef { source: "SRV".into(), name: user.into(), domain: None, sid: None },
            bucket: at.parse().unwrap(),
            files,
            bytes,
        }
    }

    /// Two counts of the same minute are one row in the table — and have to
    /// be one already before the statement, otherwise `ON CONFLICT DO
    /// UPDATE` hits the same row twice and the whole report fails.
    #[test]
    fn counts_of_one_minute_become_one_row() {
        let id = "0f9a4a6e-0000-4000-8000-000000000001";
        let rows = merge_counts(&[
            count("GL", "hans", "2026-09-10T10:00:05Z", 3, 300, None),
            count("GL", "hans", "2026-09-10T10:00:41Z", 7, 100, Some(id)),
        ]);
        assert_eq!(rows.len(), 1);
        // The larger value wins, per column separately — like GREATEST in
        // the statement. Not the last count, not their sum.
        assert_eq!((rows[0].files, rows[0].bytes), (7, 300));
        // An id replaces a missing one (COALESCE), and the minute is
        // truncated.
        assert_eq!(rows[0].rule_id, Some(Uuid::parse_str(id).unwrap()));
        assert_eq!(rows[0].bucket.to_rfc3339(), "2026-09-10T10:00:00+00:00");
    }

    /// A saturated count stays the largest number, it does not turn negative.
    #[test]
    fn a_saturated_count_is_not_stored_negative() {
        let rows = merge_counts(&[count("GL", "hans", "2026-09-10T10:00:05Z", u32::MAX, u64::MAX, None)]);
        assert_eq!((rows[0].files, rows[0].bytes), (i32::MAX, i64::MAX));
    }

    /// The bundled statement itself: types, a NULL in the id column and a
    /// hit on a row that already stands. The merging before it is checked by
    /// the test above — here it is about what Postgres makes of it. Needs
    /// `DATABASE_URL`, see docs/SERVER.md.
    /// A `denied` alarm is never silenced (README). An alert someone
    /// acknowledged while it was `new` and that the agent later re-judges as
    /// `denied` under the same id is a new alarm, not an old closed one.
    #[sqlx::test(migrations = "./migrations")]
    async fn an_alert_that_turns_denied_opens_again(pool: PgPool) {
        let agent: Uuid = sqlx::query_scalar(
            "INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after) \
             VALUES (gen_random_uuid(), 'mac', 'macos', '0.1.0', 'fp', now() + interval '1 day') RETURNING id",
        )
        .fetch_one(&pool).await.unwrap();
        let admin: Uuid = sqlx::query_scalar("INSERT INTO users (name, pw_hash, role) VALUES ('admin', '', 'admin') RETURNING id").fetch_one(&pool).await.unwrap();
        let upsert = |verdict: &'static str| {
            sqlx::query(ALERT_UPSERT)
                .bind("endpoint").bind(agent).bind(Option::<Uuid>::None).bind("mac").bind("a1")
                .bind(Utc::now()).bind(Utc::now()).bind(Option::<String>::None).bind(Option::<String>::None).bind(Option::<Uuid>::None)
                .bind("/GL/a.txt").bind("curl").bind(serde_json::json!([])).bind(1).bind(1_i64).bind("1.2.3.4:443")
                .bind(verdict).bind("").bind(serde_json::json!({})).bind(false)
                .execute(&pool)
        };
        let open = || sqlx::query_scalar::<_, bool>("SELECT acknowledged_at IS NULL FROM alerts WHERE external_id = 'a1'").fetch_one(&pool);
        upsert("new").await.unwrap();
        sqlx::query("UPDATE alerts SET acknowledged_at = now(), acknowledged_by = $1").bind(admin).execute(&pool).await.unwrap();
        upsert("new").await.unwrap();
        assert!(!open().await.unwrap(), "an acknowledged alert stays acknowledged");
        upsert("denied").await.unwrap();
        assert!(open().await.unwrap(), "a denied alarm is never silenced");
        upsert("denied").await.unwrap();
        assert!(open().await.unwrap());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn a_batch_of_counts_lands_and_a_repeat_keeps_the_larger_value(pool: PgPool) {
        let origin = Uuid::from_u128(1);
        let id = "0f9a4a6e-0000-4000-8000-000000000001";
        // Two counts in one statement, one of them without a rule id.
        let n = upsert_counts(
            &pool,
            origin,
            &[count("GL", "hans", "2026-09-10T10:00:05Z", 5, 500, None), count("HR", "anna", "2026-09-10T10:00:05Z", 2, 200, Some(id))],
        )
        .await
        .unwrap();
        assert_eq!(n, 2);
        // The same minute once more, with smaller numbers and an id handed
        // in late: the larger number stays, the id is added, and no second
        // row comes into being.
        upsert_counts(&pool, origin, &[count("GL", "hans", "2026-09-10T10:00:41Z", 1, 1, Some(id))]).await.unwrap();
        let rows: Vec<(String, i32, i64, Option<Uuid>)> =
            sqlx::query_as("SELECT path, files, bytes, rule_id FROM access_counts ORDER BY path").fetch_all(&pool).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("GL".to_string(), 5, 500, Some(Uuid::parse_str(id).unwrap())));
        assert_eq!(rows[1].3, Some(Uuid::parse_str(id).unwrap()));
    }

    /// Five values in one query: what the installation has set comes from
    /// there — what it never set, from the default. The second case is the
    /// normal one, and the one `key = ANY($1)` could quietly get wrong.
    /// Needs `DATABASE_URL`, see docs/SERVER.md.
    #[sqlx::test(migrations = "./migrations")]
    async fn agent_settings_come_from_one_query_and_fall_back_per_key(pool: PgPool) {
        // Fresh installation: `0001_init.sql` sets three of the five keys,
        // the other two do not exist at all yet.
        let s = agent_settings(&pool).await.unwrap();
        assert_eq!((s.generation, s.report_interval_secs, s.learn_days), (1, 30, 7));
        assert!(!s.learn_push_enabled && s.allow_processes.is_empty());

        set_setting(&pool, "report_interval_secs", serde_json::json!(300)).await.unwrap();
        set_setting(&pool, "learn_push_enabled", serde_json::json!(true)).await.unwrap();
        set_setting(&pool, "allow_processes", serde_json::json!("Word.exe\nExcel.exe")).await.unwrap();
        let g = bump_generation(&pool).await.unwrap();
        let s = agent_settings(&pool).await.unwrap();
        assert_eq!((s.generation, s.report_interval_secs, s.learn_days), (g, 300, 7));
        assert!(s.learn_push_enabled);
        assert_eq!(s.allow_processes, "Word.exe\nExcel.exe");
    }

    /// The nudge after an update — exactly once per build, not at every
    /// restart. Needs `DATABASE_URL`, see docs/SERVER.md.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_new_server_build_bumps_the_generation_once(pool: PgPool) {
        // The very first start at all: the build is unknown, so nudge.
        let g = bump_generation_on_new_build(&pool, "aaaa").await.unwrap().unwrap();
        assert_eq!(g, 2, "aus der Vorgabe 1 der Migration");
        // Restart of the same build: nothing. Otherwise every agent
        // re-applies its policy after every `docker compose up`.
        assert_eq!(bump_generation_on_new_build(&pool, "aaaa").await.unwrap(), None);
        assert_eq!(bump_generation_on_new_build(&pool, "aaaa").await.unwrap(), None);
        // Update: nudge once, and the marker moves along.
        assert_eq!(bump_generation_on_new_build(&pool, "bbbb").await.unwrap(), Some(3));
        assert_eq!(bump_generation_on_new_build(&pool, "bbbb").await.unwrap(), None);
        // Own file unreadable: the build is unknown, and then it is better
        // to nudge than to leave a fleet on an old state.
        assert_eq!(bump_generation_on_new_build(&pool, "").await.unwrap(), Some(4));
        assert_eq!(bump_generation_on_new_build(&pool, "").await.unwrap(), Some(5));
        // Afterwards the value stands where `agent::report` reads it.
        assert_eq!(agent_settings(&pool).await.unwrap().generation, 5);
    }

    /// What a file server reports about itself becomes the host and share of
    /// a UNC path in every endpoint's policy. Whatever cannot be spelled
    /// there is dropped; an honest server comes through whole. Needs
    /// `DATABASE_URL`, see docs/SERVER.md.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_file_server_names_only_what_a_unc_path_can_hold(pool: PgPool) {
        let add = |name: &'static str, status: serde_json::Value| {
            let pool = pool.clone();
            async move {
                sqlx::query("INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after, status) VALUES ($1, $2, 'windows_server', '0.1.0', $3, now(), $4)")
                    .bind(Uuid::new_v4())
                    .bind(name)
                    .bind(Uuid::new_v4().to_string())
                    .bind(status)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
        };
        add(
            "SRV_01",
            serde_json::json!({ "fqdn": "srv_01.corp.example", "addrs": ["192.0.2.201"], "shares": [{ "name": "GL", "path": "C:\\Freigaben\\GL" }, { "name": "C$" }] }),
        )
        .await;
        add(
            r"ZZ\C$\Windows",
            serde_json::json!({
                "fqdn": "attacker.example\\x",
                "addrs": ["203.0.113.77", "fe80::1", ".."],
                "shares": [
                    { "name": "GL", "path": "C:\\Public" },
                    { "name": "..", "path": "C:\\x" },
                    { "name": "a\\b" },
                    { "name": "UNC", "path": "\\\\other\\share" },
                    { "name": "" }
                ]
            }),
        )
        .await;
        let servers = file_servers(&pool).await.unwrap();
        let honest = &servers[0];
        assert_eq!(honest.hosts().collect::<Vec<_>>(), vec!["SRV_01", "srv_01.corp.example", "192.0.2.201"]);
        assert_eq!(honest.shares.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec!["GL", "C$"]);
        let rogue = &servers[1];
        // An empty name yields no path at all (`endpoint_rule_path`), not
        // `\\ZZ\C$\Windows\GL`.
        assert_eq!(rogue.name, "");
        assert_eq!(rogue.fqdn, "");
        assert_eq!(rogue.addrs, vec!["203.0.113.77"]);
        assert_eq!(rogue.shares.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), vec!["GL"]);
    }

    #[test]
    fn different_minute_user_or_path_stay_apart() {
        let rows = merge_counts(&[
            count("GL", "hans", "2026-09-10T10:00:05Z", 1, 1, None),
            count("GL", "hans", "2026-09-10T10:01:05Z", 1, 1, None),
            count("GL", "anna", "2026-09-10T10:00:05Z", 1, 1, None),
            count("HR", "hans", "2026-09-10T10:00:05Z", 1, 1, None),
        ]);
        assert_eq!(rows.len(), 4);
        assert!(merge_counts(&[]).is_empty());
    }
}
