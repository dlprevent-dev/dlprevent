//! Agent API on the mTLS port: enrollment (no client certificate, with a
//! token) and report (client certificate required). The answer to every
//! report is the agent's current configuration.

use crate::auth::{bad, ApiError};
use crate::db::{self, Origin};
use crate::state::{PeerAddr, PeerCert, Shared};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::Utc;
use deelpe_core::central::{AgentConfig, EnrollRequest, EnrollResponse, RenewRequest, RenewResponse, Report, ReportResponse, API_VERSION};
use serde_json::json;
use tracing::{info, warn};
use uuid::Uuid;

/// How long the previous fingerprint still counts after a renewal.
///
/// A week, not a day: a machine that fails to store the new certificate and
/// then stays off over the weekend should get back in with the certificate
/// it still holds. Against the renewal window of 30 days that is still
/// short.
///
/// It lives here because this is where the deadline is set — it used to sit
/// in `db.rs`, where nobody read it, and the comment next to it claimed the
/// query below enforced it. That one only checks `prev_cert_until`.
pub const RENEW_GRACE_HOURS: i64 = 24 * 7;

/// At most this many lines travel along with a single report. The agent
/// delivers 200; the headroom covers an agent that has caught up.
pub const LOG_LINES_MAX: usize = 500;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/agent/ca", get(ca))
        .route("/agent/enroll", post(enroll))
        .route("/agent/renew", post(renew))
        .route("/agent/report", post(report))
        // The program for an agent that was enrolled long ago: identified
        // by its certificate, not by a token. Without this an agent would
        // never get at a new build after enrollment — its token is burned.
        .route("/agent/binary", get(binary))
        // The agent program itself, identified by the enrollment token: a
        // fresh machine has no dashboard login.
        .merge(crate::binaries::agent_router())
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state)
}

async fn ca(State(st): State<Shared>) -> String {
    st.pki.ca_pem.clone()
}

async fn enroll(State(st): State<Shared>, Extension(peer): Extension<PeerAddr>, Json(req): Json<EnrollRequest>) -> Result<Json<EnrollResponse>, ApiError> {
    if req.api_version != API_VERSION {
        return Err(bad(format!("expects API version {}", API_VERSION)));
    }
    let hash = crate::auth::sha256_hex(req.token.trim());
    type TokenRow = (Uuid, String, chrono::DateTime<Utc>, bool);
    let row: Option<TokenRow> =
        sqlx::query_as("SELECT id, label, expires_at, uses >= max_uses FROM enroll_tokens WHERE token_hash = $1").bind(&hash).fetch_optional(&st.pool).await?;
    let Some((token_id, label, expires_at, spent)) = row else {
        warn!(peer = %peer.0, "enrollment with an unknown token");
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unknown token".into()));
    };
    if spent {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "token already used".into()));
    }
    if expires_at < Utc::now() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "token expired".into()));
    }
    let hostname = req.hostname.trim();
    if hostname.is_empty() || hostname.len() > 253 {
        return Err(bad("host name is missing"));
    }
    let agent_id = Uuid::new_v4();
    let (cert_pem, fp, not_after) = st.pki.sign_agent(&req.csr_pem, agent_id).map_err(|e| bad(format!("CSR: {e}")))?;
    let kind = serde_json::to_value(req.kind).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_else(|| "mac".into());
    let mut tx = st.pool.begin().await?;
    // Count the use atomically: the row lock makes simultaneous enrollments
    // queue up, so a token for N devices ends with at most N agents.
    let burned = sqlx::query("UPDATE enroll_tokens SET uses = uses + 1, used_at = now(), used_by = $2 WHERE id = $1 AND uses < max_uses")
        .bind(token_id)
        .bind(agent_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if burned == 0 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "token already used".into()));
    }
    sqlx::query("INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after, last_addr) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(agent_id)
        .bind(hostname)
        .bind(&kind)
        .bind(req.version.trim())
        .bind(&fp)
        .bind(not_after)
        .bind(peer.0.ip().to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    db::audit(&st.pool, db::Actor::SYSTEM, "agent_enroll", json!({ "id": agent_id, "name": hostname, "kind": kind, "token": label, "ip": peer.0.ip().to_string() })).await;
    info!(%agent_id, hostname, kind, "agent enrolled");
    Ok(Json(EnrollResponse { agent_id: agent_id.to_string(), cert_pem, ca_pem: st.pki.ca_pem.clone() }))
}

/// Identify the agent by its client certificate. Applies to report and
/// renewal alike: both need the same check, and it must not drift apart
/// into two versions.
/// The agent and the fingerprint it came in with. That can be the current
/// one or — during the grace period — the previous one; when renewing that
/// makes the difference.
async fn authenticated_agent(st: &Shared, peer_cert: Option<Extension<PeerCert>>) -> Result<(db::AgentRow, String), ApiError> {
    let Some(Extension(PeerCert(fp))) = peer_cert else {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "client certificate is missing".into()));
    };
    let Some(agent) = db::agent_by_fingerprint(&st.pool, &fp).await? else {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unknown certificate".into()));
    };
    if agent.revoked_at.is_some() {
        return Err(ApiError(StatusCode::FORBIDDEN, "agent revoked".into()));
    }
    Ok((agent, fp))
}

/// A new certificate for an agent the connection already identifies. No
/// token: whoever gets through here holds a valid certificate from the same
/// CA. Anyone whose certificate has expired already fails at the handshake
/// — for them only a fresh enrollment is left.
async fn renew(
    State(st): State<Shared>,
    peer_cert: Option<Extension<PeerCert>>,
    Extension(peer): Extension<PeerAddr>,
    Json(req): Json<RenewRequest>,
) -> Result<Json<RenewResponse>, ApiError> {
    if req.api_version != API_VERSION {
        return Err(bad(format!("expects API version {API_VERSION}, agent speaks {}", req.api_version)));
    }
    let (agent, presented) = authenticated_agent(&st, peer_cert).await?;
    let (cert_pem, fp, not_after) = st.pki.sign_agent(&req.csr_pem, agent.id).map_err(|e| bad(format!("CSR: {e}")))?;
    // The fingerprint the agent just presented stays valid for a while: if
    // it loses the answer, it comes back in with that one and tries again.
    //
    // The anchor only moves along if the agent came with the *current*
    // certificate. If it came with the previous one — that is, after a
    // failed store — exactly that one stays the anchor: were it displaced
    // here by the intermediate certificate that has meanwhile been lost as
    // well, the agent would be locked out for good after the second
    // failure. The deadline restarts in both cases.
    sqlx::query(
        "UPDATE agents SET cert_fingerprint = $2, cert_not_after = $3, \
         prev_cert_fingerprint = CASE WHEN cert_fingerprint = $5 THEN cert_fingerprint ELSE prev_cert_fingerprint END, \
         prev_cert_until = now() + ($4::bigint * interval '1 hour') WHERE id = $1",
    )
    .bind(agent.id)
    .bind(&fp)
    .bind(not_after)
    .bind(RENEW_GRACE_HOURS)
    .bind(&presented)
    .execute(&st.pool)
    .await?;
    db::audit(&st.pool, db::Actor::SYSTEM, "agent_cert_renew", json!({ "id": agent.id, "name": agent.name, "not_after": not_after, "ip": peer.0.ip().to_string() })).await;
    info!(agent_id = %agent.id, name = agent.name, %not_after, "Agentenzertifikat erneuert");
    Ok(Json(RenewResponse { cert_pem, not_after }))
}

/// The only agent that gets rules in their raw form: it sits on the folder
/// and can resolve a share name itself.
const FILE_SERVER: &str = "windows_server";

/// A rule as an endpoint sees it.
///
/// Three cases, and the first is the one it is all about:
///
/// 1. The rule hangs off a **file server** — `C:\Freigaben\GL` on
///    FS-01 becomes `\\FS-01\GL`. If no matching share is
///    found it is **not** delivered: a rule pointing at a place that does
///    not exist on the workstation would be a green light over nothing.
/// 2. Absolute path with no server reference: a folder on the machine
///    itself, unchanged.
/// 3. A bare share name (`GL`, scope "all"): look it up on every file
///    server. That can yield **several** paths if two servers have a share
///    of the same name — then the rule goes over the wire more than once,
///    with the same id. At the endpoint only the path counts.
///
/// For the same reason it also goes out once per name of the **same**
/// server: `\\FS-01\GL` and `\\192.0.2.201\GL` are the same
/// folder but two strings, and which one arrives is decided by the human at
/// the address bar (see `db::FileServer::hosts`).
fn endpoint_rules(r: &db::RuleRow, servers: &[db::FileServer]) -> Vec<deelpe_core::central::Rule> {
    use deelpe_core::rules::endpoint_rule_path;
    let w = r.to_wire();
    let mut paths: Vec<String> = if let Some(sv) = r.agent_id.and_then(|id| servers.iter().find(|s| s.id == id)) {
        sv.hosts().filter_map(|h| endpoint_rule_path(&r.path, Some((h, &sv.shares)))).collect()
    } else if let Some(path) = endpoint_rule_path(&r.path, None) {
        vec![path]
    } else {
        servers.iter().flat_map(|s| s.hosts().filter_map(|h| endpoint_rule_path(&r.path, Some((h, &s.shares))))).collect()
    };
    // If the rule already reads as UNC, `endpoint_rule_path` returns it
    // unchanged for every name — then the same path would be in the answer
    // several times. The repeats sit next to each other because the names of
    // one server sit next to each other.
    paths.dedup_by(|a, b| deelpe_core::path::norm(a) == deelpe_core::path::norm(b));
    paths.into_iter().map(|path| deelpe_core::central::Rule { path, ..w.clone() }).collect()
}

/// Upper bound for an agent's acknowledgements; at most 100 instructions go
/// out per report, with headroom for repeats.
const LEARN_DONE_MAX: usize = 500;

/// The agent program for **this** agent. Which file that is, is decided by
/// its role from the database — not by the agent: otherwise it could fetch
/// the file of a foreign platform.
///
/// It is served no matter whether the rollout is switched on. The switch
/// decides whether the server **orders** an update; whoever asks here has
/// already been given the checksum, and an agent that has the switch flipped
/// mid-download should not be left standing there with half a file.
async fn binary(State(st): State<Shared>, peer_cert: Option<Extension<PeerCert>>) -> Result<axum::response::Response, ApiError> {
    let (agent, _) = authenticated_agent(&st, peer_cert).await?;
    let platform = crate::binaries::platform_for(Some(agent.kind.as_str()))
        .ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no agent program for this kind of agent".into()))?;
    let (name, bytes) = crate::binaries::read(&st, platform).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "no agent program uploaded".into()))?;
    info!(agent = %agent.name, platform, bytes = bytes.len(), "agent fetches its program");
    Ok(crate::binaries::as_download(name, bytes))
}

async fn report(State(st): State<Shared>, peer_cert: Option<Extension<PeerCert>>, Extension(peer): Extension<PeerAddr>, Json(r): Json<Report>) -> Result<Json<ReportResponse>, ApiError> {
    let (agent, _) = authenticated_agent(&st, peer_cert).await?;
    if let Some(v) = r.api_version {
        if v != API_VERSION {
            return Err(bad(format!("expects API version {API_VERSION}, agent speaks {v}")));
        }
    }
    let version = r.status.as_ref().map(|s| s.version.clone()).unwrap_or(agent.version.clone());
    sqlx::query("UPDATE agents SET last_seen = now(), last_addr = $2, version = $3, status = COALESCE($4, status) WHERE id = $1")
        .bind(agent.id)
        .bind(peer.0.ip().to_string())
        .bind(version)
        .bind(r.status.as_ref().map(|s| serde_json::to_value(s).unwrap_or_default()))
        .execute(&st.pool)
        .await?;

    let origin = Origin::Agent(agent.id);
    let mut accepted_alerts = 0;
    for a in &r.alerts {
        db::upsert_endpoint_alert(&st.pool, origin, &agent.name, a).await?;
        accepted_alerts += 1;
    }
    let mut accepted_access_alerts = 0;
    for a in &r.access_alerts {
        db::upsert_access_alert(&st.pool, origin, &agent.name, a).await?;
        accepted_access_alerts += 1;
    }
    let accepted_counts = db::upsert_counts(&st.pool, agent.id, &r.counts).await?;

    // Log lines from the machine. Only an upper bound, no check of the
    // content: what an agent writes is text, and in the dashboard it stands
    // as text.
    //
    // An error here stays an error *here*: with `?` a single unwritable line
    // would reject the whole report, the agent would leave it in its ring
    // buffer and send it again with every report — and the alerts would
    // never get through again. Alerts matter more than the log, so they win.
    if !r.log.is_empty() {
        if let Err(e) = db::insert_agent_log(&st.pool, agent.id, &r.log[..r.log.len().min(LOG_LINES_MAX)]).await {
            warn!(agent = %agent.name, "could not store agent log lines: {e:#}");
        }
    }

    // Groups only travel along when they changed; `None` means "unchanged"
    // and leaves the stored ones alone.
    if let Some(groups) = &r.groups {
        let n = db::replace_agent_groups(&st.pool, agent.id, groups).await?;
        tracing::info!(agent = %agent.name, gruppen = n, "Gruppenliste uebernommen");
    }

    // First tick off what the agent carried out, then fetch the rest:
    // otherwise it would get the same instruction again in this answer.
    if !r.learn_done.is_empty() {
        // Only its own rows (`agent_id` in the query): an agent cannot
        // tick off another one's instruction. Whoever ticks off their own
        // without carrying them out only harms themselves — they stay
        // noisy. The limit merely caps the packet; we deliver at most 100.
        if r.learn_done.len() > LEARN_DONE_MAX {
            return Err(bad(format!("at most {LEARN_DONE_MAX} learning instructions per report")));
        }
        let n = db::mark_learn_applied(&st.pool, agent.id, &r.learn_done).await?;
        if n > 0 {
            tracing::info!(agent = %agent.name, anweisungen = n, "Lernanweisungen ausgefuehrt");
        }
    }
    // Settings once, bundled and held for a few seconds
    // (`state::AGENT_SETTINGS_TTL`) — not five separate queries per
    // report.
    let settings = st.agent_settings().await?;

    // The switch acts at the output, not only when queueing: whoever flips
    // it wants the effect right away, for rows already queued too.
    let learn = if settings.learn_push_enabled {
        db::pending_learn(&st.pool, agent.id).await?
    } else {
        Vec::new()
    };

    // If the agent already runs this generation, the rules stay home: it
    // would discard them anyway (`generation > st.generation`), and with ten
    // thousand agents that is the largest item on the wire.
    //
    // `None` means "send them to me" — an older agent, a freshly enrolled
    // one, or one whose copy of the rules did not survive. When in doubt,
    // deliver: an answer without rules to an agent that has none is a
    // machine without protection, and nobody would see it.
    let rules = if r.generation == Some(settings.generation) {
        Vec::new()
    } else if agent.kind == FILE_SERVER {
        db::rules_for_agent(&st.pool, agent.id).await?.iter().map(|r| r.to_wire()).collect()
    } else {
        let servers = db::file_servers(&st.pool).await?;
        db::rules_for_endpoint(&st.pool, agent.id).await?.iter().flat_map(|r| endpoint_rules(r, &servers)).collect()
    };
    // An update goes to whoever can use one and had one ordered: either via
    // the master switch (applies to all) or via the button on this one
    // agent. The button is the way for the first machine — one first, take
    // a look, then the rest.
    //
    // The comparison is the file itself, not a version number: see
    // `update_due`. Without a reported fingerprint it falls back to `false`,
    // and then nothing goes out even at the press of the button.
    let running = r.status.as_ref().map(|s| s.build.as_str()).unwrap_or_default();
    let wanted = if settings.agent_update_enabled || agent.update_requested.is_some() {
        crate::binaries::self_replacing_platform(&agent.kind).and_then(|p| crate::binaries::sha256_of(&st, p))
    } else {
        None
    };
    let update_order = wanted.filter(|sha| deelpe_core::central::update_due(sha, running));
    // Fulfilled or moot: clear the flag. An order that gets stuck cannot be
    // withdrawn — and at the next upload this one machine would help itself
    // to that too, unasked.
    if agent.update_requested.is_some() && update_order.is_none() {
        if let Err(e) = sqlx::query("UPDATE agents SET update_requested = NULL WHERE id = $1").bind(agent.id).execute(&st.pool).await {
            warn!(agent = %agent.name, "could not clear the update order: {e:#}");
        }
    }
    let config = AgentConfig {
        api_version: API_VERSION,
        generation: settings.generation,
        report_interval_secs: settings.report_interval_secs as u32,
        learn_days: settings.learn_days as u32,
        rules,
        // Split with the same parser as in the agent: otherwise one side
        // splits at comments and the other does not.
        allow_processes: deelpe_core::learn::parse_allowlist(&settings.allow_processes).into_iter().collect(),
        update_to_sha256: update_order,
    };
    Ok(Json(ReportResponse { accepted_alerts, accepted_access_alerts, accepted_counts, config, learn }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use deelpe_core::central::ShareInfo;

    fn rule(path: &str, agent_id: Option<Uuid>) -> db::RuleRow {
        db::RuleRow {
            id: Uuid::nil(),
            name: "R".into(),
            path: path.into(),
            scope: if agent_id.is_some() { "agent".into() } else { "all".into() },
            agent_id,
            source_id: None,
            allowed_groups: vec![],
            lockdown: false,
            strict: true,
            allow_destinations: vec![],
            enforce: true,
            hard_max_files: 100,
            window_secs: 60,
            ad_lock: false,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn dc(id: Uuid, name: &str, addr: &str) -> db::FileServer {
        db::FileServer {
            id,
            name: name.into(),
            shares: vec![ShareInfo { name: "GL".into(), path: Some(r"C:\Freigaben\GL".into()), remark: None, path_from: None }],
            addrs: vec![addr.into()],
            fqdn: format!("{}.corp.example", name.to_lowercase()),
        }
    }

    fn paths(v: Vec<deelpe_core::central::Rule>) -> Vec<String> {
        v.into_iter().map(|r| r.path).collect()
    }

    #[test]
    fn a_file_server_rule_reaches_the_endpoint_as_a_share_path() {
        let id = Uuid::from_u128(1);
        let servers = vec![dc(id, "FS-01", "192.0.2.201")];
        // Short name, long name, address — in that order. Otherwise
        // whoever types `\\192.0.2.201\GL` into the address bar bypasses
        // the rule, and silently at that.
        assert_eq!(
            paths(endpoint_rules(&rule(r"C:\Freigaben\GL", Some(id)), &servers)),
            vec![r"\\FS-01\GL", r"\\fs-01.corp.example\GL", r"\\192.0.2.201\GL"]
        );
        // The remaining fields of the rule stay as they were — in every
        // copy, not just the first.
        let out = endpoint_rules(&rule(r"C:\Freigaben\GL", Some(id)), &servers);
        assert!(out.iter().all(|r| r.strict && r.enforce && r.id == out[0].id));
        // Not a folder of a share: do not deliver, rather than point at nothing.
        assert!(endpoint_rules(&rule(r"C:\Windows\Temp", Some(id)), &servers).is_empty());
    }

    /// A server with no reported address behaves as before, and a rule that
    /// is already UNC goes out once instead of once per name.
    #[test]
    fn without_an_address_nothing_changes_and_a_unc_rule_stays_single() {
        let id = Uuid::from_u128(1);
        let mut sv = dc(id, "FS-01", "192.0.2.201");
        sv.addrs.clear();
        sv.fqdn.clear();
        assert_eq!(paths(endpoint_rules(&rule(r"C:\Freigaben\GL", Some(id)), &[sv])), vec![r"\\FS-01\GL"]);
        // A server without a domain reports nothing as its long name; were
        // it to report the short name after all, the duplicate path drops
        // out again.
        let mut same = dc(id, "SRV", "10.0.0.1");
        same.fqdn = "srv".into();
        same.addrs.clear();
        assert_eq!(paths(endpoint_rules(&rule(r"C:\Freigaben\GL", Some(id)), &[same])), vec![r"\\SRV\GL"]);
        let servers = vec![dc(id, "FS-01", "192.0.2.201")];
        assert_eq!(paths(endpoint_rules(&rule(r"\\FS-01\GL", Some(id)), &servers)), vec![r"\\FS-01\GL"]);
    }

    #[test]
    fn local_rules_and_share_names_keep_working() {
        let servers = vec![dc(Uuid::from_u128(1), "SRV1", "10.0.0.1"), dc(Uuid::from_u128(2), "SRV2", "10.0.0.2")];
        // A folder on the machine itself.
        assert_eq!(paths(endpoint_rules(&rule(r"C:\Users\Public", None), &servers)), vec![r"C:\Users\Public"]);
        // Share name with scope "all": every file server that has it —
        // each of them under name and address.
        assert_eq!(
            paths(endpoint_rules(&rule("GL", None), &servers)),
            vec![r"\\SRV1\GL", r"\\srv1.corp.example\GL", r"\\10.0.0.1\GL", r"\\SRV2\GL", r"\\srv2.corp.example\GL", r"\\10.0.0.2\GL"]
        );
        // Nobody knows it: nothing.
        assert!(endpoint_rules(&rule("Personal", None), &servers).is_empty());
        // A rule of this workstation itself (not a file server) stays.
        assert_eq!(paths(endpoint_rules(&rule(r"D:\Daten", Some(Uuid::from_u128(9))), &servers)), vec![r"D:\Daten"]);
    }
}

/// The report path itself, against a real database. So far no test covered
/// it — and this is where it is decided whether a machine gets rules.
/// Needs `DATABASE_URL`, see docs/SERVER.md.
#[cfg(test)]
mod report_tests {
    use super::*;
    use sqlx::PgPool;

    fn state(pool: PgPool) -> Shared {
        rustls::crypto::ring::default_provider().install_default().ok();
        let dir = std::env::temp_dir().join(format!("deelpe-agent-test-{}", Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(&dir).ok();
        std::sync::Arc::new(crate::state::AppState::new(pool, std::sync::Arc::new(pki), false, 8444, false, dir))
    }

    /// An enrolled endpoint with a rule that reaches it.
    async fn endpoint_with_a_rule(pool: &PgPool) -> String {
        let fp = "ab".repeat(32);
        sqlx::query(
            "INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after) \
             VALUES ($1, 'PC-1', 'windows_client', '0.1.0', $2, now() + interval '1 year')",
        )
        .bind(Uuid::new_v4())
        .bind(&fp)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO rules (name, path, scope) VALUES ('R', 'C:\\Daten', 'all')").execute(pool).await.unwrap();
        fp
    }

    async fn report_with(st: &Shared, fp: &str, generation: Option<i64>) -> ReportResponse {
        let peer = PeerAddr("10.0.0.9:1".parse().unwrap());
        let r = Report { api_version: Some(API_VERSION), generation, ..Default::default() };
        // `ApiError` is not `Debug` (it carries a message for the client,
        // not one for the developer); so unpack it by hand.
        match report(State(st.clone()), Some(Extension(PeerCert(fp.into()))), Extension(peer), Json(r)).await {
            Ok(Json(resp)) => resp,
            Err(ApiError(code, msg)) => panic!("Bericht abgelehnt: {code} {msg}"),
        }
    }

    /// A report that says which program this agent runs.
    async fn report_running(st: &Shared, fp: &str, build: &str) -> ReportResponse {
        let peer = PeerAddr("10.0.0.9:1".parse().unwrap());
        let status = deelpe_core::central::AgentStatus {
            version: "0.1.0".into(),
            build: build.into(),
            hostname: "PC-1".into(),
            fqdn: String::new(),
            started_at: Utc::now(),
            sensors: Vec::new(),
            watched: Vec::new(),
            learn_phase: "active".into(),
            shares: Vec::new(),
            addrs: Vec::new(),
        };
        let r = Report { api_version: Some(API_VERSION), status: Some(status), ..Default::default() };
        match report(State(st.clone()), Some(Extension(PeerCert(fp.into()))), Extension(peer), Json(r)).await {
            Ok(Json(resp)) => resp,
            Err(ApiError(code, msg)) => panic!("Bericht abgelehnt: {code} {msg}"),
        }
    }

    /// Put the program into the data directory, the way an upload in the
    /// dashboard does. Returns the checksum.
    fn upload(st: &Shared, bytes: &[u8]) -> String {
        let dir = st.data_dir.join("agents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("deelpe-winagent.exe"), bytes).unwrap();
        crate::binaries::sha256_of(st, "windows").expect("Pruefsumme")
    }

    /// The update order: only with the switch on, only with a program
    /// staged, and only if the agent runs a different one. Each of the three
    /// conditions on its own — strike one of them and you swap the program
    /// on every machine in the company without anyone having ordered it.
    #[sqlx::test(migrations = "./migrations")]
    async fn an_update_is_ordered_only_when_it_was_switched_on_and_something_else_is_running(pool: PgPool) {
        let fp = endpoint_with_a_rule(&pool).await;
        let st = state(pool.clone());
        let sha = upload(&st, b"MZ ein neues Programm");

        // Switch off: the dashboard says "outdated" at most, nothing is
        // sent.
        assert_eq!(report_running(&st, &fp, "0123456789ab").await.config.update_to_sha256, None);

        db::set_setting(&pool, "agent_update_enabled", serde_json::json!(true)).await.unwrap();
        // The settings hang in memory for `AGENT_SETTINGS_TTL`.
        tokio::time::sleep(crate::state::AGENT_SETTINGS_TTL + std::time::Duration::from_millis(200)).await;

        // Switch on, a different program: an order with the full checksum —
        // the agent has to be able to verify what it gets.
        assert_eq!(report_running(&st, &fp, "0123456789ab").await.config.update_to_sha256, Some(sha.clone()));

        // The same agent, already running the staged program: nothing to
        // do. Without this it downloads anew with every report.
        assert_eq!(report_running(&st, &fp, &sha[..12]).await.config.update_to_sha256, None);

        // An agent that does not report its fingerprint gets no program
        // sent — otherwise every older agent downloads the same four and a
        // half megabytes with every report.
        assert_eq!(report_running(&st, &fp, "").await.config.update_to_sha256, None);

        std::fs::remove_dir_all(&st.data_dir).ok();
    }

    /// The button on a single agent: the master switch applies to all, and
    /// that is exactly what you do not want the first time round. The order
    /// goes out with the next answer and clears itself away as soon as the
    /// agent runs the staged program — otherwise it could not be withdrawn,
    /// and at the next upload this one machine would help itself to that
    /// too, unasked.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_single_agent_can_be_ordered_to_update_without_the_master_switch(pool: PgPool) {
        let fp = endpoint_with_a_rule(&pool).await;
        let st = state(pool.clone());
        let sha = upload(&st, b"MZ ein neues Programm");

        // Master switch off, no order: nothing.
        assert_eq!(report_running(&st, &fp, "0123456789ab").await.config.update_to_sha256, None);

        sqlx::query("UPDATE agents SET update_requested = now()").execute(&pool).await.unwrap();
        assert_eq!(
            report_running(&st, &fp, "0123456789ab").await.config.update_to_sha256,
            Some(sha.clone()),
            "der Knopf wirkt auch ohne Hauptschalter"
        );

        // The agent runs it now: order fulfilled, flag gone.
        assert_eq!(report_running(&st, &fp, &sha[..12]).await.config.update_to_sha256, None);
        let open: Option<(Option<chrono::DateTime<Utc>>,)> =
            sqlx::query_as("SELECT update_requested FROM agents").fetch_optional(&pool).await.unwrap();
        assert_eq!(open.unwrap().0, None, "die Marke raeumt sich selbst weg");

        // And afterwards it stays quiet, even with reports still coming.
        assert_eq!(report_running(&st, &fp, &sha[..12]).await.config.update_to_sha256, None);

        std::fs::remove_dir_all(&st.data_dir).ok();
    }

    /// Only Windows gets an order. The macOS service reports the
    /// fingerprint of its program file, but what is staged is the zip around
    /// the bundle: the one checksum can never be the start of the other.
    /// Strike this limit and every Mac gets the same order it cannot carry
    /// out, in **every** answer.
    #[sqlx::test(migrations = "./migrations")]
    async fn only_an_agent_that_can_replace_itself_is_ordered_to(pool: PgPool) {
        let fp = "cd".repeat(32);
        sqlx::query(
            "INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after) \
             VALUES ($1, 'MAC-1', 'mac', '0.1.0', $2, now() + interval '1 year')",
        )
        .bind(Uuid::new_v4())
        .bind(&fp)
        .execute(&pool)
        .await
        .unwrap();
        let st = state(pool.clone());
        let dir = st.data_dir.join("agents");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("DLPrevent.zip"), b"PK ein Bundle").unwrap();
        std::fs::write(dir.join("deelpe-winagent.exe"), b"MZ ein Programm").unwrap();
        db::set_setting(&pool, "agent_update_enabled", serde_json::json!(true)).await.unwrap();

        assert_eq!(report_running(&st, &fp, "0123456789ab").await.config.update_to_sha256, None);

        // And the role → file mapping does not know Linux: before, it fell
        // into the same branch as macOS and could have downloaded a Mac
        // bundle.
        assert_eq!(crate::binaries::platform_for(Some("linux")), None);
        assert_eq!(crate::binaries::platform_for(Some("mac")), Some("mac"));
        assert_eq!(crate::binaries::platform_for(None), Some("mac"));
        assert_eq!(crate::binaries::self_replacing_platform("mac"), None);
        assert_eq!(crate::binaries::self_replacing_platform("windows_server"), Some("windows"));

        std::fs::remove_dir_all(&st.data_dir).ok();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn rules_stay_home_only_for_an_agent_that_already_runs_this_generation(pool: PgPool) {
        let fp = endpoint_with_a_rule(&pool).await;
        let st = state(pool.clone());

        // No `generation` reported -- an older agent, a freshly enrolled
        // one, or one without a copy of the rules. That one gets them.
        let resp = report_with(&st, &fp, None).await;
        let g = resp.config.generation;
        assert_eq!(resp.config.rules.len(), 1, "ohne gemeldete Generation muessen die Regeln mit");

        // If it runs the current generation, they stay home -- it would
        // discard them anyway.
        let resp = report_with(&st, &fp, Some(g)).await;
        assert!(resp.config.rules.is_empty(), "gleiche Generation: nichts schicken");
        assert_eq!(resp.config.generation, g, "die Generation selbst geht immer mit");

        // An older generation means: it missed something.
        let resp = report_with(&st, &fp, Some(g - 1)).await;
        assert_eq!(resp.config.rules.len(), 1, "veraltete Generation: nachliefern");

        // And after a rule change it grows, so deliver again -- even to
        // the one that was up to date a moment ago.
        //
        // Fresh state instead of `st`: the settings sit in memory for five
        // seconds (`state::AGENT_SETTINGS_TTL`), and a test runs faster than
        // that. In production this is the same situation as five seconds
        // later -- the delay is the price that is deliberately accepted
        // there.
        db::bump_generation(&pool).await.unwrap();
        let st = state(pool.clone());
        let resp = report_with(&st, &fp, Some(g)).await;
        assert_eq!(resp.config.generation, g + 1);
        assert_eq!(resp.config.rules.len(), 1, "nach der Aenderung muss er sie bekommen");
    }

    async fn token_with_uses(pool: &PgPool, token: &str, max_uses: Option<i32>) {
        let sql = match max_uses {
            Some(_) => "INSERT INTO enroll_tokens (token_hash, label, expires_at, max_uses) VALUES ($1, 'T', now() + interval '1 day', $2)",
            None => "INSERT INTO enroll_tokens (token_hash, label, expires_at) VALUES ($1, 'T', now() + interval '1 day')",
        };
        let q = sqlx::query(sql).bind(crate::auth::sha256_hex(token));
        let q = match max_uses {
            Some(n) => q.bind(n),
            None => q,
        };
        q.execute(pool).await.unwrap();
    }

    async fn enroll_as(st: &Shared, token: &str, host: &str) -> Result<(), String> {
        let key = rcgen::KeyPair::generate().unwrap();
        let csr_pem = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap().pem().unwrap();
        let req = EnrollRequest {
            api_version: API_VERSION,
            token: token.into(),
            hostname: host.into(),
            kind: deelpe_core::central::AgentKind::WindowsClient,
            version: "0.1.0".into(),
            csr_pem,
        };
        match enroll(State(st.clone()), Extension(PeerAddr("10.0.0.9:1".parse().unwrap())), Json(req)).await {
            Ok(_) => Ok(()),
            Err(ApiError(_, msg)) => Err(msg),
        }
    }

    /// A mass rollout hands one token to every machine. It must stop at the
    /// count it was created with, and a token created without one must stay
    /// what it always was: good for exactly one enrollment.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_token_enrolls_as_many_devices_as_it_was_created_for(pool: PgPool) {
        let st = state(pool.clone());
        token_with_uses(&pool, "fleet", Some(2)).await;
        token_with_uses(&pool, "single", None).await;

        assert_eq!(enroll_as(&st, "fleet", "PC-1").await, Ok(()));
        assert_eq!(enroll_as(&st, "fleet", "PC-2").await, Ok(()));
        assert_eq!(enroll_as(&st, "fleet", "PC-3").await, Err("token already used".into()), "the third is one too many");

        assert_eq!(enroll_as(&st, "single", "PC-4").await, Ok(()));
        assert_eq!(enroll_as(&st, "single", "PC-5").await, Err("token already used".into()));

        let (uses, used_by): (i32, Option<Uuid>) =
            sqlx::query_as("SELECT uses, used_by FROM enroll_tokens WHERE label = 'T' AND max_uses = 2").fetch_one(&pool).await.unwrap();
        assert_eq!(uses, 2);
        let last: Uuid = sqlx::query_scalar("SELECT id FROM agents WHERE name = 'PC-2'").fetch_one(&pool).await.unwrap();
        assert_eq!(used_by, Some(last), "used_by names the latest agent");
        let agents: i64 = sqlx::query_scalar("SELECT count(*) FROM agents").fetch_one(&pool).await.unwrap();
        assert_eq!(agents, 3);
    }
}
