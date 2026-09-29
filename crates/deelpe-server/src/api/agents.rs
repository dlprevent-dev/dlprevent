//! Agents, their logs, and the enrolment tokens.

use super::*;

// ---------- Agents, sources ----------

#[derive(Serialize)]
pub(super) struct AgentView {
    #[serde(flatten)]
    row: AgentRow,
    online: bool,
}

#[derive(Deserialize)]
pub(super) struct GroupQuery {
    #[serde(default)]
    q: Option<String>,
    /// Only this agent's groups — the rule does apply to a particular one.
    #[serde(default)]
    agent: Option<Uuid>,
    #[serde(default)]
    limit: Option<i64>,
}

/// Groups for the picker in a rule. Always capped: in a customer
/// environment there are tens of thousands of them, and the list is there
/// for searching, not for browsing.
pub(super) async fn groups(State(st): State<Shared>, _user: Admin, Query(q): Query<GroupQuery>) -> R<Vec<db::GroupRow>> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    Ok(Json(db::search_groups(&st.pool, q.q.as_deref(), q.agent, limit).await?))
}

pub(super) async fn agents(State(st): State<Shared>, _u: Admin) -> R<Vec<AgentView>> {
    let interval = db::setting_i64(&st.pool, "report_interval_secs", 30).await?;
    let rows: Vec<AgentRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {AGENT_COLS} FROM agents ORDER BY revoked_at NULLS FIRST, name"))).fetch_all(&st.pool).await?;
    let now = Utc::now();
    Ok(Json(
        rows.into_iter()
            .map(|row| {
                let online = row.revoked_at.is_none() && row.last_seen.map(|t| now - t < Duration::seconds(interval * 3)).unwrap_or(false);
                AgentView { row, online }
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub(super) struct LogQuery {
    /// Exactly this level: `warn` shows warnings, not errors as well.
    /// Without a value, everything.
    ///
    /// The buttons in the dashboard are compartments, not thresholds:
    /// whoever picks `Info` wants to see the infos and not the warnings in
    /// between. Nothing is lost that way — `Alle` sits next to them as a
    /// button of its own.
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
}

/// An agent's local log, as it arrived with its reports — newest line
/// first. So that the dashboard says *what* is going on on the device: why
/// a sensor has stopped, why a report did not get through, when it got
/// through again.
pub(super) async fn agent_log(State(st): State<Shared>, _u: Admin, Path(id): Path<Uuid>, Query(q): Query<LogQuery>) -> R<Vec<db::LogRow>> {
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    Ok(Json(db::agent_log(&st.pool, id, q.level.as_deref(), q.q.as_deref(), limit).await?))
}

pub(super) async fn revoke_agent(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("UPDATE agents SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL").bind(id).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::audit(&st.pool, (&user).into(), "agent_revoke", json!({ "id": id })).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Let this one agent fetch its program — without the master switch that
/// applies to everybody.
///
/// That is exactly what the button is for: one device first, check whether
/// it comes back up, then the rest. The order goes out with the next answer
/// (one report cycle, 30 seconds out of the box) and clears itself away as
/// soon as the agent runs the program that was waiting for it.
pub(super) async fn request_update(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let row: Option<(String, String, Option<DateTime<Utc>>, Option<String>)> =
        sqlx::query_as("SELECT name, kind, revoked_at, status->>'arch' FROM agents WHERE id = $1").bind(id).fetch_optional(&st.pool).await?;
    let Some((name, kind, revoked_at, arch)) = row else {
        return Err(not_found());
    };
    if revoked_at.is_some() {
        return Err(ApiError(StatusCode::CONFLICT, "the agent is revoked".into()));
    }
    // What the agent cannot do is not ordered of it: otherwise the order
    // would stand open forever, because it never gets fulfilled.
    let Some(platform) = crate::binaries::self_replacing_platform(&kind, arch.as_deref().unwrap_or_default()) else {
        return Err(bad("this agent cannot replace itself (a Mac, or a Linux agent older than 0.1.4) — see docs/INSTALL.md"));
    };
    if crate::binaries::sha256_of(&st, platform).is_none() {
        return Err(bad("no agent program uploaded yet — upload it under Agents first"));
    }
    sqlx::query("UPDATE agents SET update_requested = now() WHERE id = $1").bind(id).execute(&st.pool).await?;
    db::audit(&st.pool, (&user).into(), "agent_update_request", json!({ "id": id, "name": name })).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Finish this agent's learning phase: what it learned counts as known, and
/// from its next report on it reports new and deviating traffic.
///
/// Only an endpoint learns pairs and waits for a confirm; the file server
/// agent's baseline ends by itself. The order goes out with the next answer
/// and clears itself once the agent reports "active".
pub(super) async fn finish_learning(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let row: Option<(String, String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT name, kind, revoked_at FROM agents WHERE id = $1").bind(id).fetch_optional(&st.pool).await?;
    let Some((name, kind, revoked_at)) = row else {
        return Err(not_found());
    };
    if revoked_at.is_some() {
        return Err(ApiError(StatusCode::CONFLICT, "the agent is revoked".into()));
    }
    if kind == "windows_server" {
        return Err(bad("a file server agent ends its learning phase by itself"));
    }
    sqlx::query("UPDATE agents SET learn_confirm_requested = now() WHERE id = $1").bind(id).execute(&st.pool).await?;
    db::audit(&st.pool, (&user).into(), "agent_finish_learning", json!({ "id": id, "name": name })).await;
    Ok(StatusCode::NO_CONTENT)
}

/// When finishing the learning phase means anything at all: only an
/// endpoint learns pairs and waits for a confirm, a revoked agent takes no
/// orders, and one already asked is not asked twice.
///
/// One constant, because „finish all" and „finish the selected ones" have to
/// skip exactly the same agents — otherwise the two buttons next to each
/// other would count differently.
const CAN_FINISH_LEARNING: &str = "revoked_at IS NULL AND kind <> 'windows_server' AND learn_confirm_requested IS NULL \
     AND COALESCE(status->>'learn_phase', '') IN ('learning', 'review')";

/// The same for every endpoint agent that is still learning or waiting in
/// review. Returns how many were asked.
pub(super) async fn finish_learning_all(State(st): State<Shared>, Admin(user): Admin) -> R<serde_json::Value> {
    let n = sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE agents SET learn_confirm_requested = now() WHERE {CAN_FINISH_LEARNING}")))
        .execute(&st.pool)
        .await?
        .rows_affected();
    db::audit(&st.pool, (&user).into(), "agent_finish_learning_all", json!({ "agents": n })).await;
    Ok(Json(json!({ "agents": n })))
}

// ---------- Several at once ----------

/// What a bulk action does to the agents handed to it. The same four things
/// the buttons on a row do — a fleet of a thousand devices cannot be walked
/// through one row at a time.
#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum BulkAction {
    FinishLearning,
    Update,
    Revoke,
    Delete,
}

#[derive(Deserialize)]
pub(super) struct BulkBody {
    action: BulkAction,
    ids: Vec<Uuid>,
}

#[derive(Serialize)]
pub(super) struct BulkDone {
    /// How many agents the action actually reached. Whatever does not
    /// qualify is skipped in silence — with a selection of a thousand, an
    /// error over the one revoked device in it would only mean doing it
    /// again without that one.
    changed: u64,
    /// How many were handed in, so the dashboard can say „400 of 1000“
    /// instead of leaving the difference to be guessed at.
    asked: usize,
}

/// A selection cannot be larger than the list it comes from, and that list
/// is not paged. Well past any fleet on one screen, and still far from a
/// body that would have to be streamed.
const BULK_IDS_MAX: usize = 5000;

pub(super) async fn bulk(State(st): State<Shared>, Admin(user): Admin, Json(b): Json<BulkBody>) -> R<BulkDone> {
    if b.ids.is_empty() {
        return Err(bad("no agents given"));
    }
    if b.ids.len() > BULK_IDS_MAX {
        return Err(bad(format!("at most {BULK_IDS_MAX} agents at once")));
    }
    let changed = match b.action {
        BulkAction::FinishLearning => {
            sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE agents SET learn_confirm_requested = now() WHERE id = ANY($1) AND {CAN_FINISH_LEARNING}")))
                .bind(&b.ids)
                .execute(&st.pool)
                .await?
                .rows_affected()
        }
        BulkAction::Update => {
            // Which of them has anything to fetch is not a question SQL can
            // answer: it hangs on the role, on the architecture the agent
            // reports, and on whether what lies on the server is a different
            // file from the one the agent runs. The same question
            // `update_due` asks before an order goes out at all.
            //
            // The ones already asked stay out of it, and that is not tidiness.
            // Re-stamping an order that is stuck resets `update_requested`,
            // and with it the „not picked up" mark on the row — the one hint
            // that says the agent runs a build from before self-replacement
            // and will never see the order.
            let rows: Vec<(Uuid, String, Option<String>, Option<String>)> =
                sqlx::query_as("SELECT id, kind, status->>'arch', status->>'build' FROM agents WHERE id = ANY($1) AND revoked_at IS NULL AND update_requested IS NULL")
                    .bind(&b.ids)
                    .fetch_all(&st.pool)
                    .await?;
            // One `stat` per platform, not one per agent: `sha256_of` goes to
            // the file system and takes a lock every agent report contends
            // for, and a selection may hold thousands of rows.
            let mut staged: std::collections::HashMap<&'static str, Option<String>> = std::collections::HashMap::new();
            let able: Vec<Uuid> = rows
                .into_iter()
                .filter(|(_, kind, arch, build)| {
                    let Some(platform) = crate::binaries::self_replacing_platform(kind, arch.as_deref().unwrap_or_default()) else {
                        return false;
                    };
                    let sha = staged.entry(platform).or_insert_with(|| crate::binaries::sha256_of(&st, platform));
                    sha.as_deref().is_some_and(|sha| deelpe_core::central::update_due(sha, build.as_deref().unwrap_or_default()))
                })
                .map(|(id, ..)| id)
                .collect();
            if able.is_empty() {
                0
            } else {
                sqlx::query("UPDATE agents SET update_requested = now() WHERE id = ANY($1)").bind(&able).execute(&st.pool).await?.rows_affected()
            }
        }
        BulkAction::Revoke => sqlx::query("UPDATE agents SET revoked_at = now() WHERE id = ANY($1) AND revoked_at IS NULL")
            .bind(&b.ids)
            .execute(&st.pool)
            .await?
            .rows_affected(),
        BulkAction::Delete => {
            // Revoke first, then delete — the same order as on a single row,
            // and a device that is still allowed in is not swept off the
            // list by a tick in a box.
            let mut tx = st.pool.begin().await?;
            let gone: Vec<Uuid> = sqlx::query_scalar("DELETE FROM agents WHERE id = ANY($1) AND revoked_at IS NOT NULL RETURNING id")
                .bind(&b.ids)
                .fetch_all(&mut *tx)
                .await?;
            // `access_counts` has no foreign key on `agents`, and only what
            // is really gone takes its counts with it.
            sqlx::query("DELETE FROM access_counts WHERE origin = ANY($1)").bind(&gone).execute(&mut *tx).await?;
            tx.commit().await?;
            gone.len() as u64
        }
    };
    db::audit(&st.pool, (&user).into(), "agent_bulk", json!({ "action": b.action, "asked": b.ids.len(), "changed": changed })).await;
    Ok(Json(BulkDone { changed, asked: b.ids.len() }))
}

/// Remove a revoked agent for good. Revoke first, then delete: the
/// revocation locks the certificate out, the deletion only tidies up
/// afterwards — in a single step there would be no way to see whether a
/// device was deliberately decommissioned or merely cleared off the list.
///
/// The alerts stay. They are the evidence, and `origin_name` is in the row
/// itself; it stays readable even once the device is gone. Rules that apply
/// only to this device and its counts go with it.
pub(super) async fn delete_agent(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let row: Option<(String, Option<DateTime<Utc>>)> =
        sqlx::query_as("SELECT name, revoked_at FROM agents WHERE id = $1").bind(id).fetch_optional(&st.pool).await?;
    let Some((name, revoked_at)) = row else {
        return Err(not_found());
    };
    if revoked_at.is_none() {
        return Err(ApiError(StatusCode::CONFLICT, "revoke the agent first".into()));
    }
    let mut tx = st.pool.begin().await?;
    // `access_counts` has no foreign key on `agents`; without this cleanup
    // the counts would be left lying around as orphaned rows.
    sqlx::query("DELETE FROM access_counts WHERE origin = $1").bind(id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM agents WHERE id = $1").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    db::audit(&st.pool, (&user).into(), "agent_delete", json!({ "id": id, "name": name })).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Enrolment tokens ----------

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct TokenRow {
    id: Uuid,
    label: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    used_by: Option<Uuid>,
    max_uses: Option<i32>,
    uses: i32,
    /// Enrols file servers too, not only workstations (`agent::enroll`).
    file_server: bool,
}

pub(super) const TOKEN_COLS: &str = "id, label, created_at, expires_at, used_at, used_by, max_uses, uses, file_server";

/// Usable tokens first: a rollout token lives for weeks, and a hundred
/// single-device tokens made meanwhile must not push it out of the list —
/// the list is where it gets deleted.
pub(super) async fn tokens(State(st): State<Shared>, _u: Admin) -> R<Vec<TokenRow>> {
    let sql = format!("SELECT {TOKEN_COLS} FROM enroll_tokens ORDER BY (COALESCE(uses < max_uses, true) AND expires_at > now()) DESC, created_at DESC LIMIT 100");
    Ok(Json(sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_all(&st.pool).await?))
}

#[derive(Deserialize)]
pub(super) struct TokenBody {
    label: String,
    #[serde(default = "d24")]
    hours: i64,
    /// How many agents may enroll with it. Without a value any number,
    /// until the token is deleted after the rollout.
    #[serde(default)]
    max_uses: Option<i32>,
    /// Which kind of device the command is for: `mac`, `linux`,
    /// `windows_server` or `windows_client`. Without a value, the Mac — the
    /// way it was before.
    ///
    /// It picks the command that is offered for copying, and one thing
    /// more: only a `windows_server` token enrols a file server. Otherwise
    /// the agent says what it is when it enrolls (`EnrollRequest::kind`).
    #[serde(default)]
    platform: Option<String>,
}

/// The enrolment command per kind of device. It is in the dashboard for
/// copying; whoever gets the wrong one here enrols a workstation as a file
/// server and wonders why nothing gets reported.
/// The command the dashboard shows for copying.
///
/// If the agent program is on the central server (`sha` set), the command
/// fetches it along with everything else — otherwise somebody would have to
/// get the file onto the machine by hand beforehand, and that is exactly
/// where a rollout fails.
///
/// Verification goes through the **checksum**, not through the certificate:
/// a fresh machine does not yet know the central server's own CA, and a
/// certificate error in the middle of the one-liner gets nobody anywhere.
/// The checksum comes from the dashboard, so from a channel the
/// administrator already trusts; it binds the file more tightly than TLS
/// could.
///
/// The fetch uses `curl.exe` (shipped since Windows 10), not
/// `Invoke-WebRequest`: the agent port demands mTLS and sends a
/// `CertificateRequest` in the handshake. A fresh machine has no certificate
/// yet, and SChannel then aborts instead of sending an empty one — the
/// download fails before the first HTTP line.
///
/// The two `$LASTEXITCODE` checks are what make the one-liner stop at the
/// step that actually failed. `$ErrorActionPreference='Stop'` does not cover
/// a native program: without them a download that cannot resolve the host
/// runs on into `Get-FileHash`, and a failed enrolment still installs and
/// starts a service that has no credentials — which turns up later as a
/// service that "started and then stopped". `service install` stays
/// unguarded on purpose: on a second run it reports the service as already
/// existing, and that is no reason to skip `service start`.
fn enroll_command(platform: Option<&str>, url: &str, token: &str, ca: &str, sha: Option<&str>) -> String {
    let win = |endpoint: &str| match sha {
        None => format!("deelpe-winagent enroll {url} {token} --ca-sha256 {ca}{endpoint}"),
        Some(sha) => format!(
            "$ErrorActionPreference='Stop'; \
$d='C:\\Program Files\\deelpe'; New-Item -ItemType Directory -Force $d | Out-Null; \
curl.exe -k --fail -H \"X-Deelpe-Token: {token}\" -o \"$d\\deelpe-winagent.exe\" {url}/agent/binary/windows; \
if ($LASTEXITCODE) {{ throw 'download failed' }}; \
if ((Get-FileHash \"$d\\deelpe-winagent.exe\").Hash -ne '{upper}') {{ throw 'checksum mismatch' }}; \
& \"$d\\deelpe-winagent.exe\" enroll {url} {token} --ca-sha256 {ca}{endpoint}; \
if ($LASTEXITCODE) {{ throw 'enrolment failed' }}; \
& \"$d\\deelpe-winagent.exe\" service install; \
& \"$d\\deelpe-winagent.exe\" service start",
            upper = sha.to_uppercase()
        ),
    };
    match platform {
        Some("windows_server") => win(""),
        Some("windows_client") => win(" --endpoint"),
        _ => match sha {
            None => format!("sudo deelpe central enroll {url} {token} --ca-sha256 {ca}"),
            // On the Mac the service is installed from inside the app
            // (password dialog), which is why this command ends at opening
            // the app. The enrolment after that is a second command of its
            // own — `TokenCreated::enroll_command` — and deliberately not a
            // line inside this one: a shell comment in a block that somebody
            // pastes in one go is skipped in silence, and `deelpe` is not on
            // the PATH until the app has put it there.
            Some(sha) => format!(
                "curl -fsSLk -H 'X-Deelpe-Token: {token}' {url}/agent/binary/mac -o /tmp/DLPrevent.zip && \
echo '{sha}  /tmp/DLPrevent.zip' | shasum -a 256 -c - && \
sudo rm -rf /Applications/DLPrevent.app && sudo unzip -q /tmp/DLPrevent.zip -d /Applications && \
open /Applications/DLPrevent.app"
            ),
        },
    }
}
fn d24() -> i64 {
    24
}

#[derive(Serialize)]
pub(super) struct TokenCreated {
    id: Uuid,
    token: String,
    expires_at: DateTime<Utc>,
    agent_url: String,
    ca_sha256: String,
    command: String,
    /// macOS with the app on the server: the enrolment that only works once
    /// "Install service…" in the app has created `/usr/local/bin/deelpe`.
    /// Separate from `command` so the dashboard can show that step as a step.
    enroll_command: Option<String>,
}

pub(super) async fn create_token(State(st): State<Shared>, Admin(user): Admin, headers: HeaderMap, Json(b): Json<TokenBody>) -> R<TokenCreated> {
    let label = b.label.trim().to_string();
    if label.is_empty() {
        return Err(bad("label is missing"));
    }
    // A year at most: a rollout runs for weeks, but a token nobody remembers
    // should not outlive the people who made it.
    let hours = b.hours.clamp(1, 24 * 365);
    let max_uses = b.max_uses.map(|n| n.clamp(1, 100_000));
    let token = auth::random_token();
    let expires_at = Utc::now() + Duration::hours(hours);
    let (id,): (Uuid,) = sqlx::query_as("INSERT INTO enroll_tokens (token_hash, label, created_by, expires_at, max_uses, file_server) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id")
        .bind(auth::sha256_hex(&token))
        .bind(&label)
        .bind(user.id)
        .bind(expires_at)
        .bind(max_uses)
        .bind(b.platform.as_deref() == Some("windows_server"))
        .fetch_one(&st.pool)
        .await?;
    // The name from the address bar: behind a proxy the `Host` would
    // otherwise hold the central server, and the command would carry a name
    // no workstation resolves. But it has to point straight at the central
    // server on port 8444 — the agent port speaks mTLS and does not go
    // through the proxy (INSTALL.md).
    let host = st.public_host(&headers).unwrap_or("localhost");
    let host = host.rsplit_once(':').map(|(h, _)| h).unwrap_or(host).trim_matches(|c| c == '[' || c == ']');
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let agent_url = format!("https://{host}:{}", st.agent_port);
    let sha = crate::binaries::platform_for(b.platform.as_deref()).and_then(|p| crate::binaries::sha256_of(&st, p));
    let command = enroll_command(b.platform.as_deref(), &agent_url, &token, &st.pki.ca_fingerprint, sha.as_deref());
    // Without an uploaded app the mac command already is the enrolment; with
    // one it stops at opening the app, and the enrolment is the same line
    // again, for after "Install service…".
    let enroll = (b.platform.as_deref() == Some("mac") && sha.is_some())
        .then(|| enroll_command(b.platform.as_deref(), &agent_url, &token, &st.pki.ca_fingerprint, None));
    db::audit(&st.pool, (&user).into(), "token_create", json!({ "id": id, "label": label, "hours": hours, "max_uses": max_uses, "platform": b.platform })).await;
    Ok(Json(TokenCreated { id, token, expires_at, agent_url, ca_sha256: st.pki.ca_fingerprint.clone(), command, enroll_command: enroll }))
}

pub(super) async fn delete_token(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("DELETE FROM enroll_tokens WHERE id = $1").bind(id).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::audit(&st.pool, (&user).into(), "token_delete", json!({ "id": id })).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_command_per_platform() {
        let (u, t, c) = ("https://s:8444", "tok", "ab12");
        // Without an uploaded program it stays at the bare enrolment command.
        assert!(enroll_command(None, u, t, c, None).starts_with("sudo deelpe central enroll"));
        assert!(enroll_command(Some("mac"), u, t, c, None).starts_with("sudo deelpe central enroll"));
        // Linux shares the `deelpe` CLI with the Mac, and nothing is ever
        // stored for it (`binaries::platform_for` → `None`), so this is the
        // command the dialog shows — and the one INSTALL.md tells people to
        // run. It has to stay a bare enrolment.
        assert_eq!(enroll_command(Some("linux"), u, t, c, None), "sudo deelpe central enroll https://s:8444 tok --ca-sha256 ab12");
        assert_eq!(crate::binaries::platform_for(Some("linux")), None);
        assert_eq!(enroll_command(Some("windows_server"), u, t, c, None), "deelpe-winagent enroll https://s:8444 tok --ca-sha256 ab12");
        // The workstation needs --endpoint, otherwise the agent reads a
        // server's security log, which does not exist there.
        assert!(enroll_command(Some("windows_client"), u, t, c, None).ends_with("--endpoint"));

        // If the program is ready and waiting, the command fetches it itself
        // and checks the checksum before running it.
        let w = enroll_command(Some("windows_client"), u, t, c, Some("aa11"));
        assert!(w.contains("/agent/binary/windows"), "{w}");
        assert!(w.contains("X-Deelpe-Token"), "{w}");
        // curl.exe, not Invoke-WebRequest: see enroll_command.
        assert!(w.contains("curl.exe"), "{w}");
        assert!(!w.contains("Invoke-WebRequest"), "{w}");
        assert!(w.contains("AA11"), "Get-FileHash liefert Grossbuchstaben: {w}");
        assert!(w.contains("service install"), "{w}");
        // Without these the one-liner runs on after a failed step and leaves
        // a service behind that has no credentials.
        assert!(w.contains("throw 'download failed'"), "{w}");
        assert!(w.contains("throw 'enrolment failed'"), "{w}");
        assert!(w.contains("--endpoint"), "{w}");
        let m = enroll_command(Some("mac"), u, t, c, Some("aa11"));
        assert!(m.contains("/agent/binary/mac"), "{m}");
        assert!(m.contains("shasum -a 256 -c"), "{m}");
        // The enrolment is not in here. It needs the service that
        // "Install service…" in the app installs, and a shell comment saying
        // so is skipped without a word when the block is pasted whole.
        assert!(m.ends_with("open /Applications/DLPrevent.app"), "{m}");
        assert!(!m.contains("central enroll"), "{m}");
    }
}
