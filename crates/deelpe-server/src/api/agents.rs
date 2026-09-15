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
}

pub(super) const TOKEN_COLS: &str = "id, label, created_at, expires_at, used_at, used_by, max_uses, uses";

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
    /// It only picks the command that is offered for copying. The token
    /// itself is bound to no platform: the agent says what it is when it
    /// enrolls (`EnrollRequest::kind`).
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
    let (id,): (Uuid,) = sqlx::query_as("INSERT INTO enroll_tokens (token_hash, label, created_by, expires_at, max_uses) VALUES ($1, $2, $3, $4, $5) RETURNING id")
        .bind(auth::sha256_hex(&token))
        .bind(&label)
        .bind(user.id)
        .bind(expires_at)
        .bind(max_uses)
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
