//! The dashboard's JSON API. Everything under `/api`, session cookie
//! mandatory except for signing in (`/api/login`, `/api/login/...`).

//!
//! One module per resource; here is only what all of them need: the router,
//! the origin check and the full-text search.
use crate::auth::{self, bad, not_found, Admin, ApiError, User};
use anyhow::anyhow;
use crate::db::{self, AgentRow, AlertRow, RuleRow, SourceRow, AGENT_COLS, ALERT_COLS, RULE_COLS, SOURCE_COLS};
use crate::sql::{order_by, Binder, ListQuery};
use crate::state::{PeerAddr, Shared};
use axum::extract::{Path, Query, State};
use axum::extract::Request;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::middleware::{self, Next};
use axum::routing::{delete, get, post};
use axum::{Extension, Json, Router};
use chrono::{DateTime, Duration, Utc};
use deelpe_core::central::API_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

mod account;
mod agents;
mod release;
mod alerts;
mod assist;
mod audit;
mod keys;
mod notify;
mod reputation;
mod rules;
mod session;
mod settings;
mod sources;
mod users;

type R<T> = Result<Json<T>, ApiError>;

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/api/login", post(session::login))
        .route("/api/login/totp", post(session::login_totp))
        .route("/api/login/passkey", post(session::passkey_login_start))
        .route("/api/login/passkey/finish", post(session::passkey_login_finish))
        .route("/api/logout", post(session::logout))
        .route("/api/me", get(session::me))
        .route("/api/account", get(account::account))
        .route("/api/account/totp", post(account::totp_start).delete(account::totp_disable))
        .route("/api/account/totp/enable", post(account::totp_enable))
        .route("/api/account/passkeys", post(account::passkey_start))
        .route("/api/account/passkeys/finish", post(account::passkey_finish))
        .route("/api/account/passkeys/{id}", delete(account::delete_passkey))
        .route("/api/overview", get(alerts::overview))
        .route("/api/alerts", get(alerts::alerts))
        .route("/api/alerts/{id}/ack", post(alerts::ack_alert))
        .route("/api/alerts/ack", post(alerts::ack_alerts))
        .route("/api/alerts/{id}/learn", post(alerts::learn_alert))
        .route("/api/alerts/{id}/explain", get(assist::insight).post(assist::explain))
        .route("/api/counts", get(alerts::counts))
        .route("/api/reputation", get(reputation::reputation))
        .route("/api/reputation/{ip}", post(reputation::refresh))
        .route("/api/assist", get(assist::assist))
        .route("/api/assist/test", post(assist::test))
        .route("/api/rules", get(rules::rules).post(rules::create_rule))
        .route("/api/rules/{id}", axum::routing::put(rules::update_rule).delete(rules::delete_rule))
        .route("/api/agents", get(agents::agents))
        .route("/api/groups", get(agents::groups))
        .route("/api/agents/{id}", delete(agents::revoke_agent))
        .route("/api/agents/{id}/log", get(agents::agent_log))
        .route("/api/agents/{id}/update", post(agents::request_update))
        .route("/api/agents/{id}/finish-learning", post(agents::finish_learning))
        .route("/api/agents/finish-learning", post(agents::finish_learning_all))
        .route("/api/release", get(release::release))
        .route("/api/release/check", post(release::check))
        .route("/api/release/fetch", post(release::fetch))
        .route("/api/agents/{id}/delete", delete(agents::delete_agent))
        .route("/api/sources", get(sources::sources))
        .route("/api/sources/{id}", axum::routing::put(sources::update_source).delete(sources::delete_source))
        .route("/api/tokens", get(agents::tokens).post(agents::create_token))
        .route("/api/tokens/{id}", delete(agents::delete_token))
        .route("/api/users", get(users::users).post(users::create_user))
        .route("/api/users/{id}", delete(users::delete_user))
        .route("/api/users/{id}/password", post(users::set_password))
        .route("/api/users/{id}/second-factor", delete(users::reset_second_factor))
        .route("/api/keys", get(keys::keys).post(keys::create_key))
        .route("/api/keys/{id}", delete(keys::delete_key))
        .route("/api/settings", get(settings::settings).put(settings::update_settings))
        .route("/api/notifications", get(notify::notifications))
        .route("/api/notifications/test", post(notify::test))
        .route("/api/audit", get(audit::audit))
        // Agent programs for download; its own router because of the larger
        // upper bound for uploads.
        .merge(crate::binaries::router())
        .layer(middleware::from_fn_with_state(state.clone(), same_origin))
        .with_state(state)
}

/// A second bolt next to `SameSite=Strict`: writing requests from a foreign
/// origin are refused. If the `Origin` header is missing (command line, old
/// browsers on the same origin), the cookie protection is all there is.
async fn same_origin(State(st): State<Shared>, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let h = req.headers();
        let str_header = |n: &str| h.get(n).and_then(|v| v.to_str().ok());
        let expected = st.public_host(h);
        if let Some(origin) = str_header("origin") {
            let origin_host = origin.split_once("://").map(|(_, h)| h).unwrap_or(origin);
            if Some(origin_host) != expected {
                return ApiError(StatusCode::FORBIDDEN, "cross-origin request refused".into()).into_response();
            }
        }
    }
    next.run(req).await
}

/// Default `true` for a `#[serde(default)]` field. It stands here because
/// rules and settings both need it.
fn dtrue() -> bool {
    true
}

/// Search terms: words, LIKE metacharacters defused, at most eight.
fn search_terms(q: Option<&str>) -> Vec<String> {
    q.unwrap_or("")
        .split_whitespace()
        .map(|w| format!("%{}%", w.to_lowercase().replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")))
        .take(8)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    /// The fields of an interface from `types.ts`, top level.
    ///
    /// Braces are counted so that a nested object literal
    /// (`sensors: { name: string }[]`) belongs to its field and does not
    /// count as fields of its own.
    fn ts_fields(src: &str, iface: &str) -> Vec<String> {
        let head = format!("export interface {iface} ");
        let at = src.find(&head).unwrap_or_else(|| panic!("interface {iface} fehlt in types.ts"));
        let body = &src[at + head.len()..];
        let open = body.find('{').expect("Rumpf");
        let (mut depth, mut end) = (0usize, 0usize);
        for (i, c) in body[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + i;
                        break;
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        let (mut depth, mut field) = (0usize, String::new());
        for c in body[open + 1..end].chars() {
            match c {
                '{' | '(' | '[' => depth += 1,
                '}' | ')' | ']' => depth -= 1,
                ';' | '\n' if depth == 0 => {
                    if let Some((name, _)) = field.split_once(':') {
                        let name = name.trim().trim_end_matches('?').trim();
                        if !name.is_empty() && !name.starts_with("/") && !name.starts_with("*") {
                            out.push(name.to_string());
                        }
                    }
                    field.clear();
                }
                _ => field.push(c),
            }
        }
        out
    }

    /// The database's row types are at the same time the dashboard's
    /// response types: the SELECT column list **is** the JSON. That is cheap
    /// and stays that way — but it means that a renamed column breaks the UI
    /// without any module in between noticing a thing.
    ///
    /// `apps/web/src/lib/types.ts` is maintained by hand. That nobody looks
    /// at it was proven by a doubly declared `ShareInfo` which TypeScript
    /// quietly merged.
    ///
    /// What is checked is the dangerous direction: **what the UI expects,
    /// the API has to deliver**. The other way round the API may deliver
    /// more than the dashboard uses — that harms nobody.
    #[test]
    fn every_field_the_dashboard_expects_is_one_the_api_delivers() {
        let ts = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../apps/web/src/lib/types.ts"))
            .expect("types.ts neben dem Server");
        // Interface, column list, and fields that do not come from the
        // database row.
        let checks: &[(&str, &str, &[&str])] = &[
            ("Alert", db::ALERT_COLS, &[]),
            ("Rule", db::RULE_COLS, &[]),
            // `online` is computed by `AgentView` from the last report.
            ("Agent", db::AGENT_COLS, &["online"]),
            ("Source", db::SOURCE_COLS, &[]),
            // Second factor: computed, not selected as a column.
            ("UserRow", users::USER_COLS, &["totp_enabled", "passkeys"]),
            ("Passkey", account::PASSKEY_COLS, &[]),
            ("Token", agents::TOKEN_COLS, &[]),
            ("ApiKey", keys::KEY_COLS, &[]),
            ("AuditRow", audit::AUDIT_COLS, &[]),
            ("Insight", crate::assist::INSIGHT_COLS, &[]),
        ];
        for (iface, cols, extra) in checks {
            let api: Vec<&str> = cols.split(',').map(str::trim).collect();
            let fields = ts_fields(&ts, iface);
            assert!(!fields.is_empty(), "{iface}: keine Felder gelesen — Parser oder Datei kaputt");
            for f in fields {
                assert!(
                    api.contains(&f.as_str()) || extra.contains(&f.as_str()),
                    "types.ts erwartet {iface}.{f}, aber die API liefert es nicht (Spalten: {cols})",
                );
            }
        }

        // And no interface may be added on the quiet. What does not come
        // from a column list cannot be compared here — but at least somebody
        // should have decided that this is how it is. Without that
        // `types.ts` keeps growing unchecked; a doubly declared `ShareInfo`
        // got in in exactly that way.
        let exempt = [
            // Hand-built response shapes with no row type behind them.
            "Account", "AgentStatus", "AssistProbe", "AssistView", "Binary", "Counts", "LogRow", "NotifyView", "Overview",
            "ReleaseView", "Reputation", "ReputationView", "ShareInfo", "TotpSetup", "User",
            // One-off answers when creating something: the secret comes out
            // exactly here and stands in no column list.
            "ApiKeyCreated", "TokenCreated",
            // Has a test of its own: `every_setting_that_goes_in_comes_back_out`.
            "Settings",
        ];
        let declared: Vec<&str> = ts
            .match_indices("export interface ")
            .map(|(i, m)| ts[i + m.len()..].split_whitespace().next().unwrap_or_default())
            .collect();
        for iface in declared {
            assert!(
                checks.iter().any(|(c, _, _)| *c == iface) || exempt.contains(&iface),
                "types.ts erklaert {iface}, und nichts prueft es: entweder in `checks` aufnehmen oder in `exempt` mit Grund",
            );
        }
    }

    /// The same rule stands there in two forms: as an SQL condition for the
    /// lists (`alerts::IS_ALERT`) and as a list for sending mail
    /// (`mail::ALARM_VERDICTS`). An SQL literal and a Rust slice cannot be
    /// built from the same constant — so at least it is checked that the two
    /// agree. If they drift apart, the overview counts a verdict as an alarm
    /// that nobody gets an email about.
    #[test]
    /// A destination address's reputation is judged twice: in SQL, so that
    /// the filter works, and in TypeScript, so that the badge colours itself.
    /// That cannot be merged -- a language boundary lies in between -- but it
    /// can be held together.
    ///
    /// Until 2026-09-10 a comment did that. Whoever adjusts the threshold
    /// from the AbuseIPDB docs and touches only one side got a filter that
    /// means something other than the colour next to it.
    fn the_dashboard_and_the_filter_agree_on_what_a_ruf_is() {
        let svelte = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../apps/web/src/pages/Alerts.svelte"))
            .expect("Alerts.svelte neben dem Server");
        let line = svelte
            .lines()
            .find(|l| l.contains("function repClass"))
            .expect("repClass in Alerts.svelte");
        let nums: Vec<i64> = line
            .split(|c: char| !c.is_ascii_digit())
            .filter(|t| !t.is_empty())
            .map(|t| t.parse().expect("Zahl"))
            .collect();
        assert_eq!(
            nums,
            vec![alerts::REP_SUSPICIOUS, alerts::REP_MALICIOUS],
            "repClass urteilt nach anderen Schwellen als der Filter: {line}"
        );

        // And the SQL side really does carry the same numbers.
        let sql = format!("{:?}", alerts::rep_where_for_test("warn"));
        assert!(sql.contains(&alerts::REP_SUSPICIOUS.to_string()), "{sql}");
        let sql = format!("{:?}", alerts::rep_where_for_test("bad"));
        assert!(sql.contains(&alerts::REP_MALICIOUS.to_string()), "{sql}");
    }

    #[test]
    fn the_dashboard_and_the_mailer_agree_on_what_an_alarm_is() {
        let sql = alerts::IS_ALERT;
        for v in crate::mail::ALARM_VERDICTS {
            assert!(sql.contains(&format!("'{v}'")), "{v} fehlt in {sql}");
        }
        assert_eq!(sql.matches('\'').count() / 2, crate::mail::ALARM_VERDICTS.len(), "verschieden viele Urteile: {sql}");
    }

    /// Real sessions and the HTTP router, isolated by sqlx in a fresh database.
    /// Run with DATABASE_URL pointing at a development Postgres with CREATEDB.
    fn test_app(pool: sqlx::PgPool) -> Shared {
        // Match main(): workspace builds can enable more than one TLS provider.
        rustls::crypto::ring::default_provider().install_default().ok();
        let dir = std::env::temp_dir().join(format!("deelpe-api-test-{}", Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        std::sync::Arc::new(crate::state::AppState::new(pool, std::sync::Arc::new(pki), false, 8444, false, std::env::temp_dir().join("deelpe-test")))
    }

    async fn test_session(pool: &sqlx::PgPool, role: &str) -> String {
        let id: Uuid = sqlx::query_scalar("INSERT INTO users (name, pw_hash, role) VALUES ($1, '', $1) RETURNING id")
            .bind(role).fetch_one(pool).await.unwrap();
        let token = auth::random_token();
        sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, now() + interval '12 hours')")
            .bind(auth::sha256_hex(&token)).bind(id).execute(pool).await.unwrap();
        format!("{}={token}", auth::COOKIE)
    }

    async fn get(app: &Router, path: &str, cookie: &str) -> Response {
        app.clone().oneshot(Request::builder().uri(path).header(header::COOKIE, cookie).body(axum::body::Body::empty()).unwrap()).await.unwrap()
    }

    async fn send(app: &Router, method: &str, path: &str, header: (&str, &str), body: serde_json::Value) -> Response {
        send_h(app, method, path, &[header], body).await
    }

    async fn send_h(app: &Router, method: &str, path: &str, headers: &[(&str, &str)], body: serde_json::Value) -> Response {
        let mut b = Request::builder().method(method).uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if !body.is_null() {
            b = b.header(axum::http::header::CONTENT_TYPE, "application/json");
        }
        let body = if body.is_null() { axum::body::Body::empty() } else { axum::body::Body::from(body.to_string()) };
        app.clone().oneshot(b.body(body).unwrap()).await.unwrap()
    }

    async fn response_json(response: Response) -> serde_json::Value {
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn viewer_can_monitor_but_cannot_read_administration(pool: sqlx::PgPool) {
        let viewer = test_session(&pool, "viewer").await;
        let admin = test_session(&pool, "admin").await;
        let app = router(test_app(pool));
        for path in ["/api/me", "/api/overview", "/api/alerts?open=true", "/api/counts"] {
            assert_eq!(get(&app, path, &viewer).await.status(), StatusCode::OK, "viewer {path}");
            assert_eq!(get(&app, path, "").await.status(), StatusCode::UNAUTHORIZED, "anonymous {path}");
        }
        let mut exposed = Vec::new();
        for path in ["/api/audit", "/api/settings", "/api/notifications", "/api/tokens", "/api/keys", "/api/users", "/api/assist", "/api/alerts/1/explain", "/api/rules", "/api/agents", "/api/sources", "/api/groups"] {
            let status = get(&app, path, &viewer).await.status();
            if status != StatusCode::FORBIDDEN {
                exposed.push(format!("{path}: expected 403, got {status}"));
            }
            assert_eq!(get(&app, path, &admin).await.status(), StatusCode::OK, "admin {path}");
            assert_eq!(get(&app, path, "").await.status(), StatusCode::UNAUTHORIZED, "anonymous {path}");
        }
        assert!(exposed.is_empty(), "viewer can read administration: {}", exposed.join(", "));
    }

    /// An agent's log: write it in, get it back out filtered. The filter is
    /// the part that can go wrong — compared as text, `error` would stand
    /// before `info` and „warn and above" would show the wrong thing.
    #[sqlx::test(migrations = "./migrations")]
    async fn agent_log_is_stored_and_filtered_by_severity(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        let viewer = test_session(&pool, "viewer").await;
        let agent = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after) \
             VALUES ($1, 'srv01', 'windows_server', '0.1.0', 'fp', now() + interval '1 day')",
        )
        .bind(agent)
        .execute(&pool)
        .await
        .unwrap();
        let at = Utc::now();
        let lines: Vec<deelpe_core::central::LogLine> = [("info", "agent running"), ("warn", "report not accepted"), ("error", "sensor is dead")]
            .iter()
            .map(|(lvl, msg)| deelpe_core::central::LogLine { at, level: (*lvl).into(), target: "t".into(), msg: (*msg).into() })
            .collect();
        assert_eq!(db::insert_agent_log(&pool, agent, &lines).await.unwrap(), 3);
        // Lost answer: the agent sends the same lines again. That must not
        // duplicate anything.
        db::insert_agent_log(&pool, agent, &lines).await.unwrap();
        // Postgres does not accept a NUL byte in `text`. It has to drop out
        // here, otherwise a single line would block every further report
        // from this agent.
        let nul = deelpe_core::central::LogLine { at: Utc::now(), level: "warn".into(), target: "t".into(), msg: "pfad\u{0}kaputt".into() };
        db::insert_agent_log(&pool, agent, &[nul]).await.expect("Nullbyte darf den Bericht nicht kippen");
        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM agent_log WHERE agent_id = $1").bind(agent).fetch_one(&pool).await.unwrap();
        assert_eq!(n, 4, "dieselben Zeilen zweimal duerfen nicht doppelt dastehen");

        let app = router(test_app(pool));
        let all = response_json(get(&app, &format!("/api/agents/{agent}/log"), &admin).await).await;
        assert_eq!(all.as_array().unwrap().len(), 4);
        let warn = response_json(get(&app, &format!("/api/agents/{agent}/log?level=warn"), &admin).await).await;
        let levels: Vec<&str> = warn.as_array().unwrap().iter().map(|l| l["level"].as_str().unwrap()).collect();
        assert_eq!(levels, ["warn", "warn"], "der Filter zeigt genau die gewaehlte Stufe: {levels:?}");
        let info = response_json(get(&app, &format!("/api/agents/{agent}/log?level=info"), &admin).await).await;
        let levels: Vec<&str> = info.as_array().unwrap().iter().map(|l| l["level"].as_str().unwrap()).collect();
        assert_eq!(levels, ["info"], "Info zeigt keine Warnungen: {levels:?}");
        let found = response_json(get(&app, &format!("/api/agents/{agent}/log?q=accepted"), &admin).await).await;
        assert_eq!(found.as_array().unwrap().len(), 1, "{found}");
        // The log belongs to administration: it names the device's paths,
        // addresses and error messages.
        assert_eq!(get(&app, &format!("/api/agents/{agent}/log"), &viewer).await.status(), StatusCode::FORBIDDEN);
    }

    /// When an agent is deleted, `ON DELETE SET NULL` sets the `agent_id` of
    /// its alerts to NULL; the rows deliberately stay. Then `origin_name` is
    /// all that still marks their origin — and it has to be able to filter,
    /// otherwise half the list in the dashboard is dead.
    #[sqlx::test(migrations = "./migrations")]
    async fn alerts_filter_by_origin_name_when_the_agent_is_gone(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        for (id, origin) in [(1, "DESKTOP-EXAMPLE"), (2, "DESKTOP-EXAMPLE"), (3, "NAS01")] {
            sqlx::query("INSERT INTO alerts (id, kind, origin_name, external_id, at, verdict, detail) \
                VALUES ($1, 'endpoint', $2, $1::text, now(), 'hard_limit', '{}')")
                .bind(id as i64).bind(origin).execute(&pool).await.unwrap();
        }
        let app = router(test_app(pool));
        let rows = response_json(get(&app, "/api/alerts?origin=DESKTOP-EXAMPLE", &admin).await).await;
        assert_eq!(rows.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect::<Vec<_>>(), vec![2, 1]);
        // And the same „all" for the bulk acknowledge: NAS01 stays open.
        let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/alerts/ack")
            .header(header::COOKIE, &admin).header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(json!({"all": true, "origin": "DESKTOP-EXAMPLE"}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response_json(response).await["acked"], 2);
        let open = response_json(get(&app, "/api/alerts?open=true", &admin).await).await;
        assert_eq!(open.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect::<Vec<_>>(), vec![3]);
    }

    /// The link from the alarm email points at **one** alert. It has to hit
    /// it without anybody having to search — even when it has been
    /// acknowledged in the meantime (the list otherwise shows only open
    /// ones), even when it sits under „Notices" (the reputation trigger
    /// mails those too), and without taking the neighbours along.
    ///
    /// The full-text search cannot do that: it runs LIKE over a string that
    /// also contains `id::text` — `q=1` thereby catches the 1, the 17 and
    /// every name with a one in it, here `srv01`. Hence a filter of its own.
    #[sqlx::test(migrations = "./migrations")]
    async fn an_email_link_finds_exactly_its_alert(pool: sqlx::PgPool) {
        let viewer = test_session(&pool, "viewer").await;
        for (id, verdict, done) in [(1_i64, "denied", false), (2, "denied", true), (17, "known", false)] {
            sqlx::query("INSERT INTO alerts (id, kind, origin_name, external_id, at, verdict, detail, acknowledged_at) \
                VALUES ($1, 'access', 'srv01', $1::text, now(), $2, '{}', CASE WHEN $3 THEN now() END)")
                .bind(id).bind(verdict).bind(done).execute(&pool).await.unwrap();
        }
        let app = router(test_app(pool));
        let ids = |v: serde_json::Value| v.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect::<Vec<_>>();
        for (query, expected) in [("id=1", vec![1]), ("id=2", vec![2]), ("id=17", vec![17]), ("id=99", vec![])] {
            let rows = response_json(get(&app, &format!("/api/alerts?{query}"), &viewer).await).await;
            assert_eq!(ids(rows), expected, "{query}");
        }
        // The 17 is a notice, not an alarm: the list's category would
        // otherwise hold it back, the link still has to find it.
        for query in ["id=17", "id=17&category=alerts", "id=17&category=notices"] {
            let rows = response_json(get(&app, &format!("/api/alerts?{query}"), &viewer).await).await;
            assert_eq!(ids(rows), vec![17], "{query}");
        }
        // Without an id the category keeps filtering as it always did.
        let rows = response_json(get(&app, "/api/alerts?category=alerts", &viewer).await).await;
        assert_eq!(ids(rows), vec![2, 1], "die Kategorie gilt, wo keine Zeile benannt ist");

        // The reason for the filter of its own, as a test: `q=1` catches the
        // 1, the 17 and, via `srv01`, the 2 as well — all three.
        let rows = response_json(get(&app, "/api/alerts?q=1&category=all", &viewer).await).await;
        assert_eq!(ids(rows), vec![17, 2, 1], "die Volltextsuche trifft jede Eins");
        // What is not a number is a bad request — not a silent filter that
        // shows everything.
        assert_eq!(get(&app, "/api/alerts?id=abc", &viewer).await.status(), StatusCode::BAD_REQUEST);
    }

    /// The reputation filter goes through a JOIN onto the cache, and for
    /// that the address has to be cut out of `remote` — with a port, in
    /// brackets, without either, and sometimes there is no address there at
    /// all. Everything here hangs on exactly that, hence against a real
    /// database.
    #[sqlx::test(migrations = "./migrations")]
    async fn alerts_filter_by_the_reputation_of_their_destination(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        for (id, remote) in [
            (1i64, Some("1.2.3.4:443")),
            (2, Some("[2606:4700::1111]:443")),
            (3, Some("9.9.9.9")),
            (4, Some("volume /Volumes/Stick")),
            (5, None),
        ] {
            sqlx::query("INSERT INTO alerts (id, kind, origin_name, external_id, at, verdict, detail, remote) \
                VALUES ($1, 'endpoint', 'test', $1::text, now(), 'hard_limit', '{}', $2)")
                .bind(id).bind(remote).execute(&pool).await.unwrap();
        }
        for (ip, score, white) in [("1.2.3.4", 90, false), ("2606:4700::1111", 40, false), ("9.9.9.9", 100, true)] {
            sqlx::query("INSERT INTO ip_reputations (ip, score, is_whitelisted) VALUES ($1, $2, $3)")
                .bind(ip).bind(score).bind(white).execute(&pool).await.unwrap();
        }
        let app = router(test_app(pool));
        let ids = |v: serde_json::Value| v.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect::<Vec<_>>();
        let list = |query: &str| {
            let (app, admin) = (app.clone(), admin.clone());
            let uri = format!("/api/alerts?{query}");
            async move { ids(response_json(get(&app, &uri, &admin).await).await) }
        };
        assert_eq!(list("rep=bad").await, vec![1], "nur die 90");
        assert_eq!(list("rep=warn").await, vec![2, 1], "verdaechtig schliesst boesartig ein");
        // On the whitelist the score does not count, not even the 100.
        assert_eq!(list("rep=ok").await, vec![3]);
        assert_eq!(list("rep=none").await, vec![5, 4], "kein Eintrag und keine Adresse");
        assert_eq!(list("").await, vec![5, 4, 3, 2, 1], "ohne Filter bleibt alles stehen");
        assert_eq!(list("rep=quatsch").await, vec![5, 4, 3, 2, 1], "ein unbekannter Wert filtert nicht");
        // And sorting by the same number. The 100 on the whitelist counts as
        // 0, unchecked stands at the bottom in both directions.
        assert_eq!(list("sort=reputation&dir=desc").await, vec![1, 2, 3, 5, 4], "90, 40, Whitelist, dann ungeprueft");
        assert_eq!(list("sort=reputation&dir=asc").await, vec![5, 4, 3, 2, 1]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn dashboard_counts_only_alarms_and_keeps_notices_separate(pool: sqlx::PgPool) {
        let viewer = test_session(&pool, "viewer").await;
        let admin = test_session(&pool, "admin").await;
        // Both origins, open and closed alarms, old alarms, and every notice verdict.
        for (id, kind, verdict, days, done) in [
            (1, "access", "hard_limit", 0, false),
            (2, "endpoint", "deviation", 0, false),
            (3, "endpoint", "new", 0, false),
            (4, "endpoint", "flagged", 0, false),
            (5, "access", "no_profile", 0, false),
            (6, "endpoint", "known", 0, false),
            (7, "endpoint", "learning", 0, true),
            (8, "access", "hard_limit", 0, true),
            (9, "endpoint", "deviation", 2, false),
        ] {
            sqlx::query("INSERT INTO alerts (id, kind, origin_name, external_id, at, verdict, detail, acknowledged_at) \
                VALUES ($1, $2, 'test', $1::text, now() - ($4::int * interval '1 day'), $3, '{}', CASE WHEN $5 THEN now() END)")
                .bind(id as i64).bind(kind).bind(verdict).bind(days).bind(done).execute(&pool).await.unwrap();
        }
        let app = router(test_app(pool));
        let overview = response_json(get(&app, "/api/overview", &viewer).await).await;
        assert_eq!(overview["alerts_open"], 3, "new/flagged/no_profile/known are notices, not alarms");
        assert_eq!(overview["alerts_24h"], 3, "24h includes closed alarms but not old alarms or notices");
        // The Central server card names the version this server runs.
        assert_eq!(overview["server_version"], env!("CARGO_PKG_VERSION"));
        assert!(overview["server_build"].as_str().is_some_and(|b| b.len() == 12), "{}", overview["server_build"]);
        let mut recent_ids: Vec<_> = overview["recent"].as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect();
        recent_ids.sort();
        assert_eq!(recent_ids, vec![1, 2, 8, 9]);
        for (query, ids) in [
            ("open=true", vec![9, 2, 1]),
            ("category=notices&open=true", vec![6, 5, 4, 3]),
            ("category=notices&open=false", vec![7]),
            ("category=all&open=true", vec![9, 6, 5, 4, 3, 2, 1]),
            ("category=alerts&open=true&limit=1&offset=1", vec![2]),
            ("category=notices&open=true&q=new&sort=id&dir=asc", vec![3]),
            ("category=alerts&verdict=new", vec![]),
        ] {
            let rows = response_json(get(&app, &format!("/api/alerts?{query}"), &viewer).await).await;
            assert_eq!(rows.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect::<Vec<_>>(), ids, "{query}");
        }
        assert_eq!(get(&app, "/api/alerts?category=invalid", &viewer).await.status(), StatusCode::BAD_REQUEST);

        // Bulk-close uses exactly the same category/search filter as the list.
        for (body, expected) in [(json!({"all": true, "category": "notices", "q": "new"}), 1), (json!({"all": true}), 3)] {
            let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/alerts/ack")
                .header(header::COOKIE, &admin).header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string())).unwrap()).await.unwrap();
            assert_eq!(response_json(response).await["acked"], expected);
        }
        let overview = response_json(get(&app, "/api/overview", &viewer).await).await;
        assert_eq!(overview["alerts_open"], 0);
        let notices = response_json(get(&app, "/api/alerts?category=notices&open=true", &viewer).await).await;
        assert_eq!(notices.as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect::<Vec<_>>(), vec![6, 5, 4]);
        let all = response_json(get(&app, "/api/alerts?category=all", &viewer).await).await;
        assert_eq!(all.as_array().unwrap().len(), 9, "separation/acknowledgement must not delete records");
    }

    /// An API key is a reading account, and the master switch is the bolt
    /// above it: with the switch off, no key is valid — not even a freshly
    /// created one. That is the part that can go wrong, because a key that
    /// opens up administration or gets through despite „off" is something
    /// nobody notices in day-to-day operation.
    /// The SMTP password goes in and never comes back out — neither in the
    /// answer nor into the audit log. That is exactly where the mistake is
    /// expensive: every administrator reads the log, and it is never deleted.
    #[sqlx::test]
    /// Every field the page sends has to come back out again.
    ///
    /// Until 2026-09-10 the keys stood as bare strings once in the reading
    /// and once in the writing. Whoever adds a field and forgets one of the
    /// two places compiles cleanly: the value is saved, the default is read,
    /// and in the dashboard the value silently jumps back at the next load.
    /// That is exactly what this test catches.
    async fn every_setting_that_goes_in_comes_back_out(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        let app = router(test_app(pool.clone()));

        let mut set = response_json(get(&app, "/api/settings", &admin).await).await;
        // Away from the defaults, every field to a value of its own. The
        // secrets stay out of it: they deliberately never come back. Likewise
        // what the server merely *reports* and does not accept: `…_set`,
        // whether a secret is on file, and `…_built_in`, whether a value was
        // already fixed at compile time and therefore cannot be stored at
        // all.
        let secrets = ["smtp_pass", "abuseipdb_key", "assist_key"];
        let obj = set.as_object_mut().expect("Einstellungen sind ein Objekt");
        let mut n = 0i64;
        for (k, v) in obj.iter_mut() {
            if secrets.contains(&k.as_str()) || k.ends_with("_set") || k.ends_with("_built_in") || k == "config_generation" {
                continue;
            }
            n += 1;
            match v {
                serde_json::Value::Bool(b) => *b = !*b,
                // Stay within the bounds the validation allows.
                serde_json::Value::Number(_) => *v = json!(match k.as_str() {
                    "learn_days" => 21,
                    "report_interval_secs" => 120,
                    "alert_retain_days" => 365,
                    "count_retain_days" => 14,
                    "abuseipdb_daily_limit" => 500,
                    "assist_daily_limit" => 25,
                    "smtp_port" => 465,
                    "notify_abuse_min_score" => 60,
                    "notify_digest_mins" => 15,
                    "notify_agent_down_mins" => 30,
                    _ => 7,
                }),
                _ => {}
            }
        }
        assert!(n > 20, "der Durchlauf soll die ganze Seite abdecken, nicht drei Felder ({n})");
        // Text fields that have to have a shape.
        set["smtp_host"] = json!("mail.example.com");
        set["smtp_from"] = json!("dlp@example.com");
        set["smtp_to"] = json!("ops@example.com");
        set["smtp_security"] = json!("tls");
        set["notify_base_url"] = json!("https://dlp.example.com");
        set["report_timezone"] = json!("Europe/Zurich");
        set["allow_processes"] = json!("teams.exe");
        set["assist_base_url"] = json!("https://ai.example.com");
        set["assist_model"] = json!("some-model");
        set["smtp_enabled"] = json!(true);
        // The self-lockout guard refuses that as long as this account has no
        // second factor -- that has a test of its own.
        set["require_2fa_admin"] = json!(false);

        let saved = response_json(send(&app, "PUT", "/api/settings", (header::COOKIE.as_str(), &admin), set.clone()).await).await;
        let reloaded = response_json(get(&app, "/api/settings", &admin).await).await;

        for (k, want) in set.as_object().expect("Objekt") {
            if secrets.contains(&k.as_str()) || k.ends_with("_set") || k == "config_generation" {
                continue;
            }
            assert_eq!(&saved[k], want, "{k} kam aus dem Speichern anders zurueck");
            assert_eq!(&reloaded[k], want, "{k} ueberlebt das erneute Laden nicht");
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn the_smtp_password_goes_in_and_never_comes_back_out(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        let app = router(test_app(pool.clone()));
        let put = |body: serde_json::Value| send(&app, "PUT", "/api/settings", (header::COOKIE.as_str(), &admin), body);

        let mut set = response_json(get(&app, "/api/settings", &admin).await).await;
        assert_eq!(set["smtp_enabled"], json!(false), "ab Werk aus: {set}");
        assert_eq!(set["smtp_port"], json!(587));
        assert_eq!(set["smtp_security"], json!("starttls"));
        assert!(set.get("smtp_pass").is_none(), "das Passwortfeld gehoert nicht in die Antwort: {set}");

        set["smtp_enabled"] = json!(true);
        set["smtp_host"] = json!("  smtp.example.com  ");
        set["smtp_from"] = json!("dlp@example.com");
        set["smtp_to"] = json!("ops@example.com; duty@example.com");
        set["smtp_pass"] = json!("geheim");
        set["notify_base_url"] = json!("https://dlp.example.com/");
        let back = response_json(put(set.clone()).await).await;
        assert_eq!(back["smtp_host"], json!("smtp.example.com"), "Leerraum faellt weg: {back}");
        assert_eq!(back["smtp_to"], json!("ops@example.com, duty@example.com"), "vereinheitlicht: {back}");
        assert_eq!(back["notify_base_url"], json!("https://dlp.example.com"), "Schraegstrich am Ende faellt weg: {back}");
        assert_eq!(back["smtp_pass_set"], json!(true));
        assert!(back.get("smtp_pass").is_none(), "{back}");

        // Saving with an empty field leaves the password standing — the UI
        // never gets to see it and would otherwise delete it every time.
        set["smtp_pass"] = json!("");
        assert_eq!(response_json(put(set.clone()).await).await["smtp_pass_set"], json!(true));

        // And it stands nowhere in the audit log.
        let audit = response_json(get(&app, "/api/audit", &admin).await).await;
        assert!(!audit.to_string().contains("geheim"), "das Passwort steht im Protokoll: {audit}");

        // A hyphen deletes.
        set["smtp_pass"] = json!("-");
        assert_eq!(response_json(put(set.clone()).await).await["smtp_pass_set"], json!(false));

        // Switched on without recipients, or with a typo in them: no. An
        // error shows up when saving, not only once there is a fire.
        set["smtp_pass"] = json!("");
        for bad in ["", "ops@example.com, kein-mail"] {
            set["smtp_to"] = json!(bad);
            assert_eq!(put(set.clone()).await.status(), StatusCode::BAD_REQUEST, "{bad:?}");
        }
        set["smtp_to"] = json!("ops@example.com");
        set["smtp_from"] = json!("kein-mail");
        assert_eq!(put(set.clone()).await.status(), StatusCode::BAD_REQUEST);
        set["smtp_from"] = json!("dlp@example.com");
        set["notify_base_url"] = json!("dlp.example.com");
        assert_eq!(put(set.clone()).await.status(), StatusCode::BAD_REQUEST, "ein Verweis ohne Schema ist ein toter Verweis");
        set["notify_base_url"] = json!("");
        set["notify_digest_mins"] = json!(0);
        assert_eq!(put(set.clone()).await.status(), StatusCode::BAD_REQUEST);

        // Switched off, the form may be saved half filled in.
        set["notify_digest_mins"] = json!(5);
        set["smtp_enabled"] = json!(false);
        set["smtp_host"] = json!("");
        assert_eq!(put(set).await.status(), StatusCode::OK);
    }

    /// A rollout token: weeks instead of the one day a single machine needs,
    /// and no count unless one is given. Still usable after a thousand enrollments — including for
    /// fetching the installer, which is the first line of the command.
    #[sqlx::test(migrations = "./migrations")]
    async fn a_rollout_token_lasts_weeks_and_serves_many_devices(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        let st = test_app(pool.clone());
        let app = router(st.clone());
        let cookie = (header::COOKIE.as_str(), admin.as_str());
        let created = response_json(send(&app, "POST", "/api/tokens", cookie, json!({ "label": "rollout", "hours": 24 * 7 * 8 })).await).await;
        let expires: chrono::DateTime<chrono::Utc> = created["expires_at"].as_str().unwrap().parse().unwrap();
        let weeks = (expires - chrono::Utc::now()).num_days();
        assert!((55..=56).contains(&weeks), "eight weeks, not capped at two: {weeks} days");

        let listed = response_json(get(&app, "/api/tokens", &admin).await).await;
        assert!(listed[0]["max_uses"].is_null() && listed[0]["uses"].as_i64() == Some(0), "no count means unlimited: {listed}");

        // Neither a count nor a lifetime without bounds.
        let silly = response_json(send(&app, "POST", "/api/tokens", cookie, json!({ "label": "x", "hours": 1_000_000, "max_uses": 0 })).await).await;
        let expires: chrono::DateTime<chrono::Utc> = silly["expires_at"].as_str().unwrap().parse().unwrap();
        assert!((expires - chrono::Utc::now()).num_days() <= 365);
        let min: i32 = sqlx::query_scalar("SELECT max_uses FROM enroll_tokens WHERE label = 'x'").fetch_one(&pool).await.unwrap();
        assert_eq!(min, 1);

        sqlx::query("UPDATE enroll_tokens SET uses = 1000, used_at = now() WHERE label = 'rollout'").execute(&pool).await.unwrap();
        let agent = crate::binaries::agent_router().with_state(st);
        let token = created["token"].as_str().unwrap();
        let download = send(&agent, "GET", "/agent/binary/windows", ("x-deelpe-token", token), serde_json::Value::Null).await;
        // No program uploaded in the test: 404 means the token got through.
        assert_eq!(download.status(), StatusCode::NOT_FOUND, "a token without a count still fetches the installer after a thousand devices");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn api_key_reads_only_and_only_while_switched_on(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        let app = router(test_app(pool.clone()));
        let created = response_json(send(&app, "POST", "/api/keys", (header::COOKIE.as_str(), &admin), json!({ "label": "siem", "days": 30 })).await).await;
        let key = created["key"].as_str().unwrap().to_string();
        let id = created["id"].as_str().unwrap().to_string();
        assert!(key.starts_with(auth::API_KEY_PREFIX), "{key}");
        assert!(created["expires_at"].is_string());
        // The plaintext may stand only in the answer to the creation.
        let listed = response_json(get(&app, "/api/keys", &admin).await).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert!(listed[0].get("key").is_none(), "der Schluessel selbst gehoert nicht in die Liste: {listed}");

        let bearer = format!("Bearer {key}");
        let with_key = |path: &'static str| send(&app, "GET", path, ("authorization", &bearer), serde_json::Value::Null);
        // Out of the box access is off: the key is not valid yet.
        assert_eq!(with_key("/api/overview").await.status(), StatusCode::UNAUTHORIZED);

        db::set_setting(&pool, "api_keys_enabled", json!(true)).await.unwrap();
        assert_eq!(with_key("/api/overview").await.status(), StatusCode::OK);
        assert_eq!(with_key("/api/alerts?open=true").await.status(), StatusCode::OK);
        // Reading yes, administration no — and certainly not the keys
        // themselves. `/api/binaries` only demands `User`, not `Admin`:
        // without the path list a key would have downloaded the agent program
        // with it, even though UI and manual promise „read alarms only".
        for path in ["/api/users", "/api/settings", "/api/keys", "/api/audit", "/api/binaries", "/api/binaries/windows"] {
            assert_eq!(with_key(path).await.status(), StatusCode::FORBIDDEN, "{path}");
        }
        assert_eq!(
            send(&app, "POST", "/api/alerts/ack", ("authorization", &bearer), json!({ "all": true })).await.status(),
            StatusCode::FORBIDDEN,
            "ein Schluessel darf nichts schliessen"
        );
        // Used means used: the column carries the evidence.
        let listed = response_json(get(&app, "/api/keys", &admin).await).await;
        assert!(listed[0]["last_used_at"].is_string(), "{listed}");

        let wrong = format!("Bearer {}", auth::new_api_key());
        assert_eq!(send(&app, "GET", "/api/overview", ("authorization", &wrong), serde_json::Value::Null).await.status(), StatusCode::UNAUTHORIZED);

        // Expired does not count, and neither does deleted.
        sqlx::query("UPDATE api_keys SET expires_at = now() - interval '1 hour'").execute(&pool).await.unwrap();
        assert_eq!(with_key("/api/overview").await.status(), StatusCode::UNAUTHORIZED);
        sqlx::query("UPDATE api_keys SET expires_at = NULL").execute(&pool).await.unwrap();
        assert_eq!(with_key("/api/overview").await.status(), StatusCode::OK, "ohne Ablauf gilt er weiter");
        assert_eq!(
            send(&app, "DELETE", &format!("/api/keys/{id}"), (header::COOKIE.as_str(), &admin), serde_json::Value::Null).await.status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(with_key("/api/overview").await.status(), StatusCode::UNAUTHORIZED);
    }

    /// Signing in needs the peer's address for the lockout; in production
    /// the TLS listener puts it in (`tls.rs`), here the test does.
    fn with_peer(app: Router) -> Router {
        app.layer(Extension(PeerAddr("127.0.0.1:4711".parse().unwrap())))
    }

    /// The cookie from a sign-in answer, as the browser sends it back.
    fn cookie_of(r: &Response) -> String {
        r.headers().get(header::SET_COOKIE).expect("Set-Cookie").to_str().unwrap().split(';').next().unwrap().to_string()
    }

    /// The second factor from front to back: password alone, then mandatory
    /// by setting, setup via the account page, sign-in in two steps, a code
    /// is valid once, and the administrator resets it. A factor that can be
    /// bypassed is something nobody notices in day-to-day operation — hence
    /// every door on its own.
    #[sqlx::test(migrations = "./migrations")]
    async fn totp_is_a_second_step_that_can_be_required_and_reset(pool: sqlx::PgPool) {
        let admin = test_session(&pool, "admin").await;
        let uid: Uuid = sqlx::query_scalar("INSERT INTO users (name, pw_hash, role) VALUES ('hans', $1, 'viewer') RETURNING id")
            .bind(auth::hash_password("korrekt-und-lang-genug").unwrap()).fetch_one(&pool).await.unwrap();
        let st = test_app(pool.clone());
        let app = with_peer(router(st.clone()));
        let login = |pw: &'static str| send(&app, "POST", "/api/login", ("x-test", "1"), json!({ "name": "hans", "password": pw }));

        // Without a second factor: the password alone opens the session.
        let r = login("korrekt-und-lang-genug").await;
        assert_eq!(r.status(), StatusCode::OK);
        let cookie = cookie_of(&r);
        assert_eq!(response_json(r).await["second_factor_required"], false);
        assert_eq!(login("falsch").await.status(), StatusCode::UNAUTHORIZED);

        // Mandatory for read-only: the account only gets at itself any more.
        db::set_setting(&pool, "require_2fa_viewer", json!(true)).await.unwrap();
        assert_eq!(response_json(get(&app, "/api/me", &cookie).await).await["second_factor_required"], true);
        assert_eq!(get(&app, "/api/overview", &cookie).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(get(&app, "/api/account", &cookie).await.status(), StatusCode::OK);
        // For administrators the requirement only goes on if whoever saves
        // has a factor themselves — otherwise they lock themselves out.
        let mut settings = response_json(get(&app, "/api/settings", &admin).await).await;
        assert_eq!(send(&app, "PUT", "/api/settings", (header::COOKIE.as_str(), &admin), settings.clone()).await.status(), StatusCode::OK, "Speichern ohne Pflicht geht wie vorher");
        settings["require_2fa_admin"] = json!(true);
        assert_eq!(send(&app, "PUT", "/api/settings", (header::COOKIE.as_str(), &admin), settings).await.status(), StatusCode::BAD_REQUEST);

        // Setup: fetch the secret, compute the code, arm it.
        let setup = response_json(send(&app, "POST", "/api/account/totp", (header::COOKIE.as_str(), &cookie), json!({})).await).await;
        let secret = match st.pending.lock().unwrap().get(&format!("totp-setup:{uid}")).map(|(_, p)| p) {
            Some(crate::state::Pending::TotpSetup(s)) => s.clone(),
            _ => panic!("kein angefangenes Geheimnis"),
        };
        assert_eq!(setup["secret"], auth::base32(&secret));
        assert!(setup["otpauth"].as_str().unwrap().starts_with("otpauth://totp/DLPrevent:hans?"));
        assert!(setup["qr_svg"].as_str().unwrap().contains("<svg"));
        let code = |t: i64| format!("{:06}", auth::totp_code(&secret, t / auth::TOTP_STEP_SECS));
        let enable = |c: String| send(&app, "POST", "/api/account/totp/enable", (header::COOKIE.as_str(), &cookie), json!({ "code": c }));
        assert_eq!(enable("000000".into()).await.status(), StatusCode::BAD_REQUEST);
        // A token from the network does not reach the setup in progress: it
        // has a prefix of its own in the table.
        assert_eq!(send(&app, "POST", "/api/login/totp", ("x-test", "1"), json!({ "token": format!("totp-setup:{uid}"), "code": "000000" })).await.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(enable(code(Utc::now().timestamp())).await.status(), StatusCode::NO_CONTENT, "ein Tippfehler darf die Einrichtung nicht verwerfen");
        assert_eq!(get(&app, "/api/overview", &cookie).await.status(), StatusCode::OK, "eingerichtet: die Pflicht ist erfuellt");
        assert_eq!(response_json(get(&app, "/api/account", &cookie).await).await["totp_enabled"], true);

        // Signing in now takes two steps; the code is valid once.
        let first = response_json(login("korrekt-und-lang-genug").await).await;
        let token = first["totp"].as_str().expect("Aufforderung zum zweiten Schritt").to_string();
        assert!(first.get("id").is_none(), "vor dem Code gibt es kein Konto: {first}");
        let step = |t: &str, c: String| send(&app, "POST", "/api/login/totp", ("x-test", "1"), json!({ "token": t, "code": c }));
        assert_eq!(step(&token, "123456".into()).await.status(), StatusCode::UNAUTHORIZED);
        let now = Utc::now().timestamp() + auth::TOTP_STEP_SECS;
        let r = step(&token, code(now)).await;
        assert_eq!(r.status(), StatusCode::OK, "ein Schritt Uhrenversatz gilt, auch nach einem Tippfehler");
        let second = cookie_of(&r);
        assert_eq!(get(&app, "/api/overview", &second).await.status(), StatusCode::OK);
        assert_eq!(step(&token, code(now)).await.status(), StatusCode::UNAUTHORIZED, "die Kennung ist verbraucht");
        let again = response_json(login("korrekt-und-lang-genug").await).await;
        assert_eq!(step(again["totp"].as_str().unwrap(), code(now)).await.status(), StatusCode::UNAUTHORIZED, "derselbe Code oeffnet keine zweite Sitzung");
        let users = response_json(get(&app, "/api/users", &admin).await).await;
        let hans = users.as_array().unwrap().iter().find(|u| u["name"] == "hans").unwrap();
        assert_eq!(hans["totp_enabled"], true);
        assert_eq!(hans["passkeys"], 0);
        assert!(hans.get("totp_secret").is_none(), "das Geheimnis gehoert nicht in die Liste");

        // Phone gone: the administrator resets, the requirement bites again.
        assert_eq!(send(&app, "DELETE", &format!("/api/users/{uid}/second-factor"), (header::COOKIE.as_str(), &cookie), serde_json::Value::Null).await.status(), StatusCode::FORBIDDEN, "nur Administratoren");
        assert_eq!(send(&app, "DELETE", &format!("/api/users/{uid}/second-factor"), (header::COOKIE.as_str(), &admin), serde_json::Value::Null).await.status(), StatusCode::NO_CONTENT);
        assert_eq!(get(&app, "/api/overview", &second).await.status(), StatusCode::UNAUTHORIZED, "das verlorene Geraet bleibt nicht angemeldet");
        let r = login("korrekt-und-lang-genug").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(r.headers().contains_key(header::SET_COOKIE), "ohne Faktor wieder in einem Schritt");
        // The requirement bites again — but your own password still works.
        let third = cookie_of(&r);
        assert_eq!(get(&app, "/api/overview", &third).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            send(&app, "POST", &format!("/api/users/{uid}/password"), (header::COOKIE.as_str(), &third), json!({ "password": "neues-langes-passwort", "old_password": "korrekt-und-lang-genug" })).await.status(),
            StatusCode::NO_CONTENT
        );
        // Passkeys only, requirement on: the password alone opens nothing any
        // more, the answer sends the browser down the passkey route.
        sqlx::query("INSERT INTO passkeys (user_id, label, credential) VALUES ($1, 'x', '{}')").bind(uid).execute(&pool).await.unwrap();
        let r = login("neues-langes-passwort").await;
        assert_eq!(r.status(), StatusCode::OK);
        assert!(!r.headers().contains_key(header::SET_COOKIE));
        assert_eq!(response_json(r).await["passkey"], true);
        db::set_setting(&pool, "require_2fa_viewer", json!(false)).await.unwrap();
        assert!(login("neues-langes-passwort").await.headers().contains_key(header::SET_COOKIE), "ohne Pflicht ist der Passkey Bequemlichkeit, kein Zwang");
    }

    /// Passkeys without a browser: what can be checked is the frame — the
    /// challenge carries the name from the Host header, an IP does not work,
    /// adding one demands the password, and an unknown name gets the same
    /// answer as an account without keys. The signature check itself is
    /// webauthn-rs's business.
    #[sqlx::test(migrations = "./migrations")]
    async fn passkeys_are_bound_to_the_host_name_and_do_not_reveal_accounts(pool: sqlx::PgPool) {
        let uid: Uuid = sqlx::query_scalar("INSERT INTO users (name, pw_hash, role) VALUES ('hans', $1, 'viewer') RETURNING id")
            .bind(auth::hash_password("korrekt-und-lang-genug").unwrap()).fetch_one(&pool).await.unwrap();
        let app = with_peer(router(test_app(pool.clone())));
        let r = send(&app, "POST", "/api/login", ("x-test", "1"), json!({ "name": "hans", "password": "korrekt-und-lang-genug" })).await;
        let cookie = cookie_of(&r);
        let (app_ref, cookie_ref) = (&app, cookie.as_str());
        let start = move |host: &'static str, pw: &'static str| async move {
            send_h(app_ref, "POST", "/api/account/passkeys", &[(header::COOKIE.as_str(), cookie_ref), ("host", host)], json!({ "password": pw })).await
        };
        assert_eq!(start("localhost:8443", "falsch").await.status(), StatusCode::FORBIDDEN, "ein Passkey ist ein Dauerzugang: das Passwort muss mit");
        assert_eq!(start("10.0.0.1:8443", "korrekt-und-lang-genug").await.status(), StatusCode::BAD_REQUEST, "WebAuthn kennt keine IP-Adressen");
        let options = response_json(start("localhost:8443", "korrekt-und-lang-genug").await).await;
        assert_eq!(options["publicKey"]["rp"]["id"], "localhost");
        assert_eq!(options["publicKey"]["user"]["name"], "hans");
        assert_eq!(options["publicKey"]["authenticatorSelection"]["userVerification"], "required");
        assert!(options["publicKey"]["challenge"].as_str().unwrap().len() >= 32);
        let garbage = json!({ "label": "Telefon", "credential": { "id": "AAAA", "rawId": "AAAA", "type": "public-key",
            "response": { "attestationObject": "AAAA", "clientDataJSON": "AAAA" } } });
        let r = send_h(&app, "POST", "/api/account/passkeys/finish", &[(header::COOKIE.as_str(), &cookie), ("host", "localhost:8443")], garbage).await;
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response_json(get(&app, "/api/account", &cookie).await).await["passkeys"].as_array().unwrap().len(), 0);
        let users_row: (i64,) = sqlx::query_as("SELECT count(*) FROM passkeys WHERE user_id = $1").bind(uid).fetch_one(&pool).await.unwrap();
        assert_eq!(users_row.0, 0);

        // Sign-in: a name without keys and a name that does not exist get
        // back the same shape — namely that of a real challenge (32 bytes of
        // base64url are 43 characters).
        let mut shapes = Vec::new();
        for name in ["hans", "niemand"] {
            let r = send_h(&app, "POST", "/api/login/passkey", &[("host", "localhost:8443")], json!({ "name": name })).await;
            let v = response_json(r).await;
            let pk = &v["publicKey"];
            assert_eq!(pk["rpId"], "localhost", "{name}");
            assert_eq!(pk["userVerification"], "required");
            assert_eq!(pk["challenge"].as_str().unwrap().len(), options["publicKey"]["challenge"].as_str().unwrap().len(), "{name}: so lang wie eine echte");
            shapes.push((pk["allowCredentials"].as_array().unwrap().len(), pk["challenge"].as_str().unwrap().len()));
            let finish = json!({ "name": name, "credential": { "id": "AAAA", "rawId": "AAAA", "type": "public-key",
                "response": { "authenticatorData": "AAAA", "clientDataJSON": "AAAA", "signature": "AAAA", "userHandle": null } } });
            let r = send_h(&app, "POST", "/api/login/passkey/finish", &[("host", "localhost:8443")], finish).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{name}");
            assert!(!r.headers().contains_key(header::SET_COOKIE));
        }
        assert_eq!(shapes[0], shapes[1], "hans (kein Schluessel) und niemand (kein Konto) muessen gleich aussehen");
        assert_eq!(send_h(&app, "POST", "/api/login/passkey", &[("host", "10.0.0.1")], json!({ "name": "hans" })).await.status(), StatusCode::BAD_REQUEST);
    }

    /// Every writing route checks `Admin`. Reads the sources under
    /// `src/api` at run time: a new module is thereby checked along with the
    /// rest by itself, instead of being forgotten in an `include_str!` list.
    #[test]
    fn every_mutating_route_requires_admin() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/api");
        let src: String = std::fs::read_dir(&dir).expect("src/api").filter_map(|e| std::fs::read_to_string(e.ok()?.path()).ok()).collect();
        // Signing in, signing out, your own password and your own second
        // factor check for themselves.
        const SELF_SERVICE: [&str; 12] = [
            "login", "login_totp", "passkey_login_start", "passkey_login_finish", "logout", "set_password",
            "totp_start", "totp_enable", "totp_disable", "passkey_start", "passkey_finish", "delete_passkey",
        ];
        let routes = src.split("pub fn router").nth(1).expect("router()").split("\n}").next().unwrap();
        let mut seen = 0;
        for verb in ["post(", "put(", "delete("] {
            for part in routes.split(verb).skip(1) {
                let handler = part.split(')').next().unwrap().trim().rsplit("::").next().unwrap();
                if SELF_SERVICE.contains(&handler) {
                    continue;
                }
                let sig = src.split(&format!("async fn {handler}(")).nth(1).unwrap_or_else(|| panic!("{handler} nicht gefunden"));
                let sig = sig.split('{').next().unwrap();
                assert!(sig.contains("Admin"), "schreibende Route {handler} ohne Admin-Prüfung");
                seen += 1;
            }
        }
        assert!(seen >= 12, "Routen nicht gefunden, Test greift ins Leere ({seen})");
    }

    #[test]
    fn terms_are_split_and_escaped() {
        assert!(search_terms(None).is_empty());
        assert!(search_terms(Some("   ")).is_empty());
        assert_eq!(search_terms(Some("Hans GL")), vec!["%hans%", "%gl%"]);
        assert_eq!(search_terms(Some("100%_x")), vec!["%100\\%\\_x%"]);
        assert_eq!(search_terms(Some("a b c d e f g h i j")).len(), 8);
    }
}
