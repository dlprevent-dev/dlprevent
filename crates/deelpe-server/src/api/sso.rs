//! Single sign-on over OpenID Connect: Microsoft Entra ID, Okta, Keycloak,
//! Authentik, ADFS — anything with a discovery document.
//!
//! Authorization code flow with PKCE. The ID token comes straight from the
//! provider's token endpoint over TLS, which OpenID Connect Core (3.1.3.7)
//! accepts in place of checking its signature; issuer, audience, expiry and
//! nonce are checked all the same.
//!
//! Accounts from the provider are marked `external`: their second factor is
//! the provider's, and a provider sign-in **never** takes over a local
//! account of the same name. An account is bound to the provider's stable
//! subject (`sub`), not to the user name, which can change and be handed on.
//! The sign-in is bound to the browser that started it (a cookie carrying
//! `state`), so nobody can finish their own sign-in in someone else's
//! browser. The role follows the provider's groups on
//! every sign-in, so taking someone out of the admin group takes effect at
//! their next sign-in.

use anyhow::{anyhow, bail, Context, Result};
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crate::auth::{self, bad, Admin, ApiError};
use crate::db::{self, Actor};
use crate::state::Shared;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// The configuration, one JSON object in `settings`.
const SETTING: &str = "sso";

/// How long a sign-in may take at the provider.
const PENDING_FOR: Duration = Duration::from_secs(600);

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
struct Config {
    /// E.g. `https://login.microsoftonline.com/<tenant>/v2.0`.
    pub issuer: String,
    pub client_id: String,
    /// Never leaves the server again; empty on saving keeps the stored one.
    #[serde(default, skip_serializing)]
    pub client_secret: String,
    /// `post` (in the body) or `basic` (HTTP Basic).
    #[serde(default = "d_post")]
    pub auth_method: String,
    /// Claim that becomes the user name.
    #[serde(default = "d_username")]
    pub username_claim: String,
    #[serde(default = "d_groups")]
    pub groups_claim: String,
    /// Members become administrators. Empty: nobody does through SSO.
    #[serde(default)]
    pub admin_group: String,
    /// Only members may sign in (as read-only). Empty: everyone the
    /// provider lets through.
    #[serde(default)]
    pub viewer_group: String,
    /// Create the account on its first sign-in.
    #[serde(default = "d_true")]
    pub auto_create: bool,
    /// The provider's CA (PEM) when it uses a certificate from its own CA,
    /// as an on-premises Keycloak or ADFS often does; trusted on top of the
    /// system's roots, for the provider only.
    #[serde(default)]
    pub ca_pem: String,
}

fn d_post() -> String {
    "post".into()
}
fn d_username() -> String {
    "preferred_username".into()
}
fn d_groups() -> String {
    "groups".into()
}
fn d_true() -> bool {
    true
}

async fn config(pool: &PgPool) -> Result<Option<Config>> {
    let v: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1").bind(SETTING).fetch_optional(pool).await?;
    Ok(match v {
        // The secret is skipped when serialising, so it is read by hand.
        Some((v,)) => {
            let mut c: Config = serde_json::from_value(v.clone())?;
            c.client_secret = v["client_secret"].as_str().unwrap_or_default().to_string();
            Some(c)
        }
        None => None,
    })
}

async fn store(pool: &PgPool, c: &Config) -> Result<()> {
    let mut v = serde_json::to_value(c)?;
    v["client_secret"] = json!(c.client_secret);
    sqlx::query("INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value").bind(SETTING).bind(v).execute(pool).await?;
    Ok(())
}

// --- The pure parts ----------------------------------------------------

/// PKCE S256 (RFC 7636).
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn same_issuer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// The payload of a JWT, unverified (see the module comment for why that
/// is enough here).
fn claims(id_token: &str) -> Result<Value> {
    let payload = id_token.split('.').nth(1).context("id_token is not a JWT")?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).context("id_token payload is not base64url")?)?)
}

/// OpenID Connect Core 3.1.3.7: issuer, audience, expiry, nonce.
fn check_claims(c: &Value, issuer: &str, client_id: &str, nonce: &str, now: i64) -> Result<()> {
    if !c["iss"].as_str().is_some_and(|i| same_issuer(i, issuer)) {
        bail!("token from another issuer: {}", c["iss"]);
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == client_id,
        Value::Array(a) => a.iter().any(|x| x == client_id),
        _ => false,
    };
    if !aud_ok {
        bail!("token for another application: {}", c["aud"]);
    }
    // A minute's grace for clocks that differ.
    if !c["exp"].as_i64().is_some_and(|e| e + 60 > now) {
        bail!("token expired");
    }
    if c["nonce"].as_str() != Some(nonce) {
        bail!("nonce does not match: the answer does not belong to this sign-in");
    }
    Ok(())
}

/// Groups from a claim that may be a list or a single string.
fn groups(c: &Value, claim: &str) -> Vec<String> {
    match &c[claim] {
        Value::Array(a) => a.iter().filter_map(|g| g.as_str().map(str::to_string)).collect(),
        Value::String(s) => vec![s.clone()],
        _ => vec![],
    }
}

/// `admin`, `viewer`, or none: not allowed in.
fn role_for(groups: &[String], cfg: &Config) -> Option<&'static str> {
    let member = |g: &str| !g.is_empty() && groups.iter().any(|x| x == g);
    if member(&cfg.admin_group) {
        Some("admin")
    } else if cfg.viewer_group.is_empty() || member(&cfg.viewer_group) {
        Some("viewer")
    } else {
        None
    }
}

// --- The flow ----------------------------------------------------------

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

async fn discover(http: &reqwest::Client, issuer: &str) -> Result<Discovery> {
    let url = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let d: Discovery = http.get(&url).send().await?.error_for_status()?.json().await.with_context(|| format!("discovery at {url}"))?;
    if !same_issuer(&d.issuer, issuer) {
        bail!("the discovery document names another issuer: {}", d.issuer);
    }
    Ok(d)
}

fn client(ca_pem: &str) -> Result<reqwest::Client> {
    let b = reqwest::Client::builder().timeout(Duration::from_secs(15));
    let b = if ca_pem.trim().is_empty() { b } else { b.tls_certs_merge([reqwest::Certificate::from_pem(ca_pem.as_bytes()).context("the provider's CA certificate is not PEM")?]) };
    Ok(b.build()?)
}

/// A sign-in on its way through the provider, keyed by `state`.
struct Pending {
    at: Instant,
    verifier: String,
    nonce: String,
    redirect_uri: String,
}

static PENDING: Mutex<Option<HashMap<String, Pending>>> = Mutex::new(None);

fn remember(state: String, p: Pending) {
    let mut g = PENDING.lock().unwrap();
    let m = g.get_or_insert_with(HashMap::new);
    m.retain(|_, v| v.at.elapsed() < PENDING_FOR);
    m.insert(state, p);
}

fn take(state: &str) -> Option<Pending> {
    PENDING.lock().unwrap().as_mut()?.remove(state).filter(|p| p.at.elapsed() < PENDING_FOR)
}

/// Code for the ID token, and the account it stands for: found, created,
/// or refused. Returns the account's id and name.
async fn finish(pool: &PgPool, http: &reqwest::Client, cfg: &Config, code: &str, verifier: &str, nonce: &str, redirect_uri: &str) -> Result<(Uuid, String, &'static str)> {
    let d = discover(http, &cfg.issuer).await?;
    let mut form = vec![("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirect_uri), ("code_verifier", verifier)];
    let req = http.post(&d.token_endpoint);
    let req = if cfg.auth_method == "basic" {
        req.basic_auth(&cfg.client_id, Some(&cfg.client_secret))
    } else {
        form.push(("client_id", &cfg.client_id));
        form.push(("client_secret", &cfg.client_secret));
        req
    };
    let resp = req.form(&form).send().await.context("token endpoint")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("token endpoint answered {status}: {}", body.chars().take(300).collect::<String>());
    }
    let tokens: Value = resp.json().await.context("token endpoint answer")?;
    let id_token = tokens["id_token"].as_str().context("no id_token in the answer (is the scope openid missing?)")?;
    let c = claims(id_token)?;
    check_claims(&c, &d.issuer, &cfg.client_id, nonce, chrono::Utc::now().timestamp())?;

    let name = c[cfg.username_claim.as_str()].as_str().filter(|s| !s.trim().is_empty()).with_context(|| format!("the token has no claim '{}'", cfg.username_claim))?.trim().to_string();
    let subject = c["sub"].as_str().filter(|s| !s.is_empty()).context("the token has no subject (sub)")?;
    let role = role_for(&groups(&c, &cfg.groups_claim), cfg).ok_or_else(|| anyhow!("{name} is not in a group that may sign in"))?;
    account(pool, &d.issuer, subject, &name, role, cfg.auto_create).await.map(|(id, name)| (id, name, role))
}

/// The account for a provider identity: the one bound to its subject, or
/// an unbound external account of that name (bound now), or a new one.
async fn account(pool: &PgPool, issuer: &str, subject: &str, name: &str, role: &str, auto_create: bool) -> Result<(Uuid, String)> {
    let mut tx = pool.begin().await?;
    let bound: Option<(Uuid, String, bool)> = sqlx::query_as("SELECT u.id, u.name, u.disabled FROM sso_identities i JOIN users u ON u.id = i.user_id WHERE i.issuer = $1 AND i.subject = $2")
        .bind(issuer)
        .bind(subject)
        .fetch_optional(&mut *tx)
        .await?;
    let (id, name) = match bound {
        Some((_, name, true)) => bail!("the account {name} is disabled"),
        Some((id, name, false)) => (id, name),
        None => {
            let row: Option<(Uuid, bool, bool, bool)> = sqlx::query_as(
                "SELECT u.id, u.external, u.disabled, EXISTS (SELECT 1 FROM sso_identities i WHERE i.user_id = u.id) FROM users u WHERE u.name = $1",
            )
            .bind(name)
            .fetch_optional(&mut *tx)
            .await?;
            let id = match row {
                Some((_, false, _, _)) => bail!("a local account named {name} exists; single sign-on does not take it over"),
                Some((_, true, _, true)) => bail!("the account {name} belongs to another identity at the provider"),
                Some((_, true, true, false)) => bail!("the account {name} is disabled"),
                Some((id, true, false, false)) => id,
                None if auto_create => {
                    // A password nobody knows: this account signs in through the provider.
                    let hash = auth::hash_password(&auth::random_token())?;
                    let id: Uuid = sqlx::query_scalar("INSERT INTO users (name, pw_hash, role, external) VALUES ($1, $2, $3, true) RETURNING id")
                        .bind(name)
                        .bind(hash)
                        .bind(role)
                        .fetch_one(&mut *tx)
                        .await?;
                    db::audit(pool, Actor::SYSTEM, "user_create", json!({ "name": name, "role": role, "via": "sso" })).await;
                    id
                }
                None => bail!("{name} has no account here, and accounts are not created on sign-in"),
            };
            sqlx::query("INSERT INTO sso_identities (issuer, subject, user_id) VALUES ($1, $2, $3)").bind(issuer).bind(subject).bind(id).execute(&mut *tx).await?;
            (id, name.to_string())
        }
    };
    sqlx::query("UPDATE users SET role = $2 WHERE id = $1").bind(id).bind(role).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok((id, name))
}

/// The cookie that binds a sign-in to the browser that started it. Lax:
/// the provider's redirect back is a cross-site top-level navigation.
const STATE_COOKIE: &str = "deelpe_sso";

/// Where the provider sends the browser back; registered there.
const CALLBACK: &str = "/api/sso/callback";

fn state_cookie(value: &str, max_age: u32, secure: bool) -> String {
    format!("{STATE_COOKIE}={value}; Path={CALLBACK}; HttpOnly; SameSite=Lax; Max-Age={max_age}{}", if secure { "; Secure" } else { "" })
}

/// The `state` this browser started with, from its cookie.
fn started_state(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == STATE_COOKIE)
        .map(|(_, v)| v.to_string())
}

fn redirect_uri(st: &Shared, headers: &HeaderMap) -> Result<String, ApiError> {
    let host = st.public_host(headers).ok_or_else(|| bad("no host name in the request"))?;
    Ok(format!("{}://{host}{CALLBACK}", if st.public_https() { "https" } else { "http" }))
}

/// A page instead of JSON: the browser lands here from the provider.
fn page(status: StatusCode, msg: &str) -> Response {
    let esc = msg.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    (status, Html(format!("<!doctype html><meta charset=\"utf-8\"><title>DLPrevent sign-in</title><p>Single sign-on failed: {esc}</p><p><a href=\"/\">Back to sign-in</a></p>"))).into_response()
}

fn redirect(to: &str) -> Response {
    (StatusCode::FOUND, [(header::LOCATION, to.to_string())]).into_response()
}

async fn usable(pool: &PgPool) -> Result<Option<Config>> {
    Ok(config(pool).await?.filter(|c| !c.issuer.is_empty() && !c.client_id.is_empty()))
}

/// For the login page: offer the button or not. Public.
pub(super) async fn available(State(st): State<Shared>) -> Result<Json<Value>, ApiError> {
    Ok(Json(json!({ "enabled": usable(&st.pool).await?.is_some() })))
}

/// Off to the provider. Public.
pub(super) async fn start(State(st): State<Shared>, headers: HeaderMap) -> Response {
    let run = async {
        let cfg = usable(&st.pool).await?.context("single sign-on is not set up")?;
        let d = discover(&client(&cfg.ca_pem)?, &cfg.issuer).await?;
        let redirect_uri = redirect_uri(&st, &headers).map_err(|e| anyhow!(e.1))?;
        let (state, nonce, verifier) = (auth::random_token(), auth::random_token(), auth::random_token());
        let url = reqwest::Url::parse_with_params(
            &d.authorization_endpoint,
            &[
                ("response_type", "code"),
                ("client_id", cfg.client_id.as_str()),
                ("redirect_uri", redirect_uri.as_str()),
                ("scope", "openid profile email"),
                ("state", state.as_str()),
                ("nonce", nonce.as_str()),
                ("code_challenge", challenge(&verifier).as_str()),
                ("code_challenge_method", "S256"),
            ],
        )?;
        let cookie = state_cookie(&state, PENDING_FOR.as_secs() as u32, st.public_https());
        remember(state, Pending { at: Instant::now(), verifier, nonce, redirect_uri });
        anyhow::Ok((url.to_string(), cookie))
    };
    match run.await {
        Ok((url, cookie)) => {
            let mut r = redirect(&url);
            r.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
            r
        }
        Err(e) => page(StatusCode::SERVICE_UNAVAILABLE, &format!("{e:#}")),
    }
}

#[derive(Deserialize)]
pub(super) struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

/// Back from the provider. Public.
pub(super) async fn callback(State(st): State<Shared>, headers: HeaderMap, Query(q): Query<Callback>) -> Response {
    if let Some(e) = q.error {
        return page(StatusCode::UNAUTHORIZED, &format!("{e}: {}", q.error_description.unwrap_or_default()));
    }
    if q.state.is_none() || started_state(&headers) != q.state {
        return page(StatusCode::BAD_REQUEST, "this sign-in was started in another browser; start it again here");
    }
    let Some(p) = q.state.as_deref().and_then(take) else {
        return page(StatusCode::BAD_REQUEST, "unknown or expired sign-in, start again");
    };
    let run = async {
        let cfg = usable(&st.pool).await?.context("single sign-on is not set up")?;
        let code = q.code.as_deref().context("no code in the answer")?;
        let (id, name, role) = finish(&st.pool, &client(&cfg.ca_pem)?, &cfg, code, &p.verifier, &p.nonce, &p.redirect_uri).await?;
        let sid = auth::new_session(&st.pool, id).await?;
        db::audit(&st.pool, Actor { id: Some(id), name: &name }, "login", json!({ "method": "sso", "role": role })).await;
        anyhow::Ok(sid)
    };
    match run.await {
        Ok(sid) => {
            let mut r = redirect("/");
            r.headers_mut().append(header::SET_COOKIE, auth::session_cookie(&sid, st.public_https()).parse().unwrap());
            r.headers_mut().append(header::SET_COOKIE, state_cookie("", 0, st.public_https()).parse().unwrap());
            r
        }
        Err(e) => {
            db::audit(&st.pool, Actor::SYSTEM, "login_failed", json!({ "method": "sso", "reason": format!("{e:#}") })).await;
            page(StatusCode::FORBIDDEN, &format!("{e:#}"))
        }
    }
}

#[derive(Serialize)]
pub(super) struct View {
    #[serde(flatten)]
    config: Config,
    secret_set: bool,
    /// What to register at the provider.
    redirect_uri: String,
}

pub(super) async fn get(State(st): State<Shared>, _a: Admin, headers: HeaderMap) -> Result<Json<View>, ApiError> {
    let c = config(&st.pool).await?.unwrap_or(Config { auth_method: d_post(), username_claim: d_username(), groups_claim: d_groups(), auto_create: true, ..Default::default() });
    Ok(Json(View { secret_set: !c.client_secret.is_empty(), redirect_uri: redirect_uri(&st, &headers)?, config: c }))
}

/// The secret comes in under its own name: `Config` never serialises it.
#[derive(Deserialize)]
pub(super) struct Save {
    #[serde(flatten)]
    config: Config,
    #[serde(default)]
    secret: String,
}

pub(super) async fn put(State(st): State<Shared>, Admin(u): Admin, headers: HeaderMap, Json(b): Json<Save>) -> Result<Json<View>, ApiError> {
    let mut c = b.config;
    c.issuer = c.issuer.trim().trim_end_matches('/').to_string();
    c.client_id = c.client_id.trim().to_string();
    if !c.issuer.is_empty() && !c.issuer.starts_with("https://") {
        return Err(bad("the issuer must be an https:// URL"));
    }
    if !matches!(c.auth_method.as_str(), "post" | "basic") {
        return Err(bad("client authentication: post or basic"));
    }
    c.ca_pem = c.ca_pem.trim().to_string();
    if !c.ca_pem.is_empty() && reqwest::Certificate::from_pem(c.ca_pem.as_bytes()).is_err() {
        return Err(bad("the provider's CA certificate is not PEM"));
    }
    c.client_secret = match b.secret.trim() {
        "" => config(&st.pool).await?.map(|o| o.client_secret).unwrap_or_default(),
        "-" => String::new(),
        s => s.to_string(),
    };
    store(&st.pool, &c).await?;
    db::audit(&st.pool, Actor { id: Some(u.id), name: &u.name }, "sso_update", json!({ "issuer": c.issuer, "client_id": c.client_id, "admin_group": c.admin_group, "viewer_group": c.viewer_group })).await;
    get(State(st), Admin(u), headers).await
}

/// Is the issuer reachable and does its discovery document fit?
pub(super) async fn test(State(st): State<Shared>, _a: Admin) -> Result<Json<Value>, ApiError> {
    let cfg = config(&st.pool).await?.ok_or_else(|| bad("not set up yet"))?;
    let d = discover(&client(&cfg.ca_pem)?, &cfg.issuer).await.map_err(|e| bad(format!("{e:#}")))?;
    Ok(Json(json!({ "ok": true, "authorization_endpoint": d.authorization_endpoint, "token_endpoint": d.token_endpoint })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636, appendix B.
    #[test]
    fn pkce_matches_the_rfc_example() {
        assert_eq!(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    fn good() -> Value {
        json!({ "iss": "https://idp.example.ch/realms/x", "aud": "dlp", "exp": 2_000_000_000i64, "nonce": "n1" })
    }

    #[test]
    fn claims_are_checked_for_issuer_audience_expiry_and_nonce() {
        let ok = |c: &Value| check_claims(c, "https://idp.example.ch/realms/x/", "dlp", "n1", 1_900_000_000);
        assert!(ok(&good()).is_ok(), "a trailing slash is the same issuer");
        let mut c = good();
        c["aud"] = json!(["other", "dlp"]);
        assert!(ok(&c).is_ok(), "audience as a list");
        for (k, v) in [("iss", json!("https://evil.example")), ("aud", json!("other")), ("exp", json!(1_800_000_000i64)), ("nonce", json!("n2"))] {
            let mut c = good();
            c[k] = v;
            assert!(ok(&c).is_err(), "{k}");
        }
        let mut c = good();
        c.as_object_mut().unwrap().remove("nonce");
        assert!(ok(&c).is_err(), "no nonce");
    }

    #[test]
    fn the_payload_of_a_jwt_is_read() {
        let t = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", URL_SAFE_NO_PAD.encode(br#"{"sub":"1","preferred_username":"anna"}"#));
        assert_eq!(claims(&t).unwrap()["preferred_username"], "anna");
        assert!(claims("nojwt").is_err());
    }

    #[test]
    fn the_state_comes_back_only_from_the_browser_that_started() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "deelpe_session=x; deelpe_sso=abc123".parse().unwrap());
        assert_eq!(started_state(&h).as_deref(), Some("abc123"));
        assert_eq!(started_state(&HeaderMap::new()), None);
        assert!(state_cookie("abc", 600, true).contains("SameSite=Lax") && state_cookie("abc", 600, true).ends_with("Secure"));
    }

    #[test]
    fn groups_decide_the_role_and_who_may_sign_in() {
        let cfg = Config { admin_group: "dlp-admins".into(), viewer_group: "dlp-users".into(), ..Default::default() };
        let g = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(role_for(&g(&["dlp-admins"]), &cfg), Some("admin"));
        assert_eq!(role_for(&g(&["dlp-users", "x"]), &cfg), Some("viewer"));
        assert_eq!(role_for(&g(&["x"]), &cfg), None, "not in a group that may sign in");
        let open = Config { admin_group: "dlp-admins".into(), ..Default::default() };
        assert_eq!(role_for(&g(&[]), &open), Some("viewer"), "no viewer group: everyone the provider lets through");
        assert_eq!(role_for(&g(&[""]), &Config::default()), Some("viewer"), "an empty admin group makes nobody admin");
        assert_eq!(groups(&json!({ "roles": "a" }), "roles"), vec!["a"]);
    }

    /// A stand-in identity provider on localhost: discovery and a token
    /// endpoint that hands out whatever claims the test puts in `next`.
    async fn provider() -> (String, std::sync::Arc<Mutex<Value>>) {
        use axum::extract::Form;
        use axum::routing::{get, post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let next = std::sync::Arc::new(Mutex::new(json!({})));
        let disco = json!({ "issuer": base, "authorization_endpoint": format!("{base}/auth"), "token_endpoint": format!("{base}/token") });
        let app = axum::Router::new()
            .route("/.well-known/openid-configuration", get(move || async move { Json(disco) }))
            .route(
                "/token",
                post(|State(next): State<std::sync::Arc<Mutex<Value>>>, Form(f): Form<HashMap<String, String>>| async move {
                    // The code, the PKCE verifier and the secret must all arrive.
                    if f.get("code").map(String::as_str) != Some("c1") || f.get("code_verifier").map(String::as_str) != Some("v1") || f.get("client_secret").map(String::as_str) != Some("s3cret") {
                        return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid_grant" })));
                    }
                    let claims = next.lock().unwrap().clone();
                    let jwt = format!("eyJhbGciOiJSUzI1NiJ9.{}.sig", URL_SAFE_NO_PAD.encode(claims.to_string()));
                    (StatusCode::OK, Json(json!({ "id_token": jwt, "access_token": "x" })))
                }),
            )
            .with_state(next.clone());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, next)
    }

    fn claims_as(iss: &str, sub: &str, user: &str, groups: &[&str]) -> Value {
        json!({ "iss": iss, "aud": "dlp", "exp": chrono::Utc::now().timestamp() + 300, "nonce": "n1", "sub": sub, "preferred_username": user, "groups": groups })
    }

    fn claims_of(iss: &str, user: &str, groups: &[&str]) -> Value {
        claims_as(iss, &format!("sub-{user}"), user, groups)
    }

    /// Needs `DATABASE_URL` like the other database tests.
    #[sqlx::test(migrations = "./migrations")]
    async fn provider_accounts_are_created_follow_their_groups_and_never_take_over_local_ones(pool: PgPool) {
        rustls::crypto::ring::default_provider().install_default().ok();
        let (iss, next) = provider().await;
        let http = client("").unwrap();
        let cfg = Config {
            issuer: iss.clone(),
            client_id: "dlp".into(),
            client_secret: "s3cret".into(),
            auth_method: "post".into(),
            username_claim: "preferred_username".into(),
            groups_claim: "groups".into(),
            admin_group: "dlp-admins".into(),
            viewer_group: "dlp-users".into(),
            auto_create: true,
            ca_pem: String::new(),
        };
        let run = |nonce: &'static str| {
            let (pool, http, cfg) = (pool.clone(), http.clone(), cfg.clone());
            async move { finish(&pool, &http, &cfg, "c1", "v1", nonce, "https://dlp.example.ch/api/sso/callback").await }
        };

        *next.lock().unwrap() = claims_of(&iss, "anna", &["dlp-admins"]);
        let (id, name, role) = run("n1").await.unwrap();
        assert_eq!((name.as_str(), role), ("anna", "admin"));
        let (external, stored_role): (bool, String) = sqlx::query_as("SELECT external, role FROM users WHERE id = $1").bind(id).fetch_one(&pool).await.unwrap();
        assert!(external);
        assert_eq!(stored_role, "admin");

        *next.lock().unwrap() = claims_of(&iss, "anna", &["dlp-users"]);
        let (again, _, role) = run("n1").await.unwrap();
        assert_eq!((again, role), (id, "viewer"), "same account, demoted with the group");

        sqlx::query("INSERT INTO users (name, pw_hash, role) VALUES ('admin', 'x', 'admin')").execute(&pool).await.unwrap();
        *next.lock().unwrap() = claims_of(&iss, "admin", &["dlp-admins"]);
        let err = run("n1").await.unwrap_err().to_string();
        assert!(err.contains("local account"), "{err}");
        let (still_local,): (bool,) = sqlx::query_as("SELECT external FROM users WHERE name = 'admin'").fetch_one(&pool).await.unwrap();
        assert!(!still_local);

        *next.lock().unwrap() = claims_of(&iss, "bob", &["marketing"]);
        assert!(run("n1").await.unwrap_err().to_string().contains("not in a group"));

        *next.lock().unwrap() = claims_of(&iss, "carl", &["dlp-users"]);
        assert!(run("other-nonce").await.unwrap_err().to_string().contains("nonce"), "an answer to another sign-in");

        let wrong_secret = Config { client_secret: "nope".into(), ..cfg.clone() };
        assert!(finish(&pool, &http, &wrong_secret, "c1", "v1", "n1", "x").await.is_err());

        // The name moves at the provider: the subject keeps the account.
        *next.lock().unwrap() = claims_as(&iss, "sub-anna", "anna.muster", &["dlp-users"]);
        let (same, name, _) = run("n1").await.unwrap();
        assert_eq!((same, name.as_str()), (id, "anna"), "bound to sub, not to the name");

        // Someone else gets the name "anna" at the provider: not her account.
        *next.lock().unwrap() = claims_as(&iss, "sub-bob", "anna", &["dlp-admins"]);
        assert!(run("n1").await.unwrap_err().to_string().contains("another identity"));

        let no_create = Config { auto_create: false, ..cfg.clone() };
        *next.lock().unwrap() = claims_of(&iss, "dora", &["dlp-users"]);
        assert!(finish(&pool, &http, &no_create, "c1", "v1", "n1", "x").await.unwrap_err().to_string().contains("no account"));
    }
}
