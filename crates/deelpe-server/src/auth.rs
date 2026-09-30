//! Sign-in: Argon2 hashes, session cookie, roles. Extractors for handlers:
//! [`User`] (signed in) and [`Admin`] (role admin).

use crate::state::Shared;
use anyhow::{anyhow, Result};
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use argon2::Argon2;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::Serialize;
use uuid::Uuid;
use webauthn_rs::prelude::{Url, Webauthn, WebauthnBuilder};

pub const COOKIE: &str = "deelpe_session";
/// Session without activity; every request extends it.
pub const SESSION_HOURS: i64 = 12;

pub fn hash_password(pw: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(pw.as_bytes())
        .map_err(|e| anyhow!("{e}"))?
        .to_string())
}

pub fn verify_password(pw: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(h) => Argon2::default().verify_password(pw.as_bytes(), &h).is_ok(),
        Err(_) => false,
    }
}

pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex(s: &str) -> String {
    crate::pki::fingerprint(s.as_bytes())
}

// ---------- Second factor: TOTP (RFC 6238) ----------

/// Step size and number of digits, the way every authenticator app takes
/// them without asking back. Set differently, some apps refuse the secret.
pub const TOTP_STEP_SECS: i64 = 30;
const TOTP_DIGITS: u32 = 6;

pub fn new_totp_secret() -> Vec<u8> {
    let mut b = vec![0u8; 20];
    rand::fill(&mut b[..]);
    b
}

/// The code for one time step: HOTP (RFC 4226) with the step as the
/// counter, HMAC-SHA1, dynamic truncation.
pub fn totp_code(secret: &[u8], step: i64) -> u32 {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).expect("HMAC nimmt jede Laenge");
    mac.update(&step.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let o = (h[19] & 0x0f) as usize;
    let n = u32::from_be_bytes([h[o] & 0x7f, h[o + 1], h[o + 2], h[o + 3]]);
    n % 10u32.pow(TOTP_DIGITS)
}

/// Checks a typed-in code against the current step and against one step
/// before and one after it (clocks drift apart). Returns the step that was
/// hit, so that the caller holds on to it: the same code does not count a
/// second time afterwards, not even within its 30 seconds.
pub fn totp_verify(secret: &[u8], code: &str, now_unix: i64, used_step: i64) -> Option<i64> {
    let code: u32 = code.trim().replace(' ', "").parse().ok()?;
    let cur = now_unix / TOTP_STEP_SECS;
    (cur - 1..=cur + 1).find(|&s| s > used_step && totp_code(secret, s) == code)
}

/// RFC 4648 without padding characters — that is how the secret stands in
/// the otpauth URL, and that is how it gets typed off when the camera will
/// not cooperate.
pub fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buf, mut bits) = (String::new(), 0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn otpauth_url(user: &str, secret: &[u8]) -> String {
    let label: String = user
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    format!("otpauth://totp/DLPrevent:{label}?secret={}&issuer=DLPrevent&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECS}", base32(secret))
}

/// The secret as a QR image for the authenticator app; only shown during
/// the setup.
pub fn qr_svg(text: &str) -> Result<String> {
    let code = qrcode::QrCode::new(text.as_bytes()).map_err(|e| anyhow!("{e}"))?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(180, 180)
        .quiet_zone(false)
        .build())
}

// ---------- Second factor: passkeys (WebAuthn) ----------

/// The WebAuthn side for this request. The identifier of the relying party
/// (RP ID) and the origin come out of the `Host` header: a passkey is bound
/// to the name under which the browser sees the central server, and only the
/// browser knows that name. A fixed setting would need the same answer and
/// could be wrong; the header is already the yardstick of the origin check.
///
/// Behind a reverse proxy `X-Forwarded-Host` counts (only with
/// `trust_proxy`), and the origin is then `https`, whatever runs between the
/// proxy and the central server — the browser holds only a secure origin to
/// be fit for WebAuthn.
///
/// An IP address does not work: WebAuthn demands a name. The error says so,
/// instead of the browser refusing in silence.
pub fn webauthn(
    state: &crate::state::AppState,
    headers: &axum::http::HeaderMap,
) -> Result<Webauthn, ApiError> {
    let host = state
        .public_host(headers)
        .ok_or_else(|| bad("host header missing"))?;
    let scheme = if state.public_https() {
        "https"
    } else {
        "http"
    };
    let origin =
        Url::parse(&format!("{scheme}://{host}")).map_err(|_| bad("host header unusable"))?;
    let rp_id = origin
        .domain()
        .ok_or_else(|| {
            bad("passkeys need a host name, not an IP address: open the dashboard by name")
        })?
        .to_string();
    WebauthnBuilder::new(&rp_id, &origin)
        .and_then(|b| b.rp_name("DLPrevent").build())
        .map_err(|e| {
            ApiError(
                StatusCode::BAD_REQUEST,
                format!("passkeys unavailable for this host: {e}"),
            )
        })
}

#[derive(Clone, Debug, Serialize)]
pub struct User {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    /// Set when the session has just been extended: the cookie has to come
    /// along, otherwise it expires in the browser although the session still
    /// holds.
    #[serde(skip)]
    pub refreshed_cookie: Option<String>,
    /// The setting demands a second factor for this role, and the account
    /// has none: until it sets one up it only gets at its own account
    /// (extractor below). After that the user interface shows nothing but
    /// the account page.
    pub second_factor_required: bool,
}

/// SQL expressions, valid with `users u` in the FROM. What "has a second
/// factor" and "has to have one" mean is written down once each here: the
/// extractor builds it into its session query (one query per request stays
/// one), the sign-in and the settings ask the same thing.
pub const HAS_SECOND_FACTOR: &str =
    "(u.totp_secret IS NOT NULL OR EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id))";
/// The setting is called `require_2fa_<rolle>`. Accounts from an identity
/// provider (`external`) bring their second factor from there.
pub const SECOND_FACTOR_DEMANDED: &str = "(NOT u.external AND COALESCE((SELECT value = 'true'::jsonb FROM settings WHERE key = 'require_2fa_' || u.role), false))";

/// Mandatory for the role, but nothing set up.
pub fn second_factor_missing_sql() -> String {
    format!("({SECOND_FACTOR_DEMANDED} AND NOT {HAS_SECOND_FACTOR})")
}

pub async fn second_factor_required(pool: &sqlx::PgPool, id: Uuid) -> sqlx::Result<bool> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT {} FROM users u WHERE u.id = $1",
        second_factor_missing_sql()
    )))
    .bind(id)
    .fetch_one(pool)
    .await
}

/// A new session for an account; back comes the value for the cookie
/// ([`session_cookie`]). Every way in ends here — password, code, passkey,
/// and whatever another build adds.
pub async fn new_session(pool: &sqlx::PgPool, id: Uuid) -> sqlx::Result<String> {
    let sid = random_token();
    sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(sha256_hex(&sid))
        .bind(id)
        .bind(chrono::Utc::now() + chrono::Duration::hours(SESSION_HOURS))
        .execute(pool)
        .await?;
    sqlx::query("UPDATE users SET last_login = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(sid)
}

/// One's own password once more — above all for what would let a foreign
/// session into the account for good (new password, new passkey).
pub async fn verify_current_password(
    pool: &sqlx::PgPool,
    id: Uuid,
    password: &str,
) -> Result<(), ApiError> {
    let hash: Option<(String,)> = sqlx::query_as("SELECT pw_hash FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let (hash,) = hash.ok_or_else(not_found)?;
    if !verify_password(password, &hash) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "current password is wrong".into(),
        ));
    }
    Ok(())
}

/// What an account without the demanded second factor may still do: look at
/// itself, sign out, change its own password, and set the factor up.
fn open_without_second_factor(path: &str, id: Uuid) -> bool {
    path == "/api/me"
        || path == "/api/logout"
        || path.starts_with("/api/account")
        || path == format!("/api/users/{id}/password")
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

pub struct Admin(pub User);

pub struct ApiError(pub StatusCode, pub String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, axum::Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("{e:#}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!("db: {e}");
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, "database error".into())
    }
}

pub fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}
pub fn not_found() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "not found".into())
}

/// What an API key looks like in the dashboard and in the database. The
/// prefix makes it recognisable in logs and in scanning tools.
pub const API_KEY_PREFIX: &str = "dlp_";

/// Role of an API key: reading yes, changing no. With that the [`Admin`]
/// extractor turns it away by itself — every writing route already hangs on
/// it, there is no need for a second list that can go stale.
pub const API_KEY_ROLE: &str = "viewer";

pub fn new_api_key() -> String {
    format!("{API_KEY_PREFIX}{}", random_token())
}

fn cookie_value(parts: &Parts) -> Option<String> {
    let raw = parts.headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').map(str::trim).find_map(|kv| {
        kv.strip_prefix(COOKIE)
            .and_then(|r| r.strip_prefix('='))
            .map(str::to_string)
    })
}

fn bearer(parts: &Parts) -> Option<&str> {
    let v = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    Some(
        v.strip_prefix("Bearer ")
            .or_else(|| v.strip_prefix("bearer "))?
            .trim(),
    )
    .filter(|t| !t.is_empty())
}

/// How far an API key reaches — the monitoring views, nothing else.
///
/// An explicit list, and deliberately so: the role `viewer` on its own
/// reached further than the name "read key" promises. `/api/binaries`
/// demands only `User`, not `Admin` — a key could thereby have downloaded
/// the agent program. New routes are closed here until somebody explicitly
/// opens them; so the list can only go stale towards *safe*.
///
/// Exact path comparison, no prefix: otherwise `/api/alerts` would open
/// `/api/alerts/{id}/ack` as well.
const API_KEY_PATHS: [&str; 4] = ["/api/me", "/api/overview", "/api/alerts", "/api/counts"];

/// An API key as a reading account — or `None` when it is unknown, expired
/// or the access is switched off.
///
/// The master switch is read first: if it is off, the key is not even the
/// subject of a query, and an attacker does not learn from the runtime
/// whether it exists.
///
/// Checking and "last used" stand in one statement: one query per request,
/// as with the session cookie too, and the column is right without a second
/// write.
async fn user_from_api_key(state: &Shared, token: &str) -> Result<Option<User>, ApiError> {
    if !crate::db::setting_bool(&state.pool, "api_keys_enabled", false).await? {
        return Ok(None);
    }
    let row: Option<(Uuid, String)> = sqlx::query_as(
        "UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1 AND (expires_at IS NULL OR expires_at > now()) RETURNING id, label",
    )
    .bind(sha256_hex(token))
    .fetch_optional(&state.pool)
    .await?;
    // `id` is the one of the key, not the one of a user account: there is
    // none. That holds because a key only reads — writing routes demand
    // `Admin`, and only those write into the audit log, whose `user_id`
    // points at `users`.
    Ok(row.map(|(id, label)| User {
        id,
        name: format!("api:{label}"),
        role: API_KEY_ROLE.into(),
        refreshed_cookie: None,
        second_factor_required: false,
    }))
}

impl FromRequestParts<Shared> for User {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> std::result::Result<Self, Self::Rejection> {
        let Some(sid) = cookie_value(parts) else {
            if let Some(token) = bearer(parts) {
                if !API_KEY_PATHS.contains(&parts.uri.path()) {
                    return Err(ApiError(
                        StatusCode::FORBIDDEN,
                        "an API key may only read the monitoring views".into(),
                    ));
                }
                return match user_from_api_key(state, token).await? {
                    Some(u) => Ok(u),
                    None => Err(ApiError(
                        StatusCode::UNAUTHORIZED,
                        "unknown, expired or switched-off API key".into(),
                    )),
                };
            }
            return Err(ApiError(StatusCode::UNAUTHORIZED, "not signed in".into()));
        };
        let now = Utc::now();
        // Only the hash is in the database: whoever reads it cannot take
        // over a session with it.
        let hashed = sha256_hex(&sid);
        let row: Option<(Uuid, String, String, bool, DateTime<Utc>, bool)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT u.id, u.name, u.role, u.disabled, s.expires_at, {} FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = $1",
            second_factor_missing_sql()
        )))
        .bind(&hashed)
        .fetch_optional(&state.pool)
        .await?;
        match row {
            Some((id, name, role, disabled, exp, second_factor_required))
                if !disabled && exp > now =>
            {
                if second_factor_required && !open_without_second_factor(parts.uri.path(), id) {
                    return Err(ApiError(
                        StatusCode::FORBIDDEN,
                        "set up a second factor first (Account)".into(),
                    ));
                }
                // Extend, but do not write on every request.
                let mut refreshed_cookie = None;
                if exp - now < Duration::hours(SESSION_HOURS - 1) {
                    let _ = sqlx::query("UPDATE sessions SET expires_at = $1 WHERE id = $2")
                        .bind(now + Duration::hours(SESSION_HOURS))
                        .bind(&hashed)
                        .execute(&state.pool)
                        .await;
                    refreshed_cookie = Some(session_cookie(&sid, state.public_https()));
                }
                Ok(User {
                    id,
                    name,
                    role,
                    refreshed_cookie,
                    second_factor_required,
                })
            }
            _ => Err(ApiError(StatusCode::UNAUTHORIZED, "session expired".into())),
        }
    }
}

impl FromRequestParts<Shared> for Admin {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &Shared,
    ) -> std::result::Result<Self, Self::Rejection> {
        let u = User::from_request_parts(parts, state).await?;
        if u.is_admin() {
            Ok(Admin(u))
        } else {
            Err(ApiError(
                StatusCode::FORBIDDEN,
                "administrators only".into(),
            ))
        }
    }
}

pub fn session_cookie(id: &str, secure: bool) -> String {
    let mut c = format!(
        "{COOKIE}={id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        SESSION_HOURS * 3600
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// The signed-in user as the originator of an audit log entry.
///
/// It stands here and not in `db.rs`: that way the database side does not
/// know the extractor of the HTTP side, but only its own small
/// [`crate::db::Actor`].
impl<'a> From<&'a User> for crate::db::Actor<'a> {
    fn from(u: &'a User) -> Self {
        crate::db::Actor {
            id: Some(u.id),
            name: &u.name,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_roundtrip() {
        let h = hash_password("geheim").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("geheim", &h));
        assert!(!verify_password("falsch", &h));
        assert!(!verify_password("geheim", "kaputt"));
    }
    #[test]
    fn api_keys_are_prefixed_and_read_only() {
        let k = new_api_key();
        assert!(k.starts_with(API_KEY_PREFIX));
        assert_eq!(k.len(), API_KEY_PREFIX.len() + 64);
        assert_ne!(k, new_api_key());
        // Were the role "admin", every key would open the administration.
        assert!(!User {
            id: Uuid::nil(),
            name: "api:x".into(),
            role: API_KEY_ROLE.into(),
            refreshed_cookie: None,
            second_factor_required: false
        }
        .is_admin());
    }

    /// The vectors from RFC 6238, appendix B (SHA-1, six digits instead of eight).
    #[test]
    fn totp_matches_rfc_6238() {
        let secret = b"12345678901234567890";
        for (t, code) in [
            (59, 287082),
            (1111111109, 81804),
            (1234567890, 5924),
            (2000000000, 279037),
            (20000000000, 353130),
        ] {
            assert_eq!(totp_code(secret, t / TOTP_STEP_SECS), code, "t={t}");
        }
        // One step of offset in either direction counts, two do not; a step
        // that has been accepted once does not count a second time.
        assert_eq!(totp_verify(secret, "287082", 59, 0), Some(1));
        assert_eq!(
            totp_verify(secret, "287 082", 59 + 30, 0),
            Some(1),
            "Leerzeichen und ein Schritt spaeter"
        );
        assert_eq!(
            totp_verify(secret, "287082", 59 - 30, 0),
            Some(1),
            "ein Schritt frueher"
        );
        assert_eq!(
            totp_verify(secret, "287082", 59 + 60, 0),
            None,
            "zwei Schritte spaeter"
        );
        assert_eq!(totp_verify(secret, "287082", 59, 1), None, "Wiederholung");
        assert_eq!(totp_verify(secret, "abc", 59, 0), None);
        assert_eq!(totp_verify(b"anderes geheimnis", "287082", 59, 0), None);
    }

    #[test]
    fn base32_and_otpauth_are_what_authenticator_apps_expect() {
        assert_eq!(
            base32(b"12345678901234567890"),
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        );
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b""), "");
        let url = otpauth_url("hans müller", b"fooba");
        assert_eq!(url, "otpauth://totp/DLPrevent:hans%20m%C3%BCller?secret=MZXW6YTB&issuer=DLPrevent&algorithm=SHA1&digits=6&period=30");
        assert!(qr_svg(&url).unwrap().starts_with("<?xml"));
        assert_eq!(new_totp_secret().len(), 20);
        assert_ne!(new_totp_secret(), new_totp_secret());
    }

    #[test]
    fn tokens_are_random_hex() {
        let a = random_token();
        let b = random_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
