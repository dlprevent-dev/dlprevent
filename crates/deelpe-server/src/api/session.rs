//! Sign in, sign out, who am I.
//!
//! Three ways into a session: password alone, password and then a code from
//! the authenticator app (if the account has TOTP set up), or a passkey for
//! the user name without a password. All three end up in [`open_session`];
//! every failed attempt counts towards the same per-address lockout
//! (`state.rs`), the wrong code included — six digits are otherwise tried
//! out in minutes.

use super::*;
use crate::state::Pending;
use std::net::IpAddr;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential};

// ---------- Sign-in ----------

#[derive(Deserialize)]
pub(super) struct Login {
    name: String,
    password: String,
}

/// The address of whoever is signing in — or 429 if it is locked right now.
fn caller(st: &Shared, peer: PeerAddr, headers: &HeaderMap) -> Result<IpAddr, ApiError> {
    let ip = st.client_ip(peer.0, headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()));
    if st.login_locked(ip) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts, wait a minute".into()));
    }
    Ok(ip)
}

/// A failed attempt: counts towards the lockout, goes into the audit log,
/// and the answer does not give away what it was that went wrong.
async fn refuse(st: &Shared, ip: IpAddr, name: &str, step: &str, msg: &str) -> ApiError {
    st.login_failed(ip);
    db::audit(&st.pool, db::Actor::SYSTEM, "login_failed", json!({ "name": name, "ip": ip.to_string(), "step": step })).await;
    ApiError(StatusCode::UNAUTHORIZED, msg.into())
}

/// Create the session, set the cookie, return the account.
///
/// Not for an account from an identity provider (`external`): it signs in
/// there only. Otherwise a password an administrator set, or a passkey,
/// would skip the provider's MFA and outlive its offboarding.
async fn open_session(st: &Shared, id: Uuid, name: String, role: String, ip: IpAddr, how: &str) -> Result<Response, ApiError> {
    let external: bool = sqlx::query_scalar("SELECT external FROM users WHERE id = $1").bind(id).fetch_one(&st.pool).await?;
    if external {
        return Err(refuse(st, ip, &name, how, "this account signs in through single sign-on").await);
    }
    st.login_ok(ip);
    let sid = auth::new_session(&st.pool, id).await?;
    let user = User { id, name, role, refreshed_cookie: None, second_factor_required: auth::second_factor_required(&st.pool, id).await? };
    db::audit(&st.pool, (&user).into(), "login", json!({ "ip": ip.to_string(), "method": how })).await;
    let mut resp = Json(user).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, auth::session_cookie(&sid, st.public_https()).parse().unwrap());
    Ok(resp)
}

/// Answer: the account (the session stands) — or `{"totp": kennung}` when
/// the code is still missing, or `{"passkey": true}` when the role demands a
/// second factor and the account has passkeys only: then the password alone
/// opens nothing, and the browser is meant to take the passkey route. The
/// token binds the second step to the verified password; it is worth nothing
/// without the code and expires after five minutes.
pub(super) async fn login(State(st): State<Shared>, Extension(peer): Extension<PeerAddr>, headers: HeaderMap, Json(b): Json<Login>) -> Result<Response, ApiError> {
    let ip = caller(&st, peer, &headers)?;
    let row: Option<(Uuid, String, String, String, bool, Option<Vec<u8>>, bool)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT u.id, u.name, u.role, u.pw_hash, u.disabled, u.totp_secret, {} AND EXISTS (SELECT 1 FROM passkeys p WHERE p.user_id = u.id) FROM users u WHERE u.name = $1",
        auth::SECOND_FACTOR_DEMANDED
    )))
    .bind(b.name.trim())
    .fetch_optional(&st.pool)
    .await?;
    let ok = match &row {
        Some((_, _, _, hash, disabled, _, _)) => !disabled && auth::verify_password(&b.password, hash),
        // Same running time whether the name exists or not.
        None => {
            let _ = auth::verify_password(&b.password, "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
            false
        }
    };
    if !ok {
        return Err(refuse(&st, ip, &b.name, "password", "wrong user name or password").await);
    }
    let (id, name, role, _, _, totp, passkey_demanded) = row.unwrap();
    if totp.is_some() {
        let token = auth::random_token();
        st.pending_put(Pending::login_key(&token), Pending::Totp(id));
        return Ok(Json(json!({ "totp": token })).into_response());
    }
    if passkey_demanded {
        return Ok(Json(json!({ "passkey": true })).into_response());
    }
    open_session(&st, id, name, role, ip, "password").await
}

#[derive(Deserialize)]
pub(super) struct TotpLogin {
    token: String,
    code: String,
}

pub(super) async fn login_totp(State(st): State<Shared>, Extension(peer): Extension<PeerAddr>, headers: HeaderMap, Json(b): Json<TotpLogin>) -> Result<Response, ApiError> {
    let ip = caller(&st, peer, &headers)?;
    let key = Pending::login_key(&b.token);
    let Some((since, Pending::Totp(id))) = st.pending_take(&key) else {
        return Err(refuse(&st, ip, "?", "totp", "sign in again").await);
    };
    let row: Option<(String, String, bool, Option<Vec<u8>>, i64)> =
        sqlx::query_as("SELECT name, role, disabled, totp_secret, totp_used_step FROM users WHERE id = $1").bind(id).fetch_optional(&st.pool).await?;
    let Some((name, role, false, Some(secret), used)) = row else {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "sign in again".into()));
    };
    let Some(step) = auth::totp_verify(&secret, &b.code, Utc::now().timestamp(), used) else {
        // A typo does not cost the password a second time — but it does
        // count towards the lockout.
        st.pending_put_at(key, since, Pending::Totp(id));
        return Err(refuse(&st, ip, &name, "totp", "wrong code").await);
    };
    // Record it first, then sign in: the same code opens no second session —
    // not even when two requests arrive at the same time. The condition in
    // the UPDATE decides, not the comparison before it.
    let n = sqlx::query("UPDATE users SET totp_used_step = $2 WHERE id = $1 AND totp_used_step < $2").bind(id).bind(step).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(refuse(&st, ip, &name, "totp", "wrong code").await);
    }
    open_session(&st, id, name, role, ip, "totp").await
}

#[derive(Deserialize)]
pub(super) struct PasskeyStart {
    name: String,
}

/// First step of passkey sign-in: the challenge for the browser, with the
/// ids of this account's keys. If the account has none — or the name does
/// not exist — a challenge comes back anyway, with a made-up id in the same
/// shape (32-byte challenge, 16-byte id, base64url): in both cases the
/// browser reports „no matching passkey", and the answer does not give away
/// which names exist. Same idea as the equal running time on the password.
///
/// The half-finished step hangs off the account, not off a token: at most
/// one entry per account, no matter how often somebody asks without being
/// signed in.
pub(super) async fn passkey_login_start(State(st): State<Shared>, Extension(peer): Extension<PeerAddr>, headers: HeaderMap, Json(b): Json<PasskeyStart>) -> Result<Response, ApiError> {
    caller(&st, peer, &headers)?;
    let wa = auth::webauthn(&st, &headers)?;
    let user: Option<(Uuid, bool)> = sqlx::query_as("SELECT id, disabled FROM users WHERE name = $1").bind(b.name.trim()).fetch_optional(&st.pool).await?;
    if let Some((id, false)) = user {
        let keys: Vec<Passkey> = account::passkeys_of(&st.pool, id).await?.into_iter().map(|(_, k)| k).collect();
        if !keys.is_empty() {
            let (options, state) = wa.start_passkey_authentication(&keys).map_err(|e| anyhow!("webauthn: {e}"))?;
            st.pending_put(Pending::passkey_login_key(id), Pending::PasskeyLogin(state));
            return Ok(Json(options).into_response());
        }
    }
    // Hex is valid base64url; trimmed to the length of a real challenge.
    let rp_id = wa.get_allowed_origins().first().and_then(|o| o.domain()).unwrap_or_default();
    let decoy = json!({ "publicKey": { "challenge": &auth::random_token()[..43], "timeout": 60000, "rpId": rp_id, "userVerification": "required",
        "allowCredentials": [{ "type": "public-key", "id": &auth::random_token()[..22] }] } });
    Ok(Json(decoy).into_response())
}

#[derive(Deserialize)]
pub(super) struct PasskeyFinish {
    name: String,
    credential: PublicKeyCredential,
}

pub(super) async fn passkey_login_finish(State(st): State<Shared>, Extension(peer): Extension<PeerAddr>, headers: HeaderMap, Json(b): Json<PasskeyFinish>) -> Result<Response, ApiError> {
    let ip = caller(&st, peer, &headers)?;
    let wa = auth::webauthn(&st, &headers)?;
    let name = b.name.trim();
    let row: Option<(Uuid, String, bool)> = sqlx::query_as("SELECT id, role, disabled FROM users WHERE name = $1").bind(name).fetch_optional(&st.pool).await?;
    let Some((id, role, false)) = row else {
        return Err(refuse(&st, ip, name, "passkey", "passkey not accepted").await);
    };
    let Some((_, Pending::PasskeyLogin(state))) = st.pending_take(&Pending::passkey_login_key(id)) else {
        return Err(refuse(&st, ip, name, "passkey", "passkey not accepted").await);
    };
    let name = name.to_string();
    let result = match wa.finish_passkey_authentication(&b.credential, &state) {
        Ok(r) if r.user_verified() => r,
        Ok(_) => return Err(refuse(&st, ip, &name, "passkey", "the passkey did not verify you (PIN, fingerprint or face)").await),
        Err(e) => {
            tracing::info!("passkey refused for {name}: {e}");
            return Err(refuse(&st, ip, &name, "passkey", "passkey not accepted").await);
        }
    };
    // Update the counter and backup state of the key that was used
    // (`update_credential` recognises it by the id itself) and set the
    // timestamp.
    for (key_id, mut key) in account::passkeys_of(&st.pool, id).await? {
        if key.update_credential(&result).is_some() {
            sqlx::query("UPDATE passkeys SET credential = $2, last_used_at = now() WHERE id = $1").bind(key_id).bind(sqlx::types::Json(&key)).execute(&st.pool).await?;
        }
    }
    open_session(&st, id, name, role, ip, "passkey").await
}

pub(super) async fn logout(State(st): State<Shared>, headers: HeaderMap) -> Response {
    if let Some(raw) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        if let Some(sid) = raw.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(auth::COOKIE).and_then(|r| r.strip_prefix('='))) {
            let _ = sqlx::query("DELETE FROM sessions WHERE id = $1").bind(auth::sha256_hex(sid)).execute(&st.pool).await;
        }
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(header::SET_COOKIE, auth::clear_cookie().parse().unwrap());
    resp
}

pub(super) async fn me(State(st): State<Shared>, user: User) -> Response {
    // The session is sliding (auth.rs); the cookie has to slide along with
    // it, or the browser throws it away 12 h after sign-in even though the
    // server still knows about it. The UI calls /api/me on load.
    //
    // The time zone is tacked on here because every page fetches this answer
    // anyway and **every** role needs it: the settings are reserved for
    // administrators, the time of day concerns everybody. Until 2026-09-09
    // the UI took the browser's zone — correct as long as the viewer's clock
    // is correct, and unprovable as soon as two people see the same alert
    // with different times on it.
    let tz = crate::mail::timezone(&st.pool).await.unwrap_or(chrono_tz::Tz::UTC);
    let mut body = serde_json::to_value(&user).unwrap_or_else(|_| serde_json::json!({}));
    body["timezone"] = serde_json::json!(tz.name());
    let mut resp = Json(body).into_response();
    if let Some(c) = user.refreshed_cookie.clone() {
        if let Ok(v) = c.parse() {
            resp.headers_mut().insert(header::SET_COOKIE, v);
        }
    }
    resp
}
