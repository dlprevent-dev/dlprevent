//! Your own account: setting up a second factor and taking it down again.
//! For anybody signed in, read-only included — it is only ever about your own
//! account, which is why this says `User` and not `Admin`.
//!
//! Anything that would let a stolen session into the account for good asks
//! for the password once more: adding a passkey. Taking things down (TOTP
//! off, passkey gone) only makes the account weaker, not somebody else's;
//! that works without it.

use super::*;
use crate::state::Pending;
use webauthn_rs::prelude::{Passkey, RegisterPublicKeyCredential};

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct PasskeyRow {
    id: Uuid,
    label: String,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
}

pub(super) const PASSKEY_COLS: &str = "id, label, created_at, last_used_at";

/// An account's keys, in the form webauthn-rs needs them.
pub(super) async fn passkeys_of(
    pool: &sqlx::PgPool,
    user: Uuid,
) -> Result<Vec<(Uuid, Passkey)>, ApiError> {
    let rows: Vec<(Uuid, sqlx::types::Json<Passkey>)> =
        sqlx::query_as("SELECT id, credential FROM passkeys WHERE user_id = $1")
            .bind(user)
            .fetch_all(pool)
            .await?;
    Ok(rows.into_iter().map(|(id, k)| (id, k.0)).collect())
}

#[derive(Serialize)]
pub(super) struct Account {
    totp_enabled: bool,
    passkeys: Vec<PasskeyRow>,
}

pub(super) async fn account(State(st): State<Shared>, user: User) -> R<Account> {
    let (totp_enabled,): (bool,) =
        sqlx::query_as("SELECT totp_secret IS NOT NULL FROM users WHERE id = $1")
            .bind(user.id)
            .fetch_one(&st.pool)
            .await?;
    let passkeys = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {PASSKEY_COLS} FROM passkeys WHERE user_id = $1 ORDER BY created_at"
    )))
    .bind(user.id)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(Account {
        totp_enabled,
        passkeys,
    }))
}

// ---------- TOTP ----------

#[derive(Serialize)]
pub(super) struct TotpSetup {
    /// For typing in by hand when the camera will not cooperate.
    secret: String,
    otpauth: String,
    qr_svg: String,
}

pub(super) async fn totp_start(State(st): State<Shared>, user: User) -> R<TotpSetup> {
    let secret = auth::new_totp_secret();
    let otpauth = auth::otpauth_url(&user.name, &secret);
    let setup = TotpSetup {
        secret: auth::base32(&secret),
        qr_svg: auth::qr_svg(&otpauth)?,
        otpauth,
    };
    st.pending_put(Pending::totp_setup_key(user.id), Pending::TotpSetup(secret));
    Ok(Json(setup))
}

#[derive(Deserialize)]
pub(super) struct Code {
    code: String,
}

/// The first correct code arms the secret. Without it there would be a
/// secret in the database that the app never saw — and the account would be
/// locked out.
pub(super) async fn totp_enable(
    State(st): State<Shared>,
    user: User,
    Json(b): Json<Code>,
) -> Result<StatusCode, ApiError> {
    let key = Pending::totp_setup_key(user.id);
    let Some((since, Pending::TotpSetup(secret))) = st.pending_take(&key) else {
        return Err(bad("the setup has expired, start again"));
    };
    let Some(step) = auth::totp_verify(&secret, &b.code, Utc::now().timestamp(), 0) else {
        st.pending_put_at(key, since, Pending::TotpSetup(secret));
        return Err(bad("wrong code, try the next one the app shows"));
    };
    sqlx::query("UPDATE users SET totp_secret = $2, totp_used_step = $3 WHERE id = $1")
        .bind(user.id)
        .bind(&secret)
        .bind(step)
        .execute(&st.pool)
        .await?;
    db::audit(
        &st.pool,
        (&user).into(),
        "totp_enable",
        json!({ "id": user.id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn totp_disable(
    State(st): State<Shared>,
    user: User,
) -> Result<StatusCode, ApiError> {
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_used_step = 0 WHERE id = $1")
        .bind(user.id)
        .execute(&st.pool)
        .await?;
    db::audit(
        &st.pool,
        (&user).into(),
        "totp_disable",
        json!({ "id": user.id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------- Passkeys ----------

#[derive(Deserialize)]
pub(super) struct PasskeyStart {
    password: String,
}

pub(super) async fn passkey_start(
    State(st): State<Shared>,
    user: User,
    headers: HeaderMap,
    Json(b): Json<PasskeyStart>,
) -> Result<Response, ApiError> {
    auth::verify_current_password(&st.pool, user.id, &b.password).await?;
    let wa = auth::webauthn(&st, &headers)?;
    let exclude = passkeys_of(&st.pool, user.id)
        .await?
        .into_iter()
        .map(|(_, k)| k.cred_id().clone())
        .collect();
    let (options, state) = wa
        .start_passkey_registration(user.id, &user.name, &user.name, Some(exclude))
        .map_err(|e| anyhow!("webauthn: {e}"))?;
    st.pending_put(
        Pending::passkey_reg_key(user.id),
        Pending::PasskeyRegistration(state),
    );
    Ok(Json(options).into_response())
}

#[derive(Deserialize)]
pub(super) struct PasskeyFinish {
    label: String,
    credential: RegisterPublicKeyCredential,
}

pub(super) async fn passkey_finish(
    State(st): State<Shared>,
    user: User,
    headers: HeaderMap,
    Json(b): Json<PasskeyFinish>,
) -> R<PasskeyRow> {
    let label = b.label.trim();
    if label.is_empty() || label.len() > 64 {
        return Err(bad("name: 1 to 64 characters"));
    }
    let wa = auth::webauthn(&st, &headers)?;
    let Some((_, Pending::PasskeyRegistration(state))) =
        st.pending_take(&Pending::passkey_reg_key(user.id))
    else {
        return Err(bad("the registration has expired, start again"));
    };
    let key = wa
        .finish_passkey_registration(&b.credential, &state)
        .map_err(|e| {
            tracing::info!("passkey registration refused for {}: {e}", user.name);
            bad("the browser's answer was not accepted, try again")
        })?;
    let row: PasskeyRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("INSERT INTO passkeys (user_id, label, credential) VALUES ($1, $2, $3) RETURNING {PASSKEY_COLS}")))
        .bind(user.id)
        .bind(label)
        .bind(sqlx::types::Json(&key))
        .fetch_one(&st.pool)
        .await?;
    db::audit(
        &st.pool,
        (&user).into(),
        "passkey_add",
        json!({ "id": row.id, "label": label }),
    )
    .await;
    Ok(Json(row))
}

pub(super) async fn delete_passkey(
    State(st): State<Shared>,
    user: User,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("DELETE FROM passkeys WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user.id)
        .execute(&st.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::audit(
        &st.pool,
        (&user).into(),
        "passkey_remove",
        json!({ "id": id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
