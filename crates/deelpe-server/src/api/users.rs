//! User accounts and passwords.

use super::*;

// ---------- Users ----------

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct UserRow {
    id: Uuid,
    name: String,
    role: String,
    disabled: bool,
    created_at: DateTime<Utc>,
    last_login: Option<DateTime<Utc>>,
    /// Second factor, only whether and how many — never the secret.
    totp_enabled: bool,
    passkeys: i64,
}

pub(super) const USER_COLS: &str = "id, name, role, disabled, created_at, last_login, totp_secret IS NOT NULL AS totp_enabled, (SELECT count(*) FROM passkeys p WHERE p.user_id = users.id) AS passkeys";

pub(super) async fn users(State(st): State<Shared>, _u: Admin) -> R<Vec<UserRow>> {
    let sql = format!("SELECT {USER_COLS} FROM users ORDER BY name");
    Ok(Json(sqlx::query_as(sqlx::AssertSqlSafe(sql)).fetch_all(&st.pool).await?))
}

#[derive(Deserialize)]
pub(super) struct UserBody {
    name: String,
    password: String,
    role: String,
}

fn check_password(pw: &str) -> Result<(), ApiError> {
    if pw.chars().count() < 12 {
        return Err(bad("password: at least 12 characters"));
    }
    Ok(())
}

pub(super) async fn create_user(State(st): State<Shared>, Admin(user): Admin, Json(b): Json<UserBody>) -> R<UserRow> {
    let name = b.name.trim().to_string();
    if name.is_empty() || name.len() > 64 {
        return Err(bad("name: 1 to 64 characters"));
    }
    if !matches!(b.role.as_str(), "admin" | "viewer") {
        return Err(bad("role: admin or viewer"));
    }
    check_password(&b.password)?;
    let row: UserRow = sqlx::query_as(sqlx::AssertSqlSafe(format!("INSERT INTO users (name, pw_hash, role) VALUES ($1, $2, $3) RETURNING {USER_COLS}")))
        .bind(&name)
        .bind(auth::hash_password(&b.password)?)
        .bind(&b.role)
        .fetch_one(&st.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_unique_violation() => bad("name already taken"),
            other => other.into(),
        })?;
    db::audit(&st.pool, (&user).into(), "user_create", json!({ "id": row.id, "name": name, "role": b.role })).await;
    Ok(Json(row))
}

pub(super) async fn delete_user(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    if id == user.id {
        return Err(bad("you cannot delete yourself"));
    }
    let (admins,): (i64,) = sqlx::query_as("SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled AND id <> $1").bind(id).fetch_one(&st.pool).await?;
    if admins == 0 {
        return Err(bad("the last administrator stays"));
    }
    let n = sqlx::query("DELETE FROM users WHERE id = $1").bind(id).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::audit(&st.pool, (&user).into(), "user_delete", json!({ "id": id })).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(super) struct PasswordBody {
    password: String,
    /// Mandatory for your own password: otherwise any stolen session takes
    /// over the account with a single click.
    #[serde(default)]
    old_password: Option<String>,
}

pub(super) async fn set_password(State(st): State<Shared>, user: User, Path(id): Path<Uuid>, Json(b): Json<PasswordBody>) -> Result<StatusCode, ApiError> {
    if id != user.id && !user.is_admin() {
        return Err(ApiError(StatusCode::FORBIDDEN, "only your own password".into()));
    }
    if id == user.id {
        auth::verify_current_password(&st.pool, id, b.old_password.as_deref().unwrap_or("")).await?;
    }
    check_password(&b.password)?;
    let n = sqlx::query("UPDATE users SET pw_hash = $2 WHERE id = $1").bind(id).bind(auth::hash_password(&b.password)?).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    // End this user's other sessions.
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.pool).await;
    db::audit(&st.pool, (&user).into(), "password_change", json!({ "id": id })).await;
    Ok(StatusCode::NO_CONTENT)
}

/// An account's second factor, gone — for when the phone is lost. The
/// password stays; if the factor is mandatory for the role, after the next
/// sign-in the account only gets as far as the account page until it has a
/// new one. Open sessions end, as they do with the password: the device this
/// is all about should not stay signed in right now. An administrator may do
/// this to their own account too.
pub(super) async fn reset_second_factor(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("UPDATE users SET totp_secret = NULL, totp_used_step = 0 WHERE id = $1").bind(id).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    let keys = sqlx::query("DELETE FROM passkeys WHERE user_id = $1").bind(id).execute(&st.pool).await?.rows_affected();
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(id).execute(&st.pool).await;
    db::audit(&st.pool, (&user).into(), "second_factor_reset", json!({ "id": id, "passkeys": keys })).await;
    Ok(StatusCode::NO_CONTENT)
}
