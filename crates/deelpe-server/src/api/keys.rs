//! API keys: third-party access to the read-only API without signing in
//! through a browser.
//!
//! A key reads, nothing more — it carries the `viewer` role
//! ([`auth::API_KEY_ROLE`]), so the same routes a read-only account sees.
//! The master switch `api_keys_enabled` in the settings locks all keys out
//! at once; it is off out of the box, so that an existing central server
//! does not open itself up through the migration.

use super::*;

/// Upper bound on validity. A key without an expiry is allowed (0), but it
/// has to be created that way explicitly.
const MAX_DAYS: i64 = 3650;

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct KeyRow {
    id: Uuid,
    label: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    last_used_at: Option<DateTime<Utc>>,
}

pub(super) const KEY_COLS: &str = "id, label, created_at, expires_at, last_used_at";

pub(super) async fn keys(State(st): State<Shared>, _u: Admin) -> R<Vec<KeyRow>> {
    let sql = format!("SELECT {KEY_COLS} FROM api_keys ORDER BY created_at DESC");
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(sql))
            .fetch_all(&st.pool)
            .await?,
    ))
}

#[derive(Deserialize)]
pub(super) struct KeyBody {
    label: String,
    /// Validity in days. 0 means: never expires.
    #[serde(default)]
    days: i64,
}

#[derive(Serialize)]
pub(super) struct KeyCreated {
    #[serde(flatten)]
    row: KeyRow,
    /// Here and only here: only the hash is stored, nobody can display it a
    /// second time.
    key: String,
}

pub(super) async fn create_key(
    State(st): State<Shared>,
    Admin(user): Admin,
    Json(b): Json<KeyBody>,
) -> R<KeyCreated> {
    let label = b.label.trim().to_string();
    if label.is_empty() || label.len() > 64 {
        return Err(bad("label: 1 to 64 characters"));
    }
    if !(0..=MAX_DAYS).contains(&b.days) {
        return Err(bad(format!(
            "validity: 0 to {MAX_DAYS} days (0 = never expires)"
        )));
    }
    let key = auth::new_api_key();
    let expires_at = (b.days > 0).then(|| Utc::now() + Duration::days(b.days));
    let sql = format!("INSERT INTO api_keys (key_hash, label, created_by, expires_at) VALUES ($1, $2, $3, $4) RETURNING {KEY_COLS}");
    let row: KeyRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(auth::sha256_hex(&key))
        .bind(&label)
        .bind(user.id)
        .bind(expires_at)
        .fetch_one(&st.pool)
        .await?;
    db::audit(
        &st.pool,
        (&user).into(),
        "api_key_create",
        json!({ "id": row.id, "label": label, "expires_at": expires_at }),
    )
    .await;
    Ok(Json(KeyCreated { row, key }))
}

pub(super) async fn delete_key(
    State(st): State<Shared>,
    Admin(user): Admin,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let row: Option<(String,)> =
        sqlx::query_as("DELETE FROM api_keys WHERE id = $1 RETURNING label")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let Some((label,)) = row else {
        return Err(not_found());
    };
    db::audit(
        &st.pool,
        (&user).into(),
        "api_key_delete",
        json!({ "id": id, "label": label }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
