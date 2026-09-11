//! Syslog sources (NAS boxes without an agent).

use super::*;

pub(super) async fn sources(State(st): State<Shared>, _u: Admin) -> R<Vec<SourceRow>> {
    Ok(Json(sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT {SOURCE_COLS} FROM sources ORDER BY name"))).fetch_all(&st.pool).await?))
}

#[derive(Deserialize)]
pub(super) struct SourceBody {
    name: String,
    kind: String,
}

pub(super) async fn update_source(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>, Json(b): Json<SourceBody>) -> R<SourceRow> {
    let name = b.name.trim();
    if name.is_empty() {
        return Err(bad("name is missing"));
    }
    if !crate::syslog::KINDS.contains(&b.kind.as_str()) {
        return Err(bad("unknown kind"));
    }
    let row: Option<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!("UPDATE sources SET name = $2, kind = $3 WHERE id = $1 RETURNING {SOURCE_COLS}")))
        .bind(id)
        .bind(name)
        .bind(&b.kind)
        .fetch_optional(&st.pool)
        .await?;
    let row = row.ok_or_else(not_found)?;
    db::audit(&st.pool, (&user).into(), "source_update", json!({ "id": id, "name": name, "kind": b.kind })).await;
    Ok(Json(row))
}

pub(super) async fn delete_source(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("DELETE FROM sources WHERE id = $1").bind(id).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::audit(&st.pool, (&user).into(), "source_delete", json!({ "id": id })).await;
    Ok(StatusCode::NO_CONTENT)
}
