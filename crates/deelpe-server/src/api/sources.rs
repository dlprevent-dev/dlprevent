//! Syslog sources (NAS boxes without an agent).

use super::*;

pub(super) async fn sources(State(st): State<Shared>, _u: Admin) -> R<Vec<SourceRow>> {
    Ok(Json(
        sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT {SOURCE_COLS} FROM sources ORDER BY name"
        )))
        .fetch_all(&st.pool)
        .await?,
    ))
}

#[derive(Deserialize)]
pub(super) struct SourceBody {
    name: String,
    kind: String,
    /// Confirms the source (or takes it back); absent leaves it as it is.
    /// Only a confirmed source's lines raise alerts: syslog is
    /// unauthenticated, so an address is only trusted once an administrator
    /// says it is theirs.
    #[serde(default)]
    confirmed: Option<bool>,
}

pub(super) async fn update_source(
    State(st): State<Shared>,
    Admin(user): Admin,
    Path(id): Path<Uuid>,
    Json(b): Json<SourceBody>,
) -> R<SourceRow> {
    let name = b.name.trim();
    if name.is_empty() {
        return Err(bad("name is missing"));
    }
    if !crate::syslog::KINDS.contains(&b.kind.as_str()) {
        return Err(bad("unknown kind"));
    }
    let row: Option<SourceRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE sources SET name = $2, kind = $3, confirmed = COALESCE($4, confirmed) WHERE id = $1 RETURNING {SOURCE_COLS}"
    )))
    .bind(id)
    .bind(name)
    .bind(&b.kind)
    .bind(b.confirmed)
    .fetch_optional(&st.pool)
    .await?;
    let row = row.ok_or_else(not_found)?;
    db::audit(
        &st.pool,
        (&user).into(),
        "source_update",
        json!({ "id": id, "name": name, "kind": b.kind, "confirmed": b.confirmed }),
    )
    .await;
    Ok(Json(row))
}

pub(super) async fn delete_source(
    State(st): State<Shared>,
    Admin(user): Admin,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("DELETE FROM sources WHERE id = $1")
        .bind(id)
        .execute(&st.pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::audit(
        &st.pool,
        (&user).into(),
        "source_delete",
        json!({ "id": id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// vuln-0010: the administrator confirms a waiting source; an edit that
    /// does not mention it leaves it as it is.
    #[sqlx::test(migrations = "./migrations")]
    async fn an_administrator_confirms_a_source(pool: sqlx::PgPool) {
        let id: Uuid = sqlx::query_scalar("INSERT INTO sources (name, kind, address) VALUES ('10.0.0.66', 'unknown', '10.0.0.66') RETURNING id").fetch_one(&pool).await.unwrap();
        let st = crate::syslog::tests::state(pool.clone());
        let uid: Uuid = sqlx::query_scalar(
            "INSERT INTO users (name, pw_hash, role) VALUES ('admin', '', 'admin') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let admin = || {
            Admin(crate::auth::User {
                id: uid,
                name: "admin".into(),
                role: "admin".into(),
                refreshed_cookie: None,
                second_factor_required: false,
            })
        };
        let put = |confirmed: Option<bool>| {
            Json(SourceBody {
                name: "NAS02".into(),
                kind: "synology".into(),
                confirmed,
            })
        };
        let row = update_source(State(st.clone()), admin(), Path(id), put(None))
            .await
            .ok()
            .unwrap()
            .0;
        assert!(!row.confirmed);
        let row = update_source(State(st.clone()), admin(), Path(id), put(Some(true)))
            .await
            .ok()
            .unwrap()
            .0;
        assert!(row.confirmed);
        let row = update_source(State(st), admin(), Path(id), put(None))
            .await
            .ok()
            .unwrap()
            .0;
        assert!(row.confirmed && row.name == "NAS02");
    }
}
