//! The log of what people have done in the dashboard.

use super::*;

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct AuditRow {
    id: i64,
    at: DateTime<Utc>,
    user_name: String,
    action: String,
    detail: serde_json::Value,
}

#[derive(Deserialize)]
pub(super) struct AuditQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    dir: Option<String>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

pub(super) const AUDIT_COLS: &str = "id, at, user_name, action, detail";

const AUDIT_HAYSTACK: &str = "lower(user_name || ' ' || action || ' ' || detail::text)";

/// The log's sortable columns. The machinery around them lives in
/// [`crate::sql::ListQuery`] — here only what makes this list what it is.
const AUDIT_ORDER: &[(&str, &str)] = &[("user", "lower(user_name)"), ("action", "action")];

pub(super) async fn audit(State(st): State<Shared>, _u: Admin, Query(q): Query<AuditQuery>) -> R<Vec<AuditRow>> {
    let order = order_by(q.sort.as_deref(), q.dir.as_deref(), AUDIT_ORDER);
    let mut list = ListQuery::new();
    let action = list.binder().text(q.action.clone());
    list.and(format!("({action}::text IS NULL OR action = {action})"));
    list.search(AUDIT_HAYSTACK, &search_terms(q.q.as_deref()));
    let query = list.finish::<AuditRow>(
        AUDIT_COLS,
        "audit_log",
        &order,
        q.limit.unwrap_or(200).clamp(1, 1000),
        q.offset.unwrap_or(0).max(0),
    );
    Ok(Json(query.fetch_all(&st.pool).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only this resource's own list — that an unknown name falls back to
    /// `id` is checked once for all lists by
    /// `sql::tests::order_only_from_allowlist`.
    #[test]
    fn the_audit_log_sorts_by_user_and_action() {
        assert_eq!(order_by(Some("user"), Some("asc"), AUDIT_ORDER), "lower(user_name) ASC, id DESC");
        assert_eq!(order_by(Some("action"), None, AUDIT_ORDER), "action DESC, id DESC");
        assert_eq!(order_by(Some("detail"), None, AUDIT_ORDER), "id DESC");
    }
}
