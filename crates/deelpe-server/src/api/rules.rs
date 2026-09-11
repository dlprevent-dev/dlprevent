//! Folder rules: create, change, delete.

use super::*;

// ---------- Rules ----------

#[derive(Deserialize)]
pub(super) struct RuleBody {
    name: String,
    path: String,
    #[serde(default = "scope_all")]
    scope: String,
    #[serde(default)]
    agent_id: Option<Uuid>,
    #[serde(default)]
    source_id: Option<Uuid>,
    #[serde(default)]
    allowed_groups: Vec<String>,
    #[serde(default)]
    lockdown: bool,
    #[serde(default)]
    strict: bool,
    #[serde(default)]
    allow_destinations: Vec<String>,
    #[serde(default)]
    enforce: bool,
    #[serde(default = "d100")]
    hard_max_files: i32,
    #[serde(default = "d60")]
    window_secs: i32,
    #[serde(default)]
    ad_lock: bool,
    #[serde(default = "dtrue")]
    enabled: bool,
}
fn scope_all() -> String {
    "all".into()
}
fn d100() -> i32 {
    100
}
fn d60() -> i32 {
    60
}

impl RuleBody {
    fn validate(&mut self) -> Result<(), ApiError> {
        self.name = self.name.trim().to_string();
        self.path = self.path.trim().to_string();
        if self.name.is_empty() {
            return Err(bad("name is missing"));
        }
        if self.path.len() < 2 {
            return Err(bad("path is missing"));
        }
        match self.scope.as_str() {
            "all" => {
                self.agent_id = None;
                self.source_id = None;
            }
            "agent" if self.agent_id.is_some() => self.source_id = None,
            "source" if self.source_id.is_some() => self.agent_id = None,
            _ => return Err(bad("scope needs an agent or a source")),
        }
        if !(1..=100_000).contains(&self.hard_max_files) {
            return Err(bad("hard limit: 1 to 100000 files"));
        }
        if !(10..=3600).contains(&self.window_secs) {
            return Err(bad("window: 10 to 3600 seconds"));
        }
        self.allowed_groups = self.allowed_groups.iter().map(|g| g.trim().to_string()).filter(|g| !g.is_empty()).collect();
        self.allow_destinations = self.allow_destinations.iter().map(|d| d.trim().to_string()).filter(|d| !d.is_empty()).collect();
        for d in &self.allow_destinations {
            deelpe_core::allow::validate(d).map_err(bad)?;
        }
        // "Stop the sender" without strict mode would have nothing to react
        // to. The allow list stays: whoever switches strict mode off for a
        // moment should not have to type it in again.
        if !self.strict {
            self.enforce = false;
        }
        Ok(())
    }
}

pub(super) async fn rules(State(st): State<Shared>, _u: Admin) -> R<Vec<RuleRow>> {
    Ok(Json(db::all_rules(&st.pool).await?))
}

pub(super) async fn create_rule(State(st): State<Shared>, Admin(user): Admin, Json(mut b): Json<RuleBody>) -> R<RuleRow> {
    b.validate()?;
    let row: RuleRow = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "INSERT INTO rules (name, path, scope, agent_id, source_id, allowed_groups, lockdown, strict, allow_destinations, enforce, hard_max_files, window_secs, ad_lock, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING {RULE_COLS}"
    )))
    .bind(&b.name)
    .bind(&b.path)
    .bind(&b.scope)
    .bind(b.agent_id)
    .bind(b.source_id)
    .bind(&b.allowed_groups)
    .bind(b.lockdown)
    .bind(b.strict)
    .bind(&b.allow_destinations)
    .bind(b.enforce)
    .bind(b.hard_max_files)
    .bind(b.window_secs)
    .bind(b.ad_lock)
    .bind(b.enabled)
    .fetch_one(&st.pool)
    .await?;
    db::bump_generation(&st.pool).await?;
    db::audit(&st.pool, (&user).into(), "rule_create", serde_json::to_value(&row).unwrap_or_default()).await;
    Ok(Json(row))
}

pub(super) async fn update_rule(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>, Json(mut b): Json<RuleBody>) -> R<RuleRow> {
    b.validate()?;
    let row: Option<RuleRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE rules SET name = $2, path = $3, scope = $4, agent_id = $5, source_id = $6, allowed_groups = $7, lockdown = $8, strict = $9, allow_destinations = $10, enforce = $11, hard_max_files = $12, window_secs = $13, ad_lock = $14, enabled = $15, updated_at = now() \
         WHERE id = $1 RETURNING {RULE_COLS}"
    )))
    .bind(id)
    .bind(&b.name)
    .bind(&b.path)
    .bind(&b.scope)
    .bind(b.agent_id)
    .bind(b.source_id)
    .bind(&b.allowed_groups)
    .bind(b.lockdown)
    .bind(b.strict)
    .bind(&b.allow_destinations)
    .bind(b.enforce)
    .bind(b.hard_max_files)
    .bind(b.window_secs)
    .bind(b.ad_lock)
    .bind(b.enabled)
    .fetch_optional(&st.pool)
    .await?;
    let row = row.ok_or_else(not_found)?;
    db::bump_generation(&st.pool).await?;
    db::audit(&st.pool, (&user).into(), "rule_update", serde_json::to_value(&row).unwrap_or_default()).await;
    Ok(Json(row))
}

pub(super) async fn delete_rule(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<Uuid>) -> Result<StatusCode, ApiError> {
    let n = sqlx::query("DELETE FROM rules WHERE id = $1").bind(id).execute(&st.pool).await?.rows_affected();
    if n == 0 {
        return Err(not_found());
    }
    db::bump_generation(&st.pool).await?;
    db::audit(&st.pool, (&user).into(), "rule_delete", json!({ "id": id })).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_body(strict: bool, enforce: bool, allow: &[&str]) -> RuleBody {
        RuleBody {
            name: " GL ".into(),
            path: "/srv/GL".into(),
            scope: "all".into(),
            agent_id: None,
            source_id: None,
            allowed_groups: vec![],
            lockdown: false,
            strict,
            allow_destinations: allow.iter().map(|s| s.to_string()).collect(),
            enforce,
            hard_max_files: 100,
            window_secs: 60,
            ad_lock: false,
            enabled: true,
        }
    }

    #[test]
    fn strict_rule_validation() {
        let mut b = rule_body(true, true, &[" 10.0.0.0/8 ", "", "203.0.113.9:443"]);
        assert!(b.validate().is_ok());
        assert_eq!(b.allow_destinations, ["10.0.0.0/8", "203.0.113.9:443"]);
        assert!(b.enforce);
        // A host name has been accepted since 2026-09-08 (commit "Ein Name
        // ist genauer als ein Adressbereich"): the browser connector knows
        // the destination URL, and behind `chatgpt.com` there is an address
        // range that changes by the hour. On the network path the entry is
        // skipped, not applied wrongly -- see `deelpe_core::allow`.
        let mut b = rule_body(true, false, &["chat.example.com"]);
        assert!(b.validate().is_ok());
        assert_eq!(b.allow_destinations, ["chat.example.com"]);
        // A typo still gets rejected.
        assert!(rule_body(true, false, &["kein-punkt"]).validate().is_err());
        // Stopping without strict mode has no target.
        let mut b = rule_body(false, true, &[]);
        assert!(b.validate().is_ok());
        assert!(!b.enforce);
    }
}
