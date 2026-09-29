//! Alert list, overview, acknowledging, learning instructions, counts.

use super::*;

// ---------- Overview ----------

#[derive(Serialize)]
pub(super) struct Overview {
    agents: i64,
    agents_online: i64,
    sources: i64,
    rules: i64,
    alerts_open: i64,
    alerts_24h: i64,
    recent: Vec<AlertRow>,
    ca_fingerprint: String,
    server_started: DateTime<Utc>,
    api_version: u32,
    /// The version of this server, and the first twelve hex digits of its
    /// file's SHA-256 — the same shortening the agents report as `build`.
    server_version: &'static str,
    server_build: String,
}

pub(super) async fn overview(State(st): State<Shared>, _u: User) -> R<Overview> {
    let interval = db::setting_i64(&st.pool, "report_interval_secs", 30).await?;
    let (agents,): (i64,) = sqlx::query_as("SELECT count(*) FROM agents WHERE revoked_at IS NULL").fetch_one(&st.pool).await?;
    let (agents_online,): (i64,) = sqlx::query_as("SELECT count(*) FROM agents WHERE revoked_at IS NULL AND last_seen > now() - ($1::bigint * interval '1 second')")
        .bind(interval * 3)
        .fetch_one(&st.pool)
        .await?;
    let (sources,): (i64,) = sqlx::query_as("SELECT count(*) FROM sources").fetch_one(&st.pool).await?;
    let (rules,): (i64,) = sqlx::query_as("SELECT count(*) FROM rules WHERE enabled").fetch_one(&st.pool).await?;
    let (alerts_open, alerts_24h): (i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FILTER (WHERE acknowledged_at IS NULL), count(*) FILTER (WHERE at > now() - interval '24 hours') FROM alerts WHERE {IS_ALERT}"
    )))
    .fetch_one(&st.pool).await?;
    let recent: Vec<AlertRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {ALERT_COLS} FROM alerts WHERE {IS_ALERT} ORDER BY COALESCE(last_at, at) DESC LIMIT 10"
    ))).fetch_all(&st.pool).await?;
    Ok(Json(Overview {
        agents,
        agents_online,
        sources,
        rules,
        alerts_open,
        alerts_24h,
        recent,
        ca_fingerprint: st.pki.ca_fingerprint.clone(),
        server_started: st.started,
        api_version: API_VERSION,
        server_version: env!("CARGO_PKG_VERSION"),
        server_build: crate::build_fingerprint().chars().take(12).collect(),
    }))
}

// ---------- Alerts ----------

/// Dashboard alarms are forbidden destinations, limit overruns and
/// deviations. Other verdicts stay stored as notices and can be retrieved
/// separately.
pub(super) const IS_ALERT: &str = "verdict IN ('denied', 'hard_limit', 'deviation')";

#[derive(Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AlertCategory {
    #[default]
    Alerts,
    Notices,
    All,
}

#[derive(Deserialize)]
pub(super) struct AlertQuery {
    #[serde(default)]
    category: AlertCategory,
    #[serde(default)]
    q: Option<String>,
    /// Exactly this one alert. The link from the alarm email
    /// (`/alerts?alert=<id>`) runs through here: it is meant to hit the row
    /// without anybody having to search. The full-text search cannot do
    /// that — it runs LIKE over a string that also contains `id::text`, and
    /// with `1` it catches the 17 as well.
    ///
    /// A named id beats the category. The reputation trigger also mails an
    /// alert with a notice verdict when its destination has a bad reputation
    /// (`mail::pending_alerts`) — that one sits under „Notices", and the link
    /// from the email would otherwise run into „nothing found". Whoever calls
    /// a row by name means that row, not its drawer.
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    open: Option<bool>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    /// Only this device's alerts. Together with `source` they are mutually
    /// exclusive: an alert hangs off exactly one origin.
    #[serde(default)]
    agent: Option<Uuid>,
    #[serde(default)]
    source: Option<Uuid>,
    /// Only alerts with this origin name. For rows whose agent or source has
    /// been deleted: `agent_id` and `source_id` are then NULL
    /// (`ON DELETE SET NULL`), and `origin_name` is all that still marks the
    /// row's origin.
    #[serde(default)]
    origin: Option<String>,
    /// Reputation of the destination: `bad`, `warn`, `ok` or `none`. See [`rep_where`].
    #[serde(default)]
    rep: Option<String>,
    /// Only what happened in the last this-many hours. See [`AlertFilter::hours`].
    #[serde(default)]
    hours: Option<i64>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    dir: Option<String>,
    #[serde(default)]
    offset: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

/// Everything the full-text search runs over. One string per alert, in
/// lower case; the search splits the input into words, all of which have to
/// occur (AND).
const ALERT_HAYSTACK: &str = "lower(id::text || ' ' || coalesce(user_display,'') || ' ' || coalesce(process,'') || ' ' || coalesce(path,'') || ' ' \
     || coalesce(remote,'') || ' ' || origin_name || ' ' || verdict || ' ' || coalesce(reason,'') || ' ' || external_id || ' ' || files::text)";

/// Verdicts by weight instead of alphabetically: „denied“ and „emergency
/// brake“ belong at the front, not between „known“ and „new“.
const VERDICT_RANK: &str = "array_position(ARRAY['denied','hard_limit','deviation','flagged','new','no_profile','known','learning'], verdict)";

/// Sort columns are a fixed list: the name from the request never lands in
/// the SQL, only the expression stored here. Without a NULLS clause, so that
/// both directions mirror each other: „status“ is NULL as long as an alert is
/// open, and has to be able to come out on top ascending as well as
/// descending.
const ALERT_ORDER: &[(&str, &str)] = &[
    ("at", "coalesce(last_at, at)"),
    ("origin", "lower(origin_name)"),
    ("who", "lower(coalesce(user_display, process, ''))"),
    ("path", "lower(coalesce(path, remote, ''))"),
    ("files", "file_count"),
    ("bytes", "bytes"),
    ("verdict", VERDICT_RANK),
    ("status", "acknowledged_at"),
    ("reputation", REP_SCORE),
];



/// The filters that the list and the bulk acknowledge have in common. One
/// type for both, so that „acknowledge all matching the filter" never means a
/// different „all" than what is on the screen.
pub(super) struct AlertFilter {
    id: Option<i64>,
    open: Option<bool>,
    verdict: Option<String>,
    kind: Option<String>,
    agent: Option<Uuid>,
    source: Option<Uuid>,
    origin: Option<String>,
    rep: Option<String>,
    /// Only alerts from the last this-many hours, measured on the same
    /// timestamp the list sorts by (`coalesce(last_at, at)`) — a repeating
    /// alert from last month that came back an hour ago belongs in „last
    /// 24 hours", otherwise the newest rows would drop out of their own
    /// window. `None` or anything not positive means: no limit.
    hours: Option<i64>,
    category: AlertCategory,
    terms: Vec<String>,
}

impl AlertFilter {
    fn from_query(q: &AlertQuery) -> Self {
        Self {
            id: q.id,
            open: q.open,
            verdict: q.verdict.clone(),
            kind: q.kind.clone(),
            agent: q.agent,
            source: q.source,
            origin: q.origin.clone(),
            rep: q.rep.clone(),
            hours: q.hours,
            category: q.category,
            terms: search_terms(q.q.as_deref()),
        }
    }

    fn from_ack(b: &AckBody) -> Self {
        Self {
            // Bulk acknowledge goes through a filter, never through a
            // single row — that is what `/api/alerts/{id}/ack` is for.
            id: None,
            // Only open ones: acknowledging an already closed one again
            // would be a silent change of signature.
            open: Some(true),
            verdict: b.verdict.clone(),
            kind: b.kind.clone(),
            agent: b.agent,
            source: b.source,
            origin: b.origin.clone(),
            rep: b.rep.clone(),
            hours: b.hours,
            category: b.category,
            terms: search_terms(b.q.as_deref()),
        }
    }
}

/// The address out of `remote`, in SQL — the same splitting as
/// [`crate::abuseipdb::ip_of`], which fills the cache.
///
/// A JOIN, because the alert does not carry the reputation itself: `remote`
/// is sometimes `1.2.3.4`, sometimes `1.2.3.4:443`, sometimes
/// `[2606:4700::1111]:443` and sometimes no address at all
/// (`volume /Volumes/Stick`). Whatever does not come out of this as an
/// address finds no row in `ip_reputations` and counts as unchecked — just
/// as in the dashboard, where `–` is then shown.
macro_rules! alert_ip {
    () => {
        "CASE WHEN remote LIKE '[%' THEN split_part(substr(remote, 2), ']', 1) \
         WHEN remote ~ '^[0-9.]+:[0-9]+$' THEN split_part(remote, ':', 1) ELSE remote END"
    };
}
const ALERT_IP: &str = alert_ip!();

/// The reputation as a number, for sorting. `concat!` instead of `format!`,
/// because the sort list is a constant.
///
/// Two decisions are baked into it. **On the whitelist the score does not
/// count** — the same rule the badge colours itself by; otherwise an address
/// known to be harmless would stand at the top of the bad ones with 100. And
/// **unchecked is -1**, not NULL: that way it sits below „clean" in both
/// directions and needs no NULLS clause, which would make this column the
/// only asymmetric one.
/// From what point a destination address counts as suspicious, and from what
/// point as malicious.
///
/// The thresholds from the AbuseIPDB docs. The same judgement is made by
/// `repClass` in `apps/web/src/pages/Alerts.svelte`, rebuilt in TypeScript —
/// the test `the_dashboard_and_the_filter_agree_on_what_a_ruf_is` holds the
/// two together. Before, there was a literal here and next to it a comment
/// pointing at the twin.
pub(super) const REP_SUSPICIOUS: i64 = 25;
pub(super) const REP_MALICIOUS: i64 = 75;

const REP_SCORE: &str = concat!(
    "coalesce((SELECT CASE WHEN r.is_whitelisted THEN 0 ELSE r.score END FROM ip_reputations r WHERE r.ip = ",
    alert_ip!(),
    "), -1)"
);

/// Filter on the reputation of the destination address. `None` means: no
/// filter.
///
/// The four values are a closed list, which is why there are literals here
/// and no placeholder — an unknown value does not filter instead of guessing.
/// The thresholds are those of the AbuseIPDB docs and the same ones the badge
/// in the list colours itself by (`repClass` in the dashboard): suspicious
/// from 25, malicious from 75, and on the whitelist the score does not count.
/// `warn` includes `bad` — whoever filters for „suspicious" does not want the
/// worse cases hidden.
/// Only for the test in `api::tests`: `rep_where` is private, and that is how
/// it should stay.
#[cfg(test)]
pub(super) fn rep_where_for_test(rep: &str) -> Option<String> {
    rep_where(Some(rep))
}

fn rep_where(rep: Option<&str>) -> Option<String> {
    let bad = format!("NOT r.is_whitelisted AND r.score >= {REP_MALICIOUS}");
    let warn = format!("NOT r.is_whitelisted AND r.score >= {REP_SUSPICIOUS}");
    let ok = format!("(r.is_whitelisted OR r.score < {REP_SUSPICIOUS})");
    let cond: &str = match rep?.trim() {
        "" => return None,
        "bad" => &bad,
        "warn" => &warn,
        "ok" => &ok,
        // Never checked, or no address at all. NULL compares with nothing,
        // so `remote IS NULL` falls in here too.
        "none" => return Some(format!("NOT EXISTS (SELECT 1 FROM ip_reputations r WHERE r.ip = {ALERT_IP})")),
        _ => return None,
    };
    Some(format!("EXISTS (SELECT 1 FROM ip_reputations r WHERE r.ip = {ALERT_IP} AND {cond})"))
}

/// The alert list's condition, together with its values in the `Binder`.
///
/// It stands on its own because the bulk acknowledge has to hit exactly the
/// same one.
fn alert_where(b: &mut Binder, f: &AlertFilter) -> String {
    let id = b.i64_opt(f.id);
    let open = b.bool(f.open);
    let verdict = b.text(f.verdict.clone());
    let kind = b.text(f.kind.clone());
    let agent = b.uuid(f.agent);
    let source = b.uuid(f.source);
    let origin = b.text(f.origin.clone());
    // Not positive means no limit: the dashboard sends `0` for „any time",
    // and a negative number would otherwise quietly turn into a window in
    // the future that matches nothing.
    let hours = b.i64_opt(f.hours.filter(|h| *h > 0));
    let category = match f.category {
        // See `AlertQuery::id`: the named row beats the drawer.
        _ if f.id.is_some() => "true".to_string(),
        AlertCategory::Alerts => IS_ALERT.to_string(),
        AlertCategory::Notices => format!("NOT ({IS_ALERT})"),
        AlertCategory::All => "true".into(),
    };
    let mut sql = format!(
        "({id}::bigint IS NULL OR id = {id}) AND ({open}::bool IS NULL OR ({open} AND acknowledged_at IS NULL) OR (NOT {open} AND acknowledged_at IS NOT NULL)) \
         AND ({verdict}::text IS NULL OR verdict = {verdict}) AND ({kind}::text IS NULL OR kind = {kind}) \
         AND ({agent}::uuid IS NULL OR agent_id = {agent}) AND ({source}::uuid IS NULL OR source_id = {source}) \
         AND ({origin}::text IS NULL OR origin_name = {origin}) \
         AND ({hours}::bigint IS NULL OR coalesce(last_at, at) > now() - ({hours} * interval '1 hour')) AND {category}"
    );
    // A literal without placeholders, so it goes before the search terms: the
    // `Binder`'s numbering is left untouched by it.
    if let Some(rep) = rep_where(f.rep.as_deref()) {
        sql.push_str(&format!(" AND {rep}"));
    }
    for t in &f.terms {
        let p = b.text(Some(t.clone()));
        sql.push_str(&format!(" AND {ALERT_HAYSTACK} LIKE {p}"));
    }
    sql
}

pub(super) async fn alerts(State(st): State<Shared>, _u: User, Query(q): Query<AlertQuery>) -> R<Vec<AlertRow>> {
    let order = order_by(q.sort.as_deref(), q.dir.as_deref(), ALERT_ORDER);
    let mut list = ListQuery::new();
    // `alert_where` appends the search terms itself, so no `list.search` —
    // the bulk acknowledge has to hit the same condition, and that is not a
    // SELECT.
    let cond = alert_where(list.binder(), &AlertFilter::from_query(&q));
    list.and(cond);
    let query = list.finish::<AlertRow>(
        ALERT_COLS,
        "alerts",
        &order,
        q.limit.unwrap_or(100).clamp(1, 500),
        q.offset.unwrap_or(0).max(0),
    );
    Ok(Json(query.fetch_all(&st.pool).await?))
}

#[derive(Serialize)]
pub(super) struct AlertCount {
    total: i64,
    /// The cap was reached: there are at least `total`, possibly many more.
    capped: bool,
}

/// As far as the count is worth counting. Past it the exact number buys
/// nothing — „more than ten thousand" is the same decision — while a
/// `count(*)` over a table holding months of alerts would run once per open
/// dashboard per refresh.
const COUNT_CAP: i64 = 10_000;

/// How many alerts the filter currently on screen matches.
///
/// The list fetches a page at a time and can therefore only ever say
/// „100+". That is enough for reading, and not enough for „close all
/// matching": that one is irreversible, and a number is what makes it a
/// decision instead of a leap. Same filter, same condition, so the number
/// and the button can never mean two different „all"s.
pub(super) async fn alert_count(State(st): State<Shared>, _u: User, Query(q): Query<AlertQuery>) -> R<AlertCount> {
    let mut binder = Binder::new();
    let cond = alert_where(&mut binder, &AlertFilter::from_query(&q));
    // Counted through a window, so the scan stops at the cap instead of
    // walking the whole table. The bound is a constant of this module and
    // never a request value.
    let sql = format!("SELECT count(*) FROM (SELECT 1 FROM alerts WHERE {cond} LIMIT {}) t", COUNT_CAP + 1);
    let total: i64 = binder.bind_as(sqlx::query_as(sqlx::AssertSqlSafe(sql))).fetch_one(&st.pool).await.map(|(n,): (i64,)| n)?;
    Ok(Json(AlertCount { total: total.min(COUNT_CAP), capped: total > COUNT_CAP }))
}

pub(super) async fn ack_alert(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<i64>) -> R<AlertRow> {
    let row: Option<AlertRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "UPDATE alerts SET acknowledged_at = now(), acknowledged_by = $2 WHERE id = $1 AND acknowledged_at IS NULL RETURNING {ALERT_COLS}"
    )))
    .bind(id)
    .bind(user.id)
    .fetch_optional(&st.pool)
    .await?;
    let row = row.ok_or_else(not_found)?;
    db::audit(&st.pool, (&user).into(), "alert_ack", json!({ "id": id })).await;
    Ok(Json(row))
}

/// Bulk acknowledge. Either a list of ids (what is ticked on the screen) or
/// `all` with the same filters as the list — with several thousand open
/// alerts, ticking page by page is not a way to operate anything.
#[derive(Deserialize)]
pub(super) struct AckBody {
    #[serde(default)]
    category: AlertCategory,
    #[serde(default)]
    ids: Vec<i64>,
    /// Acknowledge everything matching the filter, not just what is loaded.
    #[serde(default)]
    all: bool,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    agent: Option<Uuid>,
    #[serde(default)]
    source: Option<Uuid>,
    #[serde(default)]
    origin: Option<String>,
    #[serde(default)]
    rep: Option<String>,
    #[serde(default)]
    hours: Option<i64>,
}

#[derive(Serialize)]
pub(super) struct Acked {
    acked: u64,
}

/// Upper bound for the id list: a page holds 100, and more than ten times
/// that does not come from anybody ticking boxes.
const ACK_IDS_MAX: usize = 1000;

pub(super) async fn ack_alerts(State(st): State<Shared>, Admin(user): Admin, Json(b): Json<AckBody>) -> R<Acked> {
    let acked = if b.all {
        // The same `WHERE` as the list, with the user behind it.
        let mut binder = Binder::new();
        let cond = alert_where(&mut binder, &AlertFilter::from_ack(&b));
        let by = binder.uuid(Some(user.id));
        let sql = format!("UPDATE alerts SET acknowledged_at = now(), acknowledged_by = {by} WHERE acknowledged_at IS NULL AND {cond}");
        binder.bind(sqlx::query(sqlx::AssertSqlSafe(sql))).execute(&st.pool).await?.rows_affected()
    } else {
        if b.ids.is_empty() {
            return Err(bad("no alerts given"));
        }
        if b.ids.len() > ACK_IDS_MAX {
            return Err(bad(format!("at most {ACK_IDS_MAX} alerts at once")));
        }
        sqlx::query("UPDATE alerts SET acknowledged_at = now(), acknowledged_by = $2 WHERE acknowledged_at IS NULL AND id = ANY($1)")
            .bind(&b.ids)
            .bind(user.id)
            .execute(&st.pool)
            .await?
            .rows_affected()
    };
    db::audit(&st.pool, (&user).into(), "alert_ack_bulk", json!({ "acked": acked, "all": b.all, "ids": b.ids.len(), "category": b.category, "q": b.q, "verdict": b.verdict, "kind": b.kind, "hours": b.hours })).await;
    Ok(Json(Acked { acked }))
}

#[derive(Deserialize)]
pub(super) struct LearnBody {
    action: deelpe_core::central::LearnAction,
}

/// „Remember the pair“ or „always report“ from the central server. The
/// instruction does not go out right away: it lies there until the agent
/// reports the next time. Only an agent's endpoint alerts have a pair — an
/// access alert from the NAS and a syslog source have none.
pub(super) async fn learn_alert(State(st): State<Shared>, Admin(user): Admin, Path(id): Path<i64>, Json(b): Json<LearnBody>) -> R<Acked> {
    let row: Option<(Option<Uuid>, String, String)> = sqlx::query_as("SELECT agent_id, kind, external_id FROM alerts WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.pool)
        .await?;
    if !db::setting_bool(&st.pool, "learn_push_enabled", false).await? {
        return Err(bad("learning instructions are switched off (Settings)"));
    }
    let (agent_id, kind, external_id) = row.ok_or_else(not_found)?;
    let Some(agent_id) = agent_id else {
        return Err(bad("only alerts from an agent can be learned"));
    };
    if kind != "endpoint" {
        return Err(bad("only endpoint alerts have a process/destination pair"));
    }
    let alert_id: i64 = external_id.parse().map_err(|_| bad("agent alert id is unreadable"))?;
    let action = match b.action {
        deelpe_core::central::LearnAction::Remember => "remember",
        deelpe_core::central::LearnAction::Flag => "flag",
    };
    db::queue_learn(&st.pool, agent_id, alert_id, action, user.id).await?;
    db::audit(&st.pool, (&user).into(), "alert_learn", json!({ "id": id, "agent": agent_id, "alert_id": alert_id, "action": action })).await;
    // What has been remembered no longer needs to stand in the open list.
    //
    // The same (process, destination) pair, and nothing else — a `denied`
    // alarm is a forbidden destination out of a strict folder, and those
    // are never learned and never silenced (README, `learn::Verdict::Denied`).
    // Without this a click on one `new` row quietly closed the `denied` row
    // beside it: the two share a process and a destination by construction,
    // because the same flow that was `new` a moment ago is `denied` the
    // moment a strict rule covers the folder. `flag` is the same: it means
    // "keep reporting", so it must not close anything either.
    let ack_verdicts: &[&str] = match b.action {
        deelpe_core::central::LearnAction::Remember => &["new", "deviation", "flagged"],
        deelpe_core::central::LearnAction::Flag => &[],
    };
    let acked = sqlx::query("UPDATE alerts SET acknowledged_at = now(), acknowledged_by = $2 WHERE acknowledged_at IS NULL AND agent_id = $3 AND kind = 'endpoint' AND verdict = ANY($4) AND process IS NOT DISTINCT FROM (SELECT process FROM alerts WHERE id = $1) AND remote IS NOT DISTINCT FROM (SELECT remote FROM alerts WHERE id = $1)")
        .bind(id)
        .bind(user.id)
        .bind(agent_id)
        .bind(ack_verdicts)
        .execute(&st.pool)
        .await?
        .rows_affected();
    Ok(Json(Acked { acked }))
}

// ---------- Counts ----------

#[derive(Deserialize)]
pub(super) struct CountQuery {
    #[serde(default)]
    hours: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct HourBucket {
    hour: DateTime<Utc>,
    files: i64,
    bytes: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub(super) struct TopUser {
    user_display: String,
    path: String,
    files: i64,
    bytes: i64,
}

#[derive(Serialize)]
pub(super) struct Counts {
    hours: i64,
    per_hour: Vec<HourBucket>,
    top: Vec<TopUser>,
}

pub(super) async fn counts(State(st): State<Shared>, _u: User, Query(q): Query<CountQuery>) -> R<Counts> {
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 30);
    let per_hour: Vec<HourBucket> = sqlx::query_as(
        "SELECT date_trunc('hour', bucket) AS hour, sum(files)::bigint AS files, sum(bytes)::bigint AS bytes FROM access_counts WHERE bucket > now() - ($1::bigint * interval '1 hour') GROUP BY 1 ORDER BY 1",
    )
    .bind(hours)
    .fetch_all(&st.pool)
    .await?;
    let top: Vec<TopUser> = sqlx::query_as(
        "SELECT user_display, path, sum(files)::bigint AS files, sum(bytes)::bigint AS bytes FROM access_counts WHERE bucket > now() - ($1::bigint * interval '1 hour') GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 15",
    )
    .bind(hours)
    .fetch_all(&st.pool)
    .await?;
    Ok(Json(Counts { hours, per_hour, top }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::Arg;

    /// Only this resource's own list — that an unknown name falls back to
    /// `id` is checked once for all lists by
    /// `sql::tests::order_only_from_allowlist`.
    #[test]
    fn alerts_sort_by_their_own_columns() {
        assert_eq!(order_by(Some("bytes"), Some("asc"), ALERT_ORDER), "bytes ASC, id DESC");
        assert_eq!(order_by(Some("at"), None, ALERT_ORDER), "coalesce(last_at, at) DESC, id DESC");
        assert_eq!(order_by(Some("verdict"), Some("asc"), ALERT_ORDER), format!("{VERDICT_RANK} ASC, id DESC"));
        // `id` is deliberately not in the list: it is the fallback.
        assert_eq!(order_by(Some("id"), Some("asc"), ALERT_ORDER), "id ASC");
        assert_eq!(order_by(Some("bytes; DROP TABLE alerts"), Some("asc; --"), ALERT_ORDER), "id DESC");
    }

    fn filter(terms: &[&str]) -> AlertFilter {
        AlertFilter {
            id: None,
            open: None,
            verdict: None,
            kind: None,
            agent: None,
            source: None,
            origin: None,
            rep: None,
            hours: None,
            category: AlertCategory::Alerts,
            terms: terms.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// A placeholder belongs to the value it was handed out with. An extra
    /// filter shifts the search terms and the bounds along with it by
    /// itself — before, the numbering lived in one constant and three
    /// offsets, and a slipped placeholder silently bound the wrong value.
    #[test]
    fn placeholders_follow_the_values_they_were_pushed_with() {
        let mut b = Binder::new();
        let cond = alert_where(&mut b, &filter(&[]));
        assert!(cond.contains("($1::bigint IS NULL OR id = $1)"), "{cond}");
        assert!(cond.contains("($5::uuid IS NULL OR agent_id = $5)"), "{cond}");
        assert!(cond.contains("($6::uuid IS NULL OR source_id = $6)"), "{cond}");
        assert!(cond.contains("($7::text IS NULL OR origin_name = $7)"), "{cond}");
        assert!(cond.contains("($8::bigint IS NULL OR coalesce(last_at, at) > now() - ($8 * interval '1 hour'))"), "{cond}");
        assert_eq!(b.i64(100), "$9", "Grenze und Versatz kommen danach");
        assert_eq!(b.i64(0), "$10");

        let mut b = Binder::new();
        let cond = alert_where(&mut b, &filter(&["%a%", "%b%"]));
        assert!(cond.contains(&format!(" AND {ALERT_HAYSTACK} LIKE $9 AND {ALERT_HAYSTACK} LIKE $10")), "{cond}");
        assert_eq!(b.i64(100), "$11");
    }

    /// „Any time" must not become a window, and neither must a negative
    /// number — that would be a window in the future and would silently
    /// match nothing at all.
    #[test]
    fn a_time_window_of_nothing_is_no_window() {
        for h in [None, Some(0), Some(-24)] {
            let mut b = Binder::new();
            let mut f = filter(&[]);
            f.hours = h;
            alert_where(&mut b, &f);
            assert_eq!(b.args()[7], Arg::I64Opt(None), "hours = {h:?}");
        }
        let mut b = Binder::new();
        let mut f = filter(&[]);
        f.hours = Some(24);
        alert_where(&mut b, &f);
        assert_eq!(b.args()[7], Arg::I64Opt(Some(24)));
    }

    /// The reputation filter must not shift the placeholders — it brings no
    /// value with it — and an unknown value must not filter on the quiet. And
    /// `warn` has to include the malicious ones, otherwise „suspicious" hides
    /// the very worst destinations of all.
    #[test]
    fn the_reputation_filter_joins_the_cache_without_binding_anything() {
        let mut b = Binder::new();
        let mut f = filter(&[]);
        f.rep = Some("bad".into());
        let cond = alert_where(&mut b, &f);
        assert!(cond.contains("EXISTS (SELECT 1 FROM ip_reputations"), "{cond}");
        assert!(cond.contains("r.score >= 75"), "{cond}");
        assert_eq!(b.i64(100), "$9", "der Ruffilter bindet keinen Wert");

        assert!(rep_where(Some("warn")).unwrap().contains("r.score >= 25"));
        assert!(rep_where(Some("ok")).unwrap().contains("r.score < 25"));
        assert!(rep_where(Some("none")).unwrap().starts_with("NOT EXISTS"));
        assert_eq!(rep_where(None), None);
        assert_eq!(rep_where(Some("")), None);
        assert_eq!(rep_where(Some("bad'; DROP TABLE alerts --")), None, "unbekannt heisst: kein Filter");
    }

    /// „Acknowledge all matching the filter" has to hit the same condition as
    /// the list, otherwise it would be a different „all" than the one on the
    /// screen. And the user is bound *after* the search terms: if the number
    /// slips, the server acknowledges under somebody else's name — or not at
    /// all, because a UUID ends up as a search term.
    #[test]
    fn bulk_ack_uses_the_same_condition_as_the_list() {
        // **Every** dimension filled in, none left at `None`. With nothing
        // but `None`, the test passed even when a dimension appeared in only
        // one of the two places: both sides produced the same empty
        // condition, and the discrepancy only shows up at the customer who
        // presses "acknowledge all" and acknowledges more than was on the
        // screen.
        let agent = Uuid::from_u128(1);
        let source = Uuid::from_u128(2);
        let q = AlertQuery {
            category: AlertCategory::Alerts,
            q: Some("hans gl".into()),
            id: None,
            open: Some(true),
            verdict: Some("denied".into()),
            kind: Some("upload".into()),
            agent: Some(agent),
            source: Some(source),
            origin: Some("DESKTOP-EXAMPLE".into()),
            rep: Some("bad".into()),
            hours: Some(24),
            sort: None,
            dir: None,
            offset: None,
            limit: None,
        };
        let body = AckBody {
            category: AlertCategory::Alerts,
            ids: vec![],
            all: true,
            q: Some("hans gl".into()),
            verdict: Some("denied".into()),
            kind: Some("upload".into()),
            agent: Some(agent),
            source: Some(source),
            origin: Some("DESKTOP-EXAMPLE".into()),
            rep: Some("bad".into()),
            hours: Some(24),
        };
        let (mut b1, mut b2) = (Binder::new(), Binder::new());
        let from_list = alert_where(&mut b1, &AlertFilter::from_query(&q));
        let from_ack = alert_where(&mut b2, &AlertFilter::from_ack(&body));
        assert_eq!(from_list, from_ack);
        // The user is bound *after* the search terms: if the number slips,
        // the server acknowledges under somebody else's name — or not at
        // all, because a UUID ends up as a search term.
        assert_eq!(b1.uuid(Some(Uuid::nil())), b2.uuid(Some(Uuid::nil())), "gleiche Bedingung, gleiche Bindestellen");
    }

    /// "Remember" closes the open notices of its (process, destination)
    /// pair — and never the strict-folder `denied` alarm beside them, which
    /// shares that pair by construction. "Flag" means "keep reporting" and
    /// closes nothing at all.
    #[sqlx::test(migrations = "./migrations")]
    async fn remembering_a_pair_leaves_its_denied_alarm_open(pool: sqlx::PgPool) {
        use tower::ServiceExt;
        rustls::crypto::ring::default_provider().install_default().ok();
        let dir = std::env::temp_dir().join(format!("deelpe-api-test-{}", Uuid::new_v4()));
        let pki = crate::pki::Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        let st = std::sync::Arc::new(crate::state::AppState::new(pool.clone(), std::sync::Arc::new(pki), false, 8444, false, std::env::temp_dir().join("deelpe-test")));
        let app = super::super::router(st, Router::new());

        let admin: Uuid = sqlx::query_scalar("INSERT INTO users (name, pw_hash, role) VALUES ('admin', '', 'admin') RETURNING id").fetch_one(&pool).await.unwrap();
        let token = crate::auth::random_token();
        sqlx::query("INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, now() + interval '12 hours')")
            .bind(crate::auth::sha256_hex(&token)).bind(admin).execute(&pool).await.unwrap();
        let cookie = format!("{}={token}", crate::auth::COOKIE);
        db::set_setting(&pool, "learn_push_enabled", json!(true)).await.unwrap();
        let agent = Uuid::new_v4();
        sqlx::query("INSERT INTO agents (id, name, kind, version, cert_fingerprint, cert_not_after) VALUES ($1, 'pc01', 'windows_client', '0.1.0', 'fp', now() + interval '1 day')")
            .bind(agent).execute(&pool).await.unwrap();
        for (id, verdict) in [(1_i64, "new"), (2, "deviation"), (3, "denied")] {
            sqlx::query("INSERT INTO alerts (id, kind, agent_id, origin_name, external_id, at, process, remote, verdict, detail) \
                         VALUES ($1, 'endpoint', $2, 'pc01', $1::text, now(), 'firefox.exe', '203.0.113.9:443', $3, '{}')")
                .bind(id).bind(agent).bind(verdict).execute(&pool).await.unwrap();
        }
        let learn = |action: &'static str| {
            let app = app.clone();
            let cookie = cookie.clone();
            async move {
                let req = axum::http::Request::builder().method("POST").uri("/api/alerts/1/learn")
                    .header(header::COOKIE, cookie).header(header::CONTENT_TYPE, "application/json")
                    .body(axum::body::Body::from(json!({ "action": action }).to_string())).unwrap();
                let r = app.oneshot(req).await.unwrap();
                assert_eq!(r.status(), StatusCode::OK, "{action}");
                let body = axum::body::to_bytes(r.into_body(), 1024).await.unwrap();
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["acked"].as_u64().unwrap()
            }
        };
        let open = || sqlx::query_scalar::<_, String>("SELECT verdict FROM alerts WHERE acknowledged_at IS NULL ORDER BY id").fetch_all(&pool);

        assert_eq!(learn("flag").await, 0, "flag keeps reporting and closes nothing");
        assert_eq!(open().await.unwrap(), ["new", "deviation", "denied"]);
        assert_eq!(learn("remember").await, 2, "the pair's notices, not its alarm");
        assert_eq!(open().await.unwrap(), ["denied"], "a strict-folder alarm is never silenced");
    }
}
