//! IP reputation for the dashboard: what is in the cache, and a forced
//! lookup for a single address.
//!
//! The worker in `crate::abuseipdb` fills the cache by itself; here we only
//! read — except for „Check again“, which costs exactly one lookup and is
//! therefore reserved for administrators.

use super::*;
use crate::abuseipdb::{self, Reputation};

#[derive(Serialize)]
pub(super) struct ReputationView {
    /// Switch on **and** key set: only then is anything asked at all.
    active: bool,
    /// What the cache holds for the requested addresses.
    items: Vec<Reputation>,
    /// Addresses in the cache in total.
    cached: i64,
    /// Lookups today (UTC) and the daily budget.
    today: i64,
    daily_limit: i64,
    /// Lookups since the central server started.
    lookups: u64,
    last_error: Option<String>,
    paused_until: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
pub(super) struct IpsQuery {
    /// Comma-separated, exactly as the alert list has them on screen.
    #[serde(default)]
    ips: Option<String>,
}

/// This many addresses one request accepts. The alert list loads 100 rows at
/// a time and can load more; twice that is enough with room to spare.
const MAX_IPS: usize = 500;

pub(super) async fn reputation(
    State(st): State<Shared>,
    _u: User,
    Query(q): Query<IpsQuery>,
) -> R<ReputationView> {
    let ips: Vec<String> = q
        .ips
        .unwrap_or_default()
        .split(',')
        .filter_map(abuseipdb::ip_of)
        .map(|ip| ip.to_string())
        .take(MAX_IPS)
        .collect();
    let items = if ips.is_empty() {
        Vec::new()
    } else {
        abuseipdb::cached(&st.pool, &ips).await?
    };
    let (cached,): (i64,) = sqlx::query_as("SELECT count(*) FROM ip_reputations")
        .fetch_one(&st.pool)
        .await?;
    let status = st.abuse.lock().unwrap().clone();
    Ok(Json(ReputationView {
        active: abuseipdb::config(&st.pool).await?.is_some(),
        items,
        cached,
        today: abuseipdb::lookups_today(&st.pool).await?,
        daily_limit: db::setting_i64(&st.pool, "abuseipdb_daily_limit", 1000).await?,
        lookups: status.lookups,
        last_error: status.last_error,
        paused_until: status.paused_until,
    }))
}

/// „Check again“: asks right away, without waiting for the worker. Counts
/// against the same daily budget, so that a twitchy finger cannot trip the
/// lockout.
pub(super) async fn refresh(
    State(st): State<Shared>,
    Admin(user): Admin,
    Path(ip): Path<String>,
) -> R<Reputation> {
    let Some(addr) = abuseipdb::ip_of(&ip) else {
        return Err(bad("not an IP address"));
    };
    if !abuseipdb::is_public(addr) {
        return Err(bad(
            "private or reserved address, AbuseIPDB does not know it",
        ));
    }
    let Some((key, daily_limit)) = abuseipdb::config(&st.pool).await? else {
        return Err(bad("AbuseIPDB is off or has no API key (Settings)"));
    };
    if abuseipdb::lookups_today(&st.pool).await? >= daily_limit {
        return Err(bad("daily lookup budget spent, try again tomorrow"));
    }
    let r = abuseipdb::check(
        &abuseipdb::client().map_err(|e| bad(e.to_string()))?,
        &addr.to_string(),
        &key,
    )
    .await
    .map_err(|e| {
        st.abuse.lock().unwrap().last_error = Some(e.to_string());
        bad(e.to_string())
    })?;
    abuseipdb::store(&st.pool, &r).await?;
    {
        let mut s = st.abuse.lock().unwrap();
        s.lookups += 1;
        s.last_error = None;
        s.paused_until = None;
    }
    db::audit(
        &st.pool,
        (&user).into(),
        "reputation_refresh",
        json!({ "ip": r.ip, "score": r.score }),
    )
    .await;
    Ok(Json(r))
}
