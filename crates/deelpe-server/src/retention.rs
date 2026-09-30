//! Cleaning up: expired sessions and tokens, old alerts (years), counts
//! (weeks), the agent log (weeks) and the IP reputation cache, according to
//! the settings.

use crate::abuseipdb;
use crate::db;
use crate::state::Shared;
use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub async fn run(state: Shared, stop: CancellationToken) -> Result<()> {
    let mut first = true;
    loop {
        let wait = if first { 60 } else { 3600 };
        first = false;
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(wait)) => {}
            _ = stop.cancelled() => return Ok(()),
        }
        if let Err(e) = sweep(&state.pool).await {
            warn!("cleanup: {e:#}");
        }
    }
}

async fn sweep(p: &sqlx::PgPool) -> Result<()> {
    let alert_days = db::setting_i64(p, "alert_retain_days", 730).await?;
    let count_days = db::setting_i64(p, "count_retain_days", 30).await?;
    // The agents' log is there for troubleshooting, not as evidence: two
    // weeks are enough, and without a limit, at 200 lines per report, it
    // fills the disk faster than anything else.
    let log_days = db::setting_i64(p, "log_retain_days", 14).await?;
    let sessions = sqlx::query("DELETE FROM sessions WHERE expires_at < now()")
        .execute(p)
        .await?
        .rows_affected();
    // Never used: a week after expiry. Used: kept a month for the record,
    // counted from when it stopped working — the last enrollment or the
    // expiry, whichever came first. LEAST skips the NULL of a token that is
    // not used up.
    let tokens = sqlx::query(
        "DELETE FROM enroll_tokens WHERE (uses = 0 AND expires_at < now() - interval '7 days') \
         OR (uses > 0 AND LEAST(expires_at, CASE WHEN uses >= max_uses THEN used_at END) < now() - interval '30 days')",
    )
        .execute(p)
        .await?
        .rows_affected();
    // Under legal hold: kept, however old.
    let alerts = sqlx::query("DELETE FROM alerts WHERE NOT legal_hold AND COALESCE(last_at, at) < now() - ($1::bigint * interval '1 day')").bind(alert_days).execute(p).await?.rows_affected();
    let counts = sqlx::query(
        "DELETE FROM access_counts WHERE bucket < now() - ($1::bigint * interval '1 day')",
    )
    .bind(count_days)
    .execute(p)
    .await?
    .rows_affected();
    let log =
        sqlx::query("DELETE FROM agent_log WHERE at < now() - ($1::bigint * interval '1 day')")
            .bind(log_days)
            .execute(p)
            .await?
            .rows_affected();
    // IP reputation: an address that still turns up in alerts is fetched
    // afresh weekly anyway (abuseipdb::CACHE_TTL_SECS). Whatever has not
    // been touched for a multiple of that does not turn up any more —
    // otherwise the cache would be the one table that grows without bound.
    let reputations = sqlx::query(
        "DELETE FROM ip_reputations WHERE checked_at < now() - ($1::bigint * interval '1 second')",
    )
    .bind(abuseipdb::CACHE_TTL_SECS * 12)
    .execute(p)
    .await?
    .rows_affected();
    if sessions + tokens + alerts + counts + log + reputations > 0 {
        info!(
            sessions,
            tokens, alerts, counts, log, reputations, "cleaned up"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn alerts_under_legal_hold_outlive_the_retention(pool: sqlx::PgPool) {
        let old = |hold: bool| {
            sqlx::query_scalar::<_, i64>(
                "INSERT INTO alerts (kind, origin_name, external_id, at, verdict, detail, legal_hold) VALUES ('endpoint', 'mac-1', gen_random_uuid()::text, now() - interval '1000 days', 'deviation', '{}', $1) RETURNING id",
            )
            .bind(hold)
        };
        let held = old(true).fetch_one(&pool).await.unwrap();
        old(false).fetch_one(&pool).await.unwrap();
        sweep(&pool).await.unwrap();
        let left: Vec<i64> = sqlx::query_scalar("SELECT id FROM alerts")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            left,
            vec![held],
            "past the default 730 days, only the held alert stays"
        );
    }
}
