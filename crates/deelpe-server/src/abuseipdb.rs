//! IP reputation via [AbuseIPDB](https://www.abuseipdb.com), API v2 `/check`.
//!
//! Until 2026-09-08 this sat in the Mac client: every Mac with its own key,
//! its own cache and its own daily budget. Now the central server asks once
//! for everybody — one key in the dashboard, one cache in `ip_reputations`,
//! one budget.
//!
//! Going easy on the quota (free plan: 1000 queries a day):
//! - Every address at most once per `CACHE_TTL`, the result in the
//!   database; a restart of the central server costs nothing.
//! - Private and reserved addresses are never queried.
//! - A daily budget (`abuseipdb_daily_limit`) counts the rows that were
//!   written today — that too survives a restart.
//! - An invalid key or an exhausted quota stop the worker instead of
//!   running into the lockout.
//! - Queries run one after another, never in parallel.
//!
//! Docs: <https://docs.abuseipdb.com/#check-endpoint>

use crate::db;
use crate::state::Shared;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub const ENDPOINT: &str = "https://api.abuseipdb.com/api/v2/check";

/// Time window of the reports. 90 days is what the AbuseIPDB docs suggest.
pub const MAX_AGE_DAYS: i64 = 90;

/// This long an answer holds. A week as in the Mac client: the reputation
/// of an address does not change by the hour, and anything below that only
/// costs quota.
pub const CACHE_TTL_SECS: i64 = 7 * 24 * 3600;

/// After an error (network, HTTP 5xx) the same address is only tried again
/// after an hour. Only in the worker's memory, as in the Mac client.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(3600);

/// This many addresses one pass fetches at most. The worker runs every
/// minute; nobody needs more than that, and with a flood of new alerts the
/// daily budget stays spread over the day this way.
const BATCH: i64 = 20;

/// Pause between two queries. AbuseIPDB names no rate per second, but a
/// burst of twenty requests without any air in between is impolite.
const BETWEEN: Duration = Duration::from_millis(300);

const SWEEP_SECS: u64 = 60;

/// Reputation of an address, cut down to what the dashboard shows. At once
/// the row of the table `ip_reputations` and the response type of the API.
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Reputation {
    pub ip: String,
    /// `abuseConfidenceScore`, 0…100.
    pub score: i32,
    pub country_code: Option<String>,
    pub isp: Option<String>,
    pub domain: Option<String>,
    pub usage_type: Option<String>,
    pub total_reports: i32,
    pub is_tor: bool,
    pub is_whitelisted: bool,
    pub checked_at: DateTime<Utc>,
}

pub const REPUTATION_COLS: &str = "ip, score, country_code, isp, domain, usage_type, total_reports, is_tor, is_whitelisted, checked_at";

#[derive(Debug, PartialEq)]
pub enum Error {
    /// 401: key missing, wrong or revoked.
    InvalidKey,
    /// 429: daily quota used up. Seconds, when the server names them.
    RateLimited(Option<i64>),
    /// 422: private or reserved address, AbuseIPDB does not know it.
    PrivateAddress,
    Http(u16, String),
    Malformed,
    Network(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "AbuseIPDB: API key invalid or revoked."),
            Error::RateLimited(Some(s)) if *s > 0 => write!(
                f,
                "AbuseIPDB: daily quota exhausted, resuming in {} min.",
                s / 60 + 1
            ),
            Error::RateLimited(_) => write!(f, "AbuseIPDB: daily quota exhausted."),
            Error::PrivateAddress => write!(f, "AbuseIPDB: private address."),
            Error::Http(code, m) => write!(f, "AbuseIPDB: HTTP {code} {m}"),
            Error::Malformed => write!(f, "AbuseIPDB: unexpected response."),
            Error::Network(m) => write!(f, "AbuseIPDB: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// What the dashboard displays about the service. In memory: it describes
/// the running process, not the installation.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Status {
    /// Queries since the start of the central server.
    pub lookups: u64,
    /// Last error that concerns anybody (key, quota).
    pub last_error: Option<String>,
    /// Until then the worker asks nothing more.
    pub paused_until: Option<DateTime<Utc>>,
}

// ---------- Wire format ----------

#[derive(serde::Deserialize)]
struct Envelope {
    data: Payload,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Payload {
    ip_address: String,
    is_public: Option<bool>,
    abuse_confidence_score: i32,
    country_code: Option<String>,
    usage_type: Option<String>,
    isp: Option<String>,
    domain: Option<String>,
    is_tor: Option<bool>,
    is_whitelisted: Option<bool>,
    total_reports: Option<i32>,
}

#[derive(serde::Deserialize)]
struct ErrorEnvelope {
    errors: Vec<ErrorItem>,
}

#[derive(serde::Deserialize)]
struct ErrorItem {
    detail: Option<String>,
}

/// Evaluates status code and body. Kept apart from `check` so that it can
/// be checked without a network.
pub fn parse(
    status: u16,
    body: &[u8],
    retry_after: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Reputation, Error> {
    match status {
        200 => {
            let env: Envelope = serde_json::from_slice(body).map_err(|_| Error::Malformed)?;
            let d = env.data;
            if !d.is_public.unwrap_or(true) {
                return Err(Error::PrivateAddress);
            }
            Ok(Reputation {
                ip: d.ip_address,
                score: d.abuse_confidence_score,
                country_code: d.country_code,
                isp: d.isp,
                domain: d.domain,
                usage_type: d.usage_type,
                total_reports: d.total_reports.unwrap_or(0),
                is_tor: d.is_tor.unwrap_or(false),
                is_whitelisted: d.is_whitelisted.unwrap_or(false),
                checked_at: now,
            })
        }
        401 => Err(Error::InvalidKey),
        422 => Err(Error::PrivateAddress),
        429 => Err(Error::RateLimited(retry_after.and_then(|v| v.parse().ok()))),
        code => {
            let detail = serde_json::from_slice::<ErrorEnvelope>(body)
                .ok()
                .and_then(|e| e.errors.into_iter().next())
                .and_then(|e| e.detail)
                .unwrap_or_default();
            Err(Error::Http(code, detail))
        }
    }
}

pub async fn check(client: &reqwest::Client, ip: &str, key: &str) -> Result<Reputation, Error> {
    // The query by hand instead of via `query`: the caller has already
    // parsed `ip` as an `IpAddr`, there is nothing in it that would need
    // encoding.
    let url = format!("{ENDPOINT}?ipAddress={ip}&maxAgeInDays={MAX_AGE_DAYS}");
    let resp = client
        .get(url)
        .header("Key", key)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| Error::Network(e.to_string()))?;
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body = resp
        .bytes()
        .await
        .map_err(|e| Error::Network(e.to_string()))?;
    parse(status, &body, retry_after.as_deref(), Utc::now())
}

// ---------- Addresses ----------

/// The column `remote` of an alert is sometimes `1.2.3.4`, sometimes
/// `1.2.3.4:443`, sometimes `volume /Volumes/Stick` — only an address may be
/// queried.
pub fn ip_of(remote: &str) -> Option<IpAddr> {
    let s = remote.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    // `ip:port` without brackets: only meaningful when exactly one colon is
    // in it — otherwise it is an IPv6 address, and `parse` above has already
    // judged that one.
    let (host, _) = s.rsplit_once(':')?;
    (!host.contains(':')).then(|| host.parse().ok()).flatten()
}

/// Only public addresses are queried: private, loopback, link-local,
/// multicast and reserved ranges are unknown to AbuseIPDB, and they would
/// only cost quota.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => is_public_v4(a),
        IpAddr::V6(a) => is_public_v6(a),
    }
}

fn is_public_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    // `is_shared` (100.64/10, CGNAT) and `is_benchmarking` (198.18/15) are
    // not stable in std yet; hence by hand.
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_unspecified()
        || o[0] == 0
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240)
}

fn is_public_v6(a: Ipv6Addr) -> bool {
    if let Some(v4) = a.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let b = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || b[0] & 0xfe == 0xfc                                    // fc00::/7 (ULA)
        || (b[0] == 0xfe && b[1] & 0xc0 == 0x80)                  // fe80::/10
        || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)) // 2001:db8::/32
}

// ---------- Cache ----------

pub async fn cached(pool: &PgPool, ips: &[String]) -> Result<Vec<Reputation>> {
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {REPUTATION_COLS} FROM ip_reputations WHERE ip = ANY($1)"
    )))
    .bind(ips)
    .fetch_all(pool)
    .await?)
}

pub async fn store(pool: &PgPool, r: &Reputation) -> Result<()> {
    sqlx::query(
        "INSERT INTO ip_reputations (ip, score, country_code, isp, domain, usage_type, total_reports, is_tor, is_whitelisted, checked_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (ip) DO UPDATE SET score = EXCLUDED.score, country_code = EXCLUDED.country_code, isp = EXCLUDED.isp, \
           domain = EXCLUDED.domain, usage_type = EXCLUDED.usage_type, total_reports = EXCLUDED.total_reports, \
           is_tor = EXCLUDED.is_tor, is_whitelisted = EXCLUDED.is_whitelisted, checked_at = EXCLUDED.checked_at",
    )
    .bind(&r.ip)
    .bind(r.score)
    .bind(&r.country_code)
    .bind(&r.isp)
    .bind(&r.domain)
    .bind(&r.usage_type)
    .bind(r.total_reports)
    .bind(r.is_tor)
    .bind(r.is_whitelisted)
    .bind(r.checked_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// How many queries have written rows today (UTC) already. That is the
/// daily budget: it counts out of the table instead of out of memory, so
/// that a restart does not set it to zero and trigger the lockout at
/// AbuseIPDB.
pub async fn lookups_today(pool: &PgPool) -> Result<i64> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM ip_reputations WHERE checked_at >= date_trunc('day', now() AT TIME ZONE 'utc') AT TIME ZONE 'utc'")
        .fetch_one(pool)
        .await?;
    Ok(n)
}

/// Key and switch from the settings. `None` means: off.
pub async fn config(pool: &PgPool) -> Result<Option<(String, i64)>> {
    if !db::setting_bool(pool, "abuseipdb_enabled", false).await? {
        return Ok(None);
    }
    let key = db::setting_str(pool, "abuseipdb_key")
        .await?
        .unwrap_or_default();
    if key.is_empty() {
        return Ok(None);
    }
    Ok(Some((
        key,
        db::setting_i64(pool, "abuseipdb_daily_limit", 1000).await?,
    )))
}

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?)
}

// ---------- Worker ----------

/// Asks at leisure after the new addresses that turn up in the alerts. Its
/// own task like `retention`: none of this may hold up an agent's report.
pub async fn run(state: Shared, stop: CancellationToken) -> Result<()> {
    let client = client()?;
    // Addresses whose query went wrong: not again before an hour is up.
    // Local, because only this task reads them — no mutex needed.
    let mut failed: HashMap<String, Instant> = HashMap::new();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(SWEEP_SECS)) => {}
            _ = stop.cancelled() => return Ok(()),
        }
        if let Err(e) = sweep(&state, &client, &mut failed).await {
            warn!("abuseipdb: {e:#}");
        }
    }
}

async fn sweep(
    state: &Shared,
    client: &reqwest::Client,
    failed: &mut HashMap<String, Instant>,
) -> Result<()> {
    let Some((key, daily_limit)) = config(&state.pool).await? else {
        return Ok(());
    };
    if let Some(until) = state.abuse.lock().unwrap().paused_until {
        if until > Utc::now() {
            return Ok(());
        }
    }
    let budget = daily_limit - lookups_today(&state.pool).await?;
    if budget <= 0 {
        return Ok(());
    }
    failed.retain(|_, at| at.elapsed() < RETRY_AFTER_FAILURE);
    let todo = missing(&state.pool, budget.min(BATCH), failed).await?;
    if todo.is_empty() {
        return Ok(());
    }
    let mut done = 0;
    for ip in &todo {
        match check(client, ip, &key).await {
            Ok(r) => {
                store(&state.pool, &r).await?;
                done += 1;
                let mut st = state.abuse.lock().unwrap();
                st.lookups += 1;
                st.last_error = None;
            }
            Err(e @ (Error::InvalidKey | Error::RateLimited(_))) => {
                // Both mean: stop, do not keep firing. A wrong key only
                // changes when it gets saved in the settings — and the pause
                // is deleted again there.
                let secs = match e {
                    Error::RateLimited(Some(s)) if s > 0 => s,
                    _ => RETRY_AFTER_FAILURE.as_secs() as i64,
                };
                let mut st = state.abuse.lock().unwrap();
                st.last_error = Some(e.to_string());
                st.paused_until = Some(Utc::now() + chrono::Duration::seconds(secs));
                warn!("abuseipdb: {e}");
                break;
            }
            // Private addresses only arrive here when AbuseIPDB judges a
            // range differently than `is_public`. Nothing to store, but no
            // reason to repeat it hourly either.
            Err(Error::PrivateAddress) => {
                failed.insert(ip.clone(), Instant::now());
            }
            Err(e) => {
                failed.insert(ip.clone(), Instant::now());
                state.abuse.lock().unwrap().last_error = Some(e.to_string());
            }
        }
        tokio::time::sleep(BETWEEN).await;
    }
    if done > 0 {
        info!(done, "abuseipdb: checked");
    }
    Ok(())
}

/// Public addresses out of the alerts of the last 30 days that are neither
/// fresh in the cache nor currently on an error pause.
async fn missing(
    pool: &PgPool,
    limit: i64,
    failed: &HashMap<String, Instant>,
) -> Result<Vec<String>> {
    // The column `remote` carries non-addresses too; the filtering
    // therefore happens in Rust, not in SQL. 30 days, because nobody looks
    // at older alerts any more.
    //
    // Filtering goes over `at`, not over `COALESCE(last_at, at)`: only `at`
    // has an index (`alerts_at`), and without it this pass would read the
    // whole table every minute — with 730 days of retention that table is
    // big. A long-running alert whose start is older drops out with this;
    // its address is as good as certain to stand in a newer alert as well.
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT remote FROM alerts WHERE remote IS NOT NULL AND at > now() - interval '30 days' ORDER BY remote LIMIT 5000",
    )
    .fetch_all(pool)
    .await?;
    let mut ips: Vec<String> = rows
        .into_iter()
        .filter_map(|(r,)| ip_of(&r))
        .filter(|ip| is_public(*ip))
        .map(|ip| ip.to_string())
        .filter(|ip| !failed.contains_key(ip))
        .collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Ok(Vec::new());
    }
    let fresh: Vec<(String,)> = sqlx::query_as("SELECT ip FROM ip_reputations WHERE ip = ANY($1) AND checked_at > now() - ($2::bigint * interval '1 second')")
        .bind(&ips)
        .bind(CACHE_TTL_SECS)
        .fetch_all(pool)
        .await?;
    let fresh: std::collections::HashSet<String> = fresh.into_iter().map(|(ip,)| ip).collect();
    Ok(ips
        .into_iter()
        .filter(|ip| !fresh.contains(ip))
        .take(limit as usize)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_public_addresses_cost_quota() {
        for s in ["1.2.3.4", "160.79.104.10", "8.8.8.8", "2606:4700::1111"] {
            assert!(is_public(ip(s)), "{s} ist öffentlich");
        }
        for s in [
            "10.0.0.1",
            "172.16.5.9",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1", // CGNAT
            "198.18.0.1", // Benchmark
            "192.0.2.7",  // TEST-NET-1
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:10.0.0.1", // IPv4-mapped, private
        ] {
            assert!(!is_public(ip(s)), "{s} ist nicht öffentlich");
        }
    }

    #[test]
    fn remote_column_yields_an_address_or_nothing() {
        assert_eq!(ip_of("1.2.3.4"), Some(ip("1.2.3.4")));
        assert_eq!(ip_of("1.2.3.4:443"), Some(ip("1.2.3.4")));
        assert_eq!(ip_of("2606:4700::1111"), Some(ip("2606:4700::1111")));
        assert_eq!(ip_of("[2606:4700::1111]:443"), Some(ip("2606:4700::1111")));
        assert_eq!(ip_of("volume /Volumes/Stick"), None);
        assert_eq!(ip_of("copy to /Users/me/Desktop"), None);
        assert_eq!(ip_of(""), None);
    }

    #[test]
    fn status_codes_become_the_errors_the_dashboard_shows() {
        let now = Utc::now();
        let body = br#"{"data":{"ipAddress":"1.2.3.4","isPublic":true,"abuseConfidenceScore":91,"countryCode":"RU","usageType":"Data Center","isp":"Acme","domain":"acme.ru","isTor":true,"totalReports":42,"isWhitelisted":false}}"#;
        let r = parse(200, body, None, now).unwrap();
        assert_eq!((r.score, r.total_reports, r.is_tor), (91, 42, true));
        assert_eq!(r.country_code.as_deref(), Some("RU"));
        assert_eq!(r.checked_at, now);

        assert_eq!(parse(401, b"", None, now).unwrap_err(), Error::InvalidKey);
        assert_eq!(
            parse(422, b"", None, now).unwrap_err(),
            Error::PrivateAddress
        );
        assert_eq!(
            parse(429, b"", Some("120"), now).unwrap_err(),
            Error::RateLimited(Some(120))
        );
        assert_eq!(
            parse(429, b"", None, now).unwrap_err(),
            Error::RateLimited(None)
        );
        assert_eq!(
            parse(200, b"nonsense", None, now).unwrap_err(),
            Error::Malformed
        );
        assert_eq!(
            parse(
                503,
                br#"{"errors":[{"detail":"Service unavailable"}]}"#,
                None,
                now
            )
            .unwrap_err(),
            Error::Http(503, "Service unavailable".into())
        );
        // A private address despite 200: AbuseIPDB reports it as `isPublic: false`.
        let private =
            br#"{"data":{"ipAddress":"10.0.0.1","isPublic":false,"abuseConfidenceScore":0}}"#;
        assert_eq!(
            parse(200, private, None, now).unwrap_err(),
            Error::PrivateAddress
        );
    }
}
