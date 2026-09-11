//! de-el-pe central server: dashboard, agent enrollment, collection point
//! for alerts and counts, syslog intake for NAS devices. Decision of
//! 2026-09-06, expansion stage Z1 (without intervention). One binary,
//! Postgres, user interface embedded.

mod abuseipdb;
mod agent;
mod api;
mod assist;
mod auth;
mod binaries;
mod db;
mod mail;
mod pki;
mod release;
mod retention;
mod sql;
mod state;
mod syslog;
mod tls;
mod ui;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "deelpe-server", about = "DLPrevent central server (deelpe-server)")]
struct Args {
    /// Postgres, e.g. postgres://deelpe:secret@localhost/deelpe
    #[arg(long, env = "DEELPE_DATABASE_URL")]
    database_url: String,
    /// CA, server certificate and key live here (0700).
    #[arg(long, env = "DEELPE_DATA_DIR", default_value = "/var/lib/deelpe-server")]
    data_dir: PathBuf,
    /// Dashboard (HTTPS with its own certificate, or HTTP with --ui-http).
    #[arg(long, env = "DEELPE_UI_ADDR", default_value = "0.0.0.0:8443")]
    ui_addr: SocketAddr,
    /// Agents (HTTPS, client certificate required except for enrollment).
    #[arg(long, env = "DEELPE_AGENT_ADDR", default_value = "0.0.0.0:8444")]
    agent_addr: SocketAddr,
    /// Syslog from NAS devices (UDP and TCP). Port 514 needs root; Docker maps 514 to 5514.
    #[arg(long, env = "DEELPE_SYSLOG_ADDR", default_value = "0.0.0.0:5514")]
    syslog_addr: SocketAddr,
    /// Names and addresses under which agents and browsers reach the server
    /// (comma separated); they go into the server certificate.
    #[arg(long, env = "DEELPE_SERVER_NAMES", default_value = "localhost,127.0.0.1")]
    server_names: String,
    /// Serve the dashboard without TLS (only behind a reverse proxy).
    #[arg(long, env = "DEELPE_UI_HTTP", default_value_t = false)]
    ui_http: bool,
    /// Behind a reverse proxy: accept `X-Forwarded-For` as the address of
    /// whoever signs in. Without it every user shares the proxy address, and
    /// with it the lockout after failed attempts. Only switch this on when a
    /// proxy really sits in front: otherwise anyone can dodge the lockout
    /// with a forged header.
    #[arg(long, env = "DEELPE_TRUST_PROXY", default_value_t = false)]
    trust_proxy: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("DEELPE_LOG").unwrap_or_else(|_| "info,sqlx=warn".into()))
        .init();
    let args = Args::parse();
    rustls::crypto::ring::default_provider().install_default().ok();

    let pool = db::connect(&args.database_url).await.context("database")?;
    sqlx::migrate!("./migrations").run(&pool).await.context("migration")?;
    let names: Vec<String> = args.server_names.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let pki = pki::Pki::load_or_create(&args.data_dir, &names).context("PKI")?;
    info!(ca = %pki.ca_fingerprint, "CA");
    // A new server version can translate the same rules differently;
    // without this nudge no agent notices. See the function.
    if let Some(g) = db::bump_generation_on_new_build(&pool, &build_fingerprint()).await? {
        info!(generation = g, "new server build — agents refetch their configuration");
    }
    if let Some(pw) = db::ensure_admin(&pool).await? {
        warn!("First start: user 'admin' created, password: {pw}");
        warn!("Change it after signing in (Users -> Password).");
    }
    let stop = CancellationToken::new();
    let state = Arc::new(state::AppState::new(pool.clone(), Arc::new(pki), !args.ui_http, args.agent_addr.port(), args.trust_proxy, args.data_dir.clone()));

    let syslog = tokio::spawn(syslog::run(state.clone(), args.syslog_addr, stop.clone()));
    let retention = tokio::spawn(retention::run(state.clone(), stop.clone()));
    let reputation = tokio::spawn(abuseipdb::run(state.clone(), stop.clone()));
    let notify = tokio::spawn(mail::run(state.clone(), stop.clone()));
    let releases = tokio::spawn(release::run(state.clone(), stop.clone()));

    let ui_router = api::router(state.clone()).merge(ui::router());
    let ui_tls = if args.ui_http { None } else { Some(state.pki.ui_config.clone()) };
    let ui = tokio::spawn(tls::serve(args.ui_addr, ui_tls, ui_router, stop.clone()));
    let agent_router = agent::router(state.clone());
    let agents = tokio::spawn(tls::serve(args.agent_addr, Some(state.pki.agent_config.clone()), agent_router, stop.clone()));
    info!(ui = %args.ui_addr, agents = %args.agent_addr, syslog = %args.syslog_addr, "ready");

    shutdown_signal().await;
    info!("Shutting down...");
    stop.cancel();
    for (name, h) in [("ui", ui), ("agents", agents), ("syslog", syslog), ("retention", retention), ("reputation", reputation), ("notifications", notify), ("releases", releases)] {
        match tokio::time::timeout(std::time::Duration::from_secs(10), h).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => error!("{name}: {e:#}"),
            Ok(Err(e)) => error!("{name}: {e}"),
            Err(_) => warn!("{name}: did not stop in time"),
        }
    }
    Ok(())
}

/// Fingerprint of the running server file — the same value that
/// `sha256sum` yields for it. Empty if it cannot be read; then the version
/// counts as unknown.
fn build_fingerprint() -> String {
    std::env::current_exe().and_then(std::fs::read).map(|b| pki::fingerprint(&b)).unwrap_or_default()
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}
