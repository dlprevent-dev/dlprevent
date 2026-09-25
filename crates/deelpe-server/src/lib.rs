//! de-el-pe central server: dashboard, agent enrollment, collection point
//! for alerts and counts, syslog intake for NAS devices. Decision of
//! 2026-09-06, expansion stage Z1 (without intervention). One binary,
//! Postgres, user interface embedded.
//!
//! A library with a thin `main.rs`, so that another build can add to the
//! server through [`Extension`] instead of forking it. The public modules
//! are that build's toolbox, not a stable API.

mod abuseipdb;
mod agent;
mod api;
mod assist;
pub mod auth;
mod binaries;
pub mod db;
pub mod mail;
mod pki;
mod release;
mod retention;
mod sql;
pub mod state;
mod syslog;
mod tls;
pub mod ui;

use anyhow::{Context, Result};
use axum::Router;
use clap::Parser;
use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

/// A background task: its name for the shutdown log, and its handle.
pub type Task = (&'static str, JoinHandle<Result<()>>);

/// Wraps the whole dashboard (API and pages) — it sees every request first.
pub type Wrap = Box<dyn FnOnce(state::Shared, Router) -> Router + Send>;

/// Runs once the database is migrated, before anything is served.
pub type StartHook = Box<dyn FnOnce(state::Shared, CancellationToken) -> Pin<Box<dyn Future<Output = Result<Vec<Task>>> + Send>> + Send>;

/// What a build adds on top of this server. The open-source binary passes
/// `Extension::default()` and is exactly the server without it.
#[derive(Default)]
pub struct Extension {
    /// More dashboard API routes, behind the same session and origin checks
    /// as `/api`.
    pub routes: Router<state::Shared>,
    /// A dashboard in place of the embedded one, see [`ui::embedded`].
    pub ui: Option<Router>,
    /// Its own migrations, then its background tasks; these stop with the
    /// server's.
    pub start: Option<StartHook>,
    /// Around the dashboard, e.g. to hold a change for a second person's
    /// approval.
    pub wrap: Option<Wrap>,
}

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

/// The whole server: arguments, database, listeners, until SIGTERM.
pub async fn run(ext: Extension) -> Result<()> {
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
    let extra = match ext.start {
        Some(start) => start(state.clone(), stop.clone()).await.context("extension")?,
        None => Vec::new(),
    };

    let ui_router = api::router(state.clone(), ext.routes).merge(ext.ui.unwrap_or_else(ui::router));
    let ui_router = match ext.wrap {
        Some(wrap) => wrap(state.clone(), ui_router),
        None => ui_router,
    };
    let ui_tls = if args.ui_http { None } else { Some(state.pki.ui_config.clone()) };
    let ui = tokio::spawn(tls::serve(args.ui_addr, ui_tls, ui_router, stop.clone()));
    let agent_router = agent::router(state.clone());
    let agents = tokio::spawn(tls::serve(args.agent_addr, Some(state.pki.agent_config.clone()), agent_router, stop.clone()));
    info!(ui = %args.ui_addr, agents = %args.agent_addr, syslog = %args.syslog_addr, "ready");

    shutdown_signal().await;
    info!("Shutting down...");
    stop.cancel();
    let own = [("ui", ui), ("agents", agents), ("syslog", syslog), ("retention", retention), ("reputation", reputation), ("notifications", notify), ("releases", releases)];
    for (name, h) in own.into_iter().chain(extra) {
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
/// counts as unknown. Read once per process: the dashboard asks for it on
/// every overview, and the file is several megabytes large.
fn build_fingerprint() -> String {
    static FP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FP.get_or_init(|| std::env::current_exe().and_then(std::fs::read).map(|b| pki::fingerprint(&b)).unwrap_or_default()).clone()
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
