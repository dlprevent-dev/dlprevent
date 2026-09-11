//! de-el-pe: one binary. `deelpe daemon` is the root service, everything
//! else is CLI.

mod daemon;
mod ui;

use deelpe::{export, ipc};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "deelpe", version, about = "DLPrevent - lean data-loss detection")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the root service (LaunchDaemon / systemd).
    Daemon,
    /// Manage protected folders.
    Watch {
        #[command(subcommand)]
        cmd: WatchCmd,
    },
    /// Show alerts (the latest 500; `--all` for everything on disk).
    Alerts {
        #[arg(long)]
        all: bool,
    },
    /// Write every stored alert as CSV or JSON (default: stdout).
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Csv)]
        format: ExportFormat,
        /// Target file; without one, stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show one alert in detail.
    Show { id: u64 },
    /// State of the service.
    Status,
    /// Processes that are never reported (signing id, `prefix.*`, `team:ID`).
    Ignore {
        #[command(subcommand)]
        cmd: IgnoreCmd,
    },
    /// Connection to the central server (deelpe-server).
    Central {
        #[command(subcommand)]
        cmd: CentralCmd,
    },
    /// Learning phase: view and curate the learned pairs (process, target).
    Learn {
        #[command(subcommand)]
        cmd: LearnCmd,
    },
}

#[derive(Subcommand)]
enum CentralCmd {
    /// Enroll with the central server (root; the command is in the dashboard under Agents).
    Enroll {
        /// Address of the agent port, e.g. https://dlp.company.local:8444
        url: String,
        /// One-time token from the dashboard
        token: String,
        /// SHA-256 of the server CA (dashboard: Agents -> Enroll agent)
        #[arg(long)]
        ca_sha256: String,
    },
    /// State of the connection (through the service, no root needed).
    Status,
    /// Remove the connection (root); the service stops reporting.
    Remove,
}

#[derive(Subcommand)]
enum LearnCmd {
    /// Phase, end of the learning phase and every pair.
    Status,
    /// Confirm the candidates; from then on only new and deviating traffic is reported.
    Confirm,
    /// Drop a pair (key from `learn status`).
    Forget { key: String },
    /// Remember this alert's pair: silent from now on.
    Remember { id: u64 },
    /// Always report this alert's pair.
    Flag { id: u64 },
    /// Start a new learning phase, drop every pair.
    Restart,
}

#[derive(Subcommand)]
enum IgnoreCmd {
    Add { rule: String },
    Remove { rule: String },
    List,
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    Csv,
    Json,
}

#[derive(Subcommand)]
enum WatchCmd {
    Add { path: PathBuf },
    Remove { path: PathBuf },
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // Only the service writes the file: a CLI call as a normal user would
    // not get at `/var/lib/deelpe` anyway, and its noise does not belong in
    // the log the central server reads.
    let file = matches!(cli.cmd, Cmd::Daemon).then(|| std::path::Path::new(daemon::LOG));
    deelpe_core::agentlog::init(file, true);
    match cli.cmd {
        Cmd::Daemon => daemon::run().await,
        Cmd::Watch { cmd } => match cmd {
            WatchCmd::Add { path } => ipc::client(ipc::Request::WatchAdd(canon(path)?)).await.map(ui::print_response),
            WatchCmd::Remove { path } => ipc::client(ipc::Request::WatchRemove(canon(path)?)).await.map(ui::print_response),
            WatchCmd::List => ipc::client(ipc::Request::WatchList).await.map(ui::print_response),
        },
        Cmd::Alerts { all: false } => ipc::client(ipc::Request::Alerts).await.map(ui::print_response),
        Cmd::Alerts { all: true } => ipc::client(ipc::Request::AlertsAll).await.map(|r| {
            // Like `alerts`: newest first; the service delivers oldest first.
            ui::print_response(match r {
                ipc::Response::Alerts(mut a) => {
                    a.reverse();
                    ipc::Response::Alerts(a)
                }
                other => other,
            })
        }),
        Cmd::Export { format, output } => {
            let alerts = match ipc::client(ipc::Request::AlertsAll).await? {
                ipc::Response::Alerts(a) => a,
                // An older service without AlertsAll answers with Err.
                ipc::Response::Err(m) => bail!("{m} (reinstall the service?)"),
                _ => bail!("unexpected answer from the service"),
            };
            let text = match format {
                ExportFormat::Csv => export::csv(&alerts),
                ExportFormat::Json => export::json(&alerts)?,
            };
            match output {
                Some(p) => {
                    // File names from protected folders are sensitive: readable only by the user.
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&p)?
                        .write_all(text.as_bytes())?;
                    eprintln!("wrote {} alerts to {}", alerts.len(), p.display());
                }
                None => std::io::stdout().write_all(text.as_bytes())?,
            }
            Ok(())
        }
        Cmd::Show { id } => ipc::client(ipc::Request::Show(id)).await.map(ui::print_response),
        Cmd::Status => ipc::client(ipc::Request::Status).await.map(ui::print_response),
        Cmd::Ignore { cmd } => match cmd {
            IgnoreCmd::Add { rule } => ipc::client(ipc::Request::IgnoreAdd(rule)).await.map(ui::print_response),
            IgnoreCmd::Remove { rule } => ipc::client(ipc::Request::IgnoreRemove(rule)).await.map(ui::print_response),
            IgnoreCmd::List => ipc::client(ipc::Request::IgnoreList).await.map(ui::print_response),
        },
        Cmd::Central { cmd } => central_cmd(cmd).await,
        Cmd::Learn { cmd } => {
            let req = match cmd {
                LearnCmd::Status => ipc::Request::LearnStatus,
                LearnCmd::Confirm => ipc::Request::LearnConfirm,
                LearnCmd::Forget { key } => ipc::Request::LearnForget(key),
                LearnCmd::Remember { id } => ipc::Request::LearnRemember(id),
                LearnCmd::Flag { id } => ipc::Request::LearnFlag(id),
                LearnCmd::Restart => ipc::Request::LearnRestart,
            };
            ipc::client(req).await.map(ui::print_response)
        }
    }
}

async fn central_cmd(cmd: CentralCmd) -> Result<()> {
    use deelpe::central::{self, CentralConfig};
    match cmd {
        CentralCmd::Enroll { url, token, ca_sha256 } => {
            if CentralConfig::load()?.is_some() {
                bail!("already enrolled ({}); run `deelpe central remove` first", central::CONFIG_PATH);
            }
            let host = central::hostname();
            let cfg = central::enroll(&url, &token, &ca_sha256, &host, env!("CARGO_PKG_VERSION")).await?;
            cfg.save().map_err(|e| anyhow::anyhow!("{e:#} (needs root: sudo deelpe central enroll ...)"))?;
            println!("Enrolled as agent {} at {}. The service reports within a minute.", cfg.agent_id, cfg.url);
            Ok(())
        }
        // As root straight from disk (the service may not be running),
        // otherwise over the socket. Output goes through ui either way.
        CentralCmd::Status if is_root() => {
            ui::print_response(ipc::Response::Central(central::info()));
            Ok(())
        }
        CentralCmd::Status => ipc::client(ipc::Request::CentralStatus).await.map(ui::print_response),
        CentralCmd::Remove => {
            if CentralConfig::remove()? {
                // The state file stays: it records which folders came from
                // the central server. The service releases them on its next
                // pass and cleans the file up itself afterwards.
                println!("Connection removed. The service releases the distributed folders within a minute.");
                println!("Revoke the agent in the dashboard.");
            } else {
                println!("Was not connected.");
            }
            Ok(())
        }
    }
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn canon(p: PathBuf) -> Result<PathBuf> {
    Ok(std::fs::canonicalize(&p).unwrap_or(p))
}
