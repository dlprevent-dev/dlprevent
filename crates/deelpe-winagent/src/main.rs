//! Windows server agent (Z2, decision of 2026-09-06): watches accesses to
//! protected folders on a file server and reports them to the central.
//! **Watch only** — this milestone blocks nothing.
//!
//! The agent sets itself up: it puts audit policy and SACL on the rule
//! folders when it takes the rules over, because that is exactly what has to
//! work at the customer's site. What is read is the security log (4663 file
//! access, 5145 share access with client IP); condensing happens locally,
//! what goes out are only counts per minute and alerts.

// Delivery, rule resolution and the cage decision are pure logic and get
// tested on the Mac as well; only the system calls underneath need Windows.
// Same as with `wfp` and `browser`.
#[cfg_attr(not(windows), allow(dead_code))]
mod agent;
#[cfg_attr(not(windows), allow(dead_code))]
mod client;
// The protocol and the verdict of the browser connector are pure logic and
// get tested on the Mac as well; only the named pipe needs Windows.
#[cfg_attr(not(windows), allow(dead_code))]
mod browser;
// The decision whether a process may be stopped is pure logic and gets
// tested on the Mac as well; only the stopping itself needs Windows. Same as
// with `evtlog`.
#[cfg_attr(not(windows), allow(dead_code))]
mod audit;
#[cfg_attr(not(windows), allow(dead_code))]
mod bootstrap;
#[cfg_attr(not(windows), allow(dead_code))]
mod config;
#[cfg_attr(not(windows), allow(dead_code))]
mod enforce;
#[cfg_attr(not(windows), allow(dead_code))]
mod groups;
/// Whose process raised the alert — on a terminal server, many people's.
mod procuser;
#[cfg(windows)]
mod rights;
#[cfg(windows)]
mod service;
#[cfg_attr(not(windows), allow(dead_code))]
mod shares;
/// The network cage: whoever has read from a strict folder reaches nothing
/// but its allowlist any more (ADR 0002).
mod wfp;
// Downloading, checking and swapping are pure file work and get tested on
// the Mac as well; only the restart afterwards needs the service manager.
#[cfg_attr(not(windows), allow(dead_code))]
mod update;
// The parser is pure logic and gets tested on the Mac as well; only reading
// the log needs Windows. Outside Windows only the tests use it.
#[cfg_attr(not(windows), allow(dead_code))]
mod evtlog;

#[cfg(not(windows))]
fn main() {
    eprintln!("deelpe-winagent runs on windows only; on macOS/Linux the service is `deelpe`.");
    std::process::exit(1);
}

/// Which loop the agent runs: a file server reads its security log, a
/// workstation its own file and network events. The role has been fixed since
/// enrollment.
///
/// Deliberately in exactly one place. Before, only the command line decided
/// this, and the service always called the file server loop — a machine
/// enrolled as a workstation then silently reported the wrong thing, and in
/// the dashboard everything looked green. Turned up exactly like that in the
/// lab on 2026-09-07.
#[cfg(windows)]
pub(crate) async fn run_role(mut stop: tokio::sync::watch::Receiver<bool>) -> anyhow::Result<()> {
    if !bootstrap::ensure_enrolled(&mut stop).await? {
        return Ok(());
    }
    match config::CentralConfig::load()?.map(|c| c.kind()) {
        Some(deelpe_core::central::AgentKind::WindowsClient) => client::run(stop).await,
        _ => agent::run(stop).await,
    }
}

#[cfg(windows)]
use clap::{Parser, Subcommand};

#[cfg(windows)]
#[derive(Parser)]
#[command(
    name = "deelpe-winagent",
    version,
    about = "DLPrevent agent for Windows file servers and workstations"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[cfg(windows)]
#[derive(Subcommand)]
enum Cmd {
    /// Enroll with the central (the command is shown in the dashboard under Agents).
    Enroll {
        url: String,
        token: String,
        /// SHA-256 of the CA from the dashboard; without a match nothing happens.
        #[arg(long)]
        ca_sha256: String,
        /// Enroll as a workstation, not as a file server: watch what
        /// processes read from protected folders and where they send it.
        #[arg(long)]
        endpoint: bool,
        /// The machine is reset to its image every night (terminal server,
        /// Citrix/VDI). Run this once on the image: the token stays on disk,
        /// and the service enrolls again on every boot as the same agent.
        /// Needs a token made for it in the dashboard.
        #[arg(long, requires = "endpoint")]
        non_persistent: bool,
    },
    /// Watch and report until Ctrl-C. For continuous operation use the
    /// service (`service install`), otherwise the agent ends with the session.
    Run,
    /// Set up and control the service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Grant, check and revoke the privileges of the service account.
    Rights {
        #[command(subcommand)]
        cmd: RightsCmd,
    },
    /// List the shares of this server (what the dashboard shows).
    Shares,
    /// State of the connection to the central.
    Status,
    /// Check audit policy and SACL of the rule folders.
    Check,
    /// Show what the agent actually sees in the security event log.
    /// For troubleshooting on site: it tells whether the events arrive
    /// and what their fields look like.
    Probe {
        /// How many records back.
        #[arg(long, default_value = "500")]
        back: u64,
        #[arg(long, default_value = "15")]
        limit: usize,
    },
    /// Workstation mode: show the raw file and network events the endpoint
    /// sensor produces. Run it, open a file on the share, watch the lines.
    /// This is the check that the event tracing actually delivers on this
    /// machine — do it once per Windows version before relying on a rule.
    Trace {
        #[arg(long, default_value = "30")]
        seconds: u64,
        /// Only events whose path or destination contains this text.
        #[arg(long)]
        filter: Option<String>,
    },
}

#[cfg(windows)]
#[derive(Subcommand)]
enum ServiceCmd {
    /// Register as a windows service (autostart).
    Install {
        /// Service account, e.g. `DOMAIN\deelpe-svc$` (gMSA, without password).
        /// Without it LocalSystem — more privilege than needed.
        #[arg(long)]
        account: Option<String>,
        /// Read the password from standard input. Never as an argument:
        /// it would show up in the process list and in the log.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Remove the service.
    Uninstall,
    Start,
    Stop,
    Status,
    /// For the service manager only; do not call by hand.
    #[command(hide = true)]
    Run,
}

#[cfg(windows)]
#[derive(Subcommand)]
enum RightsCmd {
    /// Grant exactly the required privileges — no admin rights.
    Grant {
        #[arg(long)]
        account: String,
    },
    /// Show what the account has and what is missing.
    Show {
        #[arg(long)]
        account: String,
    },
    /// Revoke the privileges again.
    Revoke {
        #[arg(long)]
        account: String,
    },
    /// Let the service account replace its own program, so updates from the
    /// dashboard work. Not needed under LocalSystem, and not needed at all
    /// if you roll the agent out by GPO or a script.
    AllowSelfUpdate {
        #[arg(long)]
        account: String,
    },
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    // If the service manager starts the process, there is no console and the
    // sequence is a different one: the dispatcher first, then the loop.
    if matches!(std::env::args().nth(1).as_deref(), Some("service"))
        && matches!(std::env::args().nth(2).as_deref(), Some("run"))
    {
        return service::run_dispatcher();
    }
    let cli = Cli::parse();
    // Only what also watches writes into the file: `run` by hand should fill
    // the same log as the service. The remaining commands stay on the
    // console — two processes with the same file open would get in each
    // other's way on rollover, and their noise does not belong in the log
    // that the central reads anyway.
    let file = matches!(cli.cmd, Cmd::Run).then(|| std::path::Path::new(config::LOG_PATH));
    deelpe_core::agentlog::init(file, true);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        match cli.cmd {
            Cmd::Enroll { url, token, ca_sha256, endpoint: true, non_persistent: true } => {
                let host = config::hostname();
                let b = config::Bootstrap { url, token, ca_sha256 };
                // Enrolling right away is the check: a wrong token or
                // fingerprint shows here, not in every clone's log tomorrow.
                let cfg = bootstrap::enroll(&b, &host).await?;
                b.save()?;
                println!("enrolled as {} at {} (workstation, non-persistent)", cfg.agent_id, cfg.url);
                println!("bootstrap: {} — every boot enrolls this way again", config::BOOTSTRAP_PATH);
                Ok(())
            }
            Cmd::Enroll { url, token, ca_sha256, endpoint, .. } => {
                let host = config::hostname();
                let kind = if endpoint {
                    deelpe_core::central::AgentKind::WindowsClient
                } else {
                    deelpe_core::central::AgentKind::WindowsServer
                };
                let e = deelpe_core::net::enroll(&url, &token, &ca_sha256, &host, kind, env!("CARGO_PKG_VERSION")).await?;
                if e.non_persistent {
                    println!("note: the token is for non-persistent machines; on a golden image enroll with --non-persistent");
                }
                let cfg = config::CentralConfig::from_enrolled(e, kind, &host);
                cfg.save()?;
                println!("enrolled as {} at {} ({})", cfg.agent_id, cfg.url, if endpoint { "workstation" } else { "file server" });
                println!("credentials: {}", config::CONFIG_PATH);
                Ok(())
            }
            Cmd::Run => {
                let (tx, rx) = tokio::sync::watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                run_role(rx).await
            }
            Cmd::Service { cmd } => match cmd {
                ServiceCmd::Install { account, password_stdin } => {
                    let pw = if password_stdin {
                        use std::io::Read;
                        let mut s = String::new();
                        std::io::stdin().read_to_string(&mut s)?;
                        Some(s.trim_end_matches(['\r', '\n']).to_string())
                    } else {
                        None
                    };
                    service::install(account, pw)
                }
                ServiceCmd::Uninstall => service::uninstall(),
                ServiceCmd::Start => service::start(),
                ServiceCmd::Stop => service::stop(),
                ServiceCmd::Status => service::status(),
                // Caught above; here only so that clap is complete.
                ServiceCmd::Run => service::run_dispatcher(),
            },
            Cmd::Status => {
                match config::CentralConfig::load()? {
                    None => println!("not enrolled. the enrollment command is shown in the dashboard under Agents."),
                    Some(cfg) => {
                        let st = config::AgentState::load();
                        println!("central:    {}", cfg.url);
                        println!("agent id:   {}", cfg.agent_id);
                        println!("reports:    {}", st.tally.reports);
                        println!("last ok:    {}", st.tally.last_ok.map(|t| t.to_rfc3339()).unwrap_or_else(|| "-".into()));
                        if let Some(e) = &st.tally.last_error {
                            println!("error:      {e}");
                        }
                        println!("generation: {}", st.generation);
                    }
                }
                Ok(())
            }
            Cmd::Check => audit::print_check(),
            Cmd::Trace { seconds, filter } => trace_events(seconds, filter).await,
            Cmd::Rights { cmd } => match cmd {
                RightsCmd::Grant { account } => rights::grant(&account),
                RightsCmd::Show { account } => rights::show(&account),
                RightsCmd::Revoke { account } => rights::revoke(&account),
                RightsCmd::AllowSelfUpdate { account } => rights::allow_self_update(&account),
            },
            Cmd::Shares => {
                let st = config::AgentState::load();
                for s in shares::list(&st.share_paths) {
                    println!(
                        "  {:<20} {:<40} {}",
                        s.name,
                        s.path.as_deref().unwrap_or("(path not readable)"),
                        s.path_from.as_deref().unwrap_or("-")
                    );
                }
                Ok(())
            }
            Cmd::Probe { back, limit } => {
                let st = config::AgentState::load();
                let from = st.last_record_id.saturating_sub(back);
                println!("reading from EventRecordID {from} (agent position: {})", st.last_record_id);
                let evs = evtlog::read_since(from, limit * 40)?;
                println!("{} events read", evs.len());
                for e in evs.iter().rev().take(limit) {
                    println!(
                        "  {} id={} user={:?} sid={:?} obj={:?} type={:?} mask={:?} ip={:?}",
                        e.record_id,
                        e.event_id,
                        e.get("SubjectUserName"),
                        e.get("SubjectUserSid"),
                        e.get("ObjectName").or_else(|| e.get("RelativeTargetName")),
                        e.get("ObjectType"),
                        e.get("AccessMask"),
                        e.get("IpAddress")
                    );
                }
                Ok(())
            }
        }
    })
}

/// Shows what the endpoint sensor sees. Without a central, without rules —
/// just the raw stream, so that on a real machine one minute is enough to
/// establish whether keywords and field names fit this Windows version.
#[cfg(windows)]
async fn trace_events(seconds: u64, filter: Option<String>) -> anyhow::Result<()> {
    use deelpe_core::event::Event;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(4096);
    for spec in deelpe_sensors::platform_sensors() {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = (spec.make)(3).run(tx).await {
                eprintln!("sensor {}: {e:#}", spec.name);
            }
        });
    }
    drop(tx);
    // `trace` deliberately shows everything: what should be visible here is
    // what the sensor delivers at all, not what a rule lets through of it.
    deelpe_sensors::set_watched(deelpe_sensors::Watch::All);
    println!("listening for {seconds} s — open a file on the share and upload something.");
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let (mut files, mut nets) = (0u64, 0u64);
    loop {
        let ev = tokio::select! {
            e = rx.recv() => match e { Some(e) => e, None => break },
            _ = tokio::time::sleep_until(deadline) => break,
        };
        let line = match &ev {
            Event::File(f) => {
                files += 1;
                // The identity is printed along with it: the lab run uses
                // that to check in one go whether the signature check bites.
                format!(
                    "file  pid={:<6} {:<24} {:?} {}",
                    f.process.pid,
                    f.process.identity.short(),
                    f.action,
                    f.path.display()
                )
            }
            Event::Net(n) => {
                nets += 1;
                format!(
                    "net   pid={:<6} {} -> {:?}:{:?} {} B",
                    n.pid, n.process_name, n.remote, n.remote_port, n.bytes_out
                )
            }
            _ => continue,
        };
        if filter
            .as_deref()
            .map(|f| line.to_lowercase().contains(&f.to_lowercase()))
            .unwrap_or(true)
        {
            println!("{line}");
        }
    }
    // Without this the session keeps running and the process never ends.
    deelpe_sensors::windows::etw::stop_session();
    let dropped = deelpe_sensors::windows::etw::dropped();
    println!("\n{files} file events, {nets} network events, {dropped} dropped.");
    if dropped > 0 {
        println!(
            "dropped events mean the console could not keep up; use --filter to narrow it down."
        );
    }
    if files == 0 {
        println!("no file events: check the keywords of Microsoft-Windows-Kernel-File in deelpe-sensors/src/windows/etw.rs.");
    }
    if nets == 0 {
        println!("no network events: check the keywords of Microsoft-Windows-Kernel-Network.");
    }
    Ok(())
}
