//! Running as a Windows service.
//!
//! Needed because a process somebody starts over a logon session ends with
//! that session — the agent would be gone after every logoff. The service
//! runs as **LocalSystem**: that account holds `SeSecurityPrivilege` (setting
//! SACLs) and may read the security log.
//!
//! At a customer site a dedicated service account with exactly these two
//! rights belongs here later instead of LocalSystem; as long as we only
//! observe (Z2), LocalSystem is defensible.

use crate::config;
use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::sync::mpsc;
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "deelpe-winagent";
const DISPLAY_NAME: &str = "DLPrevent file server agent";
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Entry point when the service control manager starts the process.
pub fn run_dispatcher() -> Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("service dispatcher")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = serve() {
        tracing::error!("service stops: {e:#}");
    }
}

fn serve() -> Result<()> {
    // A service has no console: everything into the log file.
    config::init_file_logging();

    let (tx, rx) = mpsc::channel::<()>();
    let handle = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = tx.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NotImplemented,
    })
    .context("register control handler")?;

    let running = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    };
    handle.set_service_status(running(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, Duration::default()))?;

    // Reapply the recovery action here, not only in `start`.
    //
    // `start` only reaches whoever starts the service through **this**
    // program. `Start-Service`, the services console and every reboot of the
    // machine go right past it — and then the agent replaces itself later and
    // stays down, because nobody touches it again. On 2026-09-10 in the lab
    // exactly that happened: program swapped, service stopped, no action set
    // up, device silent.
    //
    // Best effort: under LocalSystem it works, under a service account
    // without rights on its own service it does not. Then the reason is in
    // the log — and that goes to the dashboard with the next report.
    match ensure_recovery() {
        Ok(()) => {}
        Err(e) => tracing::warn!("recovery action not set ({e:#}); after replacing its program this service would stay down"),
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    // The control handler runs in a thread of the service control manager's
    // own; the stop signal comes from there into the loop.
    std::thread::spawn(move || {
        if rx.recv().is_ok() {
            let _ = stop_tx.send(true);
        }
    });

    let result = rt.block_on(crate::run_role(stop_rx));

    // A swapped program signs off as a failure. That is not glossing
    // anything over: the service is no longer running, and it is supposed to
    // be running again. That is exactly what the recovery action set up by
    // `install`/`start` hangs on — it restarts the service, and that one
    // starts into the new program. A service that stops and starts itself
    // would need rights on itself that a dedicated service account precisely
    // does not have.
    let mut stopped = running(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::default());
    if crate::update::restart_requested() {
        stopped.exit_code = ServiceExitCode::ServiceSpecific(UPDATED_EXIT_CODE);
        tracing::info!("agent program was replaced; reporting a failure so the service manager starts it again");
    }
    handle.set_service_status(stopped)?;
    result
}

/// How a service signs off that has swapped its program. Anything other than
/// zero; the number shows up in the event log and separates the planned swap
/// from a real crash.
const UPDATED_EXIT_CODE: u32 = 100;

/// Set up recovery: if the service fails, the service control manager starts
/// it again.
///
/// Two calls, not one. Out of the box the actions bite **only** when a
/// service crashes without signing off; a service that leaves properly with
/// an error code — exactly our case after a program swap — does not fall
/// under them without the second flag and would stay down.
///
/// **The handle needs `START`, not just `CHANGE_CONFIG`.** Whoever sets
/// recovery actions with `SC_ACTION_RESTART` has to be allowed to start the
/// service as well — otherwise Windows answers with "access denied", and it
/// does so even to an elevated administrator. Ran into it on 2026-09-10 on
/// the lab DC: `sc.exe failureflag` went through (no restart in it), setting
/// the actions did not.
///
/// Three times with a growing pause, then quiet: a program that does not come
/// up at all should not hang in a start loop. It then stands as offline in
/// the dashboard, and next to it lies the previous version as `.old`.
///
/// **The fourth `None` is the brake, not decoration.** If a service fails
/// more often than the list has entries, the service control manager repeats
/// the **last** one — so three restarts would mean one restart every two
/// minutes, forever, on every machine in the company. Only a closing `None`
/// stops it.
///
/// And the reset period is short (ten minutes, not a day): a *successful*
/// swap counts as a failure just as much as a failed one. With a day, `None`
/// would be next in line after the fourth update within one day — the agent
/// would swap its program and stay down. Ten minutes is longer than the
/// 5+30+120 seconds of a whole crash sequence, so a genuinely broken program
/// cannot swim free in between, and an agent that runs for ten minutes starts
/// again at five seconds.
fn set_recovery(svc: &windows_service::service::Service) -> Result<()> {
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(10 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(120) },
            ServiceAction { action_type: ServiceActionType::None, delay: Duration::default() },
        ]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    Ok(())
}

/// Is this service started again when it signs off with an error code?
///
/// Swapping the program ends with the service coming to a stop and the
/// service control manager starting it again. If no action is set up, or if
/// it does not bite on a clean stop, then the agent swaps its program and
/// **disappears** — from the dashboard, from the network, from monitoring.
/// That is exactly what happened on 2026-09-10 in the lab: program swapped,
/// service stopped, device silent, until somebody walked over by hand.
///
/// Which is why the agent asks beforehand. Better outdated and running than
/// current and dead.
pub fn restart_is_arranged() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(SERVICE_NAME, ServiceAccess::QUERY_CONFIG)?;
    let actions = svc.get_failure_actions()?;
    let restarts = actions
        .actions
        .as_ref()
        .map(|a| a.iter().any(|x| x.action_type == ServiceActionType::Restart))
        .unwrap_or(false);
    if !restarts {
        bail!(
            "no recovery action: nothing would start this service again after it replaces its program. \
             Set it once, elevated:  sc.exe failure {SERVICE_NAME} reset= 600 actions= restart/5000/restart/30000/restart/120000//0"
        );
    }
    // Out of the box the actions bite only on a crash. The agent, though,
    // signs off properly, just with an error code — without this flag it does
    // not fall under them, and the action above would stay without effect.
    if !svc.get_failure_actions_on_non_crash_failures()? {
        bail!(
            "the recovery action only covers a crash, and this service stops cleanly with an error code. \
             Set it once, elevated:  sc.exe failureflag {SERVICE_NAME} 1"
        );
    }
    Ok(())
}

/// Set the recovery action from inside the running service. See
/// [`set_recovery`]; all that is added here is the way to our own service.
fn ensure_recovery() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    set_recovery(&svc)
}

fn manager(access: ServiceManagerAccess) -> Result<ServiceManager> {
    ServiceManager::local_computer(None::<&str>, access).context("service manager (run as administrator)")
}

/// `account`: `None` = LocalSystem (last resort), otherwise a dedicated
/// account. `password` comes exclusively over standard input — never over the
/// command line, which ends up in `ps` and in the process log. A gMSA
/// (`DOMAIN\name$`) needs none at all.
pub fn install(account: Option<String>, password: Option<String>) -> Result<()> {
    let exe = std::env::current_exe().context("own path")?;
    if exe.starts_with(std::env::temp_dir()) {
        bail!("the file sits in the temp folder ({}). copy it to e.g. C:\\Program Files\\deelpe first, otherwise the service points nowhere.", exe.display());
    }
    let m = manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: SERVICE_TYPE,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe,
        launch_arguments: vec!["service".into(), "run".into()],
        dependencies: vec![],
        account_name: account.as_deref().map(Into::into),
        account_password: password.as_deref().map(Into::into),
    };
    let svc = m.create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)?;
    svc.set_description("Watches access to protected folders and reports it to the DLPrevent central.")?;
    // Without this an agent stays lying around after a program swap and out
    // of the dashboard — it signs off and nobody starts it again.
    if let Err(e) = set_recovery(&svc) {
        println!("  WARNING: recovery action not set ({e}); an update from the dashboard would not restart the service.");
    }
    match &account {
        Some(a) => {
            println!("service '{SERVICE_NAME}' created (autostart, account {a}).");
            // Without read permission on its own file the service starts
            // with "access denied" and does not say to what.
            let exe = std::env::current_exe()?;
            match crate::rights::grant_read_execute(&exe, a) {
                Ok(()) => println!("  granted read+execute on {}", exe.display()),
                Err(e) => println!("  WARNING: {} is not readable for {a} and could not be granted: {e:#}", exe.display()),
            }
            match crate::rights::grant_modify(std::path::Path::new(config::DIR), a) {
                Ok(()) => println!("  granted modify on {} (credentials and state)", config::DIR),
                Err(e) => println!("  WARNING: {} is not writable for {a}: {e:#}", config::DIR),
            }
            // Files from an earlier installation carry a protected access
            // list and therefore inherit nothing from the folder.
            for f in [config::CONFIG_PATH, config::STATE_PATH] {
                let p = std::path::Path::new(f);
                if p.exists() {
                    if let Err(e) = crate::rights::grant_modify(p, a) {
                        println!("  WARNING: {f} is not writable for {a}: {e:#}");
                    }
                }
            }
            println!("grant privileges:  deelpe-winagent rights grant --account \"{a}\"");
        }
        None => {
            println!("service '{SERVICE_NAME}' created (autostart, LocalSystem).");
            println!();
            println!("NOTE: LocalSystem is more privilege than needed. better use a dedicated account:");
            println!("  deelpe-winagent service uninstall");
            println!("  deelpe-winagent service install --account \"DOMAIN\\deelpe-svc$\"   (gMSA, without password)");
            println!("  deelpe-winagent rights grant --account \"DOMAIN\\deelpe-svc$\"");
        }
    }
    // Without the policy no browser asks, and the connector listens on a pipe
    // nobody knows. An error here should still not abort the installation:
    // the other sensors work without it too.
    match crate::browser::install_policy() {
        Ok(()) => {}
        Err(e) => println!("  WARNING: the Firefox content-analysis policy could not be written: {e:#}"),
    }
    println!("start it: deelpe-winagent service start");
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    if svc.query_status()?.current_state != ServiceState::Stopped {
        svc.stop()?;
    }
    svc.delete()?;
    // A browser that keeps asking for an agent that no longer exists waits
    // for the timeout on every upload.
    crate::browser::remove_policy()?;
    println!("service '{SERVICE_NAME}' removed.");
    Ok(())
}

pub fn start() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    let svc = m.open_service(SERVICE_NAME, ServiceAccess::START | ServiceAccess::QUERY_CONFIG)?;
    // Reapplied before every start, not only when installing — for the same
    // reason as the access list below it: a service that was installed before
    // this version has no recovery action, and without one it would stay down
    // after the first program swap.
    //
    // Deliberately a **second** handle on the same service instead of hanging
    // `CHANGE_CONFIG` on the one above: starting should not fail because
    // somebody may start the service but not reconfigure it. If it does not
    // work, the service starts anyway — it just cannot renew itself then, and
    // that is printed.
    match m
        .open_service(SERVICE_NAME, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .map_err(anyhow::Error::from)
        .and_then(|s| set_recovery(&s))
    {
        Ok(()) => {}
        Err(e) => {
            println!("WARNING: recovery action not set ({e:#});");
            println!("         an update from the dashboard would replace the program and then not restart it.");
            println!("         Set it by hand (one line, elevated):");
            println!("           sc.exe failure {SERVICE_NAME} reset= 600 actions= restart/5000/restart/30000/restart/120000//0");
            println!("           sc.exe failureflag {SERVICE_NAME} 1");
        }
    }
    // Whoever moves the .exe into place with `move` to update it brings the
    // access list of the source folder along — then the service account may
    // no longer read its own binary, and the start fails with "access
    // denied" without saying to what. Which is why this is reapplied before
    // every start, not only when installing.
    if let Ok(cfg) = svc.query_config() {
        if let Some(acct) = cfg.account_name.as_ref().map(|a| a.to_string_lossy().to_string()) {
            if !is_builtin(&acct) {
                // Not `cfg.executable_path`: that is the whole command
                // line including arguments, not a file path.
                repair_access(&std::env::current_exe()?, &acct);
            }
        }
    }
    svc.start::<&str>(&[])?;
    println!("service started. log: {}", config::LOG_PATH);
    Ok(())
}

/// Built-in accounts need nothing reapplied.
fn is_builtin(account: &str) -> bool {
    let a = account.trim().to_ascii_lowercase();
    matches!(a.as_str(), "localsystem" | "nt authority\\system" | "nt authority\\localservice" | "nt authority\\networkservice")
}

/// Binary readable, data directory writable — quiet as long as it fits.
fn repair_access(exe: &std::path::Path, account: &str) {
    let mut fixed = 0usize;
    match crate::rights::grant_read_execute(exe, account) {
        Ok(()) => fixed += 1,
        // No silent failure: without read permission the service does not
        // start, and the operator should know what it is down to.
        Err(e) => println!("WARNING: could not make {} readable for {account}: {e:#}", exe.display()),
    }
    for f in [config::DIR, config::CONFIG_PATH, config::STATE_PATH] {
        let p = std::path::Path::new(f);
        if !p.exists() {
            continue;
        }
        match crate::rights::grant_modify(p, account) {
            Ok(()) => fixed += 1,
            Err(e) => println!("WARNING: could not make {f} writable for {account}: {e:#}"),
        }
    }
    if fixed > 0 {
        println!("access rights for {account} brought up to date ({fixed} entries).");
    }
}

pub fn stop() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    m.open_service(SERVICE_NAME, ServiceAccess::STOP)?.stop()?;
    println!("service stopped.");
    Ok(())
}

pub fn status() -> Result<()> {
    let m = manager(ServiceManagerAccess::CONNECT)?;
    match m.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(svc) => println!("service: {:?}", svc.query_status()?.current_state),
        Err(_) => println!("service: not installed"),
    }
    Ok(())
}
