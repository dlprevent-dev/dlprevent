//! Platform-specific sensors. Every sensor pushes normalized
//! `deelpe_core::event::Event`s into a channel; the engine knows nothing
//! about platforms.

use async_trait::async_trait;
use deelpe_core::event::Event;
use tokio::sync::mpsc;

#[async_trait]
pub trait Sensor: Send {
    fn name(&self) -> &'static str;
    /// Runs until it fails or until the receiver is closed.
    async fn run(self: Box<Self>, tx: mpsc::Sender<Event>) -> anyhow::Result<()>;
}

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
// Pure conversion of Windows paths and number formats. Not restricted to
// Windows, so it gets tested where it is built (the agent is built for
// Windows on the Mac, see DESIGN.md).
#[cfg_attr(not(windows), allow(dead_code))]
pub mod winpath;
// The same for the sensor's bookkeeping: which events come into being at
// all, and who recently read from a protected folder.
pub mod filter;
// Reads a log, no system call of any platform: built and tested everywhere,
// run where the host sensors fill in the command lines it is joined on.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod guardlog;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod hermes;

/// Blueprint for a sensor: the service restarts it after a failure (say
/// when eslogger dies, or when disk access only comes through later), hence
/// a factory instead of a ready-made instance.
pub struct SensorSpec {
    pub name: &'static str,
    /// The network polling interval is the only parameter a sensor needs
    /// when it is built; the file sensors ignore it.
    pub make: fn(net_poll_secs: u64) -> Box<dyn Sensor>,
}

/// Which file events a sensor should pass on.
///
/// The Windows sensor has to know this: it filters inside the ETW callback,
/// **before** an event goes into the channel. Unfiltered, a freshly
/// installed Windows 11 produced over 20 000 file events in five minutes,
/// from Windows Update alone — the channel filled up, and the one access
/// that mattered was precisely the one that got dropped (lab log
/// 2026-09-07). On the other platforms the correlator filters, and nothing
/// happens here.
pub enum Watch<'a> {
    /// Let everything through. Only for `trace`: there it should be visible
    /// what the sensor actually delivers, not what a rule lets through.
    All,
    /// Only these folders — plus, for `taint_ttl`, whatever a process
    /// writes that has read from them. Without the second part the copy on
    /// the desktop would stay invisible.
    ///
    /// An empty list means "no file events at all" — the right state as
    /// long as there is no rule.
    Folders {
        paths: &'a [String],
        taint_ttl: std::time::Duration,
    },
}

/// Set the sensors' filter.
///
/// Lives here and not on the Windows sensor, so the agent never has to name
/// a platform-specific module past the `Sensor` seam. `Watch::All` exists
/// so that `trace` no longer has to do that either: before, "everything"
/// could not be expressed through this seam, and that is exactly why
/// `trace` reached into `windows::etw` directly.
pub fn set_watched(watch: Watch<'_>) {
    match watch {
        Watch::All => filter::set_file_filter(None, filter::DEFAULT_TAINT_TTL),
        Watch::Folders { paths, taint_ttl } => {
            filter::set_file_filter(Some(paths.to_vec()), taint_ttl)
        }
    }
}

/// Folders whose opens are refused ([`deelpe_core::config::Guard`]). Only
/// the Linux open guard reads them; the listener marks what is set here.
pub fn set_guarded(guards: &[deelpe_core::config::Guard]) {
    filter::set_guarded(guards)
}

/// Events that were lost because the engine could not keep up. Goes to the
/// central server as sensor status: silent loss is worse than a red line.
/// Only Windows counts them; 0 everywhere else.
pub fn dropped_events() -> u64 {
    filter::dropped()
}

/// All sensors of the current platform.
pub fn platform_sensors() -> Vec<SensorSpec> {
    #[cfg(target_os = "macos")]
    {
        vec![
            SensorSpec {
                name: "eslogger",
                make: |_| Box::new(macos::eslogger::EsLogger::default()),
            },
            SensorSpec {
                name: "nettop",
                make: |s| Box::new(macos::nettop::NetTop::new(s)),
            },
        ]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            SensorSpec {
                name: "fanotify",
                make: |_| Box::new(linux::fanotify::Fanotify),
            },
            SensorSpec {
                name: "procnet",
                make: |s| Box::new(linux::procnet::ProcNet::new(s)),
            },
            SensorSpec {
                name: "hermes",
                make: |_| Box::new(hermes::Hermes),
            },
            SensorSpec {
                name: "llm guard",
                make: |_| Box::new(guardlog::GuardLog),
            },
            SensorSpec {
                name: "open guard",
                make: |_| Box::new(linux::guard::OpenGuard),
            },
        ]
    }
    #[cfg(windows)]
    {
        // One session for both providers: file and network events come out
        // of the same stream, in the order in which they happened.
        vec![SensorSpec {
            name: "etw",
            make: |_| Box::new(windows::etw::Etw),
        }]
    }
}
