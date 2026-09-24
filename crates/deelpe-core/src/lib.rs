//! Platform-independent core of de-el-pe: event model, configuration,
//! correlation. Knows no sensors and no platform.

pub mod access;
pub mod agent;
#[cfg(feature = "net")]
pub mod agentlog;
pub mod allow;
pub mod central;
pub mod config;
pub mod correlate;
pub mod enforce;
pub mod event;
pub mod identity;
pub mod inbound;
pub mod learn;
pub mod rules;
#[cfg(feature = "net")]
pub mod session;
#[cfg(feature = "net")]
pub mod net;
#[cfg(feature = "net")]
pub mod update;
pub mod netaddr;
pub mod path;
pub mod pipeline;
