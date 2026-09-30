use crate::abuseipdb;
use crate::mail;
use crate::pki::Pki;
use axum::http::HeaderMap;
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

/// Failed sign-in attempts per address: after `LOGIN_MAX_FAILS` a pause of
/// `LOGIN_LOCK_SECS`.
pub const LOGIN_MAX_FAILS: u32 = 10;
pub const LOGIN_LOCK_SECS: u64 = 60;
/// This long a second step that has been started (code, passkey, setup)
/// waits for its completion.
pub const PENDING_SECS: u64 = 300;

/// This long the settings for agent answers are valid out of memory.
///
/// Without it every report reads five individual rows from `settings`; with
/// ten thousand agents on a half-minute cycle that is over a thousand
/// queries per second for values that almost never change.
///
/// Five seconds — shorter than any report cycle. Whoever changes an
/// interval or an allow list in the dashboard reaches the agents with it no
/// later than one round after before. And what stands here is configuration
/// on its way to the agent, not a blocking decision: that one the agent
/// makes itself, out of the rule it has had for a long time.
///
/// Deliberately without a callback: an invalidation would have to be
/// maintained by every future writer of `settings`, and whoever forgets it
/// builds a bug that only shows up weeks later. A deadline nobody forgets.
pub const AGENT_SETTINGS_TTL: Duration = Duration::from_secs(5);

/// A step that has been started and is waiting for its counterpart. In
/// memory, not in the database: it lives five minutes, and a restart of the
/// central server may forget it — then somebody types their password again.
pub enum Pending {
    /// The password was right; the code from the app is missing.
    Totp(Uuid),
    /// A fresh secret that the first correct code confirms. Before that it
    /// is written nowhere: an aborted setup leaves nothing behind.
    TotpSetup(Vec<u8>),
    PasskeyRegistration(PasskeyRegistration),
    PasskeyLogin(PasskeyAuthentication),
}

/// The keys of the table, one per kind. An identifier from the network gets
/// its own prefix: that way it can never hit the entry of a setup in
/// progress, whose key consists of the account ID.
impl Pending {
    pub fn login_key(token: &str) -> String {
        format!("login:{token}")
    }
    pub fn passkey_login_key(user: Uuid) -> String {
        format!("passkey-login:{user}")
    }
    pub fn totp_setup_key(user: Uuid) -> String {
        format!("totp-setup:{user}")
    }
    pub fn passkey_reg_key(user: Uuid) -> String {
        format!("passkey-reg:{user}")
    }
}

pub struct AppState {
    pub pool: PgPool,
    pub pki: Arc<Pki>,
    pub login_fails: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    pub pending: Mutex<HashMap<String, (Instant, Pending)>>,
    pub started: chrono::DateTime<chrono::Utc>,
    /// Dashboard runs with TLS: the cookie gets `Secure`.
    pub ui_https: bool,
    /// Port of the agent listener, for the enrollment command in the dashboard.
    pub agent_port: u16,
    /// `X-Forwarded-For` counts as the address of whoever signs in (switch
    /// on only behind a reverse proxy, otherwise the lockout is forgeable).
    pub trust_proxy: bool,
    /// Where the CA, the server certificate — and the agent programs for
    /// downloading live (`<data_dir>/agents/`).
    pub data_dir: std::path::PathBuf,
    /// State of the AbuseIPDB queries (counter, last error, pause). In
    /// memory: it describes the running process, not the installation.
    pub abuse: Mutex<abuseipdb::Status>,
    /// State of the mail sending (counter, last message, last error). In
    /// memory like `abuse`; what must not be forgotten is written as a mark
    /// on the alert or on the agent.
    pub mail: Mutex<mail::Status>,
    /// The settings from `db::agent_settings`, at most
    /// `AGENT_SETTINGS_TTL` old. In memory, because they go into every
    /// single answer to an agent.
    agent_settings: Mutex<Option<(Instant, Arc<crate::db::AgentSettings>)>>,
    /// Platform → (modification time, size, SHA-256, bytes) of the agent
    /// program lying ready. See `binaries::cached`.
    ///
    /// Two reasons, one per field. The **checksum** stands in every answer
    /// to an agent: without the cache every report reads four and a half
    /// megabytes off the disk and runs them through, only to establish that
    /// nothing has changed. The **bytes** go to every agent that fetches its
    /// new program: whoever switches the distribution on sets off a rush in
    /// which otherwise every single download fetches the same file anew from
    /// the disk and allocates it anew. `Bytes` shares the same memory,
    /// cloning costs one counter.
    pub binary_sha: Mutex<HashMap<String, (std::time::SystemTime, u64, String, axum::body::Bytes)>>,
    /// What the last query of the release turned up. In memory like `abuse`
    /// and `mail`: it describes the running process. Which version was
    /// really fetched stands in `settings`.
    pub release: Mutex<crate::release::Status>,
    /// The longest alert retention an administrator may set, in days. Asked
    /// on every save: a license can come and go while the server runs.
    pub alert_retain_max_days: fn() -> i64,
}

/// Ten years of alerts. A build that keeps a company's record for longer
/// raises it through `Extension::alert_retain_max_days`.
pub const ALERT_RETAIN_MAX_DAYS: i64 = 3650;

impl AppState {
    pub fn new(
        pool: PgPool,
        pki: Arc<Pki>,
        ui_https: bool,
        agent_port: u16,
        trust_proxy: bool,
        data_dir: std::path::PathBuf,
    ) -> Self {
        Self {
            pool,
            pki,
            login_fails: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            started: chrono::Utc::now(),
            ui_https,
            agent_port,
            trust_proxy,
            data_dir,
            abuse: Mutex::new(abuseipdb::Status::default()),
            mail: Mutex::new(mail::Status::default()),
            agent_settings: Mutex::new(None),
            binary_sha: Mutex::new(HashMap::new()),
            release: Mutex::new(Default::default()),
            alert_retain_max_days: || ALERT_RETAIN_MAX_DAYS,
        }
    }

    /// The settings for the answer to an agent.
    ///
    /// If the deadline happens to expire while many reports are pending at
    /// the same time, a few of them fetch the value in parallel — instead of
    /// all the others waiting on a holder. One query too many is cheaper
    /// than a lock held across a database round trip.
    pub async fn agent_settings(&self) -> anyhow::Result<Arc<crate::db::AgentSettings>> {
        if let Some((at, s)) = self.agent_settings.lock().unwrap().as_ref() {
            if at.elapsed() < AGENT_SETTINGS_TTL {
                return Ok(s.clone());
            }
        }
        let s = Arc::new(crate::db::agent_settings(&self.pool).await?);
        *self.agent_settings.lock().unwrap() = Some((Instant::now(), s.clone()));
        Ok(s)
    }

    /// The address that counts for the lockout after failed attempts.
    pub fn client_ip(&self, peer: SocketAddr, forwarded: Option<&str>) -> IpAddr {
        client_ip(peer, forwarded, self.trust_proxy)
    }

    /// The name under which the browser sees the central server.
    pub fn public_host<'h>(&self, headers: &'h HeaderMap) -> Option<&'h str> {
        public_host(headers, self.trust_proxy)
    }

    /// The browser speaks HTTPS: with a certificate of its own, or because
    /// the reverse proxy takes over the TLS side. Counts for the `Secure` on
    /// the session cookie and for the origin of the passkeys. A proxy that
    /// itself only offers HTTP is therefore not provided for — and for a
    /// dashboard with alerts from the whole house it is not a situation that
    /// should be served either.
    pub fn public_https(&self) -> bool {
        self.ui_https || self.trust_proxy
    }

    /// True when this address is currently locked out.
    pub fn login_locked(&self, ip: IpAddr) -> bool {
        let mut m = self.login_fails.lock().unwrap();
        match m.get(&ip) {
            Some((n, since)) if *n >= LOGIN_MAX_FAILS => {
                if since.elapsed().as_secs() >= LOGIN_LOCK_SECS {
                    m.remove(&ip);
                    false
                } else {
                    true
                }
            }
            _ => false,
        }
    }

    /// An attempt begins: it counts as failed until it proves otherwise
    /// (`login_ok`, `login_undo`). Checking and counting under one lock is
    /// the point — counting only after the password check let a burst of
    /// parallel requests all pass the gate before the first of them counted.
    /// `false` when the address is locked; then nothing is counted.
    pub fn login_begin(&self, ip: IpAddr) -> bool {
        if self.login_locked(ip) {
            return false;
        }
        let mut m = self.login_fails.lock().unwrap();
        let e = m.entry(ip).or_insert((0, Instant::now()));
        if e.0 >= LOGIN_MAX_FAILS {
            return false;
        }
        e.0 += 1;
        e.1 = Instant::now();
        true
    }

    /// The attempt was no failure but opened no session either: the password
    /// was right and the second step is still to come.
    pub fn login_undo(&self, ip: IpAddr) {
        if let Some(e) = self.login_fails.lock().unwrap().get_mut(&ip) {
            e.0 = e.0.saturating_sub(1);
        }
    }

    pub fn login_ok(&self, ip: IpAddr) {
        self.login_fails.lock().unwrap().remove(&ip);
    }

    /// Put a step on file. Clears out what has expired while doing so, so
    /// that the table does not grow with aborted sign-ins.
    pub fn pending_put(&self, key: impl Into<String>, p: Pending) {
        self.pending_put_at(key, Instant::now(), p);
    }

    /// Put back after a failed attempt — with the old timestamp, so that
    /// wrong codes do not count the five minutes from the start over and over.
    pub fn pending_put_at(&self, key: impl Into<String>, at: Instant, p: Pending) {
        let mut m = self.pending.lock().unwrap();
        m.retain(|_, (at, _)| at.elapsed().as_secs() < PENDING_SECS);
        m.insert(key.into(), (at, p));
    }

    /// Pick the step up — exactly once, together with its start.
    pub fn pending_take(&self, key: &str) -> Option<(Instant, Pending)> {
        let (at, p) = self.pending.lock().unwrap().remove(key)?;
        (at.elapsed().as_secs() < PENDING_SECS).then_some((at, p))
    }
}

pub type Shared = Arc<AppState>;

/// Fingerprint of the client certificate, put into the request by the TLS
/// listener. Missing on the dashboard port and during enrollment.
#[derive(Clone, Debug)]
pub struct PeerCert(pub String);

/// Address of whoever signs in, for the lockout after failed attempts.
/// Without `trust_proxy` always the one of the connection: a header from the
/// network must not be able to dodge the lockout. With a proxy the first
/// entry in `X-Forwarded-For` counts (the client), otherwise all users share
/// the address of the proxy and with it the lockout.
pub fn client_ip(peer: SocketAddr, forwarded: Option<&str>, trust_proxy: bool) -> IpAddr {
    if trust_proxy {
        if let Some(first) = forwarded.and_then(|v| v.split(',').next()) {
            let first = first.trim();
            if let Ok(ip) = first.parse::<IpAddr>() {
                return ip;
            }
            if let Ok(sa) = first.parse::<SocketAddr>() {
                return sa.ip();
            }
            if let Ok(ip) = first
                .trim_matches(|c| c == '[' || c == ']')
                .parse::<IpAddr>()
            {
                return ip;
            }
        }
    }
    peer.ip()
}

/// The name from the browser's address bar. Behind a reverse proxy `Host`
/// carries the name of the central server, not the one the browser knows;
/// then `X-Forwarded-Host` counts — only with `trust_proxy`, otherwise every
/// check on it could be dodged with a header from the network.
pub fn public_host(headers: &HeaderMap, trust_proxy: bool) -> Option<&str> {
    let h = |n| {
        headers
            .get(n)
            .and_then(|v: &axum::http::HeaderValue| v.to_str().ok())
    };
    h("x-forwarded-host")
        .filter(|_| trust_proxy)
        .or_else(|| h("host"))
}

#[derive(Clone, Copy, Debug)]
pub struct PeerAddr(pub SocketAddr);

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> SocketAddr {
        "10.0.0.1:5000".parse().unwrap()
    }

    #[test]
    fn forwarded_header_needs_trust() {
        assert_eq!(
            client_ip(peer(), Some("1.2.3.4"), false),
            peer().ip(),
            "ohne trust_proxy zählt die Verbindung"
        );
        assert_eq!(
            client_ip(peer(), Some("1.2.3.4, 10.0.0.1"), true).to_string(),
            "1.2.3.4"
        );
        assert_eq!(
            client_ip(peer(), Some("[2001:db8::1]:443"), true).to_string(),
            "2001:db8::1"
        );
        assert_eq!(
            client_ip(peer(), Some("2001:db8::1"), true).to_string(),
            "2001:db8::1"
        );
        assert_eq!(client_ip(peer(), Some("kaputt"), true), peer().ip());
        assert_eq!(client_ip(peer(), None, true), peer().ip());
    }

    #[test]
    fn forwarded_host_needs_trust() {
        let mut h = HeaderMap::new();
        h.insert("host", "zentrale.intern:8443".parse().unwrap());
        assert_eq!(
            public_host(&h, true),
            Some("zentrale.intern:8443"),
            "ohne Proxy-Kopf bleibt es beim Host"
        );
        h.insert("x-forwarded-host", "dlp.firma.ch".parse().unwrap());
        assert_eq!(
            public_host(&h, false),
            Some("zentrale.intern:8443"),
            "ohne trust_proxy zählt der Kopf nicht"
        );
        assert_eq!(public_host(&h, true), Some("dlp.firma.ch"));
    }
}
