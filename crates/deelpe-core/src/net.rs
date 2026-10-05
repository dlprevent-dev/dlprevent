//! An agent's network link to the central server: enrollment with a check
//! of the CA fingerprint, and the HTTPS client with a client certificate.
//!
//! Lives here and not in the individual agent, so that the check against
//! man-in-the-middle does not drift apart into two versions: the Mac
//! service (`deelpe`) and the Windows server agent (`deelpe-winagent`) use
//! the same code. All that stays platform-dependent is where the
//! credentials live and how the file is protected against onlookers — that
//! each agent does for itself.

use crate::central::{
    AgentKind, EnrollRequest, EnrollResponse, RenewRequest, RenewResponse, Report, ReportResponse,
    API_VERSION,
};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(20);
/// Timeout for the agent program; see [`Client::binary`].
const BINARY_TIMEOUT: Duration = Duration::from_secs(300);

/// This many days before expiry an agent renews its certificate.
/// Generously sized: a device that runs only occasionally must not miss
/// the window — after that the only thing left is a fresh enrollment by
/// hand.
pub const RENEW_BEFORE_DAYS: i64 = 30;

/// What an enrolled agent needs in order to report. The private key is in
/// here and never leaves the device; where this is stored is for the agent
/// to decide.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub url: String,
    pub agent_id: String,
    pub ca_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn pem_first_der(pem: &str) -> Result<Vec<u8>> {
    let mut r = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut r).collect::<std::result::Result<_, _>>()?;
    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| anyhow!("no certificate in the PEM"))
}

/// Expiry of the agent's own certificate. The agent reads it from the
/// certificate itself and not from the configuration: only the certificate
/// decides whether the connection still comes about.
pub fn cert_not_after(cert_pem: &str) -> Result<DateTime<Utc>> {
    let der = pem_first_der(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow!("certificate unreadable: {e}"))?;
    DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
        .ok_or_else(|| anyhow!("certificate has an impossible expiry"))
}

/// Is it time to renew the certificate? An unreadable certificate says no:
/// a renewal changes nothing about that, and the agent would otherwise end
/// up in a loop that never comes good.
pub fn needs_renewal(cert_pem: &str) -> bool {
    match cert_not_after(cert_pem) {
        Ok(t) => t - Utc::now() < chrono::Duration::days(RENEW_BEFORE_DAYS),
        Err(_) => false,
    }
}

/// HTTP client with the central server's CA and the agent's own certificate.
pub struct Client {
    http: reqwest::Client,
    url: String,
}

impl Client {
    pub fn new(c: &Credentials) -> Result<Self> {
        Self::with_user_agent(c, concat!("deelpe/", env!("CARGO_PKG_VERSION")))
    }

    pub fn with_user_agent(c: &Credentials, ua: &str) -> Result<Self> {
        let ca = reqwest::Certificate::from_pem(c.ca_pem.as_bytes()).context("CA")?;
        let mut id = c.cert_pem.clone();
        id.push('\n');
        id.push_str(&c.key_pem);
        let identity = reqwest::Identity::from_pem(id.as_bytes()).context("certificate/key")?;
        let http = reqwest::Client::builder()
            .add_root_certificate(ca) // reqwest 0.13 without roots feature: only this CA counts
            .identity(identity)
            .timeout(TIMEOUT)
            .user_agent(ua.to_string())
            .build()?;
        Ok(Self {
            http,
            url: c.url.trim_end_matches('/').to_string(),
        })
    }

    pub async fn report(&self, r: &Report) -> Result<ReportResponse> {
        let resp = self
            .http
            .post(format!("{}/agent/report", self.url))
            .json(r)
            .send()
            .await
            .context("Verbindung")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "central server answers {status}: {}",
                body.chars().take(200).collect::<String>()
            );
        }
        resp.json().await.context("answer")
    }

    /// The agent program that the central server keeps ready for **this**
    /// agent. Which platform is meant is decided by the central server from
    /// the certificate — the agent does not say it, and so cannot fetch
    /// itself the program belonging to somebody else's role. Only the
    /// architecture comes along: within its own role that is the one choice
    /// left (Linux, `amd64` or `arm64`), and the Windows role ignores it.
    ///
    /// Nothing is checked here: the checksum is in the answer to the
    /// report, and whoever downloads has to hold it against the bytes
    /// before writing them anywhere.
    /// The program and the release statement that came with it, if any.
    pub async fn binary(&self) -> Result<(Vec<u8>, Option<String>)> {
        // Its own timeout: the twenty seconds for a report are enough for
        // four and a half megabytes only on a fast line, and on a slow one
        // the agent would otherwise never get past the download.
        let resp = self
            .http
            .get(format!(
                "{}/agent/binary?arch={}",
                self.url,
                crate::central::arch()
            ))
            .timeout(BINARY_TIMEOUT)
            .send()
            .await
            .context("Verbindung")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "central server does not hand out the agent program ({status}): {}",
                body.chars().take(200).collect::<String>()
            );
        }
        let statement = resp
            .headers()
            .get(crate::central::RELEASE_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| crate::signing::b64(v).ok())
            .and_then(|b| String::from_utf8(b).ok());
        Ok((resp.bytes().await.context("answer")?.to_vec(), statement))
    }

    /// New key pair, new CSR, new certificate — over the existing
    /// connection, which already identifies the agent. The old key is
    /// replaced in the process, not carried on with. Returns certificate
    /// and key; where those belong only the agent knows.
    pub async fn renew(&self, hostname: &str) -> Result<(String, String, DateTime<Utc>)> {
        let key = rcgen::KeyPair::generate().context("generate key")?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, hostname);
        let csr = params.serialize_request(&key)?;
        let req = RenewRequest {
            api_version: API_VERSION,
            csr_pem: csr.pem()?,
        };
        let resp = self
            .http
            .post(format!("{}/agent/renew", self.url))
            .json(&req)
            .send()
            .await
            .context("Verbindung")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!(
                "central server refuses the renewal ({status}): {}",
                body.chars().take(200).collect::<String>()
            );
        }
        let rr: RenewResponse = resp.json().await.context("renewal answer")?;
        Ok((rr.cert_pem, key.serialize_pem(), rr.not_after))
    }
}

/// Renews the certificate when the time has come, and returns the new
/// credentials together with the new expiry. `Ok(None)` means: nothing to
/// do yet.
///
/// The saving is the caller's job — only after that may it rebuild the
/// client. If the saving goes wrong, it keeps the old credentials and gets
/// in once more during the central server's grace period.
pub async fn renew_if_due(
    client: &Client,
    creds: &Credentials,
    hostname: &str,
) -> Result<Option<(Credentials, DateTime<Utc>)>> {
    if !needs_renewal(&creds.cert_pem) {
        return Ok(None);
    }
    let (cert_pem, key_pem, not_after) = client.renew(hostname).await?;
    Ok(Some((
        Credentials {
            cert_pem,
            key_pem,
            ..creds.clone()
        },
        not_after,
    )))
}

/// What an enrollment brings back besides the credentials.
#[derive(Debug, Clone)]
pub struct Enrolled {
    pub creds: Credentials,
    /// See [`crate::central::EnrollResponse::non_persistent`].
    pub non_persistent: bool,
    /// The state the agent last left with the central server.
    pub roaming: Option<serde_json::Value>,
}

/// Enrollment with the central server. `ca_sha256` is the fingerprint from
/// the dashboard; without a match nothing happens.
pub async fn enroll(
    url: &str,
    token: &str,
    ca_sha256: &str,
    hostname: &str,
    kind: AgentKind,
    version: &str,
) -> Result<Enrolled> {
    let url = url.trim_end_matches('/');
    let expected = ca_sha256.trim().to_lowercase().replace(':', "");
    if expected.len() != 64 {
        bail!("--ca-sha256: expected 64 hex characters (the dashboard shows it under Agents)");
    }
    // Step 1: fetch the CA. The connection is not trustworthy yet, the
    // fingerprint decides.
    let probe = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(TIMEOUT)
        .build()?;
    let ca_pem = probe
        .get(format!("{url}/agent/ca"))
        .send()
        .await
        .context("central server not reachable")?
        .error_for_status()?
        .text()
        .await?;
    let der = pem_first_der(&ca_pem).context("CA of the central server")?;
    let got = sha256_hex(&der);
    if got != expected {
        bail!("CA fingerprint does not match: server {got}, expected {expected}. Wrong address, or someone in between.");
    }
    // Step 2: on with the checked CA.
    let ca = reqwest::Certificate::from_pem(ca_pem.as_bytes())?;
    let http = reqwest::Client::builder()
        .add_root_certificate(ca)
        .timeout(TIMEOUT)
        .build()?;
    let key = rcgen::KeyPair::generate().context("generate key")?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, hostname);
    let csr = params.serialize_request(&key)?;
    let req = EnrollRequest {
        api_version: API_VERSION,
        token: token.trim().to_string(),
        hostname: hostname.to_string(),
        kind,
        version: version.to_string(),
        csr_pem: csr.pem()?,
    };
    let resp = http
        .post(format!("{url}/agent/enroll"))
        .json(&req)
        .send()
        .await
        .context("enrollment request")?;
    let status = resp.status();
    if !status.is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        bail!(
            "enrollment rejected ({status}): {}",
            body.get("error").and_then(|e| e.as_str()).unwrap_or("?")
        );
    }
    let er: EnrollResponse = resp.json().await.context("enrollment answer")?;
    if er.ca_pem.trim() != ca_pem.trim() {
        bail!("the central server returns a different CA than before");
    }
    Ok(Enrolled {
        creds: Credentials {
            url: url.to_string(),
            agent_id: er.agent_id,
            ca_pem,
            cert_pem: er.cert_pem,
            key_pem: key.serialize_pem(),
        },
        non_persistent: er.non_persistent,
        roaming: er.roaming,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate that expires in `days` days.
    fn cert_expiring_in(days: i64) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.not_before = rcgen::date_time_ymd(2000, 1, 1);
        let end = chrono::Utc::now() + chrono::Duration::days(days);
        p.not_after = time::OffsetDateTime::from_unix_timestamp(end.timestamp()).unwrap();
        p.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn reads_expiry_from_the_certificate() {
        let pem = cert_expiring_in(100);
        let got = cert_not_after(&pem).unwrap();
        let want = chrono::Utc::now() + chrono::Duration::days(100);
        assert!((got - want).num_seconds().abs() < 60, "{got} != {want}");
        assert!(cert_not_after("not a certificate").is_err());
    }

    /// Renewal happens before expiry, not after: once expired the
    /// connection no longer comes about, and the renewal would run into
    /// the void.
    #[test]
    fn renews_only_inside_the_window() {
        assert!(!needs_renewal(&cert_expiring_in(RENEW_BEFORE_DAYS + 5)));
        assert!(needs_renewal(&cert_expiring_in(RENEW_BEFORE_DAYS - 5)));
        assert!(needs_renewal(&cert_expiring_in(1)));
        // Expired: it is worth a try, costs nothing, and the message in
        // the log tells the operator what is going on.
        assert!(needs_renewal(&cert_expiring_in(-1)));
        // Unreadable: do not keep trying to renew, otherwise the agent
        // runs into a loop that never comes good.
        assert!(!needs_renewal("not a certificate"));
    }
}
