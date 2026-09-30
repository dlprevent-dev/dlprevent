//! An own CA for agent certificates and the server certificate. Created on
//! the first start, loaded from `data_dir` afterwards. The agent generates
//! its key itself and sends a CSR; here it is only signed.

use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const SERVER_CERT: &str = "server.pem";
const SERVER_KEY: &str = "server.key";
/// Agent certificates are valid for two years; the renewal comes with Z2.
pub const AGENT_CERT_DAYS: i64 = 730;
const CA_YEARS: i64 = 10;
const SERVER_DAYS: i64 = 825;
/// This early the server certificate gets reissued at startup. A server
/// that starts more often than once a month notices nothing of it.
const RENEW_BEFORE_DAYS: i64 = 30;

pub struct Pki {
    pub ca_pem: String,
    pub ca_fingerprint: String,
    issuer: Issuer<'static, KeyPair>,
    pub ui_config: Arc<ServerConfig>,
    pub agent_config: Arc<ServerConfig>,
}

pub fn fingerprint(der: &[u8]) -> String {
    let d = Sha256::digest(der);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Atomic and 0600: `fs::write` followed by `set_permissions` would leave
/// the key lying there briefly with the permissions of the umask.
fn write_private(path: &Path, data: &str) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(data.as_bytes())?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Pki {
    pub fn load_or_create(dir: &Path, server_names: &[String]) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("{} anlegen", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        let ca_cert_path = dir.join(CA_CERT);
        let ca_key_path = dir.join(CA_KEY);
        let (ca_pem, ca_key) = if ca_cert_path.exists() && ca_key_path.exists() {
            let key = KeyPair::from_pem(&fs::read_to_string(&ca_key_path)?).context("ca.key")?;
            (fs::read_to_string(&ca_cert_path)?, key)
        } else {
            let mut p = CertificateParams::new(Vec::<String>::new())?;
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.distinguished_name.push(DnType::CommonName, "de-el-pe CA");
            p.distinguished_name
                .push(DnType::OrganizationName, "de-el-pe");
            p.key_usages = vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ];
            p.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
            p.not_after = OffsetDateTime::now_utc() + Duration::days(365 * CA_YEARS);
            let key = KeyPair::generate()?;
            let cert = p.self_signed(&key)?;
            write_private(&ca_key_path, &key.serialize_pem())?;
            fs::write(&ca_cert_path, cert.pem())?;
            (cert.pem(), key)
        };
        let ca_der = pem_to_der(&ca_pem).context("ca.pem")?;
        let ca_fingerprint = fingerprint(&ca_der);
        let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).context("CA laden")?;

        // A new server certificate when it is missing or the names no longer fit.
        let s_cert_path = dir.join(SERVER_CERT);
        let s_key_path = dir.join(SERVER_KEY);
        let usable = s_cert_path.exists()
            && s_key_path.exists()
            && cert_usable(&fs::read_to_string(&s_cert_path)?, server_names);
        let (server_pem, server_key_pem) = if usable {
            (
                fs::read_to_string(&s_cert_path)?,
                fs::read_to_string(&s_key_path)?,
            )
        } else {
            let mut p = CertificateParams::new(server_names.to_vec())?;
            p.distinguished_name.push(
                DnType::CommonName,
                server_names
                    .first()
                    .map(String::as_str)
                    .unwrap_or("deelpe-server"),
            );
            p.is_ca = IsCa::NoCa;
            p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            p.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ];
            p.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
            p.not_after = OffsetDateTime::now_utc() + Duration::days(SERVER_DAYS);
            let key = KeyPair::generate()?;
            let cert = p.signed_by(&key, &issuer)?;
            write_private(&s_key_path, &key.serialize_pem())?;
            fs::write(&s_cert_path, cert.pem())?;
            (cert.pem(), key.serialize_pem())
        };
        let chain = vec![
            CertificateDer::from(pem_to_der(&server_pem)?),
            CertificateDer::from(ca_der.clone()),
        ];
        let key = private_key_from_pem(&server_key_pem)?;

        let ui_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain.clone(), key.clone_key())?;
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der))?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .allow_unauthenticated()
            .build()
            .map_err(|e| anyhow!("{e}"))?;
        let agent_config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)?;

        Ok(Self {
            ca_pem,
            ca_fingerprint,
            issuer,
            ui_config: Arc::new(ui_config),
            agent_config: Arc::new(agent_config),
        })
    }

    /// Signs an agent's CSR. Only the public key is taken from it: the CN is
    /// the agent ID and every extension is ours, no matter what the agent
    /// asked for. A subjectAltName it chose would otherwise be vouched for by
    /// this CA towards everything that trusts it. Returns PEM, fingerprint,
    /// expiry.
    pub fn sign_agent(
        &self,
        csr_pem: &str,
        agent_id: Uuid,
    ) -> Result<(String, String, chrono::DateTime<chrono::Utc>)> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).context("CSR")?;
        csr.params = CertificateParams::default();
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params
            .distinguished_name
            .push(DnType::CommonName, agent_id.to_string());
        csr.params.is_ca = IsCa::NoCa;
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        let not_after = OffsetDateTime::now_utc() + Duration::days(AGENT_CERT_DAYS);
        csr.params.not_after = not_after;
        let cert = csr.signed_by(&self.issuer)?;
        let fp = fingerprint(cert.der());
        let exp = chrono::DateTime::from_timestamp(not_after.unix_timestamp(), 0)
            .unwrap_or_else(chrono::Utc::now);
        Ok((cert.pem(), fp, exp))
    }
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut r = std::io::Cursor::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut r).collect::<std::result::Result<_, _>>()?;
    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| anyhow!("no certificate in the PEM"))
}

fn private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut r = std::io::Cursor::new(pem.as_bytes());
    rustls_pemfile::private_key(&mut r)?.ok_or_else(|| anyhow!("no key in the PEM"))
}

/// Is the existing server certificate still good? It has to carry all the
/// required names **and** be valid for long enough. Without the expiry
/// check an expired certificate would be sitting there after `SERVER_DAYS`
/// that nobody replaces — and every agent would fail on the same day.
fn cert_usable(pem: &str, names: &[String]) -> bool {
    let Ok(der) = pem_to_der(pem) else {
        return false;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(&der) else {
        return false;
    };
    if cert
        .validity()
        .time_to_expiration()
        .map(|d| d < Duration::days(RENEW_BEFORE_DAYS))
        .unwrap_or(true)
    {
        return false;
    }
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    let mut have: Vec<String> = Vec::new();
    for n in &san.value.general_names {
        match n {
            x509_parser::extensions::GeneralName::DNSName(d) => have.push(d.to_string()),
            x509_parser::extensions::GeneralName::IPAddress(ip) => {
                if ip.len() == 4 {
                    have.push(std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string());
                } else if ip.len() == 16 {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(ip);
                    have.push(std::net::Ipv6Addr::from(o).to_string());
                }
            }
            _ => {}
        }
    }
    names
        .iter()
        .all(|n| have.iter().any(|h| h.eq_ignore_ascii_case(n)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed certificate with the given names and remaining lifetime.
    fn cert(names: &[&str], days: i64) -> String {
        let mut p = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap();
        p.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        p.not_after = OffsetDateTime::now_utc() + Duration::days(days);
        let key = KeyPair::generate().unwrap();
        p.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn keeps_a_certificate_that_has_the_names_and_time_left() {
        let names = vec!["dlp.firma.local".to_string()];
        assert!(cert_usable(&cert(&["dlp.firma.local"], 400), &names));
    }

    #[test]
    fn replaces_it_when_a_name_is_missing() {
        let names = vec!["dlp.firma.local".to_string(), "10.0.0.10".to_string()];
        assert!(!cert_usable(&cert(&["dlp.firma.local"], 400), &names));
    }

    /// The case that otherwise only shows up after 825 days: the names fit,
    /// but the certificate is about to expire.
    #[test]
    fn replaces_it_shortly_before_it_expires() {
        let names = vec!["dlp.firma.local".to_string()];
        assert!(!cert_usable(
            &cert(&["dlp.firma.local"], RENEW_BEFORE_DAYS - 1),
            &names
        ));
    }

    /// A CSR that asks for names, a CA flag and server use gets none of
    /// them: whatever trusts this CA would otherwise take an agent for
    /// `admin.dlp.internal`.
    #[test]
    fn an_agent_certificate_carries_nothing_the_csr_asked_for() {
        let dir = std::env::temp_dir().join(format!("deelpe-pki-test-{}", Uuid::new_v4()));
        let pki = Pki::load_or_create(&dir, &["localhost".into()]).unwrap();
        fs::remove_dir_all(&dir).ok();
        let mut p = CertificateParams::new(vec![
            "admin.dlp.internal".to_string(),
            "10.0.0.1".to_string(),
        ])
        .unwrap();
        p.distinguished_name
            .push(DnType::CommonName, "attacker-chosen-cn");
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::CodeSigning,
        ];
        let csr = p
            .serialize_request(&KeyPair::generate().unwrap())
            .unwrap()
            .pem()
            .unwrap();

        let id = Uuid::new_v4();
        let (pem, _, _) = pki.sign_agent(&csr, id).unwrap();
        let der = pem_to_der(&pem).unwrap();
        let (_, c) = x509_parser::parse_x509_certificate(&der).unwrap();
        assert!(
            c.subject_alternative_name().unwrap().is_none(),
            "no SAN from the request"
        );
        assert_eq!(
            c.subject()
                .iter_common_name()
                .next()
                .and_then(|n| n.as_str().ok()),
            Some(id.to_string().as_str())
        );
        assert_eq!(
            c.subject().iter().count(),
            1,
            "the agent id is the whole subject"
        );
        assert!(
            c.basic_constraints().unwrap().is_none_or(|b| !b.value.ca),
            "not a CA"
        );
        let eku = c.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.client_auth && !eku.server_auth && !eku.code_signing && !eku.any);
        let ku = c.key_usage().unwrap().unwrap().value;
        assert!(ku.digital_signature() && !ku.key_cert_sign());
    }
}
