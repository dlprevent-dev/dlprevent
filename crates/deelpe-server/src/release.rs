//! Fetch new agent versions from a release instead of uploading them by
//! hand.
//!
//! The path behind it already exists: whatever lies in the staging folder
//! (`<data_dir>/agents/`) is what `binaries.rs` hands out to the agents.
//! This module fills the staging folder — from the releases of a Git
//! server instead of from a human's file picker.
//!
//! **The signature decides, not the origin.** Pushing a file from the
//! network onto every workstation of a workforce is exactly the path along
//! which supply chains get attacked. A checksum from the same release is no
//! protection against that: whoever can change the release changes the
//! checksum with it. That is why every program carries a detached
//! signature, and it is checked against a key that does **not** come from
//! the release.
//!
//! Only what a human triggers is fetched, and nothing at all is rolled out:
//! `fetch` puts the file into the staging folder, no more. Who brings it
//! onto the devices is decided afterwards as before — button on the agent
//! or master switch (ADR 0004). A server that passes things through on its
//! own from the network all the way to the workstation would be a path
//! nobody can stop any more.

use crate::state::Shared;
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::time::Duration;

/// This is how often the server looks by itself. Six hours: a new version
/// is not news that matters to the minute, and a foreign server should not
/// be asked more often than necessary.
const CHECK_EVERY: Duration = Duration::from_secs(6 * 60 * 60);
/// Timeout for asking about the release.
const API_TIMEOUT: Duration = Duration::from_secs(20);
/// Timeout for the program itself — megabytes, possibly over a line that
/// someone shares.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);
/// More than this the server does not accept. Same as with an upload in
/// the dashboard (`binaries::MAX_UPLOAD`), for the same reason: a release
/// that runs out of hand must not fill the disk.
const MAX_ASSET: u64 = 64 * 1024 * 1024;

pub use deelpe_core::signing::BUILT_IN_PUBKEY;

/// What the last query turned up. Kept in memory like `abuseipdb::Status`:
/// it describes the running process, not the installation. What concerns
/// the installation — which version was really fetched — lives in
/// `settings`.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Status {
    pub checked_at: Option<DateTime<Utc>>,
    pub tag: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub url: Option<String>,
    /// Which programs the release brings along (`windows`, `mac`).
    pub platforms: Vec<String>,
    /// Why it did not work. Shown in the dashboard, not only in the log: a
    /// server that has found nothing for weeks otherwise looks like one for
    /// which there simply is nothing new.
    pub error: Option<String>,
}

/// A release, as far as it counts here. The Git server's answer has thirty
/// more fields; they are nobody's business.
#[derive(Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub html_url: String,
    pub published_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
    /// The API address of the same asset. Only GitHub sends it; Gitea does
    /// not know the field, there it stays empty.
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub size: u64,
}

/// Where the asset is fetched from.
///
/// With GitHub **not** `browser_download_url`: that address points at
/// another host which does not evaluate the token in the header, and a
/// private repo answers there with 404. The API address of the same asset
/// delivers the file — with `Accept: application/octet-stream`, see `get`.
/// Gitea sends no `url`, there the existing path stays.
///
/// Only on the repository's own host (`repo`, scheme, name and port). The
/// release document is the peer's answer: if it could name any address,
/// whoever answers `/releases/latest` would pick where this server sends
/// its next requests — the token in the header included.
fn source_of<'a>(asset: &'a Asset, repo: &reqwest::Url) -> Result<&'a str> {
    let src = if asset.url.is_empty() {
        &asset.browser_download_url
    } else {
        &asset.url
    };
    if reqwest::Url::parse(src).ok().map(|u| u.origin()) != Some(repo.origin()) {
        bail!(
            "{src} is not on the repository's host {}",
            repo.origin().ascii_serialization()
        );
    }
    Ok(src)
}

/// Program and matching signature in a release.
///
/// The signature lies next to it as a file of its own, `<name>.sig`. If it
/// is missing that is not half a find but none at all: without a signature
/// nothing is fetched, and a release without one should stand out, not slip
/// through.
pub fn assets_for<'a>(assets: &'a [Asset], file_name: &str) -> Option<(&'a Asset, &'a Asset)> {
    let sig_name = format!("{file_name}.sig");
    let file = assets.iter().find(|a| a.name == file_name)?;
    let sig = assets.iter().find(|a| a.name == sig_name)?;
    Some((file, sig))
}

/// Does this release carry a program that we can distribute?
pub fn platforms_in(assets: &[Asset]) -> Vec<String> {
    crate::binaries::known()
        .iter()
        .filter(|(_, file)| assets_for(assets, file).is_some())
        .map(|(p, _)| p.to_string())
        .collect()
}

// The statement format and its check live in `deelpe_core::signing`, shared
// with the agents, which check the same statement before they swap.
pub use deelpe_core::signing::{check_pubkey, parse_version, verify_release};

/// The key that is checked against.
///
/// The compiled-in one wins: it cannot be swapped out through the database.
/// If there is none, the one from the settings applies — then the trust
/// boundary is the administrator login, and that is the same boundary as
/// for uploading by hand.
pub async fn pubkey(st: &Shared) -> Result<Option<String>> {
    if let Some(k) = BUILT_IN_PUBKEY.map(str::trim).filter(|k| !k.is_empty()) {
        return Ok(Some(k.to_string()));
    }
    Ok(crate::db::setting_str(&st.pool, "release_pubkey")
        .await?
        .filter(|k| !k.trim().is_empty()))
}

/// Credentials for a **private** repo. Empty means public.
///
/// Without them the channel stays limited to public releases: a self-hosted
/// Gitea answers 404 for a private repo, and it does so for the files
/// themselves too. The token only goes to the address that the operator
/// entered.
pub async fn token(st: &Shared) -> Result<Option<String>> {
    Ok(crate::db::setting_str(&st.pool, "release_token")
        .await?
        .filter(|t| !t.trim().is_empty()))
}

fn client(timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(timeout)
        // Without a name of our own some Git servers do not answer at all.
        .user_agent(concat!("deelpe-server/", env!("CARGO_PKG_VERSION")))
        // A redirect is the peer's answer too: without this, the https-only
        // repository and `source_of` are one `302 Location: http://…` away
        // from any plain-HTTP address (169.254.169.254, an internal admin
        // page). GitHub sends its assets on to an https host; that stays.
        .redirect(reqwest::redirect::Policy::custom(|a| {
            if a.previous().len() >= 10 {
                a.error("too many redirects")
            } else if a.url().scheme() != "https" {
                a.error("redirect away from https")
            } else {
                a.follow()
            }
        }))
        .build()?)
}

/// The address of the latest release. `repo` is either `owner/name`
/// (then GitHub) or a full address — that keeps a self-hosted Gitea
/// reachable, whose API has the same shape.
///
/// A full address has to be `https://`: the token and the release travel
/// over it. Its host is not restricted — a Gitea on the local network is
/// normal for a server that stands on premises.
pub fn latest_url(repo: &str) -> Result<reqwest::Url> {
    let r = repo.trim().trim_end_matches('/');
    let name = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    };
    let full = if r.contains("://") {
        format!("{r}/releases/latest")
    } else {
        match r.split_once('/') {
            Some((owner, repo)) if name(owner) && name(repo) => {
                format!("https://api.github.com/repos/{r}/releases/latest")
            }
            _ => bail!("repository {r:?} is neither owner/name nor an https:// address"),
        }
    };
    let url = reqwest::Url::parse(&full)
        .with_context(|| format!("repository {r:?} is not an address"))?;
    if url.scheme() != "https"
        || url.host().is_none()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("repository {r:?} must be an https:// address — the token and the release travel over it");
    }
    Ok(url)
}

/// Look at what is there. Changes nothing except the note in memory.
pub async fn check(st: &Shared) -> Result<Status> {
    let repo = crate::db::setting_str(&st.pool, "release_repo")
        .await?
        .unwrap_or_default();
    if repo.trim().is_empty() {
        bail!("no repository configured — Settings, Interfaces");
    }
    let url = latest_url(&repo)?;
    let tok = token(st).await?;
    let out = match fetch_latest(&url, tok.as_deref()).await {
        Ok(r) => Status {
            checked_at: Some(Utc::now()),
            tag: Some(r.tag_name.clone()),
            published_at: r.published_at,
            url: (!r.html_url.is_empty()).then_some(r.html_url.clone()),
            platforms: platforms_in(&r.assets),
            error: None,
        },
        // The last good find stays in place, only the error is added to it.
        // Otherwise a single hiccup in name resolution turns "v2 is ready"
        // into a bare error message: button and link disappear and only come
        // back on the next run, up to six hours later.
        Err(e) => Status {
            checked_at: Some(Utc::now()),
            error: Some(format!("{e:#}")),
            ..st.release.lock().unwrap().clone()
        },
    };
    match (&out.error, &out.tag) {
        // Into the log, not only into the dashboard: whoever wants to know
        // whether the server looks outwards at all should not have to read
        // it off the absence of an error.
        (None, Some(tag)) => tracing::info!(tag, platforms = ?out.platforms, "release checked"),
        (Some(e), _) => tracing::warn!("release check failed: {e}"),
        (None, None) => {}
    }
    *st.release.lock().unwrap() = out.clone();
    Ok(out)
}

/// More than this is no longer a release description. Generous: GitHub
/// sends a few kilobytes, a Gitea with many assets more.
const MAX_METADATA: u64 = 2 * 1024 * 1024;

async fn fetch_latest(url: &reqwest::Url, token: Option<&str>) -> Result<Release> {
    let resp = auth(client(API_TIMEOUT)?.get(url.clone()), token)
        .send()
        .await
        .with_context(|| format!("asking {url}"))?;
    let status = resp.status();
    // The description is read under a cap too, not only the program: it is
    // the same foreign peer, and an endless JSON body fills memory long
    // before the timeout counts.
    let body = read_capped(resp, MAX_METADATA)
        .await
        .with_context(|| format!("reading the answer of {url}"))?;
    if !status.is_success() {
        bail!(
            "{url} answers {status}: {}",
            String::from_utf8_lossy(&body)
                .chars()
                .take(200)
                .collect::<String>()
        );
    }
    serde_json::from_slice(&body).context("the answer is not a release")
}

/// Fetch the programs of the latest release, verify them and put them into
/// the staging folder. Returns which platforms were renewed.
///
/// **Nothing is rolled out.** Afterwards the file lies where an upload
/// lands too; it reaches the devices only once someone presses the button.
pub async fn fetch(st: &Shared) -> Result<(String, Vec<String>, Vec<String>)> {
    let Some(key) = pubkey(st).await? else {
        bail!("no signing key configured — without it nothing from the network is trusted");
    };
    let repo = crate::db::setting_str(&st.pool, "release_repo")
        .await?
        .unwrap_or_default();
    if repo.trim().is_empty() {
        bail!("no repository configured — Settings, Interfaces");
    }
    let url = latest_url(&repo)?;
    let tok = token(st).await?;
    let rel = fetch_latest(&url, tok.as_deref()).await?;
    let http = client(DOWNLOAD_TIMEOUT)?;
    let mut done = Vec::new();
    let mut failed: Vec<String> = Vec::new();
    for (platform, file_name) in crate::binaries::known() {
        let Some((asset, sig)) = assets_for(&rel.assets, file_name) else {
            continue;
        };
        // The reported size only saves a futile download; the limit that
        // counts sits in `get`.
        // A failure on one platform must not drag the other one down with
        // it. Before, the whole call aborted: the Windows program was
        // already in the staging folder by then — and with the master
        // switch on it was distributed as well —, while the answer reported
        // an error and nobody knew what now applied.
        match one(&http, asset, sig, &url, &key, st, platform, tok.as_deref()).await {
            Ok(n) => {
                tracing::info!(platform, tag = %rel.tag_name, bytes = n, "agent program fetched from the release and verified");
                done.push(platform.to_string());
            }
            Err(e) => {
                tracing::warn!(platform, tag = %rel.tag_name, "release asset refused: {e:#}");
                failed.push(format!("{}: {e:#}", asset.name));
            }
        }
    }
    if done.is_empty() {
        if !failed.is_empty() {
            bail!("nothing was stored — {}", failed.join("; "));
        }
        bail!("release {} carries no signed agent program (expected e.g. deelpe-winagent.exe and deelpe-winagent.exe.sig)", rel.tag_name);
    }
    // The version applies to what was really fetched. Without the platforms
    // next to it the card claimed "v2 is what you have" while the Mac bundle
    // still came from v1.
    crate::db::set_settings(
        &st.pool,
        &[
            ("release_installed_tag", serde_json::json!(rel.tag_name)),
            ("release_installed_platforms", serde_json::json!(done)),
        ],
    )
    .await?;
    if !failed.is_empty() {
        // Not an error — something was fetched —, but it must not get lost.
        tracing::warn!(tag = %rel.tag_name, "some assets of the release were refused: {}", failed.join("; "));
    }
    Ok((rel.tag_name, done, failed))
}

/// Download, but no more than `cap`.
///
/// The size from the Git server's answer is a **claim** by that same
/// server, the one whose file we are precisely not believing. Whoever
/// checks it up front and then reads without a brake has checked nothing at
/// all: a peer that says "four megabytes" and then sends endlessly fills
/// the server's memory. That is why it is read in chunks and aborted when
/// it goes over.
/// One artifact: download, verify, store. Returns its size.
#[allow(clippy::too_many_arguments)]
async fn one(
    http: &reqwest::Client,
    asset: &Asset,
    sig: &Asset,
    repo: &reqwest::Url,
    key: &str,
    st: &Shared,
    platform: &str,
    token: Option<&str>,
) -> Result<usize> {
    // The announced size only saves a futile download.
    if asset.size > MAX_ASSET {
        bail!(
            "announces {} bytes, more than this server accepts",
            asset.size
        );
    }
    let bytes = get(http, source_of(asset, repo)?, MAX_ASSET, token).await?;
    // A signed statement is a few hundred characters. A kilobyte is
    // generous and keeps a peer from sending a book here.
    let sig_text = String::from_utf8(get(http, source_of(sig, repo)?, 1024, token).await?)
        .context("signature file is not text")?;
    // Verify first, then write. A file that makes it into the staging
    // folder and only stands out there is one that could already have been
    // delivered.
    let version = verify_release(&bytes, &sig_text, key, &asset.name)
        .context("does not carry a valid signature from the configured key")?;
    crate::binaries::install_signed(st, platform, &bytes, &version, &sig_text).await?;
    Ok(bytes.len())
}

/// The token in the header, if one is stored. Both Git servers understand
/// the same form.
fn auth(rb: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    match token {
        Some(t) => rb.header(reqwest::header::AUTHORIZATION, format!("token {t}")),
        None => rb,
    }
}

async fn get(http: &reqwest::Client, url: &str, cap: u64, token: Option<&str>) -> Result<Vec<u8>> {
    // Without this here, the API address of an asset delivers the
    // description as JSON instead of the file. Where the address already
    // points straight at the file (Gitea), the header changes nothing.
    let resp = auth(
        http.get(url)
            .header(reqwest::header::ACCEPT, "application/octet-stream"),
        token,
    )
    .send()
    .await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("{url} answers {status}");
    }
    read_capped(resp, cap)
        .await
        .with_context(|| format!("reading {url}"))
}

/// Read an answer, but no more than `cap`.
///
/// The announced length is a **claim** by that same peer whom we are
/// precisely not believing. Whoever checks it up front and then reads
/// without a brake has checked nothing at all: whoever says "four
/// megabytes" and then sends endlessly fills the server's memory. The
/// announcement therefore only saves a futile download; the limit that
/// counts is the one counted chunk by chunk here.
async fn read_capped(mut resp: reqwest::Response, cap: u64) -> Result<Vec<u8>> {
    if resp.content_length().is_some_and(|n| n > cap) {
        bail!("announces more than {cap} bytes");
    }
    let mut out: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if out.len() as u64 + chunk.len() as u64 > cap {
            bail!("sends more than {cap} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Look by itself, so that the dashboard says there is something new
/// without anyone having to ask for it. This fetches nothing.
pub async fn run(state: Shared, stop: tokio_util::sync::CancellationToken) -> Result<()> {
    loop {
        let on = crate::db::setting_bool(&state.pool, "release_check_enabled", false)
            .await
            .unwrap_or(false);
        if on {
            // `check` logs by itself what it did or did not find; what
            // remains here is only what went wrong before the query.
            if let Err(e) = check(&state).await {
                tracing::warn!("release check not attempted: {e:#}");
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(CHECK_EVERY) => {}
            _ = stop.cancelled() => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use deelpe_core::signing::{statement, verify};

    fn asset(name: &str) -> Asset {
        Asset {
            name: name.into(),
            browser_download_url: format!("https://example.invalid/{name}"),
            url: String::new(),
            size: 10,
        }
    }

    /// A key pair such as `deelpe-sign keygen` produces.
    fn keypair() -> (String, ring::signature::Ed25519KeyPair) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        use ring::signature::KeyPair;
        (b64_encode(kp.public_key().as_ref()), kp)
    }

    fn b64_encode(bytes: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            for i in 0..4 {
                if i <= c.len() {
                    out.push(A[((n >> (18 - i * 6)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// The core promise: only what was signed with **this** key gets
    /// through. Without it the release would be a way to put an arbitrary
    /// program onto every workstation of a workforce.
    #[test]
    fn only_what_the_key_signed_is_accepted() {
        let (pubkey, kp) = keypair();
        let bytes = b"MZ ein Programm";
        let sig = b64_encode(kp.sign(bytes).as_ref());

        assert!(verify(bytes, &sig, &pubkey).is_ok());
        // One character different in the file — and the signature no longer fits.
        assert!(verify(b"MZ ein Programm!", &sig, &pubkey).is_err());
        // A signature from someone else, using the same algorithm.
        let (_, other) = keypair();
        assert!(verify(bytes, &b64_encode(other.sign(bytes).as_ref()), &pubkey).is_err());
        // And a foreign key against the genuine signature.
        let (other_pub, _) = keypair();
        assert!(verify(bytes, &sig, &other_pub).is_err());
    }

    /// The `.sig` file states slot, version and checksum, and the signature
    /// covers all three: an old build cannot be relabelled as a new one, nor
    /// the Linux file passed off as the Windows one.
    #[test]
    fn a_signature_binds_the_file_to_its_slot_and_version() {
        let (pubkey, kp) = keypair();
        let bytes = b"MZ ein Programm";
        let sha = crate::pki::fingerprint(bytes);
        let sig_file = |file: &str, version: &str| {
            let st = statement(file, version, &sha);
            format!("{st}sig: {}\n", b64_encode(kp.sign(st.as_bytes()).as_ref()))
        };
        let good = sig_file("deelpe-winagent.exe", "0.1.8");
        assert_eq!(
            verify_release(bytes, &good, &pubkey, "deelpe-winagent.exe").unwrap(),
            "0.1.8"
        );
        assert!(
            verify_release(bytes, &good, &pubkey, "deelpe-linux-amd64").is_err(),
            "another slot"
        );
        assert!(
            verify_release(b"MZ ein Programm!", &good, &pubkey, "deelpe-winagent.exe").is_err(),
            "another file"
        );
        let relabelled = good.replace("version: 0.1.8", "version: 0.2.0");
        assert!(
            verify_release(bytes, &relabelled, &pubkey, "deelpe-winagent.exe").is_err(),
            "the version is signed too"
        );
        assert!(
            verify_release(
                bytes,
                &b64_encode(kp.sign(bytes).as_ref()),
                &pubkey,
                "deelpe-winagent.exe"
            )
            .is_err(),
            "a bare signature says no version"
        );
        assert!(
            verify_release(
                bytes,
                &sig_file("deelpe-winagent.exe", "latest"),
                &pubkey,
                "deelpe-winagent.exe"
            )
            .is_err(),
            "not a version"
        );
        assert!(
            parse_version("v0.1.10") > parse_version("0.1.9"),
            "numbers, not text"
        );
        assert_eq!(parse_version("0.1.x"), None);
    }

    /// Whatever does not have the right shape is refused before `ring` sees
    /// it — with a message that says what is missing.
    #[test]
    fn a_key_or_signature_of_the_wrong_shape_is_refused() {
        let (pubkey, kp) = keypair();
        let sig = b64_encode(kp.sign(b"x").as_ref());
        assert!(verify(b"x", &sig, "")
            .unwrap_err()
            .to_string()
            .contains("32 bytes"));
        // The same check protects storing in the settings — otherwise a
        // typo only shows up once the program has already been downloaded.
        assert!(check_pubkey(&pubkey).is_ok());
        assert!(check_pubkey("").is_err());
        assert!(
            check_pubkey("dGVzdA==").is_err(),
            "vier Bytes sind kein ed25519-Schluessel"
        );
        assert!(check_pubkey("nicht base64 !!").is_err());
        assert!(verify(b"x", "", &pubkey)
            .unwrap_err()
            .to_string()
            .contains("64 bytes"));
        assert!(verify(b"x", &sig, "nicht base64 !!").is_err());
        // Whitespace and line breaks do no harm: a signature file almost
        // always ends with a line break.
        assert!(verify(b"x", &format!("  {sig}\n"), &format!("{pubkey}\n")).is_ok());
    }

    /// A program without its signature next to it is not half a find but
    /// none at all: it should stand out, not slip through.
    #[test]
    fn a_program_without_its_signature_does_not_count() {
        let with = vec![
            asset("deelpe-winagent.exe"),
            asset("deelpe-winagent.exe.sig"),
            asset("DLPrevent.zip"),
        ];
        assert!(assets_for(&with, "deelpe-winagent.exe").is_some());
        assert!(
            assets_for(&with, "DLPrevent.zip").is_none(),
            "ohne .sig kein Fund"
        );
        assert_eq!(platforms_in(&with), vec!["windows"]);
        assert!(platforms_in(&[]).is_empty());
    }

    /// A private GitHub repo hands the asset out only through its API
    /// address; `browser_download_url` points at a host that does not
    /// evaluate the token and answers with 404. Where there is no `url`
    /// (Gitea), the existing path stays.
    #[test]
    fn a_private_repository_is_asked_through_the_api_address() {
        let gitea = asset("deelpe-winagent.exe");
        let repo = latest_url("https://example.invalid/api/v1/repos/o/r").unwrap();
        assert_eq!(
            source_of(&gitea, &repo).unwrap(),
            "https://example.invalid/deelpe-winagent.exe"
        );
        let github = Asset {
            url: "https://api.github.com/repos/o/r/releases/assets/7".into(),
            ..asset("deelpe-winagent.exe")
        };
        assert_eq!(
            source_of(&github, &latest_url("o/r").unwrap()).unwrap(),
            "https://api.github.com/repos/o/r/releases/assets/7"
        );
    }

    /// The release document names where its files lie — the host is not its
    /// to choose. Otherwise whoever answers `/releases/latest` picks which
    /// address this server asks next, with the token in the header. What
    /// GitHub and Gitea really send (2026-09-29) stays on the repository's
    /// own host: GitHub `url` on `api.github.com`, Gitea
    /// `browser_download_url` next to its API.
    #[test]
    fn a_release_cannot_send_the_download_to_another_host() {
        let repo = latest_url("https://git.example.com/api/v1/repos/owner/dlprevent").unwrap();
        let at = |u: &str| Asset {
            browser_download_url: u.into(),
            ..asset("deelpe-winagent.exe")
        };
        assert!(source_of(
            &at("https://git.example.com/owner/dlprevent/releases/download/v1/deelpe-winagent.exe"),
            &repo
        )
        .is_ok());
        for elsewhere in [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/role",
            "http://127.0.0.1:19998/internal-db-dump",
            "http://git.example.com/owner/dlprevent/releases/download/v1/x",
            "https://git.example.com:8443/x",
            "https://git.example.com.evil.example/x",
            "not a url",
        ] {
            assert!(source_of(&at(elsewhere), &repo).is_err(), "{elsewhere}");
        }
        // GitHub: the API address of the asset is on the API host; the
        // redirect from there to its storage host is GitHub's, not the
        // release document's.
        let github = Asset {
            url: "https://api.github.com/repos/o/r/releases/assets/7".into(),
            ..at("https://github.com/o/r/releases/download/v1/x")
        };
        assert!(source_of(&github, &latest_url("o/r").unwrap()).is_ok());
        let github = Asset {
            url: "https://evil.example/assets/7".into(),
            ..github
        };
        assert!(source_of(&github, &latest_url("o/r").unwrap()).is_err());
    }

    /// A short form means GitHub, a full address stays as it is — so that
    /// a self-hosted Gitea stays reachable.
    #[test]
    fn the_repository_can_be_a_short_name_or_a_full_address() {
        assert_eq!(
            latest_url("owner/dlprevent").unwrap().as_str(),
            "https://api.github.com/repos/owner/dlprevent/releases/latest"
        );
        assert_eq!(
            latest_url("https://git.example.com/api/v1/repos/owner/dlprevent/")
                .unwrap()
                .as_str(),
            "https://git.example.com/api/v1/repos/owner/dlprevent/releases/latest"
        );
        // A self-hosted Gitea on the local network is a normal case for a
        // server that stands on premises — it is not refused for its address.
        assert!(latest_url("https://192.0.2.5:3000/api/v1/repos/o/r").is_ok());
    }

    /// The token and the release travel over this address: never in clear
    /// text, and a short form is `owner/name` and nothing else.
    #[test]
    fn the_repository_is_https_or_owner_slash_name() {
        for bad in [
            "http://git.example.com/api/v1/repos/o/r",
            "ftp://x/y",
            "file:///etc/passwd",
            "https://",
            "o",
            "o/r/x",
            "../x",
            "o/..",
            "o r/x",
            "o/r?x=1",
            "o/r#x",
            "",
        ] {
            assert!(latest_url(bad).is_err(), "{bad}");
        }
        assert!(latest_url("dlprevent-dev/dlprevent").is_ok());
        assert!(latest_url("some_owner/repo.name-2").is_ok());
    }

    /// A redirect is not a way around https-only: a hop to `http://` is
    /// refused, a hop to `https://` is followed (GitHub's asset storage).
    #[tokio::test]
    async fn a_redirect_does_not_leave_https() {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let at = format!("http://{}/", l.local_addr().unwrap());
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut c, _)) = l.accept().await {
                let mut buf = [0u8; 1024];
                let n = c.read(&mut buf).await.unwrap_or(0);
                let to = if String::from_utf8_lossy(&buf[..n]).starts_with("GET /s ") {
                    "https://127.0.0.1:1/x"
                } else {
                    "http://127.0.0.1:1/x"
                };
                c.write_all(format!("HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await.ok();
            }
        });
        let http = client(Duration::from_secs(5)).unwrap();
        assert!(
            http.get(&at).send().await.unwrap_err().is_redirect(),
            "to http: refused"
        );
        let e = http.get(format!("{at}s")).send().await.unwrap_err();
        assert!(
            !e.is_redirect(),
            "to https: followed (and then refused by the closed port) — {e}"
        );
    }
}

/// The signing tool and the verification have to agree with each other.
///
/// They live in two programs and deliberately share no code — `deelpe-sign`
/// brings its own base64 along so that it needs nothing from the server.
/// That is exactly why the two can drift apart without anything breaking:
/// until a server at a customer site refuses a release that the publisher
/// has just signed.
///
/// The values below are therefore not made up but the output of
/// `deelpe-sign keygen` and `deelpe-sign sign <key> deelpe-winagent.exe 0.1.8`
/// over a file holding exactly the six bytes `deelpe` (2026-09-30).
#[cfg(test)]
mod tool_agreement {
    const PUBKEY: &str = "AcwOjMFZHDJepHUujYO8KxgJw1LvQB15VaJBisHY5ys=";
    const MESSAGE: &[u8] = b"deelpe";
    const SIG_FILE: &str = "deelpe-release-v1
file: deelpe-winagent.exe
version: 0.1.8
sha256: c81bfc68acb0520fa25a6c2d62c96cd973aa307c6414dc919974397aff6603d8
sig: jY4OEbOhCRrF1pbgMVTtI2cayG82obF+YzE+S/KEwwJ4CP0oJFkgDkHeg5V4itUYj0vk/2v8ndmH16UVnjklCQ==
";

    #[test]
    fn a_signature_written_by_the_tool_is_one_this_module_accepts() {
        let v = super::verify_release(MESSAGE, SIG_FILE, PUBKEY, "deelpe-winagent.exe")
            .expect("was das Werkzeug schreibt, muss hier durchkommen");
        assert_eq!(v, "0.1.8");
        // And the counter-check, so that the test does not simply accept
        // everything: one byte different, and it is over.
        assert!(super::verify_release(b"deelp3", SIG_FILE, PUBKEY, "deelpe-winagent.exe").is_err());
    }
}
