//! Agent programs for downloading from the dashboard.
//!
//! With this the customer gets the enrollment command **and** the program
//! from the same place, instead of somebody mailing EXEs around. The files
//! live in the data directory (`<data_dir>/agents/`), not in the database:
//! they are megabyte blobs, they belong next to the CA and the server
//! certificate, and an update is a file swap.
//!
//! Only an administrator may upload. Whoever writes here determines what
//! lands on the machines of the workforce — that is why the fingerprint
//! (SHA-256) is in the list, so that what gets delivered can be checked.

use crate::auth::{bad, not_found, Admin, ApiError, User};
use crate::state::Shared;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Platform → file name. Hard-wired: the name never comes from the
/// request, so that no `..` can end up in the path.
///
/// **Two artifacts, three roles.** Workstation and file server share the
/// same EXE under Windows — which loop it runs is decided by the enrollment
/// (`--endpoint`) and afterwards stands in `central.json`. For macOS it is
/// the app bundle; the service is created by the app itself.
///
/// **Linux keeps the bare program, one per architecture**, not the `.deb`:
/// the agent reports the fingerprint of `/usr/bin/deelpe`, and only the same
/// file can be compared against it (`update_due`). The `.deb` is for the
/// first install; from then on the agent replaces its program itself.
const KNOWN: &[(&str, &str)] = &[
    ("windows", "deelpe-winagent.exe"),
    ("mac", "DLPrevent.zip"),
    ("linux-amd64", "deelpe-linux-amd64"),
    ("linux-arm64", "deelpe-linux-arm64"),
];

/// Generous: the Windows agent sits at ~4,5 MB, the Mac binary higher.
const MAX_UPLOAD: usize = 64 * 1024 * 1024;

/// Platform and file name, for everything that runs across all known
/// programs — the list in the dashboard and the fetch from a release.
pub fn known() -> &'static [(&'static str, &'static str)] {
    KNOWN
}

fn file_name(platform: &str) -> Option<&'static str> {
    KNOWN.iter().find(|(p, _)| *p == platform).map(|(_, f)| *f)
}

fn path_for(st: &Shared, platform: &str) -> Option<std::path::PathBuf> {
    file_name(platform).map(|f| st.data_dir.join("agents").join(f))
}

#[derive(Serialize)]
pub struct Binary {
    platform: &'static str,
    file_name: &'static str,
    /// If the file is missing, everything but `platform`/`file_name` is empty.
    present: bool,
    size: u64,
    sha256: String,
    uploaded_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Which program belongs to an agent. The role is in the database
/// (`agents.kind`), but the file hangs only on the platform: workstation
/// and file server share the same EXE under Windows.
///
/// `None` means: for this role there is nothing here. Linux falls under
/// that — before, it fell into the same branch as macOS and could have
/// downloaded a Mac bundle.
pub fn platform_for(kind: Option<&str>) -> Option<&'static str> {
    match kind {
        Some("windows_server") | Some("windows_client") => Some("windows"),
        // `None` is the enrollment dialog without a role choice: that one
        // means the Mac, as it always has.
        Some("mac") | None => Some("mac"),
        _ => None,
    }
}

/// The program for an agent of this role on this architecture, as it
/// fetches it itself: the enrollment's file for Windows and the Mac, the
/// architecture's program for Linux. `arch` in Debian's spelling.
pub fn program_for(kind: &str, arch: &str) -> Option<&'static str> {
    platform_for(Some(kind)).or_else(|| self_replacing_platform(kind, arch))
}

/// Roles for which the central server may **order** an update — that is,
/// the ones that can replace themselves: Windows, and Linux on an
/// architecture we keep a program for. An agent that does not say its
/// architecture (older than the field) gets nothing.
///
/// Not the Mac, and that is not convenience: as its fingerprint the macOS
/// service reports the one of its program file (`build_fingerprint` over
/// `current_exe`), but what lies ready is the zip around the whole bundle.
/// The one checksum can never be the beginning of the other — `update_due`
/// would **always** be true there, and every Mac would get the same order
/// in every answer, one that it cannot carry out. Whoever retrofits macOS
/// first needs a fingerprint over the same artifact (ADR 0004).
pub fn self_replacing_platform(kind: &str, arch: &str) -> Option<&'static str> {
    match (kind, arch) {
        ("windows_server" | "windows_client", _) => Some("windows"),
        ("linux", "amd64") => Some("linux-amd64"),
        ("linux", "arm64") => Some("linux-arm64"),
        _ => None,
    }
}

/// SHA-256 of the program lying ready, for the enrollment command and for
/// the question whether an agent runs a different one than the one lying
/// here. `None` when nothing has been uploaded.
///
/// It is only computed when modification time or size differ. This line is
/// in **every** answer to an agent; without the cache, with ten thousand
/// agents on a half-minute cycle, the central server would read around a
/// gigabyte per second off the disk just to come out with the same number
/// every time. A file swap changes both, a `touch` only the time — both
/// lead to a recomputation, and more than that is not needed.
pub fn sha256_of(st: &Shared, platform: &str) -> Option<String> {
    cached(st, platform).map(|(sha, _)| sha)
}

/// The program lying ready itself, for the agent that fetches it.
pub fn read(st: &Shared, platform: &str) -> Option<(&'static str, axum::body::Bytes)> {
    let name = file_name(platform)?;
    let (_, bytes) = cached(st, platform)?;
    Some((name, bytes))
}

/// Checksum and bytes of the program lying ready, cached.
///
/// Reading and computing only happen when modification time or size
/// differ. A file swap changes both, a `touch` only the time — both lead to
/// a re-read, and more than that is not needed.
fn cached(st: &Shared, platform: &str) -> Option<(String, axum::body::Bytes)> {
    let f = file_name(platform)?;
    let path = st.data_dir.join("agents").join(f);
    let meta = std::fs::metadata(&path).ok()?;
    let (mtime, len) = (meta.modified().ok()?, meta.len());
    if let Some((m, l, sha, bytes)) = st.binary_sha.lock().unwrap().get(platform) {
        if *m == mtime && *l == len {
            return Some((sha.clone(), bytes.clone()));
        }
    }
    let bytes = axum::body::Bytes::from(std::fs::read(&path).ok()?);
    let sha = hex(&Sha256::digest(&bytes));
    st.binary_sha.lock().unwrap().insert(
        platform.to_string(),
        (mtime, len, sha.clone(), bytes.clone()),
    );
    Some((sha, bytes))
}

/// Wrap the program up as a response. Needed twice: once for the
/// dashboard, once for the agent.
pub fn as_download(name: &str, bytes: axum::body::Bytes) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}\""),
            ),
        ],
        bytes,
    )
        .into_response()
}

/// Download over the **agent port**, identified by a valid, as yet unused
/// enrollment token in the `X-Deelpe-Token` header.
///
/// Without it a freshly set-up machine would first have to sign in at the
/// dashboard to get the agent — nobody does that. The token is **not**
/// burned here; the enrollment itself takes care of that.
pub fn agent_router() -> Router<Shared> {
    Router::new().route("/agent/binary/{platform}", get(agent_download))
}

async fn agent_download(
    State(st): State<Shared>,
    Path(platform): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    let token = headers
        .get("x-deelpe-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_string();
    if token.is_empty() {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "enrollment token required".into(),
        ));
    }
    let hash = crate::auth::sha256_hex(&token);
    let row: Option<(bool, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT COALESCE(uses >= max_uses, false), expires_at FROM enroll_tokens WHERE token_hash = $1").bind(&hash).fetch_optional(&st.pool).await?;
    match row {
        Some((false, exp)) if exp >= chrono::Utc::now() => {}
        _ => {
            return Err(ApiError(
                StatusCode::UNAUTHORIZED,
                "token unknown, used or expired".into(),
            ))
        }
    }
    let (name, bytes) = read(&st, &platform).ok_or_else(not_found)?;
    Ok(as_download(name, bytes))
}

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/api/binaries", get(list))
        .route(
            "/api/binaries/{platform}",
            get(download).post(upload).delete(remove),
        )
        .layer(axum::extract::DefaultBodyLimit::max(MAX_UPLOAD))
}

/// What lies ready? Every signed-in user may see this — the enrollment
/// command without the matching program is of no use to anybody.
async fn list(_u: User, State(st): State<Shared>) -> Result<Json<Vec<Binary>>, ApiError> {
    let mut out = Vec::new();
    for (platform, file_name) in KNOWN {
        let p = st.data_dir.join("agents").join(file_name);
        // Over the same cache as everything else: the dashboard should not
        // compute a second time the very checksum that stands in every
        // answer to an agent.
        let (present, size, sha256, uploaded_at) = match cached(&st, platform) {
            Some((sha, bytes)) => {
                let at = std::fs::metadata(&p)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(chrono::DateTime::<chrono::Utc>::from);
                (true, bytes.len() as u64, sha, at)
            }
            None => (false, 0, String::new(), None),
        };
        out.push(Binary {
            platform,
            file_name,
            present,
            size,
            sha256,
            uploaded_at,
        });
    }
    Ok(Json(out))
}

async fn download(
    _u: User,
    State(st): State<Shared>,
    Path(platform): Path<String>,
) -> Result<Response, ApiError> {
    let (name, bytes) = read(&st, &platform).ok_or_else(not_found)?;
    Ok(as_download(name, bytes))
}

/// The signature to an upload, base64 as `deelpe-sign` writes it into the
/// `.sig` file. Only asked for when a release key exists.
#[derive(Deserialize)]
struct UploadQuery {
    sig: Option<String>,
}

async fn upload(
    Admin(a): Admin,
    State(st): State<Shared>,
    Path(platform): Path<String>,
    Query(q): Query<UploadQuery>,
    body: Bytes,
) -> Result<Json<Binary>, ApiError> {
    if file_name(&platform).is_none() {
        return Err(bad("unknown platform"));
    }
    if body.is_empty() {
        return Err(bad("empty upload"));
    }
    // With a release key, the key decides what reaches the fleet — through
    // the release channel **and** through this form. Otherwise the key would
    // only guard the door nobody has to use: one administrator login could
    // still hand every endpoint any program.
    let key = crate::release::pubkey(&st)
        .await
        .map_err(|e| bad(format!("{e:#}")))?;
    if let Some(key) = &key {
        let sig = q
            .sig
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                bad("a signing key is configured: upload the program together with its .sig file")
            })?;
        let name = file_name(&platform).unwrap_or_default();
        let version = crate::release::verify_release(&body, sig, key, name)
            .map_err(|e| bad(format!("signature: {e:#}")))?;
        install_signed(&st, &platform, &body, &version, sig)
            .await
            .map_err(|e| bad(format!("{e:#}")))?;
    } else {
        install(&st, &platform, &body).map_err(|e| bad(format!("{e:#}")))?;
        // No key here to check it with — but the agents may carry one. The
        // statement is passed on as it came; an agent with the key checks
        // it, and without it an agent carrying the key would never update.
        if let Some(sig) = q.sig.as_deref().filter(|s| !s.trim().is_empty()) {
            let path = path_for(&st, &platform).ok_or_else(|| bad("unknown platform"))?;
            write_atomic(&statement_path(&path), sig.as_bytes())
                .map_err(|e| bad(format!("{e:#}")))?;
        }
    }
    let sha256 = hex(&Sha256::digest(&body));
    tracing::info!(platform, bytes = body.len(), "agent binary uploaded");
    crate::db::audit(&st.pool, (&a).into(), "binary_upload", serde_json::json!({ "platform": platform, "size": body.len(), "sha256": sha256, "signed": key.is_some() })).await;
    Ok(Json(Binary {
        platform: KNOWN
            .iter()
            .find(|(p, _)| *p == platform)
            .map(|(p, _)| *p)
            .unwrap_or("?"),
        file_name: file_name(&platform).unwrap_or("?"),
        present: true,
        size: body.len() as u64,
        sha256,
        uploaded_at: Some(chrono::Utc::now()),
    }))
}

async fn remove(
    Admin(a): Admin,
    State(st): State<Shared>,
    Path(platform): Path<String>,
) -> Result<StatusCode, ApiError> {
    let path = path_for(&st, &platform).ok_or_else(not_found)?;
    let _ = std::fs::remove_file(statement_path(&path));
    let _ = std::fs::remove_file(path);
    crate::db::audit(
        &st.pool,
        (&a).into(),
        "binary_remove",
        serde_json::json!({ "platform": platform }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Put a program into the staging folder. One path for both sources: the
/// file picker in the dashboard and the release (`release.rs`).
///
/// First write next to it, then rename: an aborted write must never be a
/// half file that somebody installs. And **nothing** is checked here —
/// whoever arrives here already has their check behind them (the signature on
/// the release, and on an upload whenever a key exists).
pub fn install(st: &Shared, platform: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let path =
        path_for(st, platform).ok_or_else(|| anyhow::anyhow!("unknown platform {platform}"))?;
    check_header(platform, bytes)?;
    write_atomic(&path, bytes)?;
    // An unsigned program carries no statement; one left over from the
    // previous program would only make the agents refuse this one.
    let _ = std::fs::remove_file(statement_path(&path));
    Ok(())
}

/// First write next to it, then rename.
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow::anyhow!("bad path"))?;
    std::fs::create_dir_all(dir)?;
    // Its own intermediate name per write. There are two sources — the
    // file picker and the release —, and with a fixed `.part` two
    // simultaneous operations would write into the same file. The rename
    // would then publish a mixture whose checksum is right and which the
    // agents install as valid.
    let tmp = path.with_extension(format!("part-{}", uuid::Uuid::new_v4()));
    let out = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, path));
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(out?)
}

/// `<program>.sig`, next to the program.
fn statement_path(program: &std::path::Path) -> std::path::PathBuf {
    let mut p = program.as_os_str().to_owned();
    p.push(".sig");
    p.into()
}

/// The signed statement of the program lying ready, as the release or the
/// upload brought it. The agents get it with the program and check it
/// themselves (`deelpe_core::update::check_release`).
pub fn release_statement(st: &Shared, platform: &str) -> Option<String> {
    std::fs::read_to_string(statement_path(&path_for(st, platform)?)).ok()
}

/// The version each slot holds, as its signature stated it.
const VERSIONS: &str = "agent_program_versions";

/// [`install`] for a program whose signature named its version, refusing
/// one older than what the slot already held. A genuinely signed old build
/// is still an old build: without this, whoever controlled the release (or
/// an administrator login) could roll every endpoint back to a version with
/// a known hole. The record outlives a deleted program for the same reason.
///
/// The statement is kept next to the program: the agents check it again.
/// Written first — should the program then fail to land, the old program
/// meets a statement that does not fit it, and agents refuse rather than
/// swap.
pub async fn install_signed(
    st: &Shared,
    platform: &str,
    bytes: &[u8],
    version: &str,
    statement: &str,
) -> anyhow::Result<()> {
    use crate::release::parse_version;
    let mut held = crate::db::settings_map(&st.pool, &[VERSIONS])
        .await?
        .remove(VERSIONS)
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(have) = held.get(platform).and_then(|v| v.as_str()) {
        if parse_version(version) < parse_version(have) {
            anyhow::bail!("version {version} is older than the {have} this server already had for {platform} — a signed old build is still an old build");
        }
    }
    let path =
        path_for(st, platform).ok_or_else(|| anyhow::anyhow!("unknown platform {platform}"))?;
    check_header(platform, bytes)?;
    write_atomic(&statement_path(&path), statement.as_bytes())?;
    write_atomic(&path, bytes)?;
    held[platform] = serde_json::json!(version);
    crate::db::set_setting(&st.pool, VERSIONS, held).await
}

/// A Windows program starts with "MZ", a zip with "PK", a Linux program with
/// the ELF magic — and names its machine at byte 18: `amd64` is 62, `arm64`
/// is 183. An arm64 program in the amd64 slot would start on no machine it
/// is sent to.
///
/// The test does not catch a malicious program — it catches the swapped
/// file, and that is the mistake that really happens here. It deliberately
/// stands **here** and not only at upload: a release that by accident
/// attaches the Linux file as `deelpe-winagent.exe` is cleanly signed — the
/// signature says who sent the file, not what is inside it. Without these
/// two lines every Windows machine would replace its program with one that
/// does not start.
fn check_header(platform: &str, bytes: &[u8]) -> anyhow::Result<()> {
    match platform {
        "windows" if !bytes.starts_with(b"MZ") => {
            anyhow::bail!("that is not a Windows program (no MZ header)")
        }
        "mac" if !bytes.starts_with(b"PK") => {
            anyhow::bail!("that is not a zip archive (no PK header)")
        }
        "linux-amd64" | "linux-arm64" => {
            if !bytes.starts_with(b"\x7fELF") {
                anyhow::bail!("that is not a Linux program (no ELF header) — upload the bare deelpe, not the .deb");
            }
            let machine = bytes.get(18..20).map(|m| u16::from_le_bytes([m[0], m[1]]));
            let want = if platform == "linux-amd64" { 62 } else { 183 };
            if machine != Some(want) {
                anyhow::bail!(
                    "that Linux program is built for a different architecture than {platform}"
                );
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    /// Both sources — file picker and release — run through `install`, and
    /// both have to fail on the swapped file.
    #[test]
    fn a_swapped_file_does_not_get_stored() {
        assert!(super::check_header("windows", b"MZ\x90\x00").is_ok());
        assert!(super::check_header("mac", b"PK\x03\x04").is_ok());
        // The classic mistake: the Linux file attached as .exe.
        assert!(super::check_header("windows", b"\x7fELF").is_err());
        assert!(super::check_header("mac", b"MZ\x90\x00").is_err());
        assert!(super::check_header("windows", b"").is_err());
        // Linux: ELF, and the right machine. The .deb (an `ar` archive) and
        // the other architecture both fail.
        let elf = |machine: u16| {
            let mut b = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00".to_vec();
            b.extend_from_slice(&machine.to_le_bytes());
            b
        };
        assert!(super::check_header("linux-amd64", &elf(62)).is_ok());
        assert!(super::check_header("linux-arm64", &elf(183)).is_ok());
        assert!(super::check_header("linux-amd64", &elf(183)).is_err());
        assert!(super::check_header("linux-amd64", b"!<arch>\ndebian-binary").is_err());
        // An unknown platform has no header that we know; it fails even
        // earlier, at `path_for`.
        assert!(super::check_header("bsd", b"egal").is_ok());
    }
}
