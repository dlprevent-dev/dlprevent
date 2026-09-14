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
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Platform → file name. Hard-wired: the name never comes from the
/// request, so that no `..` can end up in the path.
///
/// **Two artifacts, three roles.** Workstation and file server share the
/// same EXE under Windows — which loop it runs is decided by the enrollment
/// (`--endpoint`) and afterwards stands in `central.json`. For macOS it is
/// the app bundle; the service is created by the app itself.
const KNOWN: &[(&str, &str)] = &[("windows", "deelpe-winagent.exe"), ("mac", "DLPrevent.zip")];

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

/// Roles for which the central server may **order** an update — that is,
/// the ones that can replace themselves.
///
/// Only Windows, and that is not convenience: as its fingerprint the macOS
/// service reports the one of its program file (`build_fingerprint` over
/// `current_exe`), but what lies ready is the zip around the whole bundle.
/// The one checksum can never be the beginning of the other — `update_due`
/// would **always** be true there, and every Mac would get the same order
/// in every answer, one that it cannot carry out. Whoever retrofits macOS
/// first needs a fingerprint over the same artifact (ADR 0004).
pub fn self_replacing_platform(kind: &str) -> Option<&'static str> {
    matches!(kind, "windows_server" | "windows_client").then_some("windows")
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
    st.binary_sha.lock().unwrap().insert(platform.to_string(), (mtime, len, sha.clone(), bytes.clone()));
    Some((sha, bytes))
}

/// Wrap the program up as a response. Needed twice: once for the
/// dashboard, once for the agent.
pub fn as_download(name: &str, bytes: axum::body::Bytes) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
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
    let token = headers.get("x-deelpe-token").and_then(|v| v.to_str().ok()).unwrap_or("").trim().to_string();
    if token.is_empty() {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "enrollment token required".into()));
    }
    let hash = crate::auth::sha256_hex(&token);
    let row: Option<(bool, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT uses >= max_uses, expires_at FROM enroll_tokens WHERE token_hash = $1").bind(&hash).fetch_optional(&st.pool).await?;
    match row {
        Some((false, exp)) if exp >= chrono::Utc::now() => {}
        _ => return Err(ApiError(StatusCode::UNAUTHORIZED, "token unknown, used or expired".into())),
    }
    let (name, bytes) = read(&st, &platform).ok_or_else(not_found)?;
    Ok(as_download(name, bytes))
}

pub fn router() -> Router<Shared> {
    Router::new()
        .route("/api/binaries", get(list))
        .route("/api/binaries/{platform}", get(download).post(upload).delete(remove))
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
                let at = std::fs::metadata(&p).ok().and_then(|m| m.modified().ok()).map(chrono::DateTime::<chrono::Utc>::from);
                (true, bytes.len() as u64, sha, at)
            }
            None => (false, 0, String::new(), None),
        };
        out.push(Binary { platform, file_name, present, size, sha256, uploaded_at });
    }
    Ok(Json(out))
}

async fn download(_u: User, State(st): State<Shared>, Path(platform): Path<String>) -> Result<Response, ApiError> {
    let (name, bytes) = read(&st, &platform).ok_or_else(not_found)?;
    Ok(as_download(name, bytes))
}

async fn upload(Admin(_a): Admin, State(st): State<Shared>, Path(platform): Path<String>, body: Bytes) -> Result<Json<Binary>, ApiError> {
    if file_name(&platform).is_none() {
        return Err(bad("unknown platform"));
    }
    if body.is_empty() {
        return Err(bad("empty upload"));
    }
    install(&st, &platform, &body).map_err(|e| bad(format!("{e:#}")))?;
    tracing::info!(platform, bytes = body.len(), "agent binary uploaded");
    Ok(Json(Binary {
        platform: KNOWN.iter().find(|(p, _)| *p == platform).map(|(p, _)| *p).unwrap_or("?"),
        file_name: file_name(&platform).unwrap_or("?"),
        present: true,
        size: body.len() as u64,
        sha256: hex(&Sha256::digest(&body)),
        uploaded_at: Some(chrono::Utc::now()),
    }))
}

async fn remove(Admin(_a): Admin, State(st): State<Shared>, Path(platform): Path<String>) -> Result<StatusCode, ApiError> {
    let path = path_for(&st, &platform).ok_or_else(not_found)?;
    let _ = std::fs::remove_file(path);
    Ok(StatusCode::NO_CONTENT)
}

/// Put a program into the staging folder. One path for both sources: the
/// file picker in the dashboard and the release (`release.rs`).
///
/// First write next to it, then rename: an aborted write must never be a
/// half file that somebody installs. And **nothing** is checked here —
/// whoever arrives here already has their check behind them (MZ header on
/// upload, signature on the release).
pub fn install(st: &Shared, platform: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let path = path_for(st, platform).ok_or_else(|| anyhow::anyhow!("unknown platform {platform}"))?;
    check_header(platform, bytes)?;
    let dir = path.parent().ok_or_else(|| anyhow::anyhow!("bad path"))?;
    std::fs::create_dir_all(dir)?;
    // Its own intermediate name per write. There are two sources — the
    // file picker and the release —, and with a fixed `.part` two
    // simultaneous operations would write into the same file. The rename
    // would then publish a mixture whose checksum is right and which the
    // agents install as valid.
    let tmp = path.with_extension(format!("part-{}", uuid::Uuid::new_v4()));
    let out = std::fs::write(&tmp, bytes).and_then(|()| std::fs::rename(&tmp, &path));
    if out.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(out?)
}

/// A Windows program starts with "MZ", a zip with "PK".
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
        "windows" if !bytes.starts_with(b"MZ") => anyhow::bail!("that is not a Windows program (no MZ header)"),
        "mac" if !bytes.starts_with(b"PK") => anyhow::bail!("that is not a zip archive (no PK header)"),
        _ => Ok(()),
    }
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
        // An unknown platform has no header that we know; it fails even
        // earlier, at `path_for`.
        assert!(super::check_header("bsd", b"egal").is_ok());
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
