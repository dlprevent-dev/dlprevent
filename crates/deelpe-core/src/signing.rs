//! The release signature: what `deelpe-sign` writes into a `.sig` file and
//! how it is checked. The central server checks it before it stages a
//! program; the agents check it again before they swap themselves, so that a
//! central server (or whoever holds its administrator login) cannot hand the
//! fleet a program the release key never signed.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// The key that is checked against, when it was already fixed at compile
/// time.
///
/// A compiled-in key cannot be swapped out in the database — that is the
/// difference to one that merely sits in the settings. The same variable
/// builds the server and the agents; an agent built without it swaps in
/// whatever checksum its central server announces, as before.
pub const BUILT_IN_PUBKEY: Option<&str> = option_env!("DEELPE_UPDATE_PUBKEY");

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// First line of a `.sig` file.
const STATEMENT_HEAD: &str = "deelpe-release-v1";

/// What the release key signs: not the bare file but which slot it is for,
/// which version it is, and its checksum. A bare signature over the file
/// said nothing about the version — whoever controlled the release could
/// publish an old, genuinely signed, vulnerable build under a new tag, and
/// every server took it. `deelpe-sign` writes these lines into the `.sig`
/// file, followed by `sig: <base64>` over exactly them.
pub fn statement(file_name: &str, version: &str, sha256_hex: &str) -> String {
    format!("{STATEMENT_HEAD}\nfile: {file_name}\nversion: {version}\nsha256: {sha256_hex}\n")
}

/// Do these bytes really come from whoever holds the key?
///
/// Ed25519 over the whole file, signature and key base64. `ring` is in the
/// tree anyway by way of rustls — no library is added for this.
pub fn verify(bytes: &[u8], sig_b64: &str, pubkey_b64: &str) -> Result<()> {
    let key = check_pubkey(pubkey_b64)?;
    let sig = b64(sig_b64.trim()).context("signature is not base64")?;
    if sig.len() != 64 {
        bail!("signature must be 64 bytes (ed25519), got {}", sig.len());
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &key)
        .verify(bytes, &sig)
        .map_err(|_| {
            anyhow::anyhow!(
                "signature does not match this key — the file is not the one that was signed"
            )
        })
}

/// Check a program against its `.sig` file ([`statement`]) and return the
/// version it was signed as. The slot has to match (`file_name`), and so
/// does the checksum; the signature covers both and the version.
pub fn verify_release(
    bytes: &[u8],
    sig_file: &str,
    pubkey_b64: &str,
    file_name: &str,
) -> Result<String> {
    let mut lines = sig_file.lines().map(str::trim).filter(|l| !l.is_empty());
    if lines.next() != Some(STATEMENT_HEAD) {
        bail!("not a signed release statement — sign it again with `deelpe-sign sign <key> <file> <version>`; a bare signature over the file does not say which version it is");
    }
    let mut field = |name: &str| {
        let prefix = format!("{name}:");
        lines
            .next()
            .and_then(|l| l.strip_prefix(prefix.as_str()))
            .map(|v| v.trim().to_string())
            .ok_or_else(|| {
                anyhow::anyhow!("the signature file has no `{name}:` line where it belongs")
            })
    };
    let (file, version, sha, sig) = (
        field("file")?,
        field("version")?,
        field("sha256")?,
        field("sig")?,
    );
    if file != file_name {
        bail!("signed as {file}, not as {file_name}");
    }
    if parse_version(&version).is_none() {
        bail!("signed version {version:?} is not a version (digits and dots)");
    }
    let actual = sha256_hex(bytes);
    if !sha.eq_ignore_ascii_case(&actual) {
        bail!("the file is not the one that was signed (checksum differs)");
    }
    verify(
        statement(&file, &version, &actual).as_bytes(),
        &sig,
        pubkey_b64,
    )?;
    Ok(version)
}

/// `0.1.8` or `v0.1.8` as numbers, for comparing. `None` for anything else.
pub fn parse_version(v: &str) -> Option<Vec<u64>> {
    let v = v.strip_prefix('v').unwrap_or(v);
    v.split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<Vec<u64>>>()
        .filter(|p| !p.is_empty())
}

/// Does the key even have the shape of an ed25519 key?
///
/// Stands on its own because two places need it: the check itself and
/// storing it in the settings. Whoever checks in only one of them lets a
/// typo through all the way to the point where the whole program has
/// already been downloaded.
pub fn check_pubkey(pubkey_b64: &str) -> Result<Vec<u8>> {
    let key = b64(pubkey_b64.trim()).context("not base64")?;
    if key.len() != 32 {
        bail!("must be 32 bytes (ed25519), got {}", key.len());
    }
    Ok(key)
}

/// Base64 without another library. The alphabet part is a dozen lines.
pub fn b64(s: &str) -> Result<Vec<u8>> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = A
            .iter()
            .position(|a| *a == c)
            .ok_or_else(|| anyhow::anyhow!("not base64: {:?}", c as char))? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}
