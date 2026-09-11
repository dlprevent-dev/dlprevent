//! Sign releases. The counterpart to `release::verify`.
//!
//! Without a tool here the signature check would be a hurdle without a
//! door: the central server accepts only signed programs, and nobody could
//! produce any. Ed25519 by way of `ring`, which is in the tree anyway.
//!
//! ```text
//! deelpe-sign keygen release.key          # once; writes release.key + shows the public one
//! deelpe-sign sign release.key deelpe-winagent.exe   # writes deelpe-winagent.exe.sig
//! ```
//!
//! **The private key does not belong in the repo and not onto the central
//! server.** It stays with the publisher; the central server knows only the
//! public one. Whoever keeps both in the same place has given up the
//! separation that is what makes this signature worth anything at all.

use ring::signature::{Ed25519KeyPair, KeyPair};
use std::process::ExitCode;

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(B64[((n >> (18 - i * 6)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") if args.len() == 3 => keygen(&args[2]),
        Some("sign") if args.len() == 4 => sign(&args[2], &args[3]),
        _ => {
            eprintln!("deelpe-sign keygen <key-file>");
            eprintln!("deelpe-sign sign <key-file> <file>      writes <file>.sig next to it");
            eprintln!();
            eprintln!("The public key goes into the central server (Settings, Interfaces), or into");
            eprintln!("the build as DEELPE_UPDATE_PUBKEY. The private key stays with whoever releases.");
            ExitCode::FAILURE
        }
    }
}

fn keygen(path: &str) -> ExitCode {
    if std::path::Path::new(path).exists() {
        eprintln!("{path} exists — refusing to overwrite a private key");
        return ExitCode::FAILURE;
    }
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = match Ed25519KeyPair::generate_pkcs8(&rng) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("no key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("frisch erzeugt");
    if let Err(e) = write_private(path, pkcs8.as_ref()) {
        eprintln!("{path}: {e}");
        return ExitCode::FAILURE;
    }
    println!("private key: {path}  (keep it out of the repository)");
    println!("public key:  {}", b64(kp.public_key().as_ref()));
    ExitCode::SUCCESS
}

/// 0600, and not only afterwards: between creating the file and setting the
/// permissions there would otherwise be a window in which the key is
/// readable by everyone.
fn write_private(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(bytes)
}

fn sign(key_path: &str, file: &str) -> ExitCode {
    let key = match std::fs::read(key_path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{key_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let kp = match Ed25519KeyPair::from_pkcs8(&key) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("{key_path} is not a key from `deelpe-sign keygen`");
            return ExitCode::FAILURE;
        }
    };
    let bytes = match std::fs::read(file) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{file}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let out = format!("{file}.sig");
    if let Err(e) = std::fs::write(&out, b64(kp.sign(&bytes).as_ref())) {
        eprintln!("{out}: {e}");
        return ExitCode::FAILURE;
    }
    println!("{out}");
    println!("public key: {}", b64(kp.public_key().as_ref()));
    ExitCode::SUCCESS
}
