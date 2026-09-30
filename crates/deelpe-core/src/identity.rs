use serde::{Deserialize, Serialize};
use std::fmt;

/// Who is a process? Not the name, but something that malware cannot forge
/// trivially (design: "Process identity").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProcessIdentity {
    /// macOS: signature verified by Apple.
    Signed { team_id: String, signing_id: String },
    /// Linux (or an unsigned macOS binary): path + SHA-256 of the binary.
    Hashed { path: String, sha256: String },
    /// None of that available. Always reported.
    Unknown { path: String },
}

/// The program name in comparison form: lowercased, without Windows'
/// resource suffix.
///
/// Windows likes to append a `.mui` to the name taken from the version
/// resource. Anyone comparing exactly against that will not find
/// `explorer.exe` when the process comes in as `EXPLORER.EXE.MUI` — and
/// that is exactly what made the agent shoot down the user's desktop twice
/// on 2026-09-09, even though `explorer.exe` is on every protection list.
/// Three lists asked the same question and answered it differently; now
/// they all go through here.
pub fn image_name(name: &str) -> String {
    let low = name.to_lowercase();
    low.strip_suffix(".mui").unwrap_or(&low).to_string()
}

impl ProcessIdentity {
    pub fn is_trusted_form(&self) -> bool {
        !matches!(self, ProcessIdentity::Unknown { .. })
    }

    /// Short, human-readable form for tables and notifications.
    pub fn short(&self) -> String {
        match self {
            ProcessIdentity::Signed { signing_id, .. } => signing_id.clone(),
            ProcessIdentity::Hashed { path, .. } | ProcessIdentity::Unknown { path } => {
                // Both separators: otherwise the alert from a Windows agent
                // shows the whole path instead of the program name.
                path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
            }
        }
    }
}

impl fmt::Display for ProcessIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessIdentity::Signed {
                team_id,
                signing_id,
            } => {
                write!(f, "{signing_id} (Team {team_id})")
            }
            ProcessIdentity::Hashed { path, sha256 } => {
                write!(f, "{path} [{}]", &sha256[..12.min(sha256.len())])
            }
            ProcessIdentity::Unknown { path } => write!(f, "{path} [unsigned]"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_names_on_both_platforms() {
        let mac = ProcessIdentity::Unknown {
            path: "/usr/bin/curl".into(),
        };
        assert_eq!(mac.short(), "curl");
        let win = ProcessIdentity::Unknown {
            path: r"C:\Program Files\Google\Chrome\chrome.exe".into(),
        };
        assert_eq!(win.short(), "chrome.exe");
        // Signed programs carry their ID, not the path.
        let signed = ProcessIdentity::Signed {
            team_id: "Google LLC".into(),
            signing_id: "chrome.exe".into(),
        };
        assert_eq!(signed.short(), "chrome.exe");
        assert_eq!(signed.to_string(), "chrome.exe (Team Google LLC)");
        assert!(signed.is_trusted_form());
        assert!(!win.is_trusted_form(), "unsigniert wird immer gemeldet");
    }
}
