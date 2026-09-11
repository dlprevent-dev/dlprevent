//! Matching an access path to a folder rule.
//!
//! Lives here because both sides need it and have to behave alike: the
//! central server when condensing NAS syslog and the Windows server agent
//! when condensing its own audit events. Two versions of it would drift
//! apart and nobody would notice.
//!
//! The comparison itself is in [`crate::path`]; all that is added here is
//! that a rule path may also be **relative** (`GL` instead of `\\srv\GL`).
//!
//! Plus the opposite direction: [`endpoint_rule_path`] rewrites a rule path
//! into a workstation's view, so that the same folder can be specified once
//! at the file server and rolled out everywhere.

use crate::central::ShareInfo;
use crate::path::{norm, under_norm};

/// Absolute means: drive (`C:\…`), UNC (`\\srv\…`) or Unix root. Anything
/// else is a share name and needs a share table.
fn is_absolute(norm_path: &str) -> bool {
    norm_path.starts_with('/') || norm_path.as_bytes().get(1) == Some(&b':')
}

/// A rule matches if its path (absolute) is a prefix of the event path or
/// (relative, e.g. "GL") occurs in it as a folder component.
pub fn rule_matches(rule_path: &str, event_path: &str) -> bool {
    let r = norm(rule_path);
    let e = norm(event_path);
    if r.is_empty() {
        return false;
    }
    if is_absolute(&r) {
        return under_norm(&e, &r);
    }
    // Relative: the name has to be a whole folder component, not part of a
    // name — "GL" does not match "GLOBAL".
    let hay = format!("/{}/", e.trim_start_matches('/'));
    hay.contains(&format!("/{r}/"))
}

/// A rule path as an **endpoint** has to see it.
///
/// On the file server the folder is called `C:\Freigaben\GL` or simply
/// `GL`; on the workstation neither of those exists — there the same file
/// sits under `\\SERVER\GL\…`. Without this rewriting, a rule created on
/// the file server cannot be resolved on the workstation: the agent skips
/// it, watches nothing and reports nothing. On 2026-09-08 exactly that in
/// the lab — `folders=0 strict=0`, while a strict rule showed green in the
/// dashboard.
///
/// `server` is the file server the rule hangs off, with its reported share
/// table; `None` means "not assigned to any server". Then only an absolute
/// path stays standing (a rule for a folder on the workstation itself) — a
/// share name without a server cannot be resolved at the endpoint and is
/// discarded instead of feigning protection.
pub fn endpoint_rule_path(rule_path: &str, server: Option<(&str, &[ShareInfo])>) -> Option<String> {
    let r = norm(rule_path);
    if r.is_empty() {
        return None;
    }
    // Already in the workstation's language.
    if r.starts_with("//") {
        return Some(rule_path.to_string());
    }
    let Some((name, shares)) = server else {
        return is_absolute(&r).then(|| rule_path.to_string());
    };
    // Server known, but without a name: then there is no UNC path. Leaving
    // the local path standing would be worse than nothing — on the
    // workstation it points at a folder that does not exist there.
    if name.is_empty() {
        return None;
    }
    // Longest local path first: if one share sits below another, the more
    // specific one wins.
    let mut by_path: Vec<&ShareInfo> = shares.iter().filter(|s| s.path.is_some()).collect();
    by_path.sort_by_key(|s| std::cmp::Reverse(s.path.as_deref().unwrap_or("").len()));
    for s in by_path {
        let local = norm(s.path.as_deref().unwrap_or(""));
        if local.is_empty() || !under_norm(&r, &local) {
            continue;
        }
        // `norm` changes only case and separators, not the length — so the
        // rest can be cut out of the original and keeps its upper and lower
        // case.
        // `get` instead of indexing: a spelling whose length changes when
        // lowercased would otherwise give a panicking cut in mid-character.
        let rest = rule_path.get(local.len()..).unwrap_or("").replace('/', "\\");
        return Some(format!("\\\\{name}\\{}{}", s.name, rest));
    }
    // Share name instead of path: `GL` means the share `GL`.
    if !is_absolute(&r) {
        if let Some(s) = shares.iter().find(|s| s.name.eq_ignore_ascii_case(rule_path)) {
            return Some(format!("\\\\{name}\\{}", s.name));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(name: &str, path: Option<&str>) -> ShareInfo {
        ShareInfo { name: name.into(), path: path.map(str::to_string), remark: None, path_from: None }
    }

    fn dc() -> Vec<ShareInfo> {
        vec![
            share("Allgemein", Some(r"C:\Freigaben\Allgemein")),
            share("GL", Some(r"C:\Freigaben\GL")),
            share("Finance", Some(r"C:\Freigaben\Finance")),
            share("Vertraege", Some(r"C:\Freigaben\GL\Vertraege")),
            share("Ohne", None),
        ]
    }

    #[test]
    fn a_file_server_rule_becomes_a_unc_path_for_the_endpoint() {
        let s = dc();
        let sv = Some(("FS-01", &s[..]));
        assert_eq!(endpoint_rule_path(r"C:\Freigaben\GL", sv).unwrap(), r"\\FS-01\GL");
        // The subfolder is kept, with its spelling.
        assert_eq!(endpoint_rule_path(r"C:\Freigaben\GL\Vertraege\2026", sv).unwrap(), r"\\FS-01\Vertraege\2026");
        // Share name instead of path.
        assert_eq!(endpoint_rule_path("GL", sv).unwrap(), r"\\FS-01\GL");
        assert_eq!(endpoint_rule_path("gl", sv).unwrap(), r"\\FS-01\GL", "Freigaben schreibt jeder anders");
    }

    #[test]
    fn the_deeper_share_wins() {
        let s = dc();
        // Without "longest path first" this ended up under the share GL.
        assert_eq!(endpoint_rule_path(r"C:\Freigaben\GL\Vertraege", Some(("SRV", &s[..]))).unwrap(), r"\\SRV\Vertraege");
    }

    #[test]
    fn nothing_is_invented() {
        let s = dc();
        let sv = Some(("SRV", &s[..]));
        // Not a folder of any share: better no rule than one that matches nothing.
        assert_eq!(endpoint_rule_path(r"C:\Woanders\GL", sv), None);
        assert_eq!(endpoint_rule_path("Personal", sv), None);
        // A share without a known path is only good as a name.
        assert_eq!(endpoint_rule_path("Ohne", sv).unwrap(), r"\\SRV\Ohne");
        assert_eq!(endpoint_rule_path("", sv), None);
        assert_eq!(endpoint_rule_path(r"C:\Freigaben\GL", Some(("", &s[..]))), None);
    }

    #[test]
    fn rules_without_a_file_server_stay_as_they_are() {
        // A folder on the workstation itself: pass it through unchanged.
        assert_eq!(endpoint_rule_path(r"C:\Users\Public", None).unwrap(), r"C:\Users\Public");
        assert_eq!(endpoint_rule_path("/Users/eva/Steuern", None).unwrap(), "/Users/eva/Steuern");
        // Already UNC: nothing to translate, not even with a share table.
        assert_eq!(endpoint_rule_path(r"\\srv01\GL", None).unwrap(), r"\\srv01\GL");
        // A share name without a server cannot be resolved at the endpoint.
        assert_eq!(endpoint_rule_path("GL", None), None);
    }

    #[test]
    fn relative_rule_matches_any_folder_of_that_name() {
        assert!(rule_matches("GL", "/volume1/daten/GL/zahlen.xlsx"));
        assert!(rule_matches("GL", r"C:\Freigaben\GL\Vertraege\a.dat"));
        // Only whole folder components, not parts of names.
        assert!(!rule_matches("GL", "/daten/GLOBAL/x.txt"));
        assert!(!rule_matches("GL", "/daten/EGL/x.txt"));
    }

    #[test]
    fn absolute_rule_is_a_prefix() {
        assert!(rule_matches(r"C:\Freigaben\GL", r"C:\Freigaben\GL\a.dat"));
        assert!(rule_matches(r"C:\Freigaben\GL", r"c:/freigaben/gl"));
        assert!(!rule_matches(r"C:\Freigaben\GL", r"C:\Freigaben\GL2\a.dat"));
        assert!(!rule_matches("/srv/gl", "/srv/gl2/a"));
    }
}
