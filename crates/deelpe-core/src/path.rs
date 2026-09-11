//! One place for the question "is this path inside that folder?".
//!
//! It gets asked in three places that have to behave alike: at the
//! protected folder ([`crate::config::Config::is_watched`]), when matching
//! a folder rule ([`crate::rules::rule_matches`]) and in the ETW callback
//! of the Windows sensor, which discards events outside the protected
//! folders before they go into the channel.
//!
//! Before, it stood written out three times, in three spellings: two
//! normalised to `/`, the third to `\` — and the third one normalised only
//! the filter list, not the incoming path. On Windows that went unnoticed,
//! because event tracing always delivers `\`. That is exactly how it never
//! gets noticed.
//!
//! The comparison ignores upper and lower case and ignores the separator.
//! Windows shares are not case-sensitive: without that, the rule
//! `\\srv\GL` does not match the event `\\SRV\gl\zahlen.xlsx`, and the
//! protection fails exactly when somebody spells the share differently. On
//! macOS the default file system is likewise not case-sensitive; on a
//! volume that is, the rule then also covers a folder with a different
//! spelling — too much protection, not too little.

/// Comparison form of a path: lowercased, `\` treated as `/`, without a
/// trailing separator.
pub fn norm(p: &str) -> String {
    let mut s = p.replace('\\', "/").to_lowercase();
    while s.ends_with('/') && s.len() > 1 {
        s.pop();
    }
    s
}

/// Is `file` inside `base` (or is it `base` itself)? Both are normalised.
/// Only whole folder components count: `/srv/GL` does not cover
/// `/srv/GL2`.
pub fn under(file: &str, base: &str) -> bool {
    under_norm(&norm(file), &norm(base))
}

/// Like [`under`], but both sides have already been through [`norm`].
///
/// For the hot path: the ETW callback normalises its filter list once when
/// it is set, not on every file event.
pub fn under_norm(file: &str, base: &str) -> bool {
    // An empty rule path protects nothing rather than everything. The root
    // likewise: "everything is protected" is never what is meant and could
    // not be switched off.
    if base.is_empty() || base == "/" {
        return false;
    }
    if prefix_of(file, base) {
        return true;
    }
    // The same server under its long name: the rule says `\\srv01\GL`,
    // the share is mounted as `\\srv01.example.int\GL`. For the comparison
    // those are two unrelated strings, for a human and for the file server
    // the same place — and which name arrives is decided by the drive
    // mapping, not by the rule. Hence the second attempt with a shortened
    // name.
    //
    // Only the event side is shortened: the rule stays as it is written.
    // The direction of the error is therefore "more protection" — a rule
    // for `\\srv\GL` also covers `\\srv.whatever\GL`.
    base.starts_with("//") && short_host(file).is_some_and(|f| prefix_of(&f, base))
}

fn prefix_of(file: &str, base: &str) -> bool {
    file == base || (file.len() > base.len() && file.starts_with(base) && file.as_bytes()[base.len()] == b'/')
}

/// `//srv01.example.int/gl/a` → `//srv01/gl/a`. `None` if there is nothing
/// to shorten.
fn short_host(file: &str) -> Option<String> {
    let rest = file.strip_prefix("//")?;
    let end = rest.find('/').unwrap_or(rest.len());
    let host = &rest[..end];
    // An address has no short name. Shortening `192.0.2.201` at the first
    // dot yields `10` — a machine name that does not exist, and with it a
    // comparison that at best matches nothing. Anyone who accesses via the
    // address is not caught here: the central server hands out the file
    // server's addresses as rule paths of their own (`deelpe-server`,
    // `agent::endpoint_rules`).
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let dot = host.find('.')?;
    Some(format!("//{}{}", &host[..dot], &rest[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separators_and_case_do_not_matter() {
        assert!(under(r"\\srv01\GL\zahlen.xlsx", r"\\srv01\GL"));
        assert!(under(r"\\SRV01\gl\Zahlen.xlsx", r"\\srv01\GL"), "Freigaben schreibt jeder anders");
        assert!(under(r"\\srv01\GL", r"\\srv01\GL"));
        assert!(under("//srv01/gl/a.txt", r"\\srv01\GL"), "Ereignis mit / auf Regel mit \\");
        assert!(under(r"C:\Freigaben\GL\a.dat", "c:/freigaben/gl/"), "Schlusstrenner zaehlt nicht");
    }

    #[test]
    fn a_server_under_its_long_name_is_the_same_server() {
        assert!(under(r"\\srv01.example.int\GL\zahlen.xlsx", r"\\srv01\GL"));
        assert!(under(r"\\SRV01.Example.INT\gl", r"\\srv01\GL"));
        // The other way round does no harm: the rule may carry the long name.
        assert!(under(r"\\srv01.example.int\GL\a", r"\\srv01.example.int\GL"));
        // A different server stays a different server.
        assert!(!under(r"\\srv02.example.int\GL\a", r"\\srv01\GL"));
        assert!(!under(r"\\srv01x.example.int\GL\a", r"\\srv01\GL"));
        // Only for UNC: a dot in an ordinary folder shortens nothing.
        assert!(!under("/srv.example/gl/a", "/srv/gl"));
        // An address is not shortened: `192.0.2.201` is not the machine
        // `10`. Access via the address is covered by a rule path of its
        // own, not by this shortening.
        assert!(!under(r"\\192.0.2.201\GL\a", r"\\10\GL"));
        assert!(!under(r"\\192.0.2.201\GL\a", r"\\fs-01\GL"));
        assert!(under(r"\\192.0.2.201\GL\a", r"\\192.0.2.201\GL"), "die Adresse als Regel trifft sich selbst");
    }

    #[test]
    fn only_whole_components_count() {
        assert!(!under(r"\\srv01\GL2\a.txt", r"\\srv01\GL"), "kein Treffer mitten im Namen");
        assert!(!under("/srv/gl2/a", "/srv/gl"));
        assert!(!under("/srv/g", "/srv/gl"));
        assert!(!under("/srv/andere/a.txt", "/srv/gl"));
    }

    #[test]
    fn nothing_is_under_an_empty_rule_or_the_root() {
        assert!(!under("/a/b", ""));
        assert!(!under("/a/b", "   "), "Leerzeichen sind ein Pfad, aber keiner, der passt");
        assert!(!under("/a/b", "/"), "die Wurzel schuetzt nicht alles");
        assert!(!under("", "/srv/gl"));
    }
}
