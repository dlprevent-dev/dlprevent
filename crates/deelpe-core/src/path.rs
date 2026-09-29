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

use unicode_normalization::UnicodeNormalization;

/// Comparison form of a path: lowercased, `\` treated as `/`, without a
/// trailing separator, and in one Unicode normalisation form.
///
/// The normalisation is not cosmetic. macOS hands out decomposed names
/// (NFD) for what a person typed composed (NFC), and the two are the same
/// file; without folding them onto one form the comparison says a strict
/// folder is somewhere else than where the kernel says it is.
pub fn norm(p: &str) -> String {
    let mut s = p.replace('\\', "/");
    // NFC before and after the case fold: two spellings of one name have to
    // be one string before `to_lowercase` sees them, and lowercasing can
    // itself decompose (`İ`). Pure ASCII needs neither — that is almost every
    // path, and the sensor filter runs this on every file event.
    //
    // Up, then down: NTFS compares by upper case, and some letters share an
    // upper case without sharing a lower one — `σ`/`ς`, `ı`/`i`, `ſ`/`s`,
    // `µ`/`μ`. Lowercasing alone keeps them apart (and turns a final `Σ`
    // into `ς` but leaves a typed `σ`), so `ΠΕΛΑΤΕσ` would not be the rule
    // `ΠΕΛΑΤΕΣ` although Windows opens the same folder for both. Where a
    // file system keeps such a pair apart, the rule covers both: too much
    // protection, not too little.
    if s.is_ascii() {
        s.make_ascii_lowercase();
    } else {
        s = s.nfc().collect::<String>().to_uppercase().to_lowercase().nfc().collect();
    }
    // One folder, several spellings: Win32 silently drops trailing dots and
    // spaces from a path component, so `GL.` and `GL ` are the very folder
    // named `GL`. Compare without them, or the folder the operator declared
    // is not the folder the agent sees. On macOS and Linux `GL.` is a folder
    // of its own; a rule then covers it too — as with case above, too much
    // protection, not too little.
    if s.split('/').any(|c| strip_win_tail(c).len() != c.len()) {
        s = s.split('/').map(strip_win_tail).collect::<Vec<_>>().join("/");
    }
    while s.ends_with('/') && s.len() > 1 {
        s.pop();
    }
    s
}

/// A path component without the trailing dots and spaces Win32 does not see
/// (`C:\Freigaben\GL.` is `C:\Freigaben\GL`). A component of nothing but
/// dots and spaces stays as it is: `.` and `..` are not names, and `..`
/// shortened to `.` would be a different folder.
fn strip_win_tail(comp: &str) -> &str {
    match comp.trim_end_matches(['.', ' ']) {
        "" => comp,
        t => t,
    }
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

    /// macOS hands out **decomposed** names (NFD) for what a person typed
    /// composed (NFC) — the two name the same file. A strict folder declared
    /// in one form and an event delivered in the other are the same folder,
    /// and the comparison has to say so; otherwise a strict folder simply
    /// does not protect.
    #[test]
    fn a_name_is_the_same_in_both_normalisation_forms() {
        let nfc = "/Users/eva/\u{00dc}";        // what an operator types
        let nfd = "/Users/eva/U\u{0308}";       // what the kernel reports
        assert!(under(nfc, nfd), "NFC event against an NFD rule");
        assert!(under(nfd, nfc), "NFD event against an NFC rule");
        // The other direction matters too, or a rule written in the form the
        // filesystem happens to use would not match itself.
        assert!(under(nfd, nfd));
        // Pure ASCII is untouched by the fold.
        assert!(under("/srv/GL/a", "/srv/GL"));
    }

    /// Letters that share an upper case are one letter to a case-blind file
    /// system, whatever their lower case: NTFS opens `ΠΕΛΑΤΕσ` as the folder
    /// `ΠΕΛΑΤΕΣ`, and a caller picks the spelling ETW reports.
    #[test]
    fn letters_with_one_upper_case_are_one_letter() {
        assert!(under(r"C:\Freigaben\ΠΕΛΑΤΕσ\a.xlsx", r"C:\Freigaben\ΠΕΛΑΤΕΣ"), "final sigma");
        assert!(under(r"C:\Freigaben\ΠΕΛΑΤΕΣ\a.xlsx", r"C:\Freigaben\πελατεσ"));
        assert!(under("C:\\Freigaben\\F\u{131}nance\\a", r"C:\Freigaben\Finance"), "dotless i");
        assert!(under("/srv/Ka\u{17f}\u{17f}e/a", "/srv/Kasse"), "long s");
        assert!(under("/srv/\u{b5}C/a", "/srv/\u{3bc}C"), "micro sign");
        assert!(!under("/srv/GLx/a", "/srv/GL"));
    }

    /// Win32 drops trailing dots and spaces from a path component before it
    /// looks at it: `C:\\Freigaben\\GL.` **is** `C:\\Freigaben\\GL`. So the
    /// component is compared the way the kernel sees it, or the declared
    /// folder and the opened one are two different strings.
    #[test]
    fn trailing_dots_and_spaces_are_not_part_of_a_name() {
        for spelling in [r"C:\Freigaben\GL.", r"C:\Freigaben\GL ", r"C:\Freigaben\GL . "]
            .iter()
            .map(|s| s.replace('\\', "/"))
        {
            assert!(under(&spelling, r"C:\Freigaben\GL"), "{spelling}");
            assert!(under(r"C:\Freigaben\GL\a.txt", &spelling), "rule written with the tail: {spelling}");
        }
        // Only the tail of a component goes — a name that merely *starts*
        // with a dot is a different folder and stays one.
        assert!(!under("/srv/.hidden/a", "/srv/hidden"));
        assert!(under("/srv/GL./sub/a", "/srv/GL"));
        // The current-directory designator keeps its dot: `/` and `C:.` are
        // not a folder called the empty string, and `..` is not `.`.
        assert_eq!(norm("/"), "/");
        assert_eq!(norm("C:\\."), "c:/.", "the designator is not stripped to nothing");
        assert_eq!(norm("/srv/GL/../HR"), "/srv/gl/../hr");
        assert_eq!(norm("/a/b/"), "/a/b");
    }

    #[test]
    fn nothing_is_under_an_empty_rule_or_the_root() {
        assert!(!under("/a/b", ""));
        assert!(!under("/a/b", "   "), "Leerzeichen sind ein Pfad, aber keiner, der passt");
        assert!(!under("/a/b", "/"), "die Wurzel schuetzt nicht alles");
        assert!(!under("", "/srv/gl"));
    }
}
