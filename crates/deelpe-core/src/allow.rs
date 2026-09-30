//! Allow list of the destinations of a strict folder ("block all"): a
//! process that has read from such a folder may only send to the
//! destinations listed here. Everything else is forbidden — browser, AI
//! service, PowerShell, whoever.
//!
//! Entries are **an IP or a network (CIDR), each with an optional port**:
//! `10.0.0.7`, `10.0.0.0/8`, `10.0.0.7:443`, `2001:db8::/32`,
//! `[2001:db8::1]:443` — **or a hostname**: `chatgpt.com`.
//!
//! One list, two readers, and the difference comes from what the layer in
//! question can see at all:
//!
//! - On the **network path** ([`allows`]) there is only an IP. The service
//!   has no outbound network access (by design) and cannot resolve a name;
//!   name entries are therefore passed over there. Whoever wants to allow
//!   a destination on the network side still enters the network behind it.
//! - At the **browser connector** ([`allows_host`]) the browser supplies
//!   the destination URL. There the name is the more precise statement —
//!   behind `chatgpt.com` sits an address range that changes hourly.
//!
//! A name entry covers the host itself **and its subdomains**:
//! `example.com` matches `example.com` and `chat.example.com`, not
//! `notexample.com`.

use std::net::IpAddr;

/// Is the destination on the list? Never without a known peer — a
/// destination we cannot name is not an allowed destination.
pub fn allows(list: &[String], ip: Option<IpAddr>, port: Option<u16>) -> bool {
    let Some(ip) = ip else { return false };
    list.iter().any(|e| entry_matches(e, ip, port))
}

/// Is the browser's destination URL on the list? Name entries count here,
/// IP entries only if the URL itself names an IP.
pub fn allows_host(list: &[String], url: &str) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    list.iter().any(|e| host_matches(e.trim(), &host))
}

/// The host out of a URL, lowercased and without port, userinfo part or
/// brackets. `None` if there is nothing usable there.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    // Cut off the userinfo part: `user:pw@host` — the host is behind it.
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(end) = hostport.strip_prefix('[').and_then(|r| r.split_once(']')) {
        end.0
    } else {
        hostport.split(':').next()?
    };
    let host = host.trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Does this entry cover this host? Only name entries — an IP in the list
/// does not answer the connector's question, unless the URL names the same
/// IP, and then it matches as text anyway.
fn host_matches(entry: &str, host: &str) -> bool {
    if entry.is_empty() {
        return false;
    }
    // Leading dots and stars are a widespread notation for "including
    // subdomains"; here that is the normal case anyway.
    let e = entry
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .to_ascii_lowercase();
    if e.is_empty() {
        return false;
    }
    host == e || host.ends_with(&format!(".{e}"))
}

/// Read an entry as an address, a prefix length and a port.
///
/// `None` for a name entry (`chatgpt.com`) and for anything unreadable. A
/// name entry is not wrong, it just belongs to a different layer: the
/// browser connector knows the destination URL, the network path only an
/// address.
///
/// A bare address is the network with a full prefix length — then "matches
/// exactly" and "lies inside the network" are the same question, and the
/// workstation's network filter needs no second form.
pub fn as_net(entry: &str) -> Option<(IpAddr, u8, Option<u16>)> {
    let (host, port) = split_port(entry.trim());
    match host.split_once('/') {
        Some((net, bits)) => {
            let net: IpAddr = net.parse().ok()?;
            let bits: u8 = bits.parse().ok()?;
            (bits as usize <= if net.is_ipv4() { 32 } else { 128 }).then_some((net, bits, port))
        }
        None => {
            let ip: IpAddr = host.parse().ok()?;
            Some((ip, if ip.is_ipv4() { 32 } else { 128 }, port))
        }
    }
}

fn entry_matches(entry: &str, ip: IpAddr, port: Option<u16>) -> bool {
    let Some((net, bits, want_port)) = as_net(entry) else {
        return false;
    };
    if want_port.is_some() && want_port != port {
        return false;
    }
    in_net(ip, net, u32::from(bits))
}

/// Splits off an appended port. IPv6 without brackets has colons of its
/// own and therefore never carries a port.
fn split_port(e: &str) -> (&str, Option<u16>) {
    if let Some(end) = e.find(']') {
        if e.starts_with('[') {
            return (
                &e[1..end],
                e[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok()),
            );
        }
    }
    match e.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse().ok()),
        _ => (e, None),
    }
}

fn in_net(ip: IpAddr, net: IpAddr, bits: u32) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => prefix_eq(&a.octets(), &b.octets(), bits),
        (IpAddr::V6(a), IpAddr::V6(b)) => prefix_eq(&a.octets(), &b.octets(), bits),
        _ => false,
    }
}

fn prefix_eq(a: &[u8], b: &[u8], bits: u32) -> bool {
    let bits = bits as usize;
    if bits > a.len() * 8 {
        return false;
    }
    let (full, rest) = (bits / 8, bits % 8);
    a[..full] == b[..full] && (rest == 0 || (a[full] ^ b[full]) >> (8 - rest) == 0)
}

/// Does this look like a hostname? Deliberately generous — the list is
/// maintained by hand, and a typo here costs an allowance that fails to
/// appear, not a leak. A dot is required so that a forgotten list entry
/// like `443` does not pass as a name.
fn is_hostname(h: &str) -> bool {
    let h = h.trim_start_matches("*.").trim_start_matches('.');
    // A botched IP (`10.0.0`) would otherwise pass this check as a name
    // and then match nothing. The last label of a real name is never purely
    // numeric.
    if h.rsplit('.')
        .next()
        .is_some_and(|last| last.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    h.contains('.')
        && !h.starts_with('.')
        && !h.ends_with('.')
        && h.len() <= 253
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// Checks an entry before it is stored. Otherwise a typo in the allow list
/// only shows up when the alert fails to appear.
pub fn validate(entry: &str) -> Result<(), String> {
    let e = entry.trim();
    if e.is_empty() {
        return Err("empty entry".into());
    }
    let (host, _) = split_port(e);
    let ok = match host.split_once('/') {
        Some((net, bits)) => match (net.parse::<IpAddr>(), bits.parse::<u32>()) {
            (Ok(IpAddr::V4(_)), Ok(b)) => b <= 32,
            (Ok(IpAddr::V6(_)), Ok(b)) => b <= 128,
            _ => false,
        },
        None => host.parse::<IpAddr>().is_ok() || is_hostname(host),
    };
    // A port that was split off but is unreadable looks like "no port" above.
    let port_ok = match e.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && !h.ends_with(']') => p.parse::<u16>().is_ok(),
        _ => true,
    };
    if ok && port_ok {
        Ok(())
    } else {
        Err(format!("'{entry}' is not a hostname (chatgpt.com), an IP, a network (10.0.0.0/8) or one of those with :port"))
    }
}

/// How long a network cage stays up after the last touch. Rolling: every
/// further touch pushes it ahead. Deliberately **not** the reporting window
/// of a touch (600 s) — the cage costs functionality, the report does not.
/// The same on every endpoint that has a cage (Windows WFP, Linux nftables,
/// the macOS content filter).
pub const CAGE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// One allowlist entry in the shape a packet filter needs: network, prefix
/// length, port. Name entries of the allowlist are none of that — at this
/// layer there is no resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Permit {
    pub net: IpAddr,
    pub bits: u8,
    pub port: Option<u16>,
}

impl Permit {
    pub fn covers(&self, ip: IpAddr, port: Option<u16>) -> bool {
        (self.port.is_none() || self.port == port) && in_net(ip, self.net, u32::from(self.bits))
    }
}

/// The allowlist in filter form, plus the entries that were passed over.
///
/// A name (`chatgpt.com`) drops out and that is **not an error**: it applies
/// at the browser connector, where the target URL is known. Whoever wants to
/// open a destination for PowerShell or curl too enters the network behind
/// it — exactly the sentence from the module header.
pub fn permits(allow: &[String]) -> (Vec<Permit>, Vec<String>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for e in allow {
        match as_net(e) {
            Some((net, bits, port)) => out.push(Permit { net, bits, port }),
            None => skipped.push(e.clone()),
        }
    }
    (out, skipped)
}

/// What a network cage **always** lets through: our own house.
///
/// Decision of 2026-09-09, variant (b): internal destinations are still
/// **reported**, but not **blocked**. The cage is built against outflow to
/// the outside; a process that has the internal network taken away is
/// broken without anything being prevented. On 2026-09-09 that is exactly
/// what hit the RDP clipboard and the start menu of the test client.
///
/// Loopback, link-local and multicast are in there deliberately: nothing
/// leaves the house over them, but without them name resolution on the LAN
/// and half the desktop fall over.
///
/// ponytail: hard-wired to the private ranges of RFC 1918/4193. Whoever runs
/// "internal" on their own public addresses needs a field in the settings
/// for it — then this list moves there.
const INTERNAL: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
    "ff00::/8",
];

/// [`INTERNAL`] in filter form. The entries live in the code and are
/// checked — an unreadable one would be a typo, not an operational case.
pub fn internal_permits() -> Vec<Permit> {
    INTERNAL
        .iter()
        .filter_map(|e| as_net(e).map(|(net, bits, port)| Permit { net, bits, port }))
        .collect()
}

/// What a cage for this allowlist lets through: the rule's address entries
/// plus [`internal_permits`], without duplicates. Duplicates would make the
/// list differ for the same rule — and a cage rebuilds itself when its list
/// changes. The second half is the passed-over name entries, for the log.
pub fn cage_permits(allow: &[String]) -> (Vec<Permit>, Vec<String>) {
    let (mut out, skipped) = permits(allow);
    for p in internal_permits() {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    (out, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn empty_list_allows_nothing() {
        assert!(!allows(&[], ip("10.0.0.1"), Some(443)));
    }

    #[test]
    fn exact_ip_and_port() {
        let l = vec!["10.0.0.7".to_string(), "203.0.113.9:443".to_string()];
        assert!(allows(&l, ip("10.0.0.7"), Some(80)));
        assert!(allows(&l, ip("203.0.113.9"), Some(443)));
        assert!(!allows(&l, ip("203.0.113.9"), Some(80)));
        assert!(!allows(&l, ip("203.0.113.10"), Some(443)));
    }

    #[test]
    fn networks() {
        let l = vec!["10.0.0.0/8".to_string(), "192.168.1.0/24:445".to_string()];
        assert!(allows(&l, ip("10.255.3.1"), None));
        assert!(!allows(&l, ip("11.0.0.1"), None));
        assert!(allows(&l, ip("192.168.1.50"), Some(445)));
        assert!(!allows(&l, ip("192.168.1.50"), Some(443)));
        assert!(!allows(&l, ip("192.168.2.50"), Some(445)));
        // Non-byte boundary.
        assert!(allows(&["10.0.0.0/12".to_string()], ip("10.15.0.1"), None));
        assert!(!allows(&["10.0.0.0/12".to_string()], ip("10.16.0.1"), None));
    }

    #[test]
    fn v6_and_families_do_not_mix() {
        let l = vec!["2001:db8::/32".to_string(), "[2001:db9::1]:443".to_string()];
        assert!(allows(&l, ip("2001:db8:1::5"), Some(80)));
        assert!(!allows(&l, ip("2001:dba::5"), Some(80)));
        assert!(allows(&l, ip("2001:db9::1"), Some(443)));
        assert!(!allows(&l, ip("2001:db9::1"), Some(80)));
        assert!(!allows(&["10.0.0.0/8".to_string()], ip("::1"), None));
        assert!(!allows(&["::/0".to_string()], ip("10.0.0.1"), None));
    }

    #[test]
    fn no_destination_is_never_allowed() {
        assert!(!allows(&["0.0.0.0/0".to_string()], None, Some(443)));
    }

    #[test]
    fn validation_catches_typos() {
        for good in [
            "10.0.0.1",
            "10.0.0.0/8",
            "10.0.0.1:443",
            "2001:db8::/32",
            "[2001:db8::1]:443",
            " 10.0.0.1 ",
        ] {
            assert!(validate(good).is_ok(), "{good}");
        }
        // Hostnames have counted since 2026-09-08 as well: the browser
        // connector knows the destination URL, and behind `chatgpt.com`
        // sits an address range that changes constantly.
        for good in [
            "chatgpt.com",
            "*.openai.com",
            ".anthropic.com",
            "gemini.google.com",
        ] {
            assert!(validate(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "10.0.0.1:https",
            "10.0.0.0/33",
            "10.0.0.0/x",
            "10.0.0",
            "kein-punkt",
            "a..b",
            "un terstrich.com",
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
    }

    /// A name entry covers the host and its subdomains — but not a name
    /// that merely happens to end that way.
    #[test]
    fn a_hostname_entry_covers_its_subdomains_only() {
        let list = vec![
            "chatgpt.com".to_string(),
            "*.ethical-ai.example".to_string(),
        ];
        for yes in [
            "https://chatgpt.com/",
            "https://chat.chatgpt.com/x?y=1",
            "https://a.b.ethical-ai.example/upload",
            "https://ethical-ai.example",
        ] {
            assert!(allows_host(&list, yes), "{yes}");
        }
        for no in [
            "https://notchatgpt.com/",
            "https://gemini.google.com/app",
            "https://chatgpt.com.evil.test/",
            "nicht mal eine url",
        ] {
            assert!(!allows_host(&list, no), "{no}");
        }
        // Port, userinfo part and capitalisation do not get in the way.
        assert!(allows_host(&list, "https://User@CHATGPT.com:443/pfad"));
        // An IP in the list does not answer the connector's question.
        assert!(!allows_host(
            &["10.0.0.7".to_string()],
            "https://chatgpt.com/"
        ));
    }

    fn p(s: &str) -> Permit {
        let (net, bits, port) = as_net(s).unwrap();
        Permit { net, bits, port }
    }

    /// Names apply at the browser connector, not in a packet filter — and
    /// they are not an error, they belong in the log.
    #[test]
    fn only_addresses_become_permits() {
        let allow = vec![
            "10.0.0.0/8".into(),
            "chatgpt.com".into(),
            "203.0.113.9:443".into(),
            "2001:db8::/32".into(),
        ];
        let (ps, skipped) = permits(&allow);
        assert_eq!(
            ps,
            vec![p("10.0.0.0/8"), p("203.0.113.9:443"), p("2001:db8::/32")]
        );
        assert_eq!(skipped, vec!["chatgpt.com".to_string()]);
        assert!(ps[1].covers("203.0.113.9".parse().unwrap(), Some(443)));
        assert!(!ps[1].covers("203.0.113.9".parse().unwrap(), Some(80)));
        assert!(ps[0].covers("10.1.2.3".parse().unwrap(), None));
    }

    /// Variant (b): internal gets reported, not blocked. The cage always
    /// lets our own house through, even with an empty rule allowlist — and
    /// nothing public.
    #[test]
    fn the_cage_always_lets_the_house_through() {
        let (ps, _) = cage_permits(&["10.0.0.0/8".into()]);
        assert_eq!(
            ps.iter().filter(|x| **x == p("10.0.0.0/8")).count(),
            1,
            "no duplicates"
        );
        for inside in ["10.1.1.1", "192.168.1.1", "127.0.0.1", "fd00::1", "::1"] {
            assert!(
                ps.iter().any(|q| q.covers(inside.parse().unwrap(), None)),
                "{inside}"
            );
        }
        for public in ["1.1.1.1", "20.42.73.27", "2001:db8::1"] {
            assert!(
                !ps.iter().any(|q| q.covers(public.parse().unwrap(), None)),
                "{public} counts as internal"
            );
        }
    }
}
