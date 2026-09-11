//! The device's own IP addresses — the ones it appears under on the
//! network. The agent reports them in its status, because otherwise the
//! server records them wrongly: if it sits behind Docker, a reverse proxy
//! or (in the lab) an SSH tunnel, the server sees only the last hop as its
//! peer, not the agent. On 2026-09-07 that left all three agents in the
//! dashboard with the same Docker gateway address.
//!
//! No enumerating of interfaces (that would need its own code per
//! platform): the usual trick with a connected UDP socket. For UDP,
//! `connect` sends nothing, but it does pick the outgoing interface — and
//! that interface's local address is the one under which the device
//! reaches the rest of the network. That is the one you want to see (in
//! the lab `192.0.2.10`), not `127.0.0.1`.

use std::net::UdpSocket;

/// Primary IPv4 and, if present, IPv6. Empty list if nothing can be
/// determined (no network) — then it stays with what the server sees.
pub fn local_addrs() -> Vec<String> {
    let mut out = Vec::new();
    // The destination is never contacted; it only fixes the route. Hence a
    // fixed public address and no name (the agent resolves nothing).
    if let Some(v4) = primary("0.0.0.0:0", "8.8.8.8:80") {
        out.push(v4);
    }
    if let Some(v6) = primary("[::]:0", "[2001:4860:4860::8888]:80") {
        if !out.contains(&v6) {
            out.push(v6);
        }
    }
    out
}

fn primary(bind: &str, dest: &str) -> Option<String> {
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(dest).ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() || ip.is_unspecified() {
        return None;
    }
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_a_real_address_or_nothing() {
        // On a networked machine at least one, never loopback.
        for a in local_addrs() {
            assert!(!a.starts_with("127."), "{a}");
            assert_ne!(a, "::1");
        }
    }
}
