import Foundation

/// Reverse DNS for destination addresses, so that "160.79.104.10" becomes
/// readable as "anthropic.com" and a foreign host in the same /24 stands out.
/// Runs in the app, not in the root service (that one has no network access);
/// the only thing leaving is the query to the system resolver. The result per
/// IP is kept for a week in memory and on disk, including "no name", so that
/// nothing is asked twice.
///
/// The IP reputation (AbuseIPDB) has been handled by the central server since
/// 2026-09-08, not by the app any more; `isPublic` stayed here because the
/// resolver should query public addresses only as well.
@MainActor
final class HostResolver: ObservableObject {
    static let cacheTTL: TimeInterval = 7 * 24 * 3600
    /// The file belongs to the user, the directory is created when saving.
    static let supportDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/de-el-pe", isDirectory: true)
    static let cacheFile = supportDir.appendingPathComponent("hosts-cache.json")

    struct Entry: Codable { let host: String?; let at: Date }

    @Published private(set) var hosts: [String: Entry] = [:]
    private var queue: [String] = []
    private var worker: Task<Void, Never>?

    init() { load() }

    func host(for ip: String?) -> String? {
        guard let ip, let e = hosts[ip] else { return nil }
        return e.host
    }

    /// Look up every still unknown public address from the alerts.
    func lookupMissing(ips: [String]) {
        let now = Date()
        for ip in Set(ips) where Self.isPublic(ip) {
            if let e = hosts[ip], now.timeIntervalSince(e.at) < Self.cacheTTL { continue }
            if !queue.contains(ip) { queue.append(ip) }
        }
        pump()
    }

    private func pump() {
        guard worker == nil, !queue.isEmpty else { return }
        let ip = queue.removeFirst()
        worker = Task { [weak self] in
            let host = await Self.reverse(ip)
            guard let self else { return }
            self.hosts[ip] = Entry(host: host, at: Date())
            self.save()
            self.worker = nil
            self.pump()
        }
    }

    /// getnameinfo with NI_NAMEREQD: real PTR names only, no IP echoes.
    nonisolated static func reverse(_ ip: String) async -> String? {
        await Task.detached(priority: .utility) { () -> String? in
            var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(ip, nil, &hints, &res) == 0, let info = res else { return nil }
            defer { freeaddrinfo(res) }
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NAMEREQD) == 0 else { return nil }
            let name = String(cString: buf)
            return name.isEmpty ? nil : name
        }.value
    }

    private func load() {
        guard let data = try? Data(contentsOf: Self.cacheFile),
              let dict = try? JSONDecoder().decode([String: Entry].self, from: data) else { return }
        let now = Date()
        hosts = dict.filter { now.timeIntervalSince($0.value.at) < Self.cacheTTL }
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(hosts) else { return }
        try? FileManager.default.createDirectory(at: Self.supportDir, withIntermediateDirectories: true)
        try? data.write(to: Self.cacheFile, options: .atomic)
    }

    /// Private, loopback, link-local, multicast and reserved ranges rarely
    /// have a PTR name; asking only costs a timeout in the resolver.
    static func isPublic(_ ip: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, ip, &v4) == 1 {
            return isPublicV4(UInt32(bigEndian: v4.s_addr))
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, ip, &v6) == 1 {
            let b = withUnsafeBytes(of: &v6) { Array($0) }
            return isPublicV6(b)
        }
        return false
    }

    private static func isPublicV4(_ a: UInt32) -> Bool {
        let o1 = a >> 24, o2 = (a >> 16) & 0xff
        if o1 == 0 || o1 == 10 || o1 == 127 { return false }             // 0/8, 10/8, 127/8
        if o1 == 100 && (64...127).contains(o2) { return false }           // 100.64/10 (CGNAT)
        if o1 == 169 && o2 == 254 { return false }                         // 169.254/16
        if o1 == 172 && (16...31).contains(o2) { return false }            // 172.16/12
        if o1 == 192 && o2 == 168 { return false }                         // 192.168/16
        if o1 == 192 && o2 == 0 && (a >> 8) & 0xff == 2 { return false }   // 192.0.2/24 (TEST-NET-1)
        if o1 == 198 && (o2 == 18 || o2 == 19) { return false }            // 198.18/15 (Benchmark)
        if o1 >= 224 { return false }                                      // multicast, reserved, broadcast
        return true
    }

    private static func isPublicV6(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        // ::ffff:a.b.c.d → judge it like IPv4.
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff {
            return isPublicV4(UInt32(b[12]) << 24 | UInt32(b[13]) << 16 | UInt32(b[14]) << 8 | UInt32(b[15]))
        }
        if b.allSatisfy({ $0 == 0 }) { return false }                                      // ::
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }                // ::1
        if b[0] & 0xfe == 0xfc { return false }                                            // fc00::/7 (ULA)
        if b[0] == 0xfe && b[1] & 0xc0 == 0x80 { return false }                            // fe80::/10
        if b[0] == 0xff { return false }                                                   // ff00::/8
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return false }   // 2001:db8::/32 (docs)
        return true
    }
}
