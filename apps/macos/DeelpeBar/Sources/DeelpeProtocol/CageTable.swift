import Foundation

/// The network cage as the service hands it to the content filter: which
/// processes may, for now, only reach their permits, and what every process
/// may always reach (our own house). One JSON line per change, from
/// `crates/deelpe/src/cage.rs` (`relay_line`) via `DeelpeCageRelay`.
///
/// The decision lives here and not in the filter so that it can be tested
/// without a system extension.
public struct CageTable: Codable, Equatable, Sendable {
    public var cages: [Cage]
    public var always: [CagePermit]

    public init(cages: [Cage] = [], always: [CagePermit] = []) {
        self.cages = cages
        self.always = always
    }

    public struct Cage: Codable, Equatable, Sendable {
        public var pid: Int32
        public var permits: [CagePermit]
        /// Whether the children that already ran when the cage went up count
        /// as caged. Those born afterwards always do.
        public var children: Bool
    }
}

/// An address, a prefix length and an optional port — `deelpe_core::allow::Permit`.
public struct CagePermit: Codable, Equatable, Sendable {
    public var net: String
    public var bits: UInt8
    public var port: UInt16?

    public init(net: String, bits: UInt8, port: UInt16? = nil) {
        self.net = net
        self.bits = bits
        self.port = port
    }

    /// Does this permit cover the destination? An address that does not
    /// parse is covered by nothing: a destination we cannot name is not an
    /// allowed one.
    public func covers(ip: String, port: UInt16?) -> Bool {
        if let p = self.port, p != port { return false }
        guard let a = CagePermit.bytes(ip), let b = CagePermit.bytes(net), a.count == b.count else { return false }
        let bits = Int(self.bits)
        guard bits <= a.count * 8 else { return false }
        let full = bits / 8, rest = bits % 8
        if a[..<full] != b[..<full] { return false }
        return rest == 0 || (a[full] ^ b[full]) >> (8 - rest) == 0
    }

    /// 4 or 16 bytes. A v4 address in v6 clothing (`::ffff:1.2.3.4`) is a
    /// v4 address; a scope (`fe80::1%en0`) is dropped.
    static func bytes(_ text: String) -> [UInt8]? {
        let s = String(text.split(separator: "%", maxSplits: 1).first ?? "")
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 {
            return withUnsafeBytes(of: &v4.s_addr) { Array($0) }
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, s, &v6) == 1 else { return nil }
        let b = withUnsafeBytes(of: &v6) { Array($0) }
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xff && b[11] == 0xff { return Array(b[12...]) }
        return b
    }
}

/// A process on the way from the sender up to launchd.
public struct ProcessLink: Equatable, Sendable {
    public var pid: Int32
    public var started: Date

    public init(pid: Int32, started: Date) {
        self.pid = pid
        self.started = started
    }
}

public enum CageVerdict: Equatable, Sendable {
    /// Let the flow through for good.
    case allow
    /// Refuse it.
    case drop
    /// Let it through, but keep looking at its data: the process may be caged
    /// later, and an open connection must not outlive that.
    case watch
}

extension CageTable {
    /// The verdict for a flow to `ip:port` from the process at `chain[0]`,
    /// whose ancestors follow. `armed`: when each caged PID first appeared in
    /// a table.
    ///
    /// A process is caged when it is in the table itself, or when an
    /// ancestor is and the branch towards it was born after that cage went up
    /// (or the cage takes the children that already ran). The same line the
    /// cgroup draws on Linux.
    public func verdict(ip: String, port: UInt16?, chain: [ProcessLink], armed: [Int32: Date]) -> CageVerdict {
        if always.contains(where: { $0.covers(ip: ip, port: port) }) { return .allow }
        for (i, link) in chain.enumerated() {
            guard let cage = cages.first(where: { $0.pid == link.pid }) else { continue }
            let bornInside = i > 0 && armed[link.pid].map { chain[i - 1].started >= $0 } == true
            guard i == 0 || cage.children || bornInside else { continue }
            return cage.permits.contains(where: { $0.covers(ip: ip, port: port) }) ? .allow : .drop
        }
        return .watch
    }
}

/// What the relay calls on the filter's Mach service.
@objc public protocol CageFilterXPC {
    /// `table`: one JSON line as the service wrote it. The reply is `nil`, or
    /// why the table was not taken.
    func apply(_ table: Data, withReply reply: @escaping (String?) -> Void)
    /// The flows refused since the last call, as a JSON array of `CageRefusal`.
    func refused(withReply reply: @escaping (Data) -> Void)
}
