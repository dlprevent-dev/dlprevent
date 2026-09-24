import Foundation

/// A flow the cage refused. It never sends a byte, so no sensor that counts
/// bytes sees it: the filter keeps it until the service drains the log
/// (`refused` through `DeelpeCageRelay`, read by `crates/deelpe/src/cage.rs`).
public struct CageRefusal: Codable, Equatable, Sendable {
    /// The process that tried to send.
    public var pid: Int32
    /// The caged ancestor it was refused for, or its parent: the one edge
    /// the service may not know from file events.
    public var ppid: Int32?
    public var ip: String
    public var port: UInt16?
    /// Seconds since 1970.
    public var at: Double
}

/// The refusals since the last drain, one per process and destination: a
/// browser retrying the same address is one attempt, not a thousand.
public struct CageRefusals: Sendable {
    /// ponytail: a flood of distinct destinations beyond this within one
    /// drain (5 s) is dropped from the report; the flows stay refused.
    public static let limit = 512
    private var entries: [String: CageRefusal] = [:]

    public init() {}

    public mutating func record(chain: [ProcessLink], table: CageTable, ip: String, port: UInt16?, at: Date) {
        guard let sender = chain.first else { return }
        let key = "\(sender.pid) \(ip) \(port.map(String.init) ?? "")"
        guard entries[key] == nil, entries.count < Self.limit else { return }
        let caged = chain.dropFirst().first { link in table.cages.contains { $0.pid == link.pid } }
        let ppid = (caged ?? chain.dropFirst().first)?.pid
        entries[key] = CageRefusal(pid: sender.pid, ppid: ppid, ip: ip, port: port, at: at.timeIntervalSince1970)
    }

    /// Everything recorded, oldest first; the log is empty afterwards.
    public mutating func drain() -> [CageRefusal] {
        defer { entries.removeAll() }
        return entries.values.sorted { $0.at < $1.at }
    }
}
