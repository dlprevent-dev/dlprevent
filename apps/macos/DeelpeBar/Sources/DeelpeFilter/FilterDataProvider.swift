import DeelpeProtocol
import Foundation
import Network
import NetworkExtension

/// The network cage on macOS: a content filter that refuses flows of caged
/// processes to anything outside their permits. The table comes from the
/// service through `CageListener`; the decision is `CageTable.verdict`.
///
/// Fails **open**: no table, no cage. If the relay's connection ends (the
/// service stopped or died), the table is emptied.
@objc(FilterDataProvider)
final class FilterDataProvider: NEFilterDataProvider {
    /// How much outbound data of an uncaged flow passes before the filter
    /// looks again. A connection opened before its process was caged is cut
    /// at that point.
    ///
    /// ponytail: up to this much leaves over a connection that was already
    /// open when the cage went up. Smaller costs throughput for every upload
    /// on the machine; larger leaks more.
    static let peek = 256 * 1024

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // No rules: every new flow comes to `handleNewFlow`.
        apply(NEFilterSettings(rules: [], defaultAction: .filterData)) { completionHandler($0) }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        CageStore.shared.replace(CageTable())
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        switch verdict(flow) {
        case .allow: return .allow()
        case .drop: return .drop()
        case .watch:
            return .filterDataVerdict(withFilterInbound: false, peekInboundBytes: 0, filterOutbound: true, peekOutboundBytes: Self.peek)
        }
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        switch verdict(flow) {
        case .drop: return .drop()
        case .allow: return .allow()
        case .watch: return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: Self.peek)
        }
    }

    private func verdict(_ flow: NEFilterFlow) -> CageVerdict {
        guard let socket = flow as? NEFilterSocketFlow, socket.direction == .outbound, let (ip, port) = remote(socket) else { return .allow }
        // No shortcut for an empty table: a flow allowed for good now would
        // outlive the first cage.
        let (table, armed) = CageStore.shared.snapshot()
        // The process itself first; then the app responsible for it — the
        // Safari network process sends for Safari, and hangs off launchd.
        var verdict = CageVerdict.watch
        for token in [flow.sourceProcessAuditToken, flow.sourceAppAuditToken] {
            guard let pid = Self.pid(token) else { continue }
            verdict = table.verdict(ip: ip, port: port, chain: Self.chain(pid), armed: armed)
            if verdict != .watch { break }
        }
        return verdict
    }

    private func remote(_ flow: NEFilterSocketFlow) -> (String, UInt16?)? {
        guard #available(macOS 15.0, *) else {
            guard let ep = flow.remoteEndpoint as? NWHostEndpoint else { return nil }
            return (ep.hostname, UInt16(ep.port))
        }
        guard case let .hostPort(host, port)? = flow.remoteFlowEndpoint else { return nil }
        let ip: String
        switch host {
        case .ipv4(let a): ip = "\(a)"
        case .ipv6(let a): ip = "\(a)"
        case .name(let n, _): ip = n
        @unknown default: return nil
        }
        return (ip, port.rawValue)
    }

    /// `audit_token_t` is eight `UInt32`; the PID is the sixth.
    static func pid(_ token: Data?) -> Int32? {
        guard let token, token.count >= 24 else { return nil }
        return token.withUnsafeBytes { Int32(bitPattern: $0.load(fromByteOffset: 20, as: UInt32.self)) }
    }

    /// The process and its ancestors up to launchd, with start times.
    static func chain(_ pid: Int32) -> [ProcessLink] {
        var out: [ProcessLink] = []
        var p = pid
        while p > 1, out.count < 16 {
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.stride
            var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, p]
            guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { break }
            let tv = info.kp_proc.p_un.__p_starttime
            out.append(ProcessLink(pid: p, started: Date(timeIntervalSince1970: Double(tv.tv_sec) + Double(tv.tv_usec) / 1e6)))
            p = info.kp_eproc.e_ppid
        }
        return out
    }
}

/// The table, shared between the XPC thread and the filter's threads.
final class CageStore: @unchecked Sendable {
    static let shared = CageStore()
    private let lock = NSLock()
    private var table = CageTable()
    /// When each caged PID first showed up. Kept while it stays in the table.
    private var armed: [Int32: Date] = [:]

    func replace(_ new: CageTable) {
        lock.lock()
        defer { lock.unlock() }
        let now = Date()
        armed = Dictionary(new.cages.map { ($0.pid, armed[$0.pid] ?? now) }, uniquingKeysWith: { a, _ in a })
        table = new
    }

    func snapshot() -> (CageTable, [Int32: Date]) {
        lock.lock()
        defer { lock.unlock() }
        return (table, armed)
    }
}
