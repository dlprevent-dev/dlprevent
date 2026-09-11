import Foundation

/// Wire format towards `deelpe daemon`. Source of truth:
/// crates/deelpe/src/ipc.rs and crates/deelpe/tests/wire_format.rs (serde,
/// externally tagged enums).

public enum Request: Equatable {
    case watchAdd(String)
    case watchRemove(String)
    case watchList
    /// The newest alerts (capped, for the table).
    case alerts
    /// Every stored alert, oldest first (for the export).
    case alertsAll
    case show(UInt64)
    case status
    /// Exception list: signing id, `prefix.*` or `team:ID`.
    case ignoreAdd(String)
    case ignoreRemove(String)
    case ignoreList
    /// Learning phase (M2).
    case learnStatus
    case learnConfirm
    case learnForget(String)
    case learnRemember(UInt64)
    case learnFlag(UInt64)
    case learnRestart
    /// State of the connection to the central server; readable without root.
    case centralStatus

    /// One JSON line including the line break.
    public func encodeLine() throws -> String {
        let json: Any
        switch self {
        case .watchAdd(let p): json = ["WatchAdd": p]
        case .watchRemove(let p): json = ["WatchRemove": p]
        case .watchList: json = "WatchList"
        case .alerts: json = "Alerts"
        case .alertsAll: json = "AlertsAll"
        case .show(let id): json = ["Show": id]
        case .status: json = "Status"
        case .ignoreAdd(let r): json = ["IgnoreAdd": r]
        case .ignoreRemove(let r): json = ["IgnoreRemove": r]
        case .ignoreList: json = "IgnoreList"
        case .learnStatus: json = "LearnStatus"
        case .learnConfirm: json = "LearnConfirm"
        case .learnForget(let k): json = ["LearnForget": k]
        case .learnRemember(let id): json = ["LearnRemember": id]
        case .learnFlag(let id): json = ["LearnFlag": id]
        case .learnRestart: json = "LearnRestart"
        case .centralStatus: json = "CentralStatus"
        }
        let data = try JSONSerialization.data(withJSONObject: json, options: [.fragmentsAllowed, .withoutEscapingSlashes])
        return String(decoding: data, as: UTF8.self) + "\n"
    }
}

public enum ProcessIdentity: Equatable {
    case signed(teamId: String, signingId: String)
    case hashed(path: String, sha256: String)
    case unknown(path: String)

    public var isTrustedForm: Bool {
        if case .unknown = self { return false }
        return true
    }

    /// Short form for tables, identical to `ProcessIdentity::short` in Rust.
    public var short: String {
        switch self {
        case .signed(_, let signingId): return signingId
        case .hashed(let path, _), .unknown(let path): return (path as NSString).lastPathComponent
        }
    }

    public var description: String {
        switch self {
        case .signed(let team, let id): return "\(id) (Team \(team))"
        case .hashed(let path, let sha): return "\(path) [\(sha.prefix(12))]"
        case .unknown(let path): return "\(path) [unsigned]"
        }
    }
}

public struct Alert: Equatable, Identifiable {
    public let id: UInt64
    public let at: Date
    public let pid: UInt32
    public let identity: ProcessIdentity
    public let files: [String]
    public let remote: String?
    public let remotePort: UInt16?
    public let bytesOut: UInt64
    /// How the process got at the data, when not directly (process chain, copy).
    public let via: String?
    /// Last measurement, when the alert kept running after the first report;
    /// `bytesOut` is the total then. Absent on one-off reports.
    public let lastAt: Date?
    /// Verdict of the learning phase: "new", "learning", "deviation", "flagged".
    public let verdict: String
    /// Reason for "deviation".
    public let reason: String?
    /// External volume (USB, network drive) as the destination: mount point. `remote` is nil then.
    public let volume: String?
    /// Copy out of the protected folder: the destination folder.
    public let copyTo: String?
    /// A local destination (volume or copy) instead of the network.
    public var isLocal: Bool { volume != nil || copyTo != nil }

    /// Learning and review phase: stored, but not reported.
    public var isLearning: Bool { verdict == "learning" }

    /// Short text for the table.
    public var verdictText: String {
        switch verdict {
        case "learning": return "learning"
        case "deviation": return "deviation"
        case "flagged": return "always"
        case "denied": return "denied"
        default: return "new"
        }
    }

    public var target: String {
        if let v = volume { return "volume \(v)" }
        if let d = copyTo { return "copy to \(d)" }
        guard let r = remote else { return "?" }
        return "\(r):\(remotePort ?? 0)"
    }

    /// Full-text filter of the table: every word of the query has to occur
    /// somewhere (process, identity, files, destination, route, id). A word
    /// with a leading `-` excludes, e.g. `-claude`.
    public func matches(_ query: String) -> Bool {
        let words = query.lowercased().split(whereSeparator: { $0 == " " }).map(String.init)
        if words.isEmpty { return true }
        let hay = ([String(id), identity.description, identity.short, target, via ?? "", verdictText, reason ?? ""] + files).joined(separator: "\n").lowercased()
        return words.allSatisfy { w in
            if w.hasPrefix("-") {
                let neg = String(w.dropFirst())
                return neg.isEmpty || !hay.contains(neg)
            }
            return hay.contains(w)
        }
    }
}

public struct SensorState: Equatable {
    public let name: String
    public let error: String?
    public init(name: String, error: String?) { self.name = name; self.error = error }
}

public struct Status: Equatable {
    public let touched: Int
    public let alerts: Int
    public let watched: Int
    public let uptimeSecs: UInt64
    public let sensors: [SensorState]
    /// Notices from the service, such as a file changed behind its back.
    public let warnings: [String]

    public var failedSensors: [SensorState] { sensors.filter { $0.error != nil } }
    /// eslogger reports NOT_PERMITTED when the service lacks full disk access.
    public var needsFullDiskAccess: Bool {
        sensors.contains { $0.error?.contains("NOT_PERMITTED") == true }
    }
}

/// A learned pair (process, destination network:port), see learn.rs.
public struct Pair: Equatable, Identifiable {
    public let key: String
    public let process: String
    public let identity: ProcessIdentity
    public let destination: String
    public let port: UInt16?
    /// "candidate", "known", "flagged"
    public let state: String
    public let count: UInt64
    public let bytesMax: UInt64
    public let firstSeen: Date
    public let lastSeen: Date
    public var id: String { key }
    public var target: String { port.map { "\(destination):\($0)" } ?? destination }
}

public struct LearnStatus: Equatable {
    /// "learning", "review", "active"
    public let phase: String
    public let until: Date?
    public let pairs: [Pair]
    public var candidates: [Pair] { pairs.filter { $0.state == "candidate" } }
}

/// Connection to the central server (deelpe-server), see central.rs. Without
/// key and certificate: those stay with the service.
public struct CentralInfo: Equatable {
    public let url: String
    public let agentId: String
    public let enrolledAt: Date?
    public let lastOk: Date?
    public let lastError: String?
    public let lastErrorAt: Date?
    public let reports: UInt64
    public let generation: Int64
    public let managed: [String]
    public init(url: String, agentId: String, enrolledAt: Date?, lastOk: Date?, lastError: String?, lastErrorAt: Date?, reports: UInt64, generation: Int64, managed: [String]) {
        self.url = url; self.agentId = agentId; self.enrolledAt = enrolledAt; self.lastOk = lastOk
        self.lastError = lastError; self.lastErrorAt = lastErrorAt; self.reports = reports; self.generation = generation; self.managed = managed
    }
    init(json d: [String: Any]) {
        func date(_ k: String) -> Date? { (d[k] as? String).flatMap { isoFractional.date(from: $0) ?? isoPlain.date(from: $0) } }
        self.init(url: d["url"] as? String ?? "", agentId: d["agent_id"] as? String ?? "", enrolledAt: date("enrolled_at"),
                  lastOk: date("last_ok"), lastError: d["last_error"] as? String, lastErrorAt: date("last_error_at"),
                  reports: (d["reports"] as? NSNumber)?.uint64Value ?? 0, generation: (d["generation"] as? NSNumber)?.int64Value ?? 0,
                  managed: d["managed"] as? [String] ?? [])
    }
}

public enum Response: Equatable {
    case ok(String)
    /// `nil`: not connected.
    case central(CentralInfo?)
    case learn(LearnStatus)
    case err(String)
    case watched([String])
    case alerts([Alert])
    case alert(Alert?)
    case status(Status)
    case ignored([String])
}

public enum ProtocolError: Error, LocalizedError {
    case malformed(String)
    /// The service answered with `Err`.
    case daemon(String)
    public var errorDescription: String? {
        switch self {
        case .malformed(let m): return "Unexpected response: \(m)"
        case .daemon(let m): return m
        }
    }
}

extension Response {
    public static func decode(_ line: String) throws -> Response {
        guard let data = line.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let (key, value) = obj.first
        else { throw ProtocolError.malformed(line) }
        switch key {
        case "Ok": return .ok(value as? String ?? "")
        case "Err": return .err(value as? String ?? "")
        case "Watched": return .watched(value as? [String] ?? [])
        case "Ignored": return .ignored(value as? [String] ?? [])
        case "Learn":
            guard let d = value as? [String: Any] else { throw ProtocolError.malformed(line) }
            let pairs = try (d["pairs"] as? [[String: Any]] ?? []).map(Pair.init(json:))
            let until = (d["until"] as? String).flatMap { isoFractional.date(from: $0) ?? isoPlain.date(from: $0) }
            return .learn(LearnStatus(phase: d["phase"] as? String ?? "active", until: until, pairs: pairs))
        case "Central":
            if value is NSNull { return .central(nil) }
            guard let d = value as? [String: Any] else { throw ProtocolError.malformed(line) }
            return .central(CentralInfo(json: d))
        case "Alerts": return .alerts(try (value as? [[String: Any]] ?? []).map(Alert.init(json:)))
        case "Alert":
            if value is NSNull { return .alert(nil) }
            guard let d = value as? [String: Any] else { throw ProtocolError.malformed(line) }
            return .alert(try Alert(json: d))
        case "Status":
            guard let d = value as? [String: Any] else { throw ProtocolError.malformed(line) }
            return .status(Status(
                touched: d["touched"] as? Int ?? 0,
                alerts: d["alerts"] as? Int ?? 0,
                watched: d["watched"] as? Int ?? 0,
                uptimeSecs: (d["uptime_secs"] as? NSNumber)?.uint64Value ?? 0,
                sensors: (d["sensors"] as? [[String: Any]] ?? []).map {
                    SensorState(name: $0["name"] as? String ?? "?", error: $0["error"] as? String)
                },
                warnings: d["warnings"] as? [String] ?? []))
        default: throw ProtocolError.malformed(line)
        }
    }
}

/// Used for the export as well (Export.swift).
let isoFractional: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
}()
private let isoPlain: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f
}()

extension Alert {
    init(json d: [String: Any]) throws {
        guard let id = (d["id"] as? NSNumber)?.uint64Value,
              let atStr = d["at"] as? String,
              let at = isoFractional.date(from: atStr) ?? isoPlain.date(from: atStr),
              let pid = (d["pid"] as? NSNumber)?.uint32Value,
              let idj = d["identity"] as? [String: Any]
        else { throw ProtocolError.malformed(d.description) }
        self.id = id
        self.at = at
        self.pid = pid
        self.identity = try ProcessIdentity(json: idj)
        self.files = d["files"] as? [String] ?? []
        self.remote = d["remote"] as? String
        self.remotePort = (d["remote_port"] as? NSNumber)?.uint16Value
        self.bytesOut = (d["bytes_out"] as? NSNumber)?.uint64Value ?? 0
        self.via = d["via"] as? String
        self.lastAt = (d["last_at"] as? String).flatMap { isoFractional.date(from: $0) ?? isoPlain.date(from: $0) }
        self.verdict = d["verdict"] as? String ?? "new"
        self.reason = d["reason"] as? String
        self.volume = d["volume"] as? String
        self.copyTo = d["copy_to"] as? String
    }
}

extension Pair {
    init(json d: [String: Any]) throws {
        guard let key = d["key"] as? String, let idj = d["identity"] as? [String: Any],
              let first = (d["first_seen"] as? String).flatMap({ isoFractional.date(from: $0) ?? isoPlain.date(from: $0) }),
              let last = (d["last_seen"] as? String).flatMap({ isoFractional.date(from: $0) ?? isoPlain.date(from: $0) })
        else { throw ProtocolError.malformed(d.description) }
        self.key = key
        self.process = d["process"] as? String ?? ""
        self.identity = try ProcessIdentity(json: idj)
        self.destination = d["destination"] as? String ?? "?"
        self.port = (d["port"] as? NSNumber)?.uint16Value
        self.state = d["state"] as? String ?? "candidate"
        self.count = (d["count"] as? NSNumber)?.uint64Value ?? 0
        self.bytesMax = (d["bytes_max"] as? NSNumber)?.uint64Value ?? 0
        self.firstSeen = first
        self.lastSeen = last
    }
}

extension ProcessIdentity {
    init(json d: [String: Any]) throws {
        if let s = d["Signed"] as? [String: String] {
            self = .signed(teamId: s["team_id"] ?? "", signingId: s["signing_id"] ?? "")
        } else if let h = d["Hashed"] as? [String: String] {
            self = .hashed(path: h["path"] ?? "", sha256: h["sha256"] ?? "")
        } else if let u = d["Unknown"] as? [String: String] {
            self = .unknown(path: u["path"] ?? "")
        } else {
            throw ProtocolError.malformed(d.description)
        }
    }
}

/// Identical to `ui::human_bytes` in Rust.
public func humanBytes(_ b: UInt64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"]
    var v = Double(b)
    var i = 0
    while v >= 1024, i < units.count - 1 { v /= 1024; i += 1 }
    return i == 0 ? "\(b) B" : String(format: "%.1f %@", v, units[i])
}
