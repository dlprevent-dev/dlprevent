import Foundation

/// Enrollment with the central server: address, one-time token and CA
/// fingerprint from the dashboard. The fingerprint pins the server; without a
/// match `deelpe central enroll` aborts (central.rs).
public struct EnrollCommand: Equatable {
    public var url: String
    public var token: String
    public var caSha256: String
    public static let defaultPort = 8444

    public init(url: String, token: String, caSha256: String) {
        self.url = url; self.token = token; self.caSha256 = caSha256
    }

    /// Understands the line the dashboard shows under "Enroll agent":
    /// `sudo deelpe central enroll <url> <token> --ca-sha256 <fp>`.
    public static func parse(_ text: String) -> EnrollCommand? {
        let parts = text.split(whereSeparator: { $0 == " " || $0 == "\n" || $0 == "\t" }).map(String.init)
        guard let i = parts.firstIndex(of: "enroll"), i >= 2, parts[i - 1] == "central", parts.count > i + 2 else { return nil }
        let url = parts[i + 1], token = parts[i + 2]
        var fp: String?
        var j = i + 3
        while j < parts.count {
            if parts[j] == "--ca-sha256", j + 1 < parts.count { fp = parts[j + 1]; break }
            if parts[j].hasPrefix("--ca-sha256=") { fp = String(parts[j].dropFirst("--ca-sha256=".count)); break }
            j += 1
        }
        guard let f = fp, let u = normalizeURL(url) else { return nil }
        let c = EnrollCommand(url: u, token: token, caSha256: f)
        return c.problem == nil ? c : nil
    }

    /// Takes an IP, host name, host:port or https URL and returns
    /// `https://host:port` without a path. https only, otherwise nil.
    public static func normalizeURL(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !s.contains(" ") else { return nil }
        if s.lowercased().hasPrefix("http://") { return nil }
        if s.lowercased().hasPrefix("https://") { s = String(s.dropFirst("https://".count)) }
        while s.hasSuffix("/") { s.removeLast() }
        guard !s.contains("/"), !s.contains("@") else { return nil }
        // Is there a port? Mind IPv6 in brackets.
        let hasPort: Bool
        if s.hasPrefix("[") {
            hasPort = s.range(of: "]:") != nil
        } else {
            hasPort = s.filter { $0 == ":" }.count == 1
            if s.filter({ $0 == ":" }).count > 1 { s = "[\(s)]" }
        }
        if !hasPort { s += ":\(defaultPort)" }
        return "https://" + s
    }

    private static func isHex64(_ s: String) -> Bool {
        s.count == 64 && s.allSatisfy { $0.isHexDigit }
    }

    /// The fingerprint as it goes to the CLI: lower case, without colons.
    public var fingerprint: String { caSha256.lowercased().replacingOccurrences(of: ":", with: "") }

    /// Why the details are not enough, otherwise nil.
    public var problem: String? {
        if Self.normalizeURL(url) == nil { return "Server: enter an IP, a host name or https://host:8444" }
        if token.trimmingCharacters(in: .whitespaces).count < 16 { return "Token: paste the token from the dashboard" }
        if !Self.isHex64(fingerprint) { return "CA fingerprint: 64 hex characters (dashboard → Agents → Enroll)" }
        return nil
    }

    /// Arguments for `deelpe central enroll …`.
    public var arguments: [String] {
        ["central", "enroll", Self.normalizeURL(url) ?? url, token.trimmingCharacters(in: .whitespaces), "--ca-sha256", fingerprint]
    }
}
