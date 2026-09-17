import AppKit
import Foundation

/// Installs the root service as a LaunchDaemon. The binary and the plist sit
/// in the app bundle (build.sh). Asks once for admin rights via a macOS
/// dialog.
enum Installer {
    static let binaryDest = "/usr/local/bin/deelpe"
    static let daemonPlistDest = "/Library/LaunchDaemons/ch.deelpe.daemon.plist"

    static var bundledBinary: URL? { Bundle.main.url(forResource: "deelpe", withExtension: nil) }
    static var bundledDaemonPlist: URL? { Bundle.main.url(forResource: "ch.deelpe.daemon", withExtension: "plist") }
    static var bundledAgentPlist: URL? { Bundle.main.url(forResource: "ch.deelpe.bar", withExtension: "plist") }

    static var isInstalled: Bool { FileManager.default.fileExists(atPath: daemonPlistDest) }

    enum Failure: Error, LocalizedError {
        case notBundled, script(String)
        var errorDescription: String? {
            switch self {
            case .notBundled: return "Service binary missing from the app bundle (run build.sh)."
            case .script(let m): return m
            }
        }
    }

    /// Blocks while the admin dialog is open. Call it from a background queue.
    static func installDaemon() throws {
        guard let bin = bundledBinary, let plist = bundledDaemonPlist else { throw Failure.notBundled }
        let script = """
        set -e
        mkdir -p /usr/local/bin /etc/deelpe
        launchctl bootout system \(daemonPlistDest) 2>/dev/null || true
        install -m 755 -o root -g wheel '\(bin.path)' '\(binaryDest)'
        install -m 644 -o root -g wheel '\(plist.path)' '\(daemonPlistDest)'
        # install copies the bundle's quarantine flag; since macOS 27 launchd
        # refuses a quarantined plist ("Bootstrap failed: 5").
        xattr -d com.apple.quarantine '\(binaryDest)' 2>/dev/null || true
        xattr -d com.apple.quarantine '\(daemonPlistDest)' 2>/dev/null || true
        launchctl bootstrap system '\(daemonPlistDest)'
        """
        try runAsAdmin(script)
    }

    /// Runs CLI commands as root (`deelpe watch add …`): the service only
    /// accepts changes to the protection and exception lists from root, so
    /// that no program of the user's can switch the protection off quietly.
    /// macOS remembers the authorisation for a few minutes, then it asks
    /// again.
    /// `tolerant`: commands whose failure must not abort the rest (such as a
    /// strike against a pair that has since been deleted, before
    /// confirming).
    static func runPrivileged(_ commands: [[String]], tolerant: [[String]] = []) throws {
        guard FileManager.default.isExecutableFile(atPath: binaryDest) else {
            throw Failure.script("Service is not installed yet (Install service…).")
        }
        func line(_ args: [String]) -> String {
            ([binaryDest] + args).map { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }.joined(separator: " ")
        }
        let lines = tolerant.map { line($0) + " || true" } + commands.map(line)
        try runAsAdmin((["set -e"] + lines).joined(separator: "\n"))
    }

    private static func runAsAdmin(_ shell: String) throws {
        let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let apple = "do shell script \"\(escaped)\" with administrator privileges"
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", apple]
        let err = Pipe()
        p.standardError = err
        try p.run()
        p.waitUntilExit()
        if p.terminationStatus != 0 {
            let msg = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            if msg.contains("-128") { throw Failure.script("Cancelled.") }
            throw Failure.script(msg.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }

    /// Start the app at login: a LaunchAgent in the user context, no root
    /// needed. File present = switched on; launchd reads it at the next login.
    static let agentPlistDest = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/LaunchAgents/ch.deelpe.bar.plist")

    static var isLoginItemEnabled: Bool { FileManager.default.fileExists(atPath: agentPlistDest.path) }

    static func enableLoginItem() throws {
        guard let plist = bundledAgentPlist else { throw Failure.notBundled }
        try FileManager.default.createDirectory(at: agentPlistDest.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? FileManager.default.removeItem(at: agentPlistDest)
        try FileManager.default.copyItem(at: plist, to: agentPlistDest)
        removexattr(agentPlistDest.path, "com.apple.quarantine", 0) // launchd refuses quarantined plists
    }

    static func disableLoginItem() throws {
        guard isLoginItemEnabled else { return }
        try FileManager.default.removeItem(at: agentPlistDest)
    }

    static func openFullDiskAccessSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            NSWorkspace.shared.open(url)
        }
    }
}
