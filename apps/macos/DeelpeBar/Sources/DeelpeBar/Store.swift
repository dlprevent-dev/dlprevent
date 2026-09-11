import AppKit
import Combine
import DeelpeProtocol
import UniformTypeIdentifiers
import UserNotifications

enum ExportFormat: String {
    case csv, json
    var contentType: UTType { self == .csv ? .commaSeparatedText : .json }
}

/// Holds the state for the window and the menu bar, polls the service every 3 s.
@MainActor
final class Store: ObservableObject {
    @Published var alerts: [Alert] = []
    @Published var watched: [String] = []
    /// The service's exception list (signing IDs, `prefix.*`, `team:ID`).
    @Published var ignored: [String] = []
    @Published var status: Status?
    /// Learning phase of the service; nil with an older service.
    @Published var learn: LearnStatus?
    /// Connection to the central server; nil = not connected.
    @Published var central: CentralInfo?
    /// The running service does not know `CentralStatus` (older than this app).
    @Published var centralUnsupported = false
    @Published var error: String?
    @Published var selectedAlert: Alert.ID?
    /// Table with every stored alert instead of the newest 500. Costs the
    /// whole file per query, so only on request.
    @Published var showAll = false { didSet { if showAll != oldValue { refresh() } } }
    /// Host names for destination addresses (reverse DNS), display only. Its
    /// own object; changes are forwarded to `objectWillChange` below.
    let hosts = HostResolver()
    private var hostsSink: AnyCancellable?
    /// Struck pairs, not yet sent to the service: one password dialog for the
    /// whole review instead of one per strike.
    @Published var pendingForget = Set<String>()

    /// Alerts the user has not yet seen in the window. The key is made of id
    /// and time: ids do carry on across restarts, but they start at 1 again
    /// once the log on disk has been deleted.
    @Published var unseenAlerts = 0
    private var seen = Set<String>()
    /// Set by the AppDelegate: is the window visible right now?
    var isWindowVisible: () -> Bool = { false }
    /// Set by the AppDelegate: open the window (for the popup).
    var openWindow: () -> Void = {}

    private let client = DaemonClient()
    private let queue = DispatchQueue(label: "ch.deelpe.bar.client")
    private var timer: Timer?

    @Published var installing = false
    @Published var exporting = false
    /// Green notice line in the window (service installed, export finished).
    @Published var message: String?
    /// Orange notice line: a protected folder is mirrored by a sync client
    /// and leaves the Mac through it without an alert.
    @Published var syncWarning: String?
    /// Alert ids already seen; nil until the service's first answer, so that
    /// the existing backlog does not set off a flood of notifications at
    /// startup.
    private var knownIds: Set<UInt64>?
    /// Only alerts younger than this many seconds are reported: "All stored"
    /// pulls in old rows that are not new.
    private static let notifyWindow: TimeInterval = 600

    var daemonRunning: Bool { status != nil }
    var daemonInstalled: Bool { Installer.isInstalled }

    func installDaemon() {
        installing = true
        message = nil
        queue.async {
            let r = Result { try Installer.installDaemon() }
            Task { @MainActor in
                self.installing = false
                switch r {
                case .success: self.message = "Service installed. It now starts with the system."
                case .failure(let e): self.message = e.localizedDescription
                }
                try? Installer.enableLoginItem()
                self.refresh()
            }
        }
    }

    func start() {
        hostsSink = hosts.objectWillChange.sink { [weak self] _ in self?.objectWillChange.send() }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 3, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    func refresh() {
        let all = showAll
        queue.async { [client] in
            let result: Result<(Status, [Alert], [String], [String], LearnStatus?, CentralInfo??), Error> = Result {
                guard case .status(let s) = try client.send(.status) else { throw ProtocolError.malformed("status") }
                guard case .alerts(let a) = try client.send(all ? .alertsAll : .alerts) else { throw ProtocolError.malformed("alerts") }
                guard case .watched(let w) = try client.send(.watchList) else { throw ProtocolError.malformed("watched") }
                // An older service does not know IgnoreList: then empty, no error.
                let i: [String]
                if case .ignored(let list) = try client.send(.ignoreList) { i = list } else { i = [] }
                let l: LearnStatus?
                if case .learn(let st) = try client.send(.learnStatus) { l = st } else { l = nil }
                // Doubly optional: the outer nil = the service does not know the request.
                let c: CentralInfo??
                if case .central(let info) = try client.send(.centralStatus) { c = .some(info) } else { c = nil }
                return (s, a, w, i, l, c)
            }
            Task { @MainActor in self.apply(result) }
        }
    }

    private func apply(_ result: Result<(Status, [Alert], [String], [String], LearnStatus?, CentralInfo??), Error>) {
        switch result {
        case .success(let (s, a, w, i, l, c)):
            status = s
            centralUnsupported = c == nil
            central = c ?? nil
            watched = w
            ignored = i
            learn = l
            alerts = a
            hosts.lookupMissing(ips: a.compactMap(\.remote))
            // Learning-phase rows do not count as unseen: they are collected
            // material, not an alert.
            if isWindowVisible() { markSeen() } else { unseenAlerts = a.filter { !$0.isLearning && !seen.contains(key($0)) }.count }
            notifyNew(in: a)
            error = nil
        case .failure(let e):
            status = nil
            error = e.localizedDescription
        }
    }

    func markSeen() {
        seen.formUnion(alerts.map(key))
        unseenAlerts = 0
    }

    private func key(_ a: Alert) -> String { "\(a.id)@\(a.at.timeIntervalSince1970)" }

    /// System notification for new alerts. Runs in the app, not in the root
    /// service: that one has no login session and does not reach the user.
    /// Updates (same id, higher total) do not notify again. Not by highest id:
    /// a deviation of a known pair gets the id of its flow, which can be older
    /// than later alerts.
    private func notifyNew(in alerts: [Alert]) {
        let ids = Set(alerts.map(\.id))
        defer { knownIds = (knownIds ?? []).union(ids) }
        guard let known = knownIds else { return }
        let cutoff = Date().addingTimeInterval(-Self.notifyWindow)
        let fresh = alerts.filter { !known.contains($0.id) && !$0.isLearning && ($0.lastAt ?? $0.at) > cutoff }.sorted { $0.at < $1.at }
        guard !fresh.isEmpty else { return }
        Notifier.post(fresh)
    }

    func addFolderViaDialog() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Protect"
        panel.message = "Choose folders whose data must not leave this Mac unnoticed"
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK else { return }
        let paths = panel.urls.map(\.path)
        // One password dialog for all the chosen folders.
        sendPrivileged(paths.map { ["watch", "add", $0] })
        let synced = paths.compactMap { p in SyncDetector.client(forPath: p).map { (p, $0) } }
        if let (p, client) = synced.first {
            syncWarning = "\(abbreviate(p)) is synced by \(client). Sync clients are on the ignore list, so data in this folder leaves this Mac without an alert."
        }
    }

    func removeFolder(_ path: String) { sendPrivileged([["watch", "remove", path]]) }

    /// Rule for the exception list, bound to the team (`TEAM/signing-id`, as
    /// `Config::ignore_rule_for` in Rust). Signed processes only.
    static func ignoreRule(for identity: ProcessIdentity) -> String? {
        if case .signed(let teamId, let signingId) = identity, !signingId.isEmpty { return "\(teamId)/\(signingId)" }
        return nil
    }

    func ignore(_ rule: String) { sendPrivileged([["ignore", "add", rule]]) }

    // Learning phase: everything through the CLI as root, like the protection list.
    /// Confirm together with every collected strike in one dialog. The strikes
    /// stay until the call has succeeded (cancelling loses nothing).
    func learnConfirm() {
        let strikes = pendingForget.map { ["learn", "forget", $0] }
        sendPrivileged([["learn", "confirm"]], tolerant: strikes) { self.pendingForget = [] }
    }
    /// Apply strikes without confirming (active phase).
    func learnApplyStrikes() {
        let strikes = pendingForget.map { ["learn", "forget", $0] }
        if !strikes.isEmpty { sendPrivileged([], tolerant: strikes) { self.pendingForget = [] } }
    }
    func toggleStrike(_ key: String) {
        if pendingForget.contains(key) { pendingForget.remove(key) } else { pendingForget.insert(key) }
    }
    func learnRemember(_ id: UInt64) { sendPrivileged([["learn", "remember", String(id)]]) }
    func learnFlag(_ id: UInt64) { sendPrivileged([["learn", "flag", String(id)]]) }
    func learnRestart() { sendPrivileged([["learn", "restart"]]) }
    func unignore(_ rule: String) { sendPrivileged([["ignore", "remove", rule]]) }

    /// Enrollment with the central server through the admin dialog. The token
    /// is one-time and burnt afterwards; the CA fingerprint pins the server.
    func centralEnroll(_ cmd: EnrollCommand) {
        sendPrivileged([cmd.arguments]) { self.message = "Connected. The service reports to the central server within a minute." }
    }
    func centralRemove() {
        sendPrivileged([["central", "remove"]]) { self.message = "Disconnected. Revoke the agent in the dashboard as well." }
    }

    /// The service only accepts changes to the protection and exception lists
    /// from root: the CLI therefore runs through the admin dialog
    /// (Installer.runPrivileged).
    private func sendPrivileged(_ commands: [[String]], tolerant: [[String]] = [], onSuccess: @escaping @MainActor () -> Void = {}) {
        queue.async {
            let r = Result { try Installer.runPrivileged(commands, tolerant: tolerant) }
            Task { @MainActor in
                switch r {
                case .failure(let e): self.error = e.localizedDescription
                case .success: onSuccess()
                }
                self.refresh()
            }
        }
    }

    /// Fetch every stored alert (not just the 50 in the table) and save it as
    /// CSV or JSON, whichever the user picks. The same columns as
    /// `deelpe export`; the IP reputation is shown by the central dashboard.
    func exportAlerts(_ format: ExportFormat) {
        exporting = true
        message = nil
        queue.async { [client] in
            let r: Result<[Alert], Error> = Result {
                switch try client.send(.alertsAll) {
                case .alerts(let a): return a
                // An older service without AlertsAll.
                case .err(let m): throw ProtocolError.daemon("\(m) Reinstall the service (gear icon → Reinstall service) to enable export.")
                default: throw ProtocolError.malformed("alerts")
                }
            }
            Task { @MainActor in self.finishExport(r, format: format) }
        }
    }

    private func finishExport(_ result: Result<[Alert], Error>, format: ExportFormat) {
        exporting = false
        let alerts: [Alert]
        switch result {
        case .success(let a): alerts = a
        case .failure(let e): error = "Export failed: \(e.localizedDescription)"; return
        }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [format.contentType]
        panel.canCreateDirectories = true
        panel.prompt = "Export"
        panel.message = "Save all \(alerts.count) stored alerts as \(format.rawValue.uppercased())"
        panel.nameFieldStringValue = "deelpe-alerts-\(Self.fileStamp.string(from: Date())).\(format.rawValue)"
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data: Data
            switch format {
            case .csv: data = Data(AlertExport.csv(alerts).utf8)
            case .json: data = try AlertExport.json(alerts)
            }
            try data.write(to: url, options: .atomic)
            message = "Exported \(alerts.count) alerts to \(abbreviate(url.path))."
            error = nil
        } catch let e {
            error = "Export failed: \(e.localizedDescription)"
        }
    }

    private static let fileStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd-HHmm"
        return f
    }()
}
