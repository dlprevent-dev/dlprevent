import SwiftUI
import DeelpeProtocol

/// A table row. Since 2026-09-08 the IP reputation is shown by the central
/// dashboard, not by the app any more: one key and one cache for all devices
/// instead of one per Mac.
struct AlertRow: Identifiable {
    let alert: DeelpeProtocol.Alert
    var id: DeelpeProtocol.Alert.ID { alert.id }
}

struct MainView: View {
    @ObservedObject var store: Store
    /// Sort order of the alerts; newest first, until the user clicks a column.
    @State private var sortOrder = [KeyPathComparator(\AlertRow.alert.at, order: .reverse)]
    @State private var showSettings = false
    /// Full-text filter of the table, see `Alert.matches`.
    @State private var filter = ""

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if let notice = notice { notice; Divider() }
            HSplitView {
                alertsPane
                    .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                foldersPane
                    .frame(minWidth: 180, idealWidth: 220, maxWidth: 320, maxHeight: .infinity, alignment: .top)
            }
        }
        .frame(minWidth: 560, minHeight: 320)
        .onAppear { store.markSeen() }
    }

    // MARK: Header

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: store.daemonRunning ? "lock.shield.fill" : "lock.slash")
                .font(.title3)
                .foregroundStyle(store.daemonRunning ? .green : .secondary)
            Text("DLPrevent").font(.headline)
            Text("·").foregroundStyle(.tertiary)
            if let s = store.status {
                Text("up \(uptime(s.uptimeSecs))").foregroundStyle(.secondary)
                Text("·").foregroundStyle(.tertiary)
                Text("\(s.touched) processes touched").foregroundStyle(.secondary)
            } else {
                Text(store.error ?? "Service not reachable").foregroundStyle(.red)
            }
            Spacer()
            if let e = store.error, store.daemonRunning {
                Text(e).foregroundStyle(.red).lineLimit(1).truncationMode(.middle)
            }
            Button { store.refresh() } label: { Image(systemName: "arrow.clockwise") }
                .buttonStyle(.borderless).help("Refresh now")
            Button { showSettings.toggle() } label: { Image(systemName: "gearshape") }
                .buttonStyle(.borderless).help("Settings")
                .popover(isPresented: $showSettings, arrowEdge: .bottom) { SettingsView(store: store) }
        }
        .font(.callout)
        .padding(.horizontal, 12)
        .padding(.vertical, 7)
    }

    // MARK: Notice bar (service missing / full disk access / sensor dead)

    @ViewBuilder
    private var notice: (some View)? {
        if !store.daemonRunning {
            noticeBar(.orange, "exclamationmark.triangle.fill",
                      store.daemonInstalled
                        ? "The service is installed but not responding."
                        : "The background service is not installed yet. It runs as a system service and needs your admin password once.") {
                Button(store.daemonInstalled ? "Reinstall…" : "Install service…") { store.installDaemon() }
                    .disabled(store.installing)
            }
        } else if let s = store.status, let w = s.warnings.first {
            noticeBar(.red, "exclamationmark.lock.fill",
                      "\(w). Someone edited the service's files directly, bypassing the password dialog. Check the protected folders, ignore list and learned pairs; details in /var/lib/deelpe/changes.log.") {
                Button("Reinstall service…") { store.installDaemon() }.disabled(store.installing)
            }
        } else if let s = store.status, s.needsFullDiskAccess {
            noticeBar(.red, "lock.open.trianglebadge.exclamationmark",
                      "The service lacks “Full Disk Access”. Without it, it cannot see file reads. In System Settings press + and add /usr/local/bin/deelpe (⌘⇧G), then restart the service.") {
                Button("Open System Settings") { Installer.openFullDiskAccessSettings() }
                Button("Restart service…") { store.installDaemon() }.disabled(store.installing)
            }
        } else if let s = store.status, let f = s.failedSensors.first {
            noticeBar(.red, "exclamationmark.triangle.fill", "Sensor \(f.name) failed: \(f.error?.split(separator: "\n").first ?? "")") {
                Button("Restart service…") { store.installDaemon() }.disabled(store.installing)
            }
        } else if let l = store.learn, l.phase == "review" {
            noticeBar(.orange, "graduationcap.fill",
                      "Learning finished with \(l.candidates.count) process–destination pairs. Review the list, strike what you don't recognise, then confirm. Until then nothing is reported.") {
                Button("Review…") { showSettings = true }
                Button("Confirm all") { store.learnConfirm() }
            }
        } else if let w = store.syncWarning {
            noticeBar(.orange, "icloud.and.arrow.up", w) { Button("OK") { store.syncWarning = nil } }
        } else if let m = store.message {
            noticeBar(.green, "checkmark.circle.fill", m) { Button("OK") { store.message = nil } }
        }
    }

    private func noticeBar<A: View>(_ color: Color, _ symbol: String, _ text: String, @ViewBuilder actions: () -> A) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(color)
            Text(text).font(.callout).fixedSize(horizontal: false, vertical: true)
            Spacer()
            if store.installing || store.exporting { ProgressView().controlSize(.small) }
            if let m = store.message, !store.daemonRunning || store.status?.needsFullDiskAccess == true {
                Text(m).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            actions()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(color.opacity(0.08))
    }

    // MARK: Alerts

    private var alertsPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 4) {
                // Counter from the status: more are stored than the table loads.
                sectionTitle("Alerts", count: store.status?.alerts ?? store.alerts.count)
                if !filter.isEmpty || store.showAll {
                    Text(rowsLabel).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                TextField("Filter: process, file, IP, -word", text: $filter)
                    .textFieldStyle(.roundedBorder).font(.caption).frame(maxWidth: 220)
                    .help("Every word must match somewhere; a word starting with - must not, e.g. “-claude”. Process, identity, files, destination, how, ID.")
                Toggle("All stored", isOn: $store.showAll)
                    .toggleStyle(.checkbox).font(.caption)
                    .help("Load every stored alert instead of the newest 500. Slower with many alerts.")
                // With a label: a bare icon is barely visible in the borderless style.
                Menu {
                    Button("Export as CSV…") { store.exportAlerts(.csv) }
                    Button("Export as JSON…") { store.exportAlerts(.json) }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
                .menuStyle(.borderlessButton).fixedSize()
                .help("Export all stored alerts as CSV or JSON")
                .disabled(!store.daemonRunning || store.exporting)
                .padding(.trailing, 8)
            }
            if store.alerts.isEmpty {
                emptyState("checkmark.shield", "No alerts",
                           "No process has read from a protected folder and then sent data.")
            } else if rows.isEmpty {
                emptyState("line.3.horizontal.decrease.circle", "No match",
                           "No loaded alert matches “\(filter)”. Try “All stored” to search everything.")
            } else {
                // Columns with min/ideal instead of a fixed width, so the user can
                // drag them; `value:` makes the column headers sortable.
                Table(rows, selection: $store.selectedAlert, sortOrder: $sortOrder) {
                    TableColumn("Time", value: \.alert.at) { r in
                        Text(stamp(r.alert.at))
                            .foregroundStyle(.secondary).monospacedDigit()
                            .help(stampInUTC(r.alert.at))
                    }.width(min: 90, ideal: 145)
                    TableColumn("Verdict", value: \.alert.verdict) { r in
                        Text(r.alert.verdictText).foregroundStyle(verdictColor(r.alert.verdict))
                    }.width(min: 50, ideal: 70)
                    TableColumn("Process", value: \.alert.identity.short) { r in
                        Text(r.alert.identity.short).foregroundStyle(r.alert.identity.isTrustedForm ? Color.primary : Color.red)
                    }.width(min: 80, ideal: 200)
                    TableColumn("File", value: \.alert.lastFileName) { r in
                        Text(r.alert.lastFileName).foregroundStyle(.secondary)
                    }.width(min: 60, ideal: 180)
                    TableColumn("Destination", value: \.alert.target) { r in
                        if let h = store.hosts.host(for: r.alert.remote) {
                            Text(h).help(r.alert.target)
                        } else {
                            Text(r.alert.target).monospacedDigit()
                        }
                    }.width(min: 80, ideal: 150)
                    TableColumn("Sent", value: \.alert.bytesOut) { r in
                        Text(r.alert.isLocal ? "–" : humanBytes(r.alert.bytesOut)).foregroundStyle(.orange).monospacedDigit()
                    }.width(min: 60, ideal: 80)
                }
                .tableStyle(.inset(alternatesRowBackgrounds: true))
                if let sel = store.alerts.first(where: { $0.id == store.selectedAlert }) {
                    Divider()
                    AlertDetail(alert: sel,
                                onIgnore: { store.ignore($0) }, onRemember: { store.learnRemember($0) }, onFlag: { store.learnFlag($0) },
                                host: store.hosts.host(for: sel.remote)).padding(10)
                }
            }
        }
    }

    private var rows: [AlertRow] {
        store.alerts.lazy.filter { $0.matches(filter) }
            .map { AlertRow(alert: $0) }
            .sorted(using: sortOrder)
    }

    private var rowsLabel: String {
        let shown = store.alerts.filter { $0.matches(filter) }.count
        return filter.isEmpty ? "\(shown) loaded" : "\(shown) of \(store.alerts.count) loaded"
    }

    // MARK: Folders

    private var foldersPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 4) {
                sectionTitle("Protected", count: store.watched.count)
                Spacer()
                Button { store.addFolderViaDialog() } label: { Image(systemName: "plus") }
                    .buttonStyle(.borderless).help("Add folder").padding(.trailing, 8)
            }
            if store.watched.isEmpty {
                emptyState("folder.badge.plus", "No folders", "Press + to choose a folder.")
            } else {
                List(store.watched, id: \.self) { path in
                    HStack(spacing: 6) {
                        Image(systemName: "folder.fill").foregroundStyle(.secondary).font(.caption)
                        Text(abbreviate(path)).lineLimit(1).truncationMode(.middle).help(path)
                        if let client = SyncDetector.client(forPath: path) {
                            Image(systemName: "icloud.and.arrow.up").foregroundStyle(.orange).font(.caption)
                                .help("Synced by \(client): its data leaves this Mac through the sync client, which is not reported.")
                        }
                        Spacer(minLength: 4)
                        Button { store.removeFolder(path) } label: { Image(systemName: "xmark.circle.fill") }
                            .buttonStyle(.plain).foregroundStyle(.tertiary).help("Stop protecting")
                    }
                    .font(.callout)
                }
                .listStyle(.inset)
            }
        }
    }

    // MARK: Building blocks

    private func sectionTitle(_ title: String, count: Int) -> some View {
        HStack(spacing: 6) {
            Text(title).font(.subheadline.bold())
            if count > 0 {
                Text("\(count)")
                    .font(.caption2.bold()).foregroundStyle(.secondary)
                    .padding(.horizontal, 5).padding(.vertical, 1)
                    .background(.quaternary, in: Capsule())
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
    }

    private func emptyState(_ symbol: String, _ title: String, _ text: String) -> some View {
        VStack(spacing: 6) {
            Image(systemName: symbol).font(.system(size: 28)).foregroundStyle(.quaternary)
            Text(title).font(.subheadline.bold()).foregroundStyle(.secondary)
            Text(text).font(.caption).foregroundStyle(.tertiary).multilineTextAlignment(.center)
        }
        .padding(16)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct AlertDetail: View {
    let alert: DeelpeProtocol.Alert
    /// For "Ignore this process"; nil in previews without a service.
    var onIgnore: ((String) -> Void)? = nil
    var onRemember: ((UInt64) -> Void)? = nil
    var onFlag: ((UInt64) -> Void)? = nil
    /// Reverse DNS name of the destination, if known.
    var host: String? = nil

    private var verdictLine: String {
        switch alert.verdict {
        case "learning": return "learning phase: collected, not reported"
        case "deviation": return "known pair, but " + (alert.reason ?? "deviates")
        case "flagged": return "always reported (your choice)"
        case "denied": return alert.reason ?? "destination is not on the allowlist of a strict folder"
        case "inbound": return alert.via ?? "a file landed in the protected folder"
        default: return alert.identity.isTrustedForm ? "new process–destination pair" : "unsigned process, always reported"
        }
    }

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 3) {
            GridRow {
                label("Process")
                HStack(spacing: 8) {
                    Text("\(alert.identity.description) · PID \(alert.pid)")
                    if let rule = Store.ignoreRule(for: alert.identity), let onIgnore {
                        Button("Ignore this process") { onIgnore(rule) }
                            .buttonStyle(.link)
                            .help("Never report \(rule) again. Asks for the admin password. Undo in Settings.")
                    }
                }
            }
            GridRow {
                label("Verdict")
                HStack(spacing: 8) {
                    Text(verdictLine).foregroundStyle(verdictColor(alert.verdict))
                    if alert.identity.isTrustedForm, let onRemember, let onFlag {
                        if alert.verdict != "flagged" {
                            Button("Remember") { onRemember(alert.id) }.buttonStyle(.link)
                                .help("This process may send to this destination: stay silent from now on, unless amount or time deviate strongly. Asks for the admin password.")
                        }
                        Button("Always report") { onFlag(alert.id) }.buttonStyle(.link)
                            .help("Report every transfer of this process to this destination. Asks for the admin password.")
                    }
                }
            }
            GridRow {
                label("Destination")
                HStack(spacing: 6) {
                    Text(alert.target).monospaced()
                    if let host { Text("· \(host)").foregroundStyle(.secondary) }
                    if alert.volume != nil { Text("· external volume, not a network destination").foregroundStyle(.secondary) }
                    if alert.copyTo != nil { Text("· copied out of the protected folder; an upload of the copy is reported separately").foregroundStyle(.secondary) }
                }
            }
            GridRow {
                label("Sent")
                HStack(spacing: 6) {
                    Text(humanBytes(alert.bytesOut)).foregroundStyle(.orange)
                    if let l = alert.lastAt {
                        Text("in total, still sending at \(stamp(l, seconds: true))").foregroundStyle(.secondary)
                    }
                }
            }
            if let v = alert.via {
                GridRow(alignment: .top) { label("How"); Text(v).foregroundStyle(.orange) }
            }
            GridRow(alignment: .top) {
                label("Files")
                // Up to 64 paths hang off one alert (MAX_TOUCHED_FILES in
                // correlate.rs). Uncapped, the list pushed the table out of
                // the window and SwiftUI drew the rows on top of each other:
                // six are shown, the rest scrolls.
                ScrollView {
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(alert.files, id: \.self) {
                            Text($0).monospaced().lineLimit(1).truncationMode(.middle).help($0)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: min(CGFloat(alert.files.count), 6) * 15)
            }
        }
        .font(.caption)
        .textSelection(.enabled)
    }

    private func label(_ s: String) -> some View { Text(s).foregroundStyle(.secondary) }
}

func verdictColor(_ verdict: String) -> Color {
    switch verdict {
    case "learning": return .secondary
    case "flagged": return .orange
    case "denied": return .purple
    // Something came in, nothing went out: not an alarm colour.
    case "inbound": return .blue
    default: return .red
    }
}

/// A group in the gear window that folds open and shut. Folded up, only the
/// header with the state remains; that keeps the window short even when a
/// group explains a lot. The state survives closing.
private struct SettingsSection<Status: View, Content: View>: View {
    private let title: String
    private let icon: String
    private let status: Status
    private let content: Content
    @AppStorage private var open: Bool

    init(
        id: String,
        title: String,
        icon: String,
        @ViewBuilder status: () -> Status,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.icon = icon
        self.status = status()
        self.content = content()
        _open = AppStorage(wrappedValue: false, SettingsSection.key(id))
    }

    /// Used from outside too: a notice bar can fold a group open.
    static func key(_ id: String) -> String { "settings.section.\(id).open" }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.easeInOut(duration: 0.15)) { open.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "chevron.right")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .rotationEffect(.degrees(open ? 90 : 0))
                        .frame(width: 10)
                    Image(systemName: icon).foregroundStyle(.secondary)
                    Text(title).font(.subheadline.weight(.semibold))
                    Spacer()
                    status
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(open ? "Collapse" : "Expand")
            if open { content }
        }
    }
}

/// Height of the content, so that the window grows with it but never runs off
/// the screen: beyond that it scrolls.
private struct SettingsHeightKey: PreferenceKey {
    static var defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) { value = max(value, nextValue()) }
}

/// The popover behind the gear: start at login, central server, learning
/// phase, ignored processes. Each group folds open on its own, so that the
/// window does not span half the screen.
struct SettingsView: View {
    @ObservedObject var store: Store
    @State private var loginItem = Installer.isLoginItemEnabled
    @State private var loginError: String?
    @State private var ignoreDraft = ""
    @State private var enrollPaste = ""
    @State private var enroll = EnrollCommand(url: "", token: "", caSha256: "")
    /// Initial value roughly as tall as five folded groups: otherwise the
    /// window visibly jumps open once.
    @State private var height: CGFloat = 220

    /// Folded up, all groups are the same height; only what needs attention
    /// folds open by itself on opening.
    private static let maxHeight: CGFloat = 560

    init(store: Store) {
        self.store = store
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 6) {
                SettingsSection(id: "general", title: "General", icon: "gearshape") {
                    EmptyView()
                } content: {
                    generalSection
                }
                Divider()
                SettingsSection(id: "central", title: "Central server", icon: "server.rack") {
                    centralStatus
                } content: {
                    centralSection
                }
                Divider()
                SettingsSection(id: "learning", title: "Learning", icon: "graduationcap") {
                    if let l = store.learn {
                        Text(learnPhaseText(l))
                            .foregroundStyle(l.phase == "review" ? .orange : .secondary).font(.caption)
                    }
                } content: {
                    learningSection
                }
                Divider()
                SettingsSection(id: "ignored", title: "Ignored processes", icon: "eye.slash") {
                    Text("\(store.ignored.count)").foregroundStyle(.secondary).font(.caption)
                } content: {
                    ignoredSection
                }
            }
            .padding(12)
            .background(GeometryReader { g in
                Color.clear.preference(key: SettingsHeightKey.self, value: g.size.height)
            })
        }
        .onPreferenceChange(SettingsHeightKey.self) { height = $0 }
        .frame(width: 380, height: min(max(height, 80), Self.maxHeight))
        .onAppear(perform: openWhatNeedsAttention)
    }

    /// The notice bars send the user here with "Review…" or "Settings…"; the
    /// group they mean has to be open then.
    private func openWhatNeedsAttention() {
        if store.learn?.phase == "review" {
            UserDefaults.standard.set(true, forKey: SettingsSection<EmptyView, EmptyView>.key("learning"))
        }
    }

    @ViewBuilder
    private var generalSection: some View {
        Toggle("Start at login", isOn: $loginItem)
            .onChange(of: loginItem) { _, on in
                do {
                    if on { try Installer.enableLoginItem() } else { try Installer.disableLoginItem() }
                    loginError = nil
                } catch {
                    loginError = error.localizedDescription
                    loginItem = Installer.isLoginItemEnabled
                }
            }
        if let e = loginError { Text(e).font(.caption).foregroundStyle(.red) }
        Text("The background service always starts with the system once installed. This only controls the menu bar app.")
            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        HStack {
            Text("Service").foregroundStyle(.secondary).font(.caption)
            Spacer()
            if store.installing { ProgressView().controlSize(.small) }
            Button("Reinstall service…") { store.installDaemon() }
                .disabled(store.installing)
                .help("Replaces the background service with the version bundled in this app. Asks for the admin password.")
        }
    }

    @ViewBuilder
    private var ignoredSection: some View {
        Text("Never reported, even when they read protected files and send data: indexers, backup, cloud sync, antivirus. Add one with “Ignore this process” in an alert, or type TEAM/signing-id, TEAM/prefix.*, or team:TEAM. Without a team the rule matches any signature using that name.")
            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        if !store.ignored.isEmpty {
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(store.ignored, id: \.self) { rule in
                        HStack(spacing: 6) {
                            Text(rule).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Button { store.unignore(rule) } label: { Image(systemName: "xmark.circle.fill") }
                                .buttonStyle(.plain).foregroundStyle(.tertiary).help("Report again")
                        }
                    }
                }
            }
            .frame(maxHeight: 110)
        }
        HStack {
            TextField("ABC123/com.example.app or team:ABC123", text: $ignoreDraft)
                .textFieldStyle(.roundedBorder).font(.caption)
                .onSubmit(addIgnore)
            Button("Add", action: addIgnore)
                .disabled(ignoreDraft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    @ViewBuilder
    private var centralStatus: some View {
        if let c = store.central {
            if c.lastError != nil {
                Label("error", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.caption)
            } else if c.lastOk != nil {
                Label("connected", systemImage: "checkmark.circle.fill").foregroundStyle(.green).font(.caption)
            } else {
                Text("waiting for first report").foregroundStyle(.secondary).font(.caption)
            }
        } else {
            Text("off").foregroundStyle(.secondary).font(.caption)
        }
    }

    /// Connection to the central server (deelpe-server). Address, one-time
    /// token and CA fingerprint come from the dashboard; the fingerprint pins
    /// the server so that nobody can intercept the enrollment. Runs as
    /// `deelpe central enroll` through the admin dialog.
    @ViewBuilder
    private var centralSection: some View {
        if store.centralUnsupported {
            Text("The installed service is older than this app. Use “Reinstall service…” in General first.")
                .font(.caption).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
        } else if let c = store.central {
            Grid(alignment: .leading, horizontalSpacing: 8, verticalSpacing: 2) {
                GridRow { Text("server").foregroundStyle(.secondary); Text(c.url).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle) }
                GridRow { Text("agent").foregroundStyle(.secondary); Text(c.agentId).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle) }
                GridRow { Text("last report").foregroundStyle(.secondary); Text(c.lastOk.map(relative) ?? "never") }
                GridRow { Text("reports").foregroundStyle(.secondary); Text("\(c.reports)") }
                if !c.managed.isEmpty {
                    GridRow(alignment: .top) { Text("folders from server").foregroundStyle(.secondary); Text(c.managed.joined(separator: "\n")).font(.caption.monospaced()) }
                }
                if let e = c.lastError {
                    GridRow(alignment: .top) { Text("error").foregroundStyle(.secondary); Text(e).foregroundStyle(.orange) }
                }
            }
            .font(.caption)
            HStack {
                Spacer()
                Button("Disconnect…", role: .destructive) { store.centralRemove() }
                    .help("Removes the connection on this Mac. Asks for the admin password. Revoke the agent in the dashboard too.")
            }
        } else {
            Text("Reports alerts and status to the DLPrevent central server and receives protected folders from it. Only the configured server is contacted, with a client certificate; the CA fingerprint pins the server. The token is single-use.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TextField("Paste the enrollment command from the dashboard (Agents → Enroll)", text: $enrollPaste)
                .textFieldStyle(.roundedBorder).font(.caption)
                .onChange(of: enrollPaste) { _, v in
                    if let c = EnrollCommand.parse(v) { enroll = c; enrollPaste = "" }
                }
            TextField("Server: IP, host name or https://host:8444", text: $enroll.url)
                .textFieldStyle(.roundedBorder).font(.caption)
            SecureField("Token", text: $enroll.token)
                .textFieldStyle(.roundedBorder).font(.caption)
            TextField("CA SHA-256 fingerprint", text: $enroll.caSha256)
                .textFieldStyle(.roundedBorder).font(.caption.monospaced())
            HStack {
                if let p = enroll.problem, !enroll.url.isEmpty || !enroll.token.isEmpty || !enroll.caSha256.isEmpty {
                    Text(p).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                Button("Connect…") {
                    store.centralEnroll(enroll)
                    enroll = EnrollCommand(url: "", token: "", caSha256: "")
                }
                .disabled(enroll.problem != nil || !store.daemonRunning)
                .help("Runs `deelpe central enroll` with the admin password.")
            }
        }
    }

    @ViewBuilder
    private var learningSection: some View {
        if let l = store.learn {
            Text(learnHelp(l)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if !l.pairs.isEmpty {
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(l.pairs.sorted { $0.lastSeen > $1.lastSeen }) { p in
                            let struck = store.pendingForget.contains(p.key)
                            HStack(spacing: 6) {
                                Circle().fill(pairColor(p.state)).frame(width: 6, height: 6)
                                Text(p.process).lineLimit(1).truncationMode(.middle).strikethrough(struck)
                                Text("→ \(p.target)").foregroundStyle(.secondary).monospacedDigit().lineLimit(1).strikethrough(struck)
                                Spacer()
                                Text("\(p.count)× · max \(humanBytes(p.bytesMax))").foregroundStyle(.tertiary).monospacedDigit()
                                Button { store.toggleStrike(p.key) } label: { Image(systemName: struck ? "arrow.uturn.backward.circle.fill" : "xmark.circle.fill") }
                                    .buttonStyle(.plain).foregroundStyle(struck ? AnyShapeStyle(.orange) : AnyShapeStyle(.tertiary))
                                    .help(struck ? "Undo strike" : "Strike: report this pair again as new. Applied with one password dialog on Confirm.")
                            }
                            .font(.caption)
                            .help("\(p.identity.description) → \(p.target)\n\(p.state), first \(stamp(p.firstSeen)), last \(stamp(p.lastSeen))")
                        }
                    }
                }
                .frame(maxHeight: 140)
            }
            HStack {
                Button("Restart learning…", role: .destructive) { store.learnRestart() }
                    .help("Forget every pair and start a new learning phase.")
                Spacer()
                let strikes = store.pendingForget.count
                if l.phase != "active" {
                    Button(strikes > 0 ? "Strike \(strikes), confirm \(l.candidates.count - strikes)" : "Confirm \(l.candidates.count) pairs") { store.learnConfirm() }
                        .keyboardShortcut(.defaultAction)
                        .help("These pairs are normal. From now on only new pairs and deviations are reported. One password dialog for everything.")
                } else if strikes > 0 {
                    Button("Apply \(strikes) strikes") { store.learnApplyStrikes() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        } else {
            Text("The service does not report a learning phase (reinstall it).").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func learnPhaseText(_ l: LearnStatus) -> String {
        switch l.phase {
        case "learning": return "learning until " + (l.until.map { stamp($0) } ?? "?")
        case "review": return "review needed"
        default: return "active · \(l.pairs.count) pairs"
        }
    }

    private func learnHelp(_ l: LearnStatus) -> String {
        switch l.phase {
        case "learning": return "Every process–destination pair is collected silently. Alerts still appear in the table (verdict “learning”) but are not announced."
        case "review": return "Learning is over. Strike pairs you don't recognise, then confirm. Nothing is announced until you do."
        default: return "Only new pairs and deviations (amount over 4× the usual maximum, or an unusual hour) are reported. “Remember” in an alert adds a pair; “Always report” flags one."
        }
    }

    private func pairColor(_ state: String) -> Color {
        switch state {
        case "known": return .green
        case "flagged": return .orange
        default: return .yellow
        }
    }

    private func addIgnore() {
        let r = ignoreDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !r.isEmpty else { return }
        store.ignore(r)
        ignoreDraft = ""
    }

}

extension DeelpeProtocol.Alert {
    var lastFileName: String { ((files.last ?? "") as NSString).lastPathComponent }
}

func abbreviate(_ path: String) -> String {
    let home = NSHomeDirectory()
    return path == home || path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
}

/// Timestamp as in the dashboard: "06 Sept 2026, 17:47", local time of this
/// Mac. Hard-wired instead of the system language, so that the menu bar and
/// the dashboard show the same string; the day comes first and the month as a
/// word, because depending on where you are from 06/09 is 6 September or
/// 9 June.
private func stampFormatter(_ pattern: String) -> DateFormatter {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_GB")
    f.dateFormat = pattern
    return f
}
private let stampMinutes = stampFormatter("dd MMM yyyy, HH:mm")
private let stampSeconds = stampFormatter("dd MMM yyyy, HH:mm:ss")
private let stampUTC: DateFormatter = {
    let f = stampFormatter("dd MMM yyyy, HH:mm")
    f.timeZone = TimeZone(identifier: "UTC")
    return f
}()

func stamp(_ d: Date, seconds: Bool = false) -> String {
    (seconds ? stampSeconds : stampMinutes).string(from: d)
}

/// The same time in UTC, as evidence in the tooltip next to local time.
func stampInUTC(_ d: Date) -> String { stampUTC.string(from: d) + " UTC" }

/// "2 minutes ago" instead of the system language, so that nothing in the
/// window is half German, half English.
private let relativeFormat = Date.RelativeFormatStyle(presentation: .named, locale: Locale(identifier: "en_GB"))

func relative(_ d: Date) -> String { d.formatted(relativeFormat) }

func uptime(_ s: UInt64) -> String {
    let h = s / 3600, m = (s % 3600) / 60
    return h > 0 ? "\(h) h \(m) min" : "\(m) min"
}
