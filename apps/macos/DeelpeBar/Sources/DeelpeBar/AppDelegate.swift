import AppKit
import SwiftUI
import Combine
import UserNotifications

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate {
    private let store = Store()
    private var statusItem: NSStatusItem!
    private var window: NSWindow?
    private var stateItem: NSMenuItem!
    private var subs = Set<AnyCancellable>()

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.mainMenu = editMenu()
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.image = NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "DLPrevent")
        statusItem.button?.imagePosition = .imageLeading
        statusItem.menu = buildMenu()
        store.isWindowVisible = { [weak self] in self?.window?.isVisible ?? false }
        store.openWindow = { [weak self] in self?.openWindow() }

        store.$unseenAlerts.combineLatest(store.$status)
            .receive(on: RunLoop.main)
            .sink { [weak self] unseen, status in self?.updateIcon(unseen: unseen, running: status != nil) }
            .store(in: &subs)
        if Notifier.available {
            UNUserNotificationCenter.current().delegate = self
            Notifier.requestPermission()
        }
        store.start()
        if CommandLine.arguments.contains("--open") { openWindow() }
    }

    /// Show it even when the app is in the foreground.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        completionHandler([.banner, .sound])
    }

    /// Click on the notification: open the window with the alert.
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        let id = (response.notification.request.content.userInfo[Notifier.alertKey] as? NSNumber)?.uint64Value
        Task { @MainActor in
            if let id { self.store.selectedAlert = id }
            self.openWindow()
            completionHandler()
        }
    }

    private func updateIcon(unseen: Int, running: Bool) {
        guard let b = statusItem.button else { return }
        let name = !running ? "lock.slash" : (unseen > 0 ? "exclamationmark.shield.fill" : "lock.shield")
        b.image = NSImage(systemSymbolName: name, accessibilityDescription: "DLPrevent")
        b.title = unseen > 0 ? " \(unseen)" : ""
        b.contentTintColor = !running ? .secondaryLabelColor : (unseen > 0 ? .systemRed : nil)
        stateItem.title = stateText()
    }

    private func stateText() -> String {
        store.status.map { "running · \($0.alerts) alerts · \($0.watched) folders" } ?? "Service not reachable"
    }

    /// Invisible main menu. Without an "Edit" menu carrying the standard
    /// selectors, macOS knows no ⌘V/⌘C/⌘X/⌘A in a menu bar app, for example in
    /// the key field.
    private func editMenu() -> NSMenu {
        let main = NSMenu()
        let edit = NSMenu(title: "Edit")
        edit.addItem(withTitle: "Undo", action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: "Redo", action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
        let item = NSMenuItem(); item.submenu = edit
        main.addItem(item)
        return main
    }

    private func buildMenu() -> NSMenu {
        let m = NSMenu()
        stateItem = NSMenuItem(title: stateText(), action: nil, keyEquivalent: "")
        stateItem.isEnabled = false
        m.addItem(stateItem)
        m.addItem(.separator())
        m.addItem(withTitle: "Open Window", action: #selector(openWindow), keyEquivalent: "o")
        m.addItem(withTitle: "Protect Folder…", action: #selector(addFolder), keyEquivalent: "n")
        let export = NSMenu(title: "Export Alerts")
        export.addItem(withTitle: "As CSV…", action: #selector(exportCSV), keyEquivalent: "")
        export.addItem(withTitle: "As JSON…", action: #selector(exportJSON), keyEquivalent: "")
        export.items.forEach { $0.target = self }
        let exportItem = NSMenuItem(title: "Export Alerts", action: nil, keyEquivalent: "")
        exportItem.submenu = export
        m.addItem(exportItem)
        m.addItem(.separator())
        m.addItem(withTitle: "Quit DLPrevent", action: #selector(quit), keyEquivalent: "q")
        m.items.forEach { $0.target = self }
        return m
    }

    @objc private func openWindow() {
        if window == nil {
            let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 900, height: 480),
                             styleMask: [.titled, .closable, .resizable, .miniaturizable],
                             backing: .buffered, defer: false)
            w.title = "DLPrevent"
            w.contentView = NSHostingView(rootView: MainView(store: store))
            w.isReleasedWhenClosed = false
            w.center()
            window = w
        }
        store.markSeen()
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }

    @objc private func addFolder() { store.addFolderViaDialog() }
    @objc private func exportCSV() { store.exportAlerts(.csv) }
    @objc private func exportJSON() { store.exportAlerts(.json) }
    @objc private func quit() { NSApp.terminate(nil) }
}
