import AppKit
import DeelpeProtocol
import UserNotifications

/// System notifications via UNUserNotificationCenter. Only possible from
/// inside an app bundle; `swift run` without a bundle would crash, hence the
/// check in `available`.
enum Notifier {
    static let category = "ch.deelpe.alert"
    static let alertKey = "alert"

    static var available: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    static func requestPermission() {
        guard available else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { _, _ in }
    }

    /// Up to three alerts individually, above that a single summary.
    static func post(_ fresh: [Alert]) {
        guard available else { return }
        let center = UNUserNotificationCenter.current()
        if fresh.count > 3 {
            let c = UNMutableNotificationContent()
            c.title = "DLPrevent: \(fresh.count) new alerts"
            c.body = fresh.map(\.identity.short).uniqued().prefix(4).joined(separator: ", ")
            c.sound = .default
            c.userInfo = [alertKey: fresh.last!.id]
            center.add(UNNotificationRequest(identifier: "alerts-\(fresh.last!.id)", content: c, trigger: nil))
            return
        }
        for a in fresh {
            let c = UNMutableNotificationContent()
            c.title = "DLPrevent: data leaving this Mac?"
            c.body = a.isLocal
                ? "\(a.identity.short) read \(a.lastFileName): \(a.target)."
                : "\(a.identity.short) read \(a.lastFileName) and sent \(humanBytes(a.bytesOut)) to \(a.target)."
            if a.verdict == "deviation", let r = a.reason { c.body += " \(r)." }
            c.sound = .default
            c.userInfo = [alertKey: a.id]
            center.add(UNNotificationRequest(identifier: "alert-\(a.id)", content: c, trigger: nil))
        }
    }
}

private extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
