import AppKit

@main
struct DeelpeBarMain {
    @MainActor static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)   // no dock icon, menu bar only
        app.run()
    }
}
