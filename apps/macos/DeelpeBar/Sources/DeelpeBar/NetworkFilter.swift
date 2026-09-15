import Foundation
import NetworkExtension
import SystemExtensions

/// Switches on the network cage's content filter: activate the system
/// extension (the user approves it once in System Settings), then enable the
/// filter configuration (macOS asks once more). Without it the service can
/// only report flows out of a strict folder, not stop them.
@MainActor
final class NetworkFilter: NSObject, ObservableObject {
    static let extensionID = "ch.deelpe.bar.filter"

    @Published var enabled = false
    @Published var note: String?

    /// Only a signed build carries the extension (build.sh with DEVELOPER_ID).
    var bundled: Bool {
        FileManager.default.fileExists(atPath: Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/SystemExtensions/\(Self.extensionID).systemextension").path)
    }

    func refresh() {
        NEFilterManager.shared().loadFromPreferences { _ in
            Task { @MainActor in self.enabled = NEFilterManager.shared().isEnabled }
        }
    }

    func enable() {
        note = "Waiting for macOS…"
        let r = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: Self.extensionID, queue: .main)
        r.delegate = self
        OSSystemExtensionManager.shared.submitRequest(r)
    }

    private func configure() {
        NEFilterManager.shared().loadFromPreferences { error in
            Task { @MainActor in
                let m = NEFilterManager.shared()
                if let error { self.note = error.localizedDescription; return }
                if m.providerConfiguration == nil {
                    let c = NEFilterProviderConfiguration()
                    c.filterSockets = true
                    c.filterPackets = false
                    m.providerConfiguration = c
                }
                m.localizedDescription = "DLPrevent"
                m.isEnabled = true
                m.saveToPreferences { error in
                    Task { @MainActor in
                        self.note = error?.localizedDescription
                        self.refresh()
                    }
                }
            }
        }
    }
}

extension NetworkFilter: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in
            self.note = "Allow DLPrevent in System Settings › General › Login Items & Extensions › Network Extensions."
        }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in self.configure() }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Task { @MainActor in self.note = error.localizedDescription }
    }
}
