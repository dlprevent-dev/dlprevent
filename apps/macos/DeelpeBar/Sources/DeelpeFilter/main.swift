import DeelpeProtocol
import Foundation
import NetworkExtension

/// Takes cage tables from `DeelpeCageRelay`, which the service starts as root.
final class CageListener: NSObject, NSXPCListenerDelegate, CageFilterXPC {
    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        // Only root may hand out cages: the service runs as root, and a
        // user's program that could empty the table could switch the cage off.
        // ponytail: checks the user, not the code signature of the relay.
        guard c.effectiveUserIdentifier == 0 else { return false }
        c.exportedInterface = NSXPCInterface(with: CageFilterXPC.self)
        c.exportedObject = self
        // The service is gone: fail open.
        c.invalidationHandler = { CageStore.shared.replace(CageTable()) }
        c.resume()
        return true
    }

    func apply(_ table: Data, withReply reply: @escaping (String?) -> Void) {
        do {
            CageStore.shared.replace(try JSONDecoder().decode(CageTable.self, from: table))
            reply(nil)
        } catch {
            reply("the filter could not read the cage table: \(error)")
        }
    }
}

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

let delegate = CageListener()
let name = (Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any])?["NEMachServiceName"] as? String ?? ""
let listener = NSXPCListener(machServiceName: name)
listener.delegate = delegate
listener.resume()
dispatchMain()
