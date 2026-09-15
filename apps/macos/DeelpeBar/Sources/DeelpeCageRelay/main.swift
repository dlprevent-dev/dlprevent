import DeelpeProtocol
import Foundation

// The service (Rust, root) cannot speak XPC; this helper can. One JSON line
// from the service on stdin, one answer on stdout: `ok` or `error: …`,
// always within two seconds. It ends when the filter's connection does — the
// service notices at its next table and starts it again.

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("DeelpeCageRelay: \(message)\n".utf8))
    exit(1)
}

// The filter's Mach service name carries the team ID, so it is read from the
// extension's own Info.plist in this app instead of being written down twice.
let contents = Bundle.main.bundleURL.appendingPathComponent("Contents")
let plist = contents.appendingPathComponent("Library/SystemExtensions/ch.deelpe.bar.filter.systemextension/Contents/Info.plist")
guard let info = NSDictionary(contentsOf: plist),
      let service = (info["NetworkExtension"] as? [String: Any])?["NEMachServiceName"] as? String
else { fail("no network filter in this app (\(plist.path)); the app was built without signing") }

let connection = NSXPCConnection(machServiceName: service, options: .privileged)
connection.remoteObjectInterface = NSXPCInterface(with: CageFilterXPC.self)
connection.invalidationHandler = { fail("the network filter is not reachable; enable it in the DLPrevent app") }
// The filter restarted and lost its table: better the service sends it anew.
connection.interruptionHandler = { fail("the network filter restarted") }
connection.resume()

final class Answer: @unchecked Sendable {
    private let lock = NSLock()
    private var text = "error: no answer from the network filter within 2 s"
    func set(_ s: String) { lock.lock(); text = s; lock.unlock() }
    func get() -> String { lock.lock(); defer { lock.unlock() }; return text }
}

while let line = readLine() {
    let answer = Answer()
    let done = DispatchSemaphore(value: 0)
    let proxy = connection.remoteObjectProxyWithErrorHandler { error in
        answer.set("error: \(error.localizedDescription)")
        done.signal()
    } as? CageFilterXPC
    guard let proxy else { fail("the network filter speaks a different protocol") }
    proxy.apply(Data(line.utf8)) { error in
        answer.set(error.map { "error: \($0)" } ?? "ok")
        done.signal()
    }
    _ = done.wait(timeout: .now() + 2)
    print(answer.get())
    fflush(stdout)
}
