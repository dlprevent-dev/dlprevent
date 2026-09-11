import Foundation

/// Blocking Unix socket client: one line there, one back.
/// From the app, always call it on a background queue.
public struct DaemonClient: Sendable {
    public static let socketPath = "/var/run/deelpe.sock"

    public enum ClientError: Error, LocalizedError {
        case notRunning
        case io(String)
        public var errorDescription: String? {
            switch self {
            case .notRunning: return "Service not reachable"
            case .io(let m): return "Connection: \(m)"
            }
        }
    }

    public init() {}

    public func send(_ req: Request) throws -> Response {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ClientError.io("socket()") }
        defer { close(fd) }
        var tv = timeval(tv_sec: 5, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Self.socketPath.utf8CString
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        withUnsafeMutablePointer(to: &addr) { aptr in
            let dst = UnsafeMutableRawPointer(aptr).advanced(by: MemoryLayout<sockaddr_un>.offset(of: \.sun_path)!)
            path.withUnsafeBufferPointer { src in _ = memcpy(dst, src.baseAddress, min(src.count, capacity - 1)) }
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else { throw ClientError.notRunning }

        let line = Array(try req.encodeLine().utf8)
        var sent = 0
        while sent < line.count {
            let n = line[sent...].withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { throw ClientError.io("write") }
            sent += n
        }

        var buf = [UInt8](repeating: 0, count: 65536)
        var out = [UInt8]()
        while true {
            let n = read(fd, &buf, buf.count)
            if n < 0 { throw ClientError.io("timeout or read error") }
            if n == 0 { break }
            out.append(contentsOf: buf[0..<n])
            if out.last == UInt8(ascii: "\n") { break }
        }
        return try Response.decode(String(decoding: out, as: UTF8.self))
    }
}
