import XCTest
@testable import DeelpeProtocol

final class CageTableTests: XCTestCase {
    /// The literal comes from `the_relay_line_is_what_the_filter_decodes` in
    /// crates/deelpe/src/cage.rs, shortened to one `always` entry.
    func testDecodesTheServiceLine() throws {
        let line = #"{"always":[{"bits":8,"net":"10.0.0.0","port":null}],"cages":[{"children":false,"permits":[{"bits":32,"net":"203.0.113.9","port":443}],"pid":4242}]}"#
        let t = try JSONDecoder().decode(CageTable.self, from: Data(line.utf8))
        XCTAssertEqual(t.always, [CagePermit(net: "10.0.0.0", bits: 8)])
        XCTAssertEqual(t.cages, [.init(pid: 4242, permits: [CagePermit(net: "203.0.113.9", bits: 32, port: 443)], children: false)])
    }

    func testPermitsCoverNetworksAndPorts() {
        let net = CagePermit(net: "10.0.0.0", bits: 12)
        XCTAssertTrue(net.covers(ip: "10.15.0.1", port: nil))
        XCTAssertFalse(net.covers(ip: "10.16.0.1", port: nil))
        XCTAssertTrue(net.covers(ip: "::ffff:10.1.2.3", port: 80), "v4 in v6 clothing")
        let port = CagePermit(net: "203.0.113.9", bits: 32, port: 443)
        XCTAssertTrue(port.covers(ip: "203.0.113.9", port: 443))
        XCTAssertFalse(port.covers(ip: "203.0.113.9", port: 80))
        let v6 = CagePermit(net: "fe80::", bits: 10)
        XCTAssertTrue(v6.covers(ip: "fe80::1%en0", port: nil))
        XCTAssertFalse(v6.covers(ip: "10.0.0.1", port: nil), "families do not mix")
        XCTAssertFalse(net.covers(ip: "chatgpt.com", port: nil), "a name is covered by nothing")
    }

    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    private func table(children: Bool = false) -> CageTable {
        CageTable(cages: [.init(pid: 100, permits: [CagePermit(net: "203.0.113.9", bits: 32)], children: children)],
                  always: [CagePermit(net: "192.168.0.0", bits: 16)])
    }

    func testTheCagedProcessReachesItsPermitsAndTheHouseOnly() {
        let chain = [ProcessLink(pid: 100, started: t0)]
        let armed: [Int32: Date] = [100: t0.addingTimeInterval(5)]
        XCTAssertEqual(table().verdict(ip: "1.1.1.1", port: 443, chain: chain, armed: armed), .drop)
        XCTAssertEqual(table().verdict(ip: "203.0.113.9", port: 443, chain: chain, armed: armed), .allow)
        XCTAssertEqual(table().verdict(ip: "192.168.1.5", port: 445, chain: chain, armed: armed), .allow)
    }

    func testOthersAreWatchedNotBlocked() {
        let chain = [ProcessLink(pid: 7, started: t0), ProcessLink(pid: 1, started: t0)]
        XCTAssertEqual(table().verdict(ip: "1.1.1.1", port: 443, chain: chain, armed: [100: t0]), .watch)
        XCTAssertEqual(table().verdict(ip: "192.168.1.5", port: 445, chain: chain, armed: [100: t0]), .allow, "the house needs no watching")
    }

    /// `x=$(cat f); curl …`: the shell is caged, the curl it starts afterwards
    /// is born inside. A child that already ran stays free — unless the cage
    /// takes the children.
    func testChildrenBornAfterTheCageAreInside() {
        let armed: [Int32: Date] = [100: t0.addingTimeInterval(10)]
        let later = [ProcessLink(pid: 300, started: t0.addingTimeInterval(20)), ProcessLink(pid: 200, started: t0.addingTimeInterval(15)), ProcessLink(pid: 100, started: t0)]
        XCTAssertEqual(table().verdict(ip: "1.1.1.1", port: 443, chain: later, armed: armed), .drop, "grandchild of a branch born inside")
        let before = [ProcessLink(pid: 200, started: t0.addingTimeInterval(1)), ProcessLink(pid: 100, started: t0)]
        XCTAssertEqual(table().verdict(ip: "1.1.1.1", port: 443, chain: before, armed: armed), .watch)
        XCTAssertEqual(table(children: true).verdict(ip: "1.1.1.1", port: 443, chain: before, armed: armed), .drop)
    }

    /// The service reads this line in `crates/deelpe/src/cage.rs`
    /// (`the_refused_line_is_what_the_service_reads`).
    func testARefusalIsReportedOncePerProcessAndDestination() throws {
        var log = CageRefusals()
        let chain = [ProcessLink(pid: 300, started: t0), ProcessLink(pid: 200, started: t0), ProcessLink(pid: 100, started: t0)]
        log.record(chain: chain, table: table(), ip: "1.1.1.1", port: 443, at: t0)
        log.record(chain: chain, table: table(), ip: "1.1.1.1", port: 443, at: t0.addingTimeInterval(1))
        let drained = log.drain()
        XCTAssertEqual(drained, [CageRefusal(pid: 300, ppid: 100, ip: "1.1.1.1", port: 443, at: 1_000_000)], "the caged ancestor, not the parent")
        XCTAssertEqual(log.drain(), [], "drained is gone")
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        XCTAssertEqual(String(decoding: try encoder.encode(drained), as: UTF8.self), #"[{"at":1000000,"ip":"1.1.1.1","pid":300,"port":443,"ppid":100}]"#)
    }
}
