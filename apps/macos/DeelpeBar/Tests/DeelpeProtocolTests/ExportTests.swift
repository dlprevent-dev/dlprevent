import XCTest
@testable import DeelpeProtocol

/// CSV columns as in `deelpe export` (crates/deelpe/tests/export.rs).
final class ExportTests: XCTestCase {
    private func alerts() throws -> [Alert] {
        let line = #"{"Alerts":[{"id":1,"at":"2026-09-05T15:44:45.179Z","pid":39416,"identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.curl"}},"files":["/Users/me/Steuern/a, \"b\".pdf","/Users/me/Steuern/c.txt"],"remote":"100.59.99.192","remote_port":443,"bytes_out":201438},{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil\nx"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5,"via":"read by com.apple.cat (PID 11)","verdict":"deviation","reason":"amount 5 B is over 4× the usual maximum of 1 B"}]}"#
        guard case .alerts(let a) = try Response.decode(line) else { XCTFail("kein .alerts"); return [] }
        return a
    }

    func testCSVHeaderAndEscaping() throws {
        let out = AlertExport.csv(try alerts())
        let lines = out.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(lines[0], "id,time,process,identity,pid,destination,port,bytes_out,files,via,verdict,reason")
        XCTAssertEqual(lines[1], #"1,2026-09-05T15:44:45.179Z,com.apple.curl,com.apple.curl (Team apple),39416,100.59.99.192,443,201438,"/Users/me/Steuern/a, ""b"".pdf; /Users/me/Steuern/c.txt",,new,"#)
        // A line break in the path stays inside the quoted field (process and identity, so two).
        XCTAssertEqual(lines[2...4].joined(separator: "\n"), "2,2026-09-05T15:44:45.000Z,\"evil\nx\",\"/tmp/evil\nx [unsigned]\",1,,,5,,read by com.apple.cat (PID 11),deviation,amount 5 B is over 4× the usual maximum of 1 B")
        XCTAssertTrue(out.hasSuffix("\n"))
        XCTAssertEqual(lines.count, 6, "letzte Zeile endet mit Umbruch, danach nichts")
    }

    func testCSVEmptyIsHeaderOnly() {
        XCTAssertEqual(AlertExport.csv([]), AlertExport.csvHeader + "\n")
    }

    func testJSONKeepsWireShape() throws {
        let data = try AlertExport.json(try alerts())
        let back = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [[String: Any]])
        XCTAssertEqual(back.count, 2)
        XCTAssertEqual(back[0]["id"] as? Int, 1)
        XCTAssertEqual(back[0]["at"] as? String, "2026-09-05T15:44:45.179Z")
        XCTAssertEqual((back[0]["identity"] as? [String: [String: String]])?["Signed"]?["signing_id"], "com.apple.curl")
        XCTAssertEqual(back[0]["files"] as? [String], ["/Users/me/Steuern/a, \"b\".pdf", "/Users/me/Steuern/c.txt"])
        XCTAssertEqual(back[0]["remote_port"] as? Int, 443)
        XCTAssertTrue(back[1]["remote"] is NSNull)
        XCTAssertNil(back[0]["via"])
        XCTAssertEqual(back[1]["via"] as? String, "read by com.apple.cat (PID 11)")
        XCTAssertEqual(back[0]["verdict"] as? String, "new")
        XCTAssertNil(back[0]["reason"])
        XCTAssertEqual(back[1]["reason"] as? String, "amount 5 B is over 4× the usual maximum of 1 B")
        XCTAssertEqual((back[1]["identity"] as? [String: [String: String]])?["Unknown"]?["path"], "/tmp/evil\nx")
        XCTAssertTrue(String(decoding: data, as: UTF8.self).contains("\n"), "lesbar formatiert")
    }
}
