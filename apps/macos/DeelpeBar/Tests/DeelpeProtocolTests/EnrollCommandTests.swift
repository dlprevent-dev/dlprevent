import XCTest
@testable import DeelpeProtocol

final class EnrollCommandTests: XCTestCase {
    let tok = String(repeating: "a", count: 64)
    let fp = String(repeating: "b", count: 64)

    func testParsesDashboardCommand() {
        let c = EnrollCommand.parse("sudo deelpe central enroll https://dlp.firma.local:8444 \(tok) --ca-sha256 \(fp)")
        XCTAssertEqual(c?.url, "https://dlp.firma.local:8444")
        XCTAssertEqual(c?.token, tok)
        XCTAssertEqual(c?.caSha256, fp)
        XCTAssertNotNil(EnrollCommand.parse("deelpe central enroll https://1.2.3.4:8444 \(tok) --ca-sha256=\(fp)"))
        XCTAssertNil(EnrollCommand.parse("deelpe central enroll https://x:8444 \(tok)"))
        XCTAssertNil(EnrollCommand.parse("rm -rf /"))
    }

    func testNormalizesServerInput() {
        XCTAssertEqual(EnrollCommand.normalizeURL("192.0.2.10"), "https://192.0.2.10:8444")
        XCTAssertEqual(EnrollCommand.normalizeURL(" dlp.firma.local "), "https://dlp.firma.local:8444")
        XCTAssertEqual(EnrollCommand.normalizeURL("dlp.firma.local:9000"), "https://dlp.firma.local:9000")
        XCTAssertEqual(EnrollCommand.normalizeURL("https://dlp.firma.local:8444/"), "https://dlp.firma.local:8444")
        XCTAssertEqual(EnrollCommand.normalizeURL("http://dlp.firma.local:8444"), nil, "nur https")
        XCTAssertEqual(EnrollCommand.normalizeURL("[fd00::1]"), "https://[fd00::1]:8444")
        XCTAssertNil(EnrollCommand.normalizeURL(""))
        XCTAssertNil(EnrollCommand.normalizeURL("a b"))
    }

    func testValidation() {
        XCTAssertNil(EnrollCommand(url: "https://h:8444", token: tok, caSha256: fp).problem)
        XCTAssertNotNil(EnrollCommand(url: "https://h:8444", token: "kurz", caSha256: fp).problem)
        XCTAssertNotNil(EnrollCommand(url: "https://h:8444", token: tok, caSha256: "zz").problem)
        XCTAssertNil(EnrollCommand(url: "https://h:8444", token: tok, caSha256: fp.uppercased()).problem)
        XCTAssertEqual(EnrollCommand(url: "https://h:8444", token: tok, caSha256: "AB:CD" + fp.dropFirst(4)).arguments[5].count, 64, "Doppelpunkte entfernt")
    }
}
