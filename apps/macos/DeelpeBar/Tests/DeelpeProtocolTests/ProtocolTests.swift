import XCTest
@testable import DeelpeProtocol

/// The literals are identical to crates/deelpe/tests/wire_format.rs.
final class ProtocolTests: XCTestCase {
    func testEncodesRequests() throws {
        XCTAssertEqual(try Request.alerts.encodeLine(), "\"Alerts\"\n")
        XCTAssertEqual(try Request.alertsAll.encodeLine(), "\"AlertsAll\"\n")
        XCTAssertEqual(try Request.status.encodeLine(), "\"Status\"\n")
        XCTAssertEqual(try Request.watchList.encodeLine(), "\"WatchList\"\n")
        XCTAssertEqual(try Request.show(7).encodeLine(), "{\"Show\":7}\n")
        XCTAssertEqual(try Request.watchAdd("/Users/me/Steuern").encodeLine(), "{\"WatchAdd\":\"/Users/me/Steuern\"}\n")
        XCTAssertEqual(try Request.watchRemove("/x").encodeLine(), "{\"WatchRemove\":\"/x\"}\n")
        XCTAssertEqual(try Request.ignoreAdd("com.apple.backupd").encodeLine(), "{\"IgnoreAdd\":\"com.apple.backupd\"}\n")
        XCTAssertEqual(try Request.ignoreRemove("team:ABC").encodeLine(), "{\"IgnoreRemove\":\"team:ABC\"}\n")
        XCTAssertEqual(try Request.ignoreList.encodeLine(), "\"IgnoreList\"\n")
        XCTAssertEqual(try Request.learnStatus.encodeLine(), "\"LearnStatus\"\n")
        XCTAssertEqual(try Request.learnConfirm.encodeLine(), "\"LearnConfirm\"\n")
        XCTAssertEqual(try Request.learnForget("apple/com.apple.curl→1.2.3.0/24:443").encodeLine(), "{\"LearnForget\":\"apple/com.apple.curl→1.2.3.0/24:443\"}\n")
        XCTAssertEqual(try Request.learnRemember(7).encodeLine(), "{\"LearnRemember\":7}\n")
        XCTAssertEqual(try Request.learnFlag(7).encodeLine(), "{\"LearnFlag\":7}\n")
        XCTAssertEqual(try Request.learnRestart.encodeLine(), "\"LearnRestart\"\n")
        XCTAssertEqual(try Request.centralStatus.encodeLine(), "\"CentralStatus\"\n")
    }

    func testDecodesCentral() throws {
        guard case .central(let none) = try Response.decode(#"{"Central":null}"#) else { return XCTFail("kein .central") }
        XCTAssertNil(none)
        let line = #"{"Central":{"url":"https://z:8444","agent_id":"a1","enrolled_at":"2026-09-06T10:00:00Z","last_ok":"2026-09-06T10:00:00Z","last_error":"Verbindung","last_error_at":null,"reports":3,"generation":2,"managed":["/Users/me/GL"]}}"#
        guard case .central(let c?) = try Response.decode(line) else { return XCTFail("kein .central") }
        XCTAssertEqual(c.url, "https://z:8444")
        XCTAssertEqual(c.agentId, "a1")
        XCTAssertEqual(c.lastOk.map { Int($0.timeIntervalSince1970) }, 1788688800)
        XCTAssertEqual(c.lastError, "Verbindung")
        XCTAssertNil(c.lastErrorAt)
        XCTAssertEqual(c.reports, 3)
        XCTAssertEqual(c.managed, ["/Users/me/GL"])
    }

    func testDecodesLearnAndVerdict() throws {
        let line = #"{"Learn":{"phase":"learning","until":"2026-09-12T15:44:45Z","pairs":[{"key":"apple/com.apple.curl→100.59.99.0/24:443","process":"com.apple.curl","identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.curl"}},"destination":"100.59.99.0/24","port":443,"state":"candidate","count":1,"bytes_max":4096,"prev_max":0,"last_id":1,"first_seen":"2026-09-05T15:44:45Z","last_seen":"2026-09-05T15:44:45Z","hours":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}]}}"#
        guard case .learn(let l) = try Response.decode(line) else { return XCTFail("kein .learn") }
        XCTAssertEqual(l.phase, "learning")
        XCTAssertEqual(l.until.map { Int($0.timeIntervalSince1970) }, 1789227885)
        XCTAssertEqual(l.pairs.count, 1)
        XCTAssertEqual(l.pairs[0].target, "100.59.99.0/24:443")
        XCTAssertEqual(l.pairs[0].state, "candidate")
        XCTAssertEqual(l.candidates.count, 1)
        guard case .learn(let active) = try Response.decode(#"{"Learn":{"phase":"active","until":null,"pairs":[]}}"#) else { return XCTFail() }
        XCTAssertNil(active.until)
        let alerts = #"{"Alerts":[{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5,"verdict":"deviation","reason":"unusual time"},{"id":3,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5}]}"#
        guard case .alerts(let a) = try Response.decode(alerts) else { return XCTFail() }
        XCTAssertEqual(a[0].verdict, "deviation"); XCTAssertEqual(a[0].reason, "unusual time")
        XCTAssertEqual(a[1].verdict, "new", "alte Zeilen ohne Urteil"); XCTAssertNil(a[1].reason)
        XCTAssertTrue(a[0].matches("deviation unusual"))
    }

    func testDecodesAlerts() throws {
        let line = #"{"Alerts":[{"id":1,"at":"2026-09-05T15:44:45.179509Z","pid":39416,"identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.curl"}},"files":["/Users/me/Steuern/deelpe-test.bin"],"remote":"100.59.99.192","remote_port":443,"bytes_out":201438}]}"#
        guard case .alerts(let alerts) = try Response.decode(line) else { return XCTFail("kein .alerts") }
        XCTAssertEqual(alerts.count, 1)
        let a = alerts[0]
        XCTAssertEqual(a.id, 1)
        XCTAssertEqual(a.pid, 39416)
        XCTAssertEqual(a.identity, .signed(teamId: "apple", signingId: "com.apple.curl"))
        XCTAssertEqual(a.identity.short, "com.apple.curl")
        XCTAssertEqual(a.files, ["/Users/me/Steuern/deelpe-test.bin"])
        XCTAssertEqual(a.remote, "100.59.99.192")
        XCTAssertEqual(a.remotePort, 443)
        XCTAssertEqual(a.bytesOut, 201438)
        XCTAssertEqual(Int(a.at.timeIntervalSince1970), 1788623085)
        XCTAssertNil(a.via)
    }

    func testDecodesViaAndIgnored() throws {
        let line = #"{"Alerts":[{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5,"via":"read by com.apple.cat (PID 11), via copy /tmp/x"}]}"#
        guard case .alerts(let alerts) = try Response.decode(line) else { return XCTFail("kein .alerts") }
        XCTAssertEqual(alerts[0].via, "read by com.apple.cat (PID 11), via copy /tmp/x")
        XCTAssertNil(alerts[0].lastAt)
        let grown = #"{"Alerts":[{"id":3,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":9000,"via":"read by com.apple.cat (PID 11), via copy /tmp/x","last_at":"2026-09-05T15:50:00Z"}]}"#
        guard case .alerts(let g) = try Response.decode(grown) else { return XCTFail("kein .alerts") }
        XCTAssertEqual(g[0].bytesOut, 9000)
        XCTAssertEqual(g[0].lastAt.map { Int($0.timeIntervalSince1970) }, 1788623400)
        guard case .ignored(let rules) = try Response.decode(#"{"Ignored":["com.apple.backupd"]}"#) else { return XCTFail() }
        XCTAssertEqual(rules, ["com.apple.backupd"])
    }

    func testDecodesUnknownIdentityAndNulls() throws {
        let line = #"{"Alerts":[{"id":2,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Unknown":{"path":"/tmp/evil"}},"files":[],"remote":null,"remote_port":null,"bytes_out":5}]}"#
        guard case .alerts(let alerts) = try Response.decode(line) else { return XCTFail("kein .alerts") }
        XCTAssertEqual(alerts[0].identity, .unknown(path: "/tmp/evil"))
        XCTAssertEqual(alerts[0].identity.short, "evil")
        XCTAssertFalse(alerts[0].identity.isTrustedForm)
        XCTAssertNil(alerts[0].remote)
    }

    func testDecodesStatusWatchedOkErrAlert() throws {
        guard case .status(let s) = try Response.decode(#"{"Status":{"touched":5,"alerts":1,"watched":1,"uptime_secs":87,"sensors":[{"name":"eslogger","error":"ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"},{"name":"nettop","error":null}]}}"#) else { return XCTFail() }
        XCTAssertEqual(s.touched, 5); XCTAssertEqual(s.alerts, 1); XCTAssertEqual(s.watched, 1); XCTAssertEqual(s.uptimeSecs, 87)
        XCTAssertEqual(s.sensors, [SensorState(name: "eslogger", error: "ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"), SensorState(name: "nettop", error: nil)])
        XCTAssertTrue(s.needsFullDiskAccess)
        XCTAssertEqual(s.warnings, [])
        guard case .status(let w) = try Response.decode(#"{"Status":{"touched":0,"alerts":0,"watched":0,"uptime_secs":1,"sensors":[],"warnings":["config.json changed outside the service"]}}"#) else { return XCTFail() }
        XCTAssertEqual(w.warnings, ["config.json changed outside the service"])
        guard case .alerts(let usb) = try Response.decode(#"{"Alerts":[{"id":9,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.cp"}},"files":["/Users/me/Steuern/a.pdf"],"remote":null,"remote_port":null,"bytes_out":0,"via":"1 file written to volume /Volumes/USB, last /Volumes/USB/a.pdf","verdict":"new","volume":"/Volumes/USB"}]}"#) else { return XCTFail() }
        XCTAssertEqual(usb[0].volume, "/Volumes/USB")
        XCTAssertEqual(usb[0].target, "volume /Volumes/USB")
        guard case .alerts(let cp) = try Response.decode(#"{"Alerts":[{"id":10,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Signed":{"team_id":"apple","signing_id":"com.apple.cp"}},"files":["/Users/me/Steuern/a.pdf"],"remote":null,"remote_port":null,"bytes_out":0,"via":"1 file copied out of the protected folder to /Users/me/Desktop, last /Users/me/Desktop/a.pdf","verdict":"new","copy_to":"/Users/me/Desktop"}]}"#) else { return XCTFail() }
        XCTAssertEqual(cp[0].copyTo, "/Users/me/Desktop")
        XCTAssertEqual(cp[0].target, "copy to /Users/me/Desktop")
        XCTAssertTrue(cp[0].isLocal)
        XCTAssertEqual(s.failedSensors.map(\.name), ["eslogger"])
        guard case .watched(let w) = try Response.decode(#"{"Watched":["/Users/me/Steuern"]}"#) else { return XCTFail() }
        XCTAssertEqual(w, ["/Users/me/Steuern"])
        guard case .ok(let m) = try Response.decode(#"{"Ok":"x"}"#) else { return XCTFail() }
        XCTAssertEqual(m, "x")
        guard case .err(let e) = try Response.decode(#"{"Err":"kaputt"}"#) else { return XCTFail() }
        XCTAssertEqual(e, "kaputt")
        guard case .alert(let none) = try Response.decode(#"{"Alert":null}"#) else { return XCTFail() }
        XCTAssertNil(none)
    }

    func testFilterMatches() throws {
        let line = #"{"Alerts":[{"id":12,"at":"2026-09-05T15:44:45Z","pid":1,"identity":{"Signed":{"team_id":"Q6L2","signing_id":"com.anthropic.claude-code"}},"files":["/Users/me/Nextcloud/README.md"],"remote":"160.79.104.10","remote_port":443,"bytes_out":5,"via":"read by com.apple.cat (PID 11)"}]}"#
        guard case .alerts(let a) = try Response.decode(line) else { return XCTFail() }
        let x = a[0]
        XCTAssertTrue(x.matches(""))
        XCTAssertTrue(x.matches("   "))
        XCTAssertTrue(x.matches("Claude"))
        XCTAssertTrue(x.matches("readme 160.79"))
        XCTAssertTrue(x.matches("cat"))
        XCTAssertTrue(x.matches("12"))
        XCTAssertFalse(x.matches("curl"))
        XCTAssertFalse(x.matches("-claude"))
        XCTAssertTrue(x.matches("-curl readme"))
        XCTAssertTrue(x.matches("-"))
    }

    func testHumanBytes() {
        XCTAssertEqual(humanBytes(512), "512 B")
        XCTAssertEqual(humanBytes(201438), "196.7 KB")
        XCTAssertEqual(humanBytes(5 * 1024 * 1024), "5.0 MB")
    }
}
