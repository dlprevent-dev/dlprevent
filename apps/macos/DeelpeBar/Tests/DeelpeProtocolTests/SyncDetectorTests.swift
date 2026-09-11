import XCTest
@testable import DeelpeProtocol

final class SyncDetectorTests: XCTestCase {
    let home = "/Users/me"

    func testKnownRoots() {
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Library/Mobile Documents/com~apple~CloudDocs/Steuern", home: home), "iCloud Drive")
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Nextcloud/Steuern", home: home), "Nextcloud")
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Nextcloud", home: home), "Nextcloud")
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Dropbox/x", home: home), "Dropbox")
    }

    func testFileProviderNameFromAccountFolder() {
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Library/CloudStorage/Nextcloud-anna@next.example/Steuern", home: home), "Nextcloud")
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Library/CloudStorage/OneDrive-Firma/x", home: home), "OneDrive")
        XCTAssertEqual(SyncDetector.client(forPath: "/Users/me/Library/CloudStorage", home: home), "a cloud sync client")
    }

    func testUnrelatedPathsAreNil() {
        XCTAssertNil(SyncDetector.client(forPath: "/Users/me/Steuern", home: home))
        XCTAssertNil(SyncDetector.client(forPath: "/Users/me/NextcloudBackup", home: home), "kein Präfix-Treffer ohne Trenner")
        XCTAssertNil(SyncDetector.client(forPath: "/Users/other/Nextcloud", home: home))
    }
}
