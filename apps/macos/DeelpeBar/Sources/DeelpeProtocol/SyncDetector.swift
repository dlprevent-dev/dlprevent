import Foundation

/// Detects whether a folder is mirrored by a sync client (iCloud Drive,
/// Nextcloud, Dropbox, OneDrive, Google Drive, Proton Drive). Sync clients are
/// on the exception list, or end up there as soon as they become annoying; so
/// a protected folder underneath one leaves the Mac without an alert. The user
/// should see that instead of feeling protected.
public enum SyncDetector {
    /// Known roots relative to the home directory; first match wins.
    static let knownRoots: [(String, String)] = [
        ("Library/Mobile Documents", "iCloud Drive"),
        ("Library/CloudStorage", ""), // File Provider: name from the account folder
        ("Nextcloud", "Nextcloud"),
        ("Dropbox", "Dropbox"),
        ("OneDrive", "OneDrive"),
        ("Google Drive", "Google Drive"),
        ("Proton Drive", "Proton Drive"),
    ]

    /// Pure path comparison, no file system (testable). Name of the client or nil.
    public static func client(forPath path: String, home: String) -> String? {
        for (root, name) in knownRoots {
            let full = home + "/" + root
            guard path == full || path.hasPrefix(full + "/") else { continue }
            if name.isEmpty {
                // ~/Library/CloudStorage/Nextcloud-konto@server/… → "Nextcloud"
                let rest = path.dropFirst(full.count + 1)
                let account = rest.split(separator: "/").first.map(String.init) ?? ""
                let provider = account.split(separator: "-").first.map(String.init) ?? ""
                return provider.isEmpty ? "a cloud sync client" : provider
            }
            return name
        }
        return nil
    }

    /// With the file system: additionally the iCloud attribute, which Desktop
    /// and Documents carry too when they are synced via iCloud.
    public static func client(forPath path: String) -> String? {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if let c = client(forPath: path, home: home) { return c }
        if let v = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.isUbiquitousItemKey]), v.isUbiquitousItem == true {
            return "iCloud Drive"
        }
        return nil
    }
}
