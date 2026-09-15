// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DeelpeBar",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "DeelpeProtocol"),
        .executableTarget(name: "DeelpeBar", dependencies: ["DeelpeProtocol"]),
        // The network cage's content filter (system extension) and the helper
        // the service hands its table to. Bundled by build.sh, signed builds only.
        .executableTarget(name: "DeelpeFilter", dependencies: ["DeelpeProtocol"]),
        .executableTarget(name: "DeelpeCageRelay", dependencies: ["DeelpeProtocol"]),
        .testTarget(name: "DeelpeProtocolTests", dependencies: ["DeelpeProtocol"]),
    ]
)
