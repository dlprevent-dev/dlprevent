// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "DeelpeBar",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "DeelpeProtocol"),
        .executableTarget(name: "DeelpeBar", dependencies: ["DeelpeProtocol"]),
        .testTarget(name: "DeelpeProtocolTests", dependencies: ["DeelpeProtocol"]),
    ]
)
