// swift-tools-version:5.10
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftyPing",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "SwiftyPing",
            targets: ["SwiftyPing"]),
    ],
    targets: [
        .target(name: "SwiftyPing"),
        .testTarget(
            name: "SwiftyPingTests",
            dependencies: ["SwiftyPing"]
        ),
    ],
    swiftLanguageVersions: [
        .v5,
        .version("6"),
    ]
)
