// swift-tools-version: 6.2
import PackageDescription

/// SSRF-style URL policy validation, with a WHATWG-conformant host parser.
///
/// The package is Foundation-only and has no dependencies, so it stays usable from an app
/// extension, from a command-line tool, and on Linux. Unlike the sibling networking
/// packages it does not set `defaultIsolation(MainActor.self)`: validation is synchronous
/// and works on value types, so nonisolated - the language default - is both correct and
/// free of `nonisolated` annotations on every declaration.
let package = Package(
    name: "SafeURLKit",
    platforms: [.macOS(.v14), .iOS(.v17), .tvOS(.v17), .watchOS(.v10), .visionOS(.v1)],
    products: [
        .library(name: "SafeURLKit", targets: ["SafeURLKit"])
    ],
    targets: [
        .target(
            name: "SafeURLKit",
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("InferIsolatedConformances")
            ]
        ),
        .testTarget(
            name: "SafeURLKitTests",
            dependencies: ["SafeURLKit"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("InferIsolatedConformances")
            ]
        )
    ]
)
