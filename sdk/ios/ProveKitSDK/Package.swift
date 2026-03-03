// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ProveKitSDK",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "ProveKit", targets: ["ProveKit"])
    ],
    targets: [
        .target(
            name: "ProveKit",
            dependencies: ["ProveKitFFI"],
            path: "Sources/ProveKitSDK"
        ),
        .binaryTarget(
            name: "ProveKitFFI",
            path: "ProveKitFFI.xcframework"
        ),
        .testTarget(
            name: "ProveKitTests",
            dependencies: ["ProveKit"],
            path: "Tests/ProveKitSDKTests",
            resources: [.copy("Fixtures")]
        )
    ]
)
