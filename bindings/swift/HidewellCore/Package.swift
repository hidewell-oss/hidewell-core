// swift-tools-version:5.9
// Generated bindings for hidewell-core. Rebuild with scripts/build-ios.sh.
import PackageDescription

let package = Package(
    name: "HidewellCore",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "HidewellCore", targets: ["HidewellCore"]),
    ],
    targets: [
        .binaryTarget(name: "HidewellCoreFFI", path: "HidewellCoreFFI.xcframework"),
        .target(
            name: "HidewellCore",
            dependencies: ["HidewellCoreFFI"],
            path: "Sources/HidewellCore"
        ),
        .testTarget(
            name: "HidewellCoreTests",
            dependencies: ["HidewellCore"],
            path: "Tests/HidewellCoreTests"
        ),
    ]
)
