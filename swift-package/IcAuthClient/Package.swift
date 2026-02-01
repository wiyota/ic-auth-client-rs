// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IcAuthClient",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "IcAuthClient", targets: ["IcAuthClient"])
    ],
    dependencies: [
        .package(url: "https://github.com/kosta-bity/IcpKit.git", .upToNextMajor(from: "0.2.0"))
    ],
    targets: [
        .binaryTarget(
            name: "IcAuthClientFFI",
            path: "IcAuthClientFFI.xcframework"
        ),
        .target(
            name: "IcAuthClient",
            dependencies: ["IcAuthClientFFI"],
            path: "Sources/IcAuthClient",
            linkerSettings: [
                .linkedFramework("Carbon", .when(platforms: [.macOS]))
            ]
        ),
        .testTarget(
            name: "IntegrationTests",
            dependencies: [
                "IcAuthClient",
                .product(name: "IcpKit", package: "IcpKit"),
            ],
            path: "Tests/IntegrationTests"
        ),
    ]
)
