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
        .package(
            url: "https://github.com/wiyota/IcpKit.git", branch: "feature/for-ic-auth-client")
    ],
    targets: [
        .binaryTarget(
            name: "IcAuthClientFFI",
            path: "IcAuthClientFFI.xcframework"
        ),
        .target(
            name: "IcAuthClient",
            dependencies: [
                "IcAuthClientFFI",
                .product(name: "IcpKit", package: "IcpKit"),
            ],
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
