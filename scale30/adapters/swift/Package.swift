// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "adapter",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", exact: "5.7.1"),
    ],
    targets: [
        .executableTarget(name: "adapter", dependencies: [
            .product(name: "JWTKit", package: "jwt-kit"),
        ]),
    ]
)
