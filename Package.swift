// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-libp2p-crypto",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibP2PCrypto",
            targets: ["LibP2PCrypto"]),
    ],
    dependencies: [
        // Multibase Support
        .package(url: "https://github.com/swift-libp2p/swift-multibase.git", .upToNextMajor(from: "0.0.1")),
        // Protobuf Marshaling
        .package(url: "https://github.com/apple/swift-protobuf.git", .upToNextMajor(from: "1.12.0")),
        // RSA Import / Export Support
        .package(url: "https://github.com/nextincrement/rsa-public-key-importer-exporter.git", .upToNextMajor(from: "0.1.0")),
        // Secp256k1 Support
        .package(url: "https://github.com/Boilertalk/secp256k1.swift.git", .exact("0.1.6")),
        // 🔑 Hashing (BCrypt, SHA2, HMAC), encryption (AES), public-key (RSA), PEM and DER file handling, and random data generation.
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMajor(from: "1.5.0")),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMajor(from: "0.0.1")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "LibP2PCrypto",
            dependencies: [
                .product(name: "Multibase", package: "swift-multibase"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
                .product(name: "RSAPublicKeyExporter", package: "rsa-public-key-importer-exporter"),
                .product(name: "RSAPublicKeyImporter", package: "rsa-public-key-importer-exporter"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
            ],
            resources: [
              .copy("Protobufs/keys.proto")
            ]),
        .testTarget(
            name: "LibP2PCryptoTests",
            dependencies: ["LibP2PCrypto"]),
    ]
)
