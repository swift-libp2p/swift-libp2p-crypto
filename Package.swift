// swift-tools-version:5.5
//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-libp2p-crypto",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "LibP2PCrypto",
            targets: ["LibP2PCrypto"]
        )
    ],
    dependencies: [
        // Multibase Support
        .package(url: "https://github.com/swift-libp2p/swift-multibase.git", .upToNextMinor(from: "0.0.1")),
        // Protobuf Marshaling
        .package(
            name: "SwiftProtobuf",
            url: "https://github.com/apple/swift-protobuf.git",
            .upToNextMajor(from: "1.12.0")
        ),
        // Secp256k1 Support
        .package(name: "secp256k1", url: "https://github.com/Boilertalk/secp256k1.swift.git", .exact("0.1.7")),
        // 🔑 Hashing (BCrypt, SHA2, HMAC), encryption (AES), public-key (RSA), PEM and DER file handling, and random data generation.
        .package(url: "https://github.com/apple/swift-crypto.git", .upToNextMajor(from: "4.1.0")),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", .upToNextMinor(from: "1.8.1")),
        .package(url: "https://github.com/swift-libp2p/swift-multihash.git", .upToNextMinor(from: "0.0.1")),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "LibP2PCrypto",
            dependencies: [
                .product(name: "Multibase", package: "swift-multibase"),
                .product(name: "Multihash", package: "swift-multihash"),
                .product(name: "SwiftProtobuf", package: "SwiftProtobuf"),
                .product(name: "secp256k1", package: "secp256k1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoSwift", package: "CryptoSwift"),
            ],
            resources: [
                .copy("Protobufs/keys.proto")
            ]
        ),
        .testTarget(
            name: "LibP2PCryptoTests",
            dependencies: ["LibP2PCrypto"]
        ),
    ]
)
