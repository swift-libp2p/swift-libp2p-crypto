//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2026 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import Foundation
import Multibase

// MARK: - Keys

extension LibP2PCrypto.Keys {
    @available(*, deprecated, renamed: "KeyType")
    public typealias GenericKeyType = KeyType

    @available(*, deprecated, renamed: "EllipticCurve")
    public typealias ElipticCurveType = EllipticCurve

    @available(*, deprecated, renamed: "marshalPrivateKey(raw:keyType:fromBase:)")
    public static func marshalPrivateKey(
        raw: String,
        asKeyType: KeyPairType,
        fromBase base: BaseEncoding? = nil
    ) throws -> [UInt8] {
        try self.marshalPrivateKey(raw: raw, keyType: asKeyType.keyType, fromBase: base)
    }

    @available(*, deprecated, message: "Use marshalPrivateKey(raw:keyType:) with a KeyType")
    public static func marshalPrivateKey(raw: Data, keyType: KeyPairType) throws -> [UInt8] {
        try self.marshalPrivateKey(raw: raw, keyType: keyType.keyType)
    }
}

extension LibP2PCrypto.Keys.KeyPairType {
    @available(*, deprecated, renamed: "rsa(bits:)")
    public static func RSA(bits: LibP2PCrypto.Keys.RSABitLength = .b2048) -> Self { .rsa(bits: bits) }

    @available(*, deprecated, renamed: "ed25519")
    public static var Ed25519: Self { .ed25519 }

    @available(*, deprecated, renamed: "secp256k1")
    public static var Secp256k1: Self { .secp256k1 }
}

extension LibP2PCrypto.Keys.RSABitLength {
    @available(*, deprecated, renamed: "b2048")
    public static var B2048: Self { .b2048 }

    @available(*, deprecated, renamed: "b3072")
    public static var B3072: Self { .b3072 }

    @available(*, deprecated, renamed: "b4096")
    public static var B4096: Self { .b4096 }
}

// MARK: - PEM

extension LibP2PCrypto.PEM.CipherAlgorithm {
    @available(*, deprecated, renamed: "aes128CBC(iv:)")
    public static func aes_128_cbc(iv: [UInt8]) -> Self { .aes128CBC(iv: iv) }

    @available(*, deprecated, renamed: "aes256CBC(iv:)")
    public static func aes_256_cbc(iv: [UInt8]) -> Self { .aes256CBC(iv: iv) }
}

extension DERDecodable {
    @available(*, deprecated, renamed: "init(pem:password:)", message: "`Self` determines the expected key type")
    public init<Key: DERDecodable>(pem: String, password: String? = nil, asType: Key.Type) throws {
        try self.init(pem: pem, password: password)
    }

    @available(*, deprecated, renamed: "init(pem:password:)", message: "`Self` determines the expected key type")
    public init<Key: DERDecodable>(pem: Data, password: String? = nil, asType: Key.Type) throws {
        try self.init(pem: pem, password: password)
    }

    @available(*, deprecated, renamed: "init(pem:password:)", message: "`Self` determines the expected key type")
    public init<Key: DERDecodable>(pem: [UInt8], password: String? = nil, asType: Key.Type) throws {
        try self.init(pem: pem, password: password)
    }
}

// MARK: - HMAC

extension LibP2PCrypto.HMAC.CryptoAlgorithm {
    @available(*, deprecated, message: "MD5 is cryptographically broken, use sha256 or stronger")
    public static var MD5: Self { .md5 }

    @available(*, deprecated, message: "SHA1 is considered to be cryptographically insecure, use sha256 or stronger")
    public static var SHA1: Self { .sha1 }

    @available(*, deprecated, renamed: "sha256")
    public static var SHA256: Self { .sha256 }

    @available(*, deprecated, renamed: "sha384")
    public static var SHA384: Self { .sha384 }

    @available(*, deprecated, renamed: "sha512")
    public static var SHA512: Self { .sha512 }
}
