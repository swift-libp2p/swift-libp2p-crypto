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
import P256K

public final class Secp256k1PrivateKey: Sendable {

    // MARK: - Properties

    /// The raw private key bytes
    public let rawPrivateKey: [UInt8]

    /// The public key associated with this private key
    public let publicKey: Secp256k1PublicKey

    /// The underlying P256K private key
    let key: P256K.Signing.PrivateKey

    // MARK: - Initialization

    /// Initializes a new cryptographically secure, randomly generated `Secp256k1PrivateKey`.
    public convenience init() throws {
        let key: P256K.Signing.PrivateKey
        do {
            key = try P256K.Signing.PrivateKey(format: .compressed)
        } catch {
            throw Error.internalError
        }
        try self.init(key: key)
    }

    /// Convenience initializer for `init(privateKey:)`
    public required convenience init(_ bytes: [UInt8]) throws {
        try self.init(privateKey: bytes)
    }

    /// Initializes a new instance of `Secp256k1PrivateKey` with the given `privateKey` Bytes.
    ///
    /// - Parameters:
    ///   - privateKey: The private key bytes. Must be exactly a big endian 32 Byte array representing the private key.
    /// - throws: Secp256k1PrivateKey.Error.keyMalformed if the restrictions described above are not met.
    ///           Secp256k1PrivateKey.Error.pubKeyGenerationFailed if the public key extraction from the private key fails.
    /// - Note: `privateKey` must be in the secp256k1 range as described in: https://en.bitcoin.it/wiki/Private_key
    /// ```
    /// So any number between
    /// 0x0000000000000000000000000000000000000000000000000000000000000001
    /// and
    /// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
    /// is considered to be a valid secp256k1 private key.
    ///  ```
    public convenience init(privateKey: [UInt8]) throws {
        guard privateKey.count == 32 else {
            throw Error.keyMalformed
        }

        let key: P256K.Signing.PrivateKey
        do {
            key = try P256K.Signing.PrivateKey(dataRepresentation: privateKey, format: .compressed)
        } catch {
            throw Error.keyMalformed
        }
        try self.init(key: key)
    }

    /// Designated initializer wrapping an already validated P256K private key.
    init(key: P256K.Signing.PrivateKey) throws {
        self.key = key
        self.rawPrivateKey = [UInt8](key.dataRepresentation)
        do {
            self.publicKey = try Secp256k1PublicKey(key: key.publicKey)
        } catch {
            throw Error.pubKeyGenerationFailed
        }
    }

    /// Initializes a new instance of `Secp256k1PrivateKey` with the given `hexPrivateKey` hex string.
    ///
    /// - Parameters:
    ///   - hexPrivateKey: must be either 64 characters long or 66 characters (with the hex prefix 0x).
    /// - throws: Secp256k1PrivateKey.Error.keyMalformed if the restrictions described above are not met.
    ///           Secp256k1PrivateKey.Error.pubKeyGenerationFailed if the public key extraction from the private key fails.
    /// - Note: `privateKey` must be in the secp256k1 range as described in: https://en.bitcoin.it/wiki/Private_key
    /// ```
    /// So any number between
    /// 0x0000000000000000000000000000000000000000000000000000000000000001
    /// and
    /// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
    /// is considered to be a valid secp256k1 private key.
    ///  ```
    public convenience init(hexPrivateKey: String) throws {
        guard hexPrivateKey.count == 64 || hexPrivateKey.count == 66 else {
            throw Error.keyMalformed
        }

        var hexPrivateKey = hexPrivateKey

        if hexPrivateKey.count == 66 {
            let s = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: 0)
            let e = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: 2)
            let prefix = String(hexPrivateKey[s..<e])

            guard prefix == "0x" else {
                throw Error.keyMalformed
            }

            // Remove prefix
            hexPrivateKey = String(hexPrivateKey[e...])
        }

        var raw = [UInt8]()
        for i in stride(from: 0, to: hexPrivateKey.count, by: 2) {
            let s = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: i)
            let e = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: i + 2)

            guard let b = UInt8(String(hexPrivateKey[s..<e]), radix: 16) else {
                throw Error.keyMalformed
            }
            raw.append(b)
        }

        try self.init(privateKey: raw)
    }

    // MARK: - Signatures

    /// Signs the SHA-256 hash of `message` and returns the DER encoded ECDSA signature (as specified by libp2p).
    /// - Note: Signatures are deterministic (RFC6979) and always low-S normalized.
    func signatureDER(for message: Data) -> Data {
        self.key.signature(for: message).derRepresentation
    }

    /// Returns this private key serialized as a hex string.
    public func hex() -> String {
        rawPrivateKey.asString(base: .base16)
    }

    // MARK: - Errors

    public enum Error: Swift.Error {

        case internalError
        case keyMalformed
        case pubKeyGenerationFailed
    }
}

// MARK: - Equatable

extension Secp256k1PrivateKey: Equatable {

    public static func == (_ lhs: Secp256k1PrivateKey, _ rhs: Secp256k1PrivateKey) -> Bool {
        lhs.rawPrivateKey == rhs.rawPrivateKey
    }
}

// MARK: - BytesConvertible

extension Secp256k1PrivateKey {

    public func makeBytes() -> [UInt8] {
        rawPrivateKey
    }
}

// MARK: - Hashable

extension Secp256k1PrivateKey: Hashable {

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawPrivateKey)
    }
}
