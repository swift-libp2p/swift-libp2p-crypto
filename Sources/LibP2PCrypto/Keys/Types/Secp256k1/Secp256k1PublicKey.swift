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

public final class Secp256k1PublicKey: Sendable {

    /// The length of an uncompressed public key without its 0x04 prefix (`X || Y`)
    private static let uncompressedLength = 64

    /// The length of an uncompressed public key with its 0x04 prefix (`0x04 || X || Y`)
    private static let uncompressedLengthWithPrefix = 65

    /// The length of a compressed public key with its 0x02 / 0x03 prefix (`0x02 / 0x03 || X`)
    private static let compressedLengthWithPrefix = 33

    /// SEC1 EC point encoding prefixes
    private enum Prefix: UInt8 {
        case even = 0x02
        case odd = 0x03
        case uncompressed = 0x04
        //case hybridEven = 0x06
        //case hybridOdd = 0x07
    }

    // MARK: - Properties

    /// The raw uncompressed public key bytes (without the 0x04 header prefix)
    public let rawPublicKey: [UInt8]

    /// The underlying P256K public key (always held in its compressed format)
    let key: P256K.Signing.PublicKey

    // MARK: - Initialization

    /// Convenient initializer for `init(publicKey:)`
    public convenience init(_ bytes: [UInt8]) throws {
        try self.init(publicKey: bytes)
    }

    /// Initializes a new instance of `Secp256k1PublicKey` with the given raw public key Bytes.
    /// - Parameters:
    ///   - rawPublicKeyData: The public key, either compressed (33 bytes) or uncompressed (65 bytes), with the proper key type header prefix (0x04 in the case of standard uncompressed key). A 64 byte uncompressed key without the header prefix is also accepted.
    /// - Throws:
    ///   - `KeyError.invalidRawRepresentation` if the given `publicKey` does not fulfill the requirements from above.
    public init(publicKey rawPublicKeyData: [UInt8]) throws {
        var rawPublicKeyData = rawPublicKeyData

        // A 64 byte key is an uncompressed `X || Y` key missing its 0x04 prefix
        if rawPublicKeyData.count == Self.uncompressedLength {
            rawPublicKeyData.insert(Prefix.uncompressed.rawValue, at: 0)
        }

        // Parse and validate the key (P256K selects the format based on the length)
        let parsed: P256K.Signing.PublicKey
        do {
            parsed = try P256K.Signing.PublicKey(x963Representation: rawPublicKeyData)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("Secp256k::PublicKey: \(error)")
        }

        // `uncompressedRepresentation` is re-serialized by libsecp256k1, so it's always the canonical 0x04 form
        let uncompressed = [UInt8](parsed.uncompressedRepresentation)
        guard uncompressed.count == Self.uncompressedLengthWithPrefix else {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation(
                "Secp256k1 public key: unexpected uncompressed length \(uncompressed.count)"
            )
        }

        // Normalize the stored key to its compressed format (0x02 / 0x03 prefix based on the parity of Y)
        let parity = uncompressed[64] & 1 == 0 ? Prefix.even : Prefix.odd
        let compressed = [parity.rawValue] + uncompressed[1...32]
        do {
            self.key = try P256K.Signing.PublicKey(dataRepresentation: compressed, format: .compressed)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("Secp256k::PublicKey: \(error)")
        }

        // Store the uncompressed public key in our rawPublicKey field
        self.rawPublicKey = Array(uncompressed.dropFirst())
    }

    /// Initializes a new instance of `Secp256k1PublicKey` from an already validated P256K public key.
    convenience init(key: P256K.Signing.PublicKey) throws {
        try self.init(publicKey: [UInt8](key.uncompressedRepresentation))
    }

    /// Returns the 33 byte compressed public key (with the 0x02 / 0x03 header prefix)
    public func compressPublicKey() throws -> [UInt8] {
        let compressed = [UInt8](self.key.dataRepresentation)
        guard compressed.count == Self.compressedLengthWithPrefix else {
            throw LibP2PCrypto.Keys.KeyError.internalError(
                "Secp256k1: unexpected compressed public key length \(compressed.count)"
            )
        }
        return compressed
    }

    /// Initializes a new instance of `SecP256k1PublicKey` with the given a hex string.
    /// - Parameter hexPublicKey: The uncompressed (or compressed) hex public key either with the hex prefix `0x` or without.
    /// - throws:
    ///   - `KeyError.invalidRawRepresentation` if the given `hexPublicKey` does not fulfill the requirements from above or fails to parse / validate.
    public convenience init(hexPublicKey: String) throws {
        var hexPublicKey = Substring(hexPublicKey)
        if hexPublicKey.hasPrefix("0x") || hexPublicKey.hasPrefix("0X") {
            hexPublicKey = hexPublicKey.dropFirst(2)
        }

        let byteCount = hexPublicKey.count
        guard byteCount == 128 || byteCount == 130 || byteCount == 64 || byteCount == 66 else {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("Secp256k::PublicKey: invalid hex length")
        }

        let bytes: [UInt8]
        do {
            bytes = try BaseEncoding.decode(String(hexPublicKey), as: .base16)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("Secp256k::PublicKey: invalid hex")
        }
        try self.init(publicKey: bytes)
    }

    // MARK: - Signatures

    /// Verifies a DER encoded ECDSA signature against the SHA-256 hash of `message` (as specified by libp2p).
    /// - Note: Non-canonical (high-S) signatures are rejected.
    /// - Throws: `KeyError.invalidParameters` if the signature isn't valid DER.
    func isValidSignature(der signature: Data, for message: Data) throws -> Bool {
        let sig: P256K.Signing.ECDSASignature
        do {
            sig = try P256K.Signing.ECDSASignature(derRepresentation: signature)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters(
                "Secp256k1: signature is not a valid DER encoded signature"
            )
        }
        return self.key.isValidSignature(sig, for: message)
    }

    /// Returns this public key serialized as a hex string.
    /// - Uncompressed 64 byte public key without the header prefix (0x04)
    public func hex() -> String {
        rawPublicKey.asString(base: .base16)
    }
}

// MARK: - Equatable

extension Secp256k1PublicKey: Equatable {

    public static func == (_ lhs: Secp256k1PublicKey, _ rhs: Secp256k1PublicKey) -> Bool {
        lhs.rawPublicKey == rhs.rawPublicKey
    }
}

// MARK: - Hashable

extension Secp256k1PublicKey: Hashable {

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawPublicKey)
    }
}
