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

    static let UNCOMPRESSED_LENGTH = 64
    static let UNCOMPRESSED_LENGTH_WITH_HEADER = 65
    static let COMPRESSED_LENGTH = 32
    static let COMPRESSED_LENGTH_WITH_HEADER = 33

    public enum KeyFormat: UInt8 {
        case EVEN = 0x02
        case ODD = 0x03
        case UNCOMPRESSED = 0x04
        case HYBRID_EVEN = 0x06
        case HYBRID_ODD = 0x07
    }

    // MARK: - Properties

    /// The raw uncompressed public key bytes (without the 0x04 header prefix)
    public let rawPublicKey: [UInt8]

    /// The underlying P256K public key (always held in its compressed format)
    let key: P256K.Signing.PublicKey

    // MARK: - Initialization

    /// Convenient initializer for `init(publicKey:)`
    public required convenience init(_ bytes: [UInt8]) throws {
        try self.init(publicKey: bytes)
    }

    /// Initializes a new instance of `Secp256k1PublicKey` with the given raw public key Bytes.
    /// - Parameters:
    ///   - rawPublicKeyData: The public key, either compressed (33 bytes) or uncompressed (65 bytes), with the proper key type header prefix (0x04 in the case of standard uncompressed key). A 64 byte uncompressed key without the header prefix is also accepted.
    /// - Throws:
    ///    Secp256k1PublicKey.Error.keyMalformed if the given `publicKey` does not fulfill the requirements from above.
    public init(publicKey rawPublicKeyData: [UInt8]) throws {
        var rawPublicKeyData = rawPublicKeyData

        // WARNING:
        // We assume if we're provided a 64 byte key its the standard uncompressed key without the 0x04 header
        // This is a bad assumption because it would also be a hybrid key
        if rawPublicKeyData.count == Secp256k1PublicKey.UNCOMPRESSED_LENGTH {
            rawPublicKeyData.insert(KeyFormat.UNCOMPRESSED.rawValue, at: 0)
        }

        // Parse and validate the key (P256K selects the format based on the length)
        let parsed: P256K.Signing.PublicKey
        do {
            parsed = try P256K.Signing.PublicKey(x963Representation: rawPublicKeyData)
        } catch {
            throw Error.keyMalformed
        }

        // `uncompressedRepresentation` is re-serialized by libsecp256k1, so it's always the canonical 0x04 form
        let uncompressed = [UInt8](parsed.uncompressedRepresentation)
        guard uncompressed.count == Secp256k1PublicKey.UNCOMPRESSED_LENGTH_WITH_HEADER else {
            throw Error.keyMalformed
        }

        // Normalize the stored key to its compressed format (0x02 / 0x03 prefix based on the parity of Y)
        let parity = uncompressed[64] & 1 == 0 ? KeyFormat.EVEN : KeyFormat.ODD
        let compressed = [parity.rawValue] + uncompressed[1...32]
        do {
            self.key = try P256K.Signing.PublicKey(dataRepresentation: compressed, format: .compressed)
        } catch {
            throw Error.keyMalformed
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
        guard compressed.count == Secp256k1PublicKey.COMPRESSED_LENGTH_WITH_HEADER else {
            throw Error.internalError
        }
        return compressed
    }

    /// Initializes a new instance of `SecP256k1PublicKey` with the given a hex string.
    /// - Parameter hexPublicKey: The uncompressed (or compressed) hex public key either with the hex prefix `0x` or without.
    /// - throws: SecP256k1PublicKey.Error.keyMalformed if the given `hexPublicKey` does not fulfill the requirements from above. Or a SecP256k1PublicKey.Error.internalError if a secp256k1 library fails to parse / validate the provided key.
    public convenience init(hexPublicKey: String) throws {
        var hexPublicKey = Substring(hexPublicKey)
        if hexPublicKey.hasPrefix("0x") || hexPublicKey.hasPrefix("0X") {
            hexPublicKey = hexPublicKey.dropFirst(2)
        }

        let byteCount = hexPublicKey.count
        guard byteCount == 128 || byteCount == 130 || byteCount == 64 || byteCount == 66 else {
            throw Error.keyMalformed
        }

        let bytes: [UInt8]
        do {
            bytes = try BaseEncoding.decode(String(hexPublicKey), as: .base16)
        } catch {
            throw Error.keyMalformed
        }
        try self.init(publicKey: bytes)
    }

    // MARK: - Signatures

    /// Verifies a DER encoded ECDSA signature against the SHA-256 hash of `message` (as specified by libp2p).
    /// - Note: Non-canonical (high-S) signatures are rejected.
    /// - Throws: Secp256k1PublicKey.Error.signatureMalformed if the signature isn't valid DER.
    func isValidSignature(der signature: Data, for message: Data) throws -> Bool {
        let sig: P256K.Signing.ECDSASignature
        do {
            sig = try P256K.Signing.ECDSASignature(derRepresentation: signature)
        } catch {
            throw Error.signatureMalformed
        }
        return self.key.isValidSignature(sig, for: message)
    }

    /// Returns this public key serialized as a hex string.
    /// - Uncompressed 64 byte public key without the header prefix (0x04)
    public func hex() -> String {
        rawPublicKey.asString(base: .base16)
    }

    // MARK: - Errors

    public enum Error: Swift.Error {

        case internalError
        case keyMalformed
        case signatureMalformed
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
