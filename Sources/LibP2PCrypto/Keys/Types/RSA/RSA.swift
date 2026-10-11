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

import Crypto
import CryptoExtras
import Foundation
import SwiftProtobuf

/// The RSA key sizes (in bits) we accept
private let supportedBitRange = LibP2PCrypto.Keys.RSABitLength.supportedBitRange

/// A description of `supportedBitRange` for error messages
private let supportedBitRangeDescription = "\(supportedBitRange.lowerBound)-\(supportedBitRange.upperBound) bits"

/// An RSA public key (backed by swift-crypto's `_RSA`)
///
/// - Note: Signatures use RSASSA-PKCS1-v1_5 with SHA-256 and encryption uses RSAES-PKCS1-v1_5, per the libp2p spec.
/// - Note: Keys must be between 2048 and 8192 bits, matching swift-crypto and go-libp2p's limits.
public struct RSAPublicKey: CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.KeyType { .rsa }

    /// The underlying swift-crypto RSA key
    private let key: _RSA.Signing.PublicKey

    fileprivate init(_ key: _RSA.Signing.PublicKey) {
        self.key = key
    }

    /// Instantiates an RSA public key from either a DER encoded SubjectPublicKeyInfo or a DER encoded PKCS#1 RSAPublicKey
    ///
    /// - Throws: `KeyError.invalidRawRepresentation` if the DER is malformed or the key isn't within the support bit range (2048-8192 bits)
    public init(rawRepresentation raw: Data) throws {
        let key: _RSA.Signing.PublicKey
        do {
            // swift-crypto rejects keys outside of 2048-8192 bits while parsing, so the cause of a failure here
            // (malformed DER vs an unsupported size) can't be distinguished
            key = try _RSA.Signing.PublicKey(derRepresentation: raw)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation(
                "RSA public key: expected a valid DER encoded key of \(supportedBitRangeDescription): \(error)"
            )
        }
        guard supportedBitRange.contains(key.keySizeInBits) else {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation(
                "RSA public key: unsupported key size \(key.keySizeInBits) bits, expected \(supportedBitRangeDescription)"
            )
        }
        self.key = key
    }

    public init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }

    /// The DER encoded SubjectPublicKeyInfo representation of the public key
    public var rawRepresentation: Data {
        key.derRepresentation
    }

    /// The DER encoded PKCS#1 RSAPublicKey (the SubjectPublicKeyInfo's BIT STRING contents)
    var pkcs1DERRepresentation: Data {
        key.pkcs1DERRepresentation
    }

    /// The size of the RSA modulus in bits
    public var keySizeInBits: Int {
        key.keySizeInBits
    }

    /// Encrypts the data using RSAES-PKCS1-v1_5 padding
    public func encrypt(data: Data) throws -> Data {
        do {
            return try _RSA.Encryption.PublicKey(derRepresentation: key.derRepresentation)
                .encrypt(data, padding: ._WEAK_AND_INSECURE_PKCS_V1_5)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.encryptionFailed("RSA: \(error)")
        }
    }

    /// Verifies an RSASSA-PKCS1-v1_5 SHA-256 signature for an expected block of data
    ///
    /// - Returns: `false` if the signature doesn't match the data
    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        key.isValidSignature(
            _RSA.Signing.RSASignature(rawRepresentation: signature),
            for: expectedData,
            padding: .insecurePKCS1v1_5
        )
    }

    public func marshal() throws -> Data {
        var publicKey = ProtoPublicKey()
        publicKey.type = .rsa
        publicKey.data = self.rawRepresentation
        return try publicKey.serializedData()
    }
}

/// An RSA private key (backed by swift-crypto's `_RSA`)
///
/// - Note: Signatures use RSASSA-PKCS1-v1_5 with SHA-256 and decryption uses RSAES-PKCS1-v1_5, per the libp2p spec.
/// - Note: Keys must be between 2048 and 8192 bits, matching swift-crypto and go-libp2p's limits.
public struct RSAPrivateKey: CommonPrivateKey {
    public static var keyType: LibP2PCrypto.Keys.KeyType { .rsa }

    /// The underlying swift-crypto RSA key
    private let key: _RSA.Signing.PrivateKey

    /// Generates a new RSA key of the specified bit size
    /// - Throws: `KeyError.invalidParameters` if the bit size isn't within the supported range (2048-8192 bits)
    public init(keySize: LibP2PCrypto.Keys.RSABitLength) throws {
        // Check the size up front, swift-crypto only rejects oversized keys after generating them
        guard supportedBitRange.contains(keySize.bits) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters(
                "RSA: unsupported key size \(keySize.bits) bits, expected \(supportedBitRangeDescription)"
            )
        }
        do {
            self.key = try _RSA.Signing.PrivateKey(keySize: _RSA.Signing.KeySize(bitCount: keySize.bits))
        } catch {
            throw LibP2PCrypto.Keys.KeyError.keyGenerationFailed("RSA: \(error)")
        }
    }

    /// Instantiates an RSA private key from either a DER encoded PKCS#1 RSAPrivateKey or a DER encoded PKCS#8 PrivateKeyInfo
    ///
    /// - Throws: `KeyError.invalidRawRepresentation` if the DER is malformed or the key isn't within the supported range (2048-8192 bits)
    public init(rawRepresentation raw: Data) throws {
        let key: _RSA.Signing.PrivateKey
        do {
            // swift-crypto rejects keys outside of 2048-8192 bits while parsing, so the cause of a
            // failure here (malformed DER vs an unsupported size) can't be distinguished
            key = try _RSA.Signing.PrivateKey(derRepresentation: raw)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation(
                "RSA private key: expected a valid DER encoded key of \(supportedBitRangeDescription): \(error)"
            )
        }
        guard supportedBitRange.contains(key.keySizeInBits) else {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation(
                "RSA private key: unsupported key size \(key.keySizeInBits) bits, expected \(supportedBitRangeDescription)"
            )
        }
        self.key = key
    }

    public init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }

    /// The DER encoded PKCS#1 RSAPrivateKey representation of the private key
    public var rawRepresentation: Data {
        key.derRepresentation
    }

    /// The size of the RSA modulus in bits
    public var keySizeInBits: Int {
        key.keySizeInBits
    }

    public func derivePublicKey() throws -> CommonPublicKey {
        RSAPublicKey(key.publicKey)
    }

    /// Decrypts RSAES-PKCS1-v1_5 encrypted data
    public func decrypt(data: Data) throws -> Data {
        do {
            return try _RSA.Encryption.PrivateKey(derRepresentation: key.derRepresentation)
                .decrypt(data, padding: ._WEAK_AND_INSECURE_PKCS_V1_5)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.decryptionFailed("RSA: \(error)")
        }
    }

    /// Signs the message using RSASSA-PKCS1-v1_5 with SHA-256
    public func sign(message: Data) throws -> Data {
        do {
            return try key.signature(for: message, padding: .insecurePKCS1v1_5).rawRepresentation
        } catch {
            throw LibP2PCrypto.Keys.KeyError.signatureFailed("RSA: \(error)")
        }
    }

    public func marshal() throws -> Data {
        var privateKey = ProtoPrivateKey()
        privateKey.type = .rsa
        privateKey.data = self.rawRepresentation
        return try privateKey.serializedData()
    }
}

extension RSAPublicKey: Equatable {
    public static func == (lhs: RSAPublicKey, rhs: RSAPublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension RSAPrivateKey: Equatable {
    /// Compares the private keys in constant time
    public static func == (lhs: RSAPrivateKey, rhs: RSAPrivateKey) -> Bool {
        LibP2PCrypto.constantTimeEquals(lhs.rawRepresentation, rhs.rawRepresentation)
    }
}
