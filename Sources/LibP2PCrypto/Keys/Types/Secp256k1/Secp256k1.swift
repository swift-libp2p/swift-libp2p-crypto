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

import CryptoSwift
import Foundation
import SwiftASN1
import SwiftProtobuf

extension Secp256k1PublicKey: CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .secp256k1 }

    public convenience init(rawRepresentation raw: Data) throws {
        try self.init(raw.byteArray)
    }

    public convenience init(marshaledData data: Data) throws {
        // The marshaled and RawRespresentation are the same thing for SecP256k1 keys
        try self.init(rawRepresentation: data)
    }

    public var rawRepresentation: Data {
        Data(self.rawPublicKey)
    }

    public func encrypt(data: Data) throws -> Data {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("Secp256k1 keys don't support encryption")
    }

    /// Verifies a DER encoded ECDSA signature over the SHA-256 hash of `expectedData` (as specified by libp2p).
    /// - Throws: if the signature isn't valid DER.
    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        try self.isValidSignature(der: signature, for: expectedData)
    }

    public func marshal() throws -> Data {
        var publicKey = PublicKey()
        publicKey.type = .secp256K1
        publicKey.data = try Data(self.compressPublicKey())
        return try publicKey.serializedData()
    }
}

extension Secp256k1PrivateKey: CommonPrivateKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .secp256k1 }

    public convenience init(rawRepresentation raw: Data) throws {
        try self.init(raw.byteArray)
    }

    public convenience init(marshaledData data: Data) throws {
        // The marshaled and RawRespresentation are the same thing for SecP256k1 keys
        try self.init(rawRepresentation: data)
    }

    public var rawRepresentation: Data {
        Data(self.rawPrivateKey)
    }

    /// Derives a Public Key from the Private Key
    public func derivePublicKey() throws -> CommonPublicKey {
        self.publicKey
    }

    public func decrypt(data: Data) throws -> Data {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("Secp256k1 keys don't support decryption")
    }

    /// Signs the SHA-256 hash of `data` and returns a DER encoded ECDSA signature (as specified by libp2p).
    public func sign(message data: Data) throws -> Data {
        self.signatureDER(for: data)
    }

    public func marshal() throws -> Data {
        var privateKey = PrivateKey()
        privateKey.type = .secp256K1
        privateKey.data = self.rawRepresentation
        return try privateKey.serializedData()
    }

}

extension Secp256k1PublicKey: DERCodable {
    /// id-ecPublicKey (1.2.840.10045.2.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.idEcPublicKey }
    /// secp256k1 named curve (1.3.132.0.10)
    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { ASN1ObjectIdentifier.LibP2P.secp256k1 }

    /// Expects the SubjectPublicKeyInfo's BIT STRING contents, either a 65 byte uncompressed (`0x04 || X || Y`)
    /// or a 33 byte compressed (`0x02 / 0x03 || X`) EC point
    public convenience init(publicDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(publicDER))
    }

    public convenience init(privateDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a private key from a public DER representation"
        )
    }

    public func publicKeyDER() throws -> [UInt8] {
        [0x04] + self.rawRepresentation
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("A public key has no private DER representation")
    }
}

extension Secp256k1PrivateKey: DERCodable {
    /// id-ecPublicKey (1.2.840.10045.2.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.idEcPublicKey }
    /// secp256k1 named curve (1.3.132.0.10)
    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { ASN1ObjectIdentifier.LibP2P.secp256k1 }

    public convenience init(publicDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a private key from a public DER representation"
        )
    }

    /// Expects either the raw 32 byte private key scalar or a DER encoded SEC1 ECPrivateKey
    /// (as nested inside a PKCS #8 PrivateKeyInfo, where the named curve parameter is optional)
    public convenience init(privateDER: [UInt8]) throws {
        guard privateDER.count > 32 else {
            // Raw scalar, left pad it in case an encoder stripped leading zeros
            try self.init(rawRepresentation: Data(repeating: 0, count: 32 - privateDER.count) + privateDER)
            return
        }

        let ecPrivateKey: ECPrivateKey
        do {
            ecPrivateKey = try ECPrivateKey(derEncoded: privateDER)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                "Secp256k1: private key is not a valid ECPrivateKey"
            )
        }
        if let namedCurve = ecPrivateKey.namedCurve, namedCurve != ASN1ObjectIdentifier.LibP2P.secp256k1 {
            throw LibP2PCrypto.PEM.Error.objectIdentifierMismatch(
                got: namedCurve,
                expected: ASN1ObjectIdentifier.LibP2P.secp256k1
            )
        }
        let scalar = Array(ecPrivateKey.privateKey.bytes)
        guard !scalar.isEmpty, scalar.count <= 32 else {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                "Secp256k1: invalid private key length \(scalar.count)"
            )
        }
        try self.init(rawRepresentation: Data(repeating: 0, count: 32 - scalar.count) + scalar)

        // Ensure the (optional) attached public key matches the private key
        if let attachedPublicKey = ecPrivateKey.publicKey {
            guard try self.publicKeyDER() == Array(attachedPublicKey.bytes) else {
                throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                    "Secp256k1: unable to validate attached public key"
                )
            }
        }
    }

    public func publicKeyDER() throws -> [UInt8] {
        try self.publicKey.publicKeyDER()
    }

    public func privateKeyDER() throws -> [UInt8] {
        self.rawRepresentation.byteArray
    }

    /// The DER encoded PKCS #8 PrivateKeyInfo (wrapping a SEC1 ECPrivateKey), as required when encrypting the key
    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        try PrivateKeyInfo(
            algorithmIdentifier: AlgorithmIdentifier(
                algorithm: Self.primaryObjectIdentifier,
                parameters: .objectIdentifier(ASN1ObjectIdentifier.LibP2P.secp256k1)
            ),
            privateKey: ECPrivateKey(
                privateKey: self.rawRepresentation.byteArray,
                namedCurve: nil,
                publicKey: self.publicKeyDER()
            ).serializedDERBytes()
        ).serializedDERBytes()
    }

    /// The DER encoded SEC1 ECPrivateKey (including the named curve and public key)
    func sec1DER() throws -> [UInt8] {
        try ECPrivateKey(
            privateKey: self.rawRepresentation.byteArray,
            namedCurve: ASN1ObjectIdentifier.LibP2P.secp256k1,
            publicKey: self.publicKeyDER()
        ).serializedDERBytes()
    }

    /// Exports the private key as a SEC1 `EC PRIVATE KEY` PEM
    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        try LibP2PCrypto.PEM.armor(self.sec1DER(), as: .ecPrivateKey, withHeaderAndFooter: withHeaderAndFooter)
    }
}
