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
import Foundation
import SwiftASN1

// MARK: - Public Key

extension P521.Signing.PublicKey: CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .ecdsa }

    /// Instantiates a public key from its marshaled DER encoded SubjectPublicKeyInfo
    init(marshaledData data: Data) throws {
        self = try ECDSAKeys.publicKey(fromSPKI: data)
    }

    public func encrypt(data: Data) throws -> Data {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("ECDSA keys don't support encryption")
    }

    /// Verifies a DER encoded ECDSA signature against the SHA-256 hash of `expectedData`
    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        try ECDSAKeys.verify(signature, for: expectedData, with: self)
    }

    public func marshal() throws -> Data {
        try ECDSAKeys.marshal(publicKey: self)
    }
}

extension P521.Signing.PublicKey: ECDSAPublicKeyBacking {
    static var curve: LibP2PCrypto.Keys.ElipticCurveType { .P521 }
}

extension P521.Signing.PublicKey: DERCodable {
    /// id-ecPublicKey (1.2.840.10045.2.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.idEcPublicKey }
    /// secp521r1 named curve (1.3.132.0.35)
    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { ASN1ObjectIdentifier.LibP2P.secp521r1 }

    /// Expects the SubjectPublicKeyInfo's BIT STRING contents (a compressed or uncompressed EC point)
    public init(publicDER: [UInt8]) throws {
        self = try ECDSAKeys.publicKey(fromPoint: publicDER)
    }

    public init(privateDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a public key from a private DER representation"
        )
    }

    /// The uncompressed `0x04 || X || Y` EC point
    public func publicKeyDER() throws -> [UInt8] {
        [UInt8](self.x963Representation)
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("A public key has no private DER representation")
    }
}

extension P521.Signing.PublicKey: @retroactive Equatable {
    public static func == (lhs: P521.Signing.PublicKey, rhs: P521.Signing.PublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

// MARK: - Private Key

extension P521.Signing.PrivateKey: CommonPrivateKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .ecdsa }

    /// Instantiates a private key from its marshaled DER encoded SEC1 ECPrivateKey
    init(marshaledData data: Data) throws {
        self = try ECDSAKeys.privateKey(fromSEC1: data)
    }

    public func derivePublicKey() throws -> CommonPublicKey {
        self.publicKey
    }

    public func decrypt(data: Data) throws -> Data {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("ECDSA keys don't support decryption")
    }

    /// Signs the SHA-256 hash of `data` and returns a DER encoded ECDSA signature
    public func sign(message data: Data) throws -> Data {
        try ECDSAKeys.sign(data, with: self)
    }

    public func marshal() throws -> Data {
        try ECDSAKeys.marshal(privateKey: self)
    }
}

extension P521.Signing.PrivateKey: ECDSAPrivateKeyBacking {}

extension P521.Signing.PrivateKey: DERCodable {
    /// id-ecPublicKey (1.2.840.10045.2.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.idEcPublicKey }
    /// secp521r1 named curve (1.3.132.0.35)
    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { ASN1ObjectIdentifier.LibP2P.secp521r1 }

    public init(publicDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a private key from a public DER representation"
        )
    }

    /// Expects either the raw private key scalar or a DER encoded SEC1 ECPrivateKey
    public init(privateDER: [UInt8]) throws {
        self = try ECDSAKeys.privateKey(fromPrivateDER: privateDER)
    }

    public func publicKeyDER() throws -> [UInt8] {
        try self.publicKey.publicKeyDER()
    }

    /// The DER encoded SEC1 ECPrivateKey
    public func privateKeyDER() throws -> [UInt8] {
        try ECDSAKeys.sec1DER(for: self)
    }

    /// The DER encoded PKCS #8 PrivateKeyInfo (including the named curve parameter)
    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        [UInt8](self.derRepresentation)
    }
}

extension P521.Signing.PrivateKey: @retroactive Equatable {
    public static func == (lhs: P521.Signing.PrivateKey, rhs: P521.Signing.PrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}
