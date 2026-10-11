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

import Crypto
import CryptoSwift
import Foundation
import SwiftASN1
import SwiftProtobuf

extension Curve25519.Signing.PublicKey: CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .ed25519 }

    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }

    public func encrypt(data: Data) throws -> Data {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("Ed25519 keys don't support encryption")
    }

    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        self.isValidSignature(signature, for: expectedData)
    }

    public func marshal() throws -> Data {
        var publicKey = PublicKey()
        publicKey.type = .ed25519
        publicKey.data = self.rawRepresentation
        return try publicKey.serializedData()
    }
}

extension Curve25519.Signing.PrivateKey: CommonPrivateKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .ed25519 }

    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }

    public func derivePublicKey() throws -> CommonPublicKey {
        self.publicKey
    }

    public func decrypt(data: Data) throws -> Data {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("Ed25519 keys don't support decryption")
    }

    public func sign(message data: Data) throws -> Data {
        try self.signature(for: data)
    }

    public func marshal() throws -> Data {
        var privateKey = PrivateKey()
        privateKey.type = .ed25519
        privateKey.data = self.rawRepresentation
        return try privateKey.serializedData()
    }
}

extension Curve25519.Signing.PublicKey: @retroactive Equatable {
    public static func == (lhs: Curve25519.Signing.PublicKey, rhs: Curve25519.Signing.PublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension Curve25519.Signing.PrivateKey: @retroactive Equatable {
    public static func == (lhs: Curve25519.Signing.PrivateKey, rhs: Curve25519.Signing.PrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

/// - Note: Ed25519 AlgorithmIdentifiers have no parameters (RFC 8410 §3), so the `DEREncodable`
///   default PEM exports (driven by a `nil` secondaryObjectIdentifier) are used as is.
extension Curve25519.Signing.PublicKey: DERCodable {
    /// id-Ed25519 (1.3.101.112)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.ed25519 }
    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { nil }

    public init(publicDER: [UInt8]) throws {
        try self.init(rawRepresentation: publicDER)
    }

    public init(privateDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a public key from a private DER representation"
        )
    }

    public func publicKeyDER() throws -> [UInt8] {
        self.rawRepresentation.byteArray
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("A public key has no private DER representation")
    }
}

extension Curve25519.Signing.PrivateKey: DERCodable {
    /// id-Ed25519 (1.3.101.112)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.ed25519 }
    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { nil }

    public init(publicDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a private key from a public DER representation"
        )
    }

    public init(privateDER: [UInt8]) throws {
        // CurvePrivateKey ::= OCTET STRING (RFC 8410 §7)
        guard let curvePrivateKey = try? ASN1OctetString(derEncoded: privateDER) else {
            throw LibP2PCrypto.PEM.Error.invalidParameters
        }
        try self.init(rawRepresentation: curvePrivateKey.bytes)
    }

    public func publicKeyDER() throws -> [UInt8] {
        try self.publicKey.publicKeyDER()
    }

    public func privateKeyDER() throws -> [UInt8] {
        // CurvePrivateKey ::= OCTET STRING (RFC 8410 §7)
        try ASN1OctetString(contentBytes: self.rawRepresentation.byteArray[...]).serializedDERBytes()
    }
}
