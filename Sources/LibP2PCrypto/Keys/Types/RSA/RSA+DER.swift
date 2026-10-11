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
import SwiftASN1

extension RSAPublicKey: DERCodable {
    /// rsaEncryption (1.2.840.113549.1.1.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.rsaEncryption }

    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { nil }

    /// The DER encoded PKCS#1 RSAPublicKey (the SubjectPublicKeyInfo's BIT STRING contents)
    public func publicKeyDER() throws -> [UInt8] {
        Array(self.pkcs1DERRepresentation)
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("A public key has no private DER representation")
    }

    /// Expects a DER encoded PKCS#1 RSAPublicKey (a full SubjectPublicKeyInfo is also accepted)
    public init(publicDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(publicDER))
    }

    public init(privateDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a public key from a private DER representation"
        )
    }
}

extension RSAPrivateKey: DERCodable {
    /// rsaEncryption (1.2.840.113549.1.1.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.rsaEncryption }

    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { nil }

    /// The DER encoded PKCS#1 RSAPublicKey of the derived public key
    public func publicKeyDER() throws -> [UInt8] {
        try self.derivePublicKey().publicKeyDER()
    }

    public func privateKeyDER() throws -> [UInt8] {
        Array(self.rawRepresentation)
    }

    public init(publicDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a private key from a public DER representation"
        )
    }

    public init(privateDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(privateDER))
    }

    /// The DER encoded PKCS #8 PrivateKeyInfo (rsaEncryption requires an explicit NULL parameter, RFC 3279 §2.3.1)
    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        try PrivateKeyInfo(
            algorithmIdentifier: .rsaEncryption,
            privateKey: self.privateKeyDER()
        ).serializedDERBytes()
    }
}
