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

import CryptoSwift
import Foundation
import SwiftASN1

extension RSAPublicKey: DERCodable {
    /// rsaEncryption (1.2.840.113549.1.1.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.rsaEncryption }

    public static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { nil }

    public func publicKeyDER() throws -> [UInt8] {
        self.rawRepresentation.byteArray
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation("A public key has no private DER representation")
    }

    init(publicDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(publicDER))
    }

    init(privateDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a public key from a private DER representation"
        )
    }

    public func exportPublicKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let publicDER = try self.publicKeyDER()

        let base64String = publicDER.toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes

        if withHeaderAndFooter {
            let header = LibP2PCrypto.PEM.PEMType.publicKey.headerBytes + [0x0a]
            let footer = [0x0a] + LibP2PCrypto.PEM.PEMType.publicKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }
}

extension RSAPrivateKey: DERCodable {
    /// rsaEncryption (1.2.840.113549.1.1.1)
    public static var primaryObjectIdentifier: ASN1ObjectIdentifier { ASN1ObjectIdentifier.LibP2P.rsaEncryption }

    static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { nil }

    func publicKeyDER() throws -> [UInt8] {
        try self.derivePublicKey().rawRepresentation.byteArray
    }

    func privateKeyDER() throws -> [UInt8] {
        self.rawRepresentation.byteArray
    }

    init(publicDER: [UInt8]) throws {
        throw LibP2PCrypto.Keys.KeyError.unsupportedOperation(
            "Can't instantiate a private key from a public DER representation"
        )
    }

    init(privateDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(privateDER))
    }

    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        try PrivateKeyInfo(
            algorithmIdentifier: .rsaEncryption,
            privateKey: self.privateKeyDER()
        ).serializedDERBytes()
    }

    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let base64String = try self.exportPrivateKeyPEMRaw().toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes

        if withHeaderAndFooter {
            let header = LibP2PCrypto.PEM.PEMType.privateKey.headerBytes + [0x0a]
            let footer = [0x0a] + LibP2PCrypto.PEM.PEMType.privateKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }
}
