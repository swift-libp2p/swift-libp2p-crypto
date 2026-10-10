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

    //    public convenience init(pem:String) throws {
    //        let chunks = pem.split(separator: "\n")
    //        guard chunks.count > 3,
    //              let f = chunks.first, f.hasPrefix("-----BEGIN"),
    //              let l = chunks.last, l.hasSuffix("-----") else {
    //            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
    //        }
    //
    //        //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
    //        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
    //        //print(raw.data)
    //
    //        //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
    //
    //        let asn1 = try LibP2PCrypto.Keys.parseASN1(pemData: raw.data)
    //
    //        guard asn1.isPrivateKey == false else {
    //            throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
    //        }
    //
    //        if asn1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
    //            print("Trying to Init EC Key")
    //            self = try Secp256k1PublicKey(publicKey: asn1.keyBits.bytes)
    //        }
    //
    //        throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
    //    }
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

    public func exportPublicKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let spki = try SubjectPublicKeyInfo(
            algorithmIdentifier: AlgorithmIdentifier(
                algorithm: Self.primaryObjectIdentifier,
                parameters: .objectIdentifier(ASN1ObjectIdentifier.LibP2P.secp256k1)
            ),
            key: self.publicKeyDER()
        )

        let base64String = try spki.serializedDERBytes().toBase64()
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

    public convenience init(privateDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(privateDER))
    }

    public func publicKeyDER() throws -> [UInt8] {
        try self.publicKey.publicKeyDER()
    }

    public func privateKeyDER() throws -> [UInt8] {
        self.rawRepresentation.byteArray
    }

    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        try ECPrivateKey(
            privateKey: self.rawRepresentation.byteArray,
            namedCurve: Self.primaryObjectIdentifier,
            publicKey: self.publicKeyDER()
        ).serializedDERBytes()
    }

    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let base64String = try self.exportPrivateKeyPEMRaw().toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes

        if withHeaderAndFooter {
            let header = LibP2PCrypto.PEM.PEMType.ecPrivateKey.headerBytes + [0x0a]
            let footer = [0x0a] + LibP2PCrypto.PEM.PEMType.ecPrivateKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }

}
