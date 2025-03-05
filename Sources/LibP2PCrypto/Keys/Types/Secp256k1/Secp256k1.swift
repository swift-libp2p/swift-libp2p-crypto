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

import Foundation

extension Secp256k1PublicKey: CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .secp256k1 }

    public convenience init(rawRepresentation raw: Data) throws {
        try self.init(raw.bytes)
    }

    public convenience init(marshaledData data: Data) throws {
        // The marshaled and RawRespresentation are the same thing for SecP256k1 keys
        try self.init(rawRepresentation: data)
    }

    public var rawRepresentation: Data {
        Data(self.rawPublicKey)
    }

    public func encrypt(data: Data) throws -> Data {
        throw NSError(domain: "Secp256k1 Keys don't support encryption", code: 0)
    }

    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        guard signature.count >= 32 + 32 + 1 else {
            throw NSError(
                domain: "Invalid Signature Length, expected at least 65 bytes, got \(signature.count)",
                code: 0,
                userInfo: nil
            )
        }
        let bytes = signature.bytes
        let v: [UInt8] = [UInt8](bytes[0..<1])  //First byte
        let r: [UInt8] = [UInt8](bytes[1...32])  //Next 32 bytes
        let s: [UInt8] = [UInt8](bytes[33...64])  //Last 32 bytes
        return try self.verifySignature(message: expectedData.bytes, v: v, r: r, s: s)
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
        try self.init(raw.bytes)
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
        throw NSError(domain: "Secp256k1 Keys don't support decryption", code: 0)
    }

    public func sign(message data: Data) throws -> Data {
        let signature = try sign(message: data.bytes)
        return Data([UInt8(signature.v)] + signature.r + signature.s)
    }

    public func marshal() throws -> Data {
        var privateKey = PrivateKey()
        privateKey.type = .secp256K1
        privateKey.data = self.rawRepresentation
        return try privateKey.serializedData()
    }

}

extension Secp256k1PublicKey: DERCodable {
    public static var primaryObjectIdentifier: [UInt8] { [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] }
    public static var secondaryObjectIdentifier: [UInt8]? { [0x2B, 0x81, 0x04, 0x00, 0x0A] }

    public convenience init(publicDER: [UInt8]) throws {
        /// Expects a 0x0422 32byte long octetString as the rawRepresentation
        try self.init(rawRepresentation: Data(publicDER))
    }

    public convenience init(privateDER: [UInt8]) throws {
        throw NSError(domain: "Can't instantiate private key from public DER representation", code: 0)
    }

    public func publicKeyDER() throws -> [UInt8] {
        [0x04] + self.rawRepresentation
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw NSError(domain: "Public Key doesn't have private DER representation", code: 0)
    }

    public func exportPublicKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let publicDER = try self.publicKeyDER()

        let asnNodes: ASN1.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Self.primaryObjectIdentifier)),
                .objectIdentifier(data: Data(Self.secondaryObjectIdentifier!)),
            ]),
            .bitString(data: Data(publicDER)),
        ])

        let base64String = ASN1.Encoder.encode(asnNodes).toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes

        if withHeaderAndFooter {
            let header = PEM.PEMType.publicKey.headerBytes + [0x0a]
            let footer = [0x0a] + PEM.PEMType.publicKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }
}

extension Secp256k1PrivateKey: DERCodable {
    public static var primaryObjectIdentifier: [UInt8] { [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A] }
    public static var secondaryObjectIdentifier: [UInt8]? { nil }

    public convenience init(publicDER: [UInt8]) throws {
        throw NSError(domain: "Can't instantiate private key from public DER representation", code: 0)
    }

    public convenience init(privateDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(privateDER))
    }

    public func publicKeyDER() throws -> [UInt8] {
        try self.publicKey.publicKeyDER()
    }

    public func privateKeyDER() throws -> [UInt8] {
        self.rawRepresentation.bytes
    }

    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        let publicDER = try self.publicKeyDER()

        let pubKeyBitString: ASN1.Node = .bitString(data: Data(publicDER))

        let asnNodes: ASN1.Node = .sequence(nodes: [
            .integer(data: Data(hex: "0x01")),
            .octetString(data: self.rawRepresentation),
            .ecObject(data: Data(Self.primaryObjectIdentifier)),
            .ecBits(data: Data(ASN1.Encoder.encode(pubKeyBitString))),
        ])

        return ASN1.Encoder.encode(asnNodes)
    }

    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let base64String = try self.exportPrivateKeyPEMRaw().toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes

        if withHeaderAndFooter {
            let header = PEM.PEMType.ecPrivateKey.headerBytes + [0x0a]
            let footer = [0x0a] + PEM.PEMType.ecPrivateKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }

}
