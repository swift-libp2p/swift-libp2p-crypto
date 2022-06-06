//
//  Ed25519.swift
//  
//
//  Created by Brandon Toms on 5/22/22.
//

import Foundation
import Crypto
//import PEM

extension Curve25519.Signing.PublicKey:CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .ed25519 }
    
    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }
    
    public func encrypt(data: Data) throws -> Data {
        throw NSError(domain: "Ed25519 Keys don't support encryption", code: 0)
    }
    
    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        return self.isValidSignature(signature, for: expectedData)
    }
    
    public func marshal() throws -> Data {
        var publicKey = PublicKey()
        publicKey.type = .ed25519
        publicKey.data = self.rawRepresentation
        return try publicKey.serializedData()
    }
    
//    public init(pem:String) throws {
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
//            self = try Curve25519.Signing.PublicKey(rawRepresentation: asn1.keyBits)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
//    }
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
        throw NSError(domain: "ED25519 keys don't support decryption", code: 0)
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
    
//    public init(pemRSA:String) throws { throw NSError(domain: "EC Key Can't be initialized with an RSA PEM", code: 0, userInfo: nil) }
//    public init(pemEC:String) throws {
//        let chunks = pemEC.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN PRIVATE"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//        //print(raw.data)
//
//        var octet = try LibP2PCrypto.Keys.parseASN1ECPrivate(pemData: raw.data)
//
//        let bytes = octet.bytes.count
//
//        // TODO Create a PublicKey and PrivateKey Protocol that SecKey and these keys can conform to so we can return a common type...
//        if bytes <= 32 { //P256 Pivate Key
//            while octet.bytes.count < 32 { octet.insert(0, at: 0) }
//            self = try Curve25519.Signing.PrivateKey(rawRepresentation: octet)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(octet)", code: 0, userInfo: nil)
//    }
//
//    public func derivePublicKey() throws -> CommonPublicKey {
//        self.publicKey
//    }
}


extension Curve25519.Signing.PublicKey:Equatable {
    public static func == (lhs: Curve25519.Signing.PublicKey, rhs: Curve25519.Signing.PublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension Curve25519.Signing.PrivateKey:Equatable {
    public static func == (lhs: Curve25519.Signing.PrivateKey, rhs: Curve25519.Signing.PrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension Curve25519.Signing.PublicKey:DERCodable {
    public static var primaryObjectIdentifier: Array<UInt8> { [0x2B, 0x65, 0x70] } 
    public static var secondaryObjectIdentifier: Array<UInt8>? { nil }
    
    public init(publicDER: Array<UInt8>) throws {
        try self.init(rawRepresentation: publicDER)
    }
    
    public init(privateDER: Array<UInt8>) throws {
        throw NSError(domain: "Can't instantiate private key from public DER representation", code: 0)
    }
    
    public func publicKeyDER() throws -> Array<UInt8> {
        self.rawRepresentation.bytes
    }
    
    public func privateKeyDER() throws -> Array<UInt8> {
        throw NSError(domain: "Public Key doesn't have private DER representation", code: 0)
    }
}

extension Curve25519.Signing.PrivateKey:DERCodable {
    public static var primaryObjectIdentifier: Array<UInt8> { [0x2B, 0x65, 0x70] }
    public static var secondaryObjectIdentifier: Array<UInt8>? { nil }
    
    public init(publicDER: Array<UInt8>) throws {
        throw NSError(domain: "Can't instantiate private key from public DER representation", code: 0)
    }
    
    public init(privateDER: Array<UInt8>) throws {
        guard case .octetString(let rawData) = try ASN1.Decoder.decode(data: Data(privateDER)) else {
            throw PEM.Error.invalidParameters
        }
        try self.init(rawRepresentation: rawData)
    }
    
    public func publicKeyDER() throws -> Array<UInt8> {
        try self.publicKey.publicKeyDER()
    }
    
    public func privateKeyDER() throws -> Array<UInt8> {
        self.rawRepresentation.bytes
    }
}

