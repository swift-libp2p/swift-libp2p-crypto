//
//  SecKey+Common.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import Crypto
import Multibase
import Multihash

protocol PublicKeyDerivation {
    func derivePublicKey() throws -> RawPublicKey
}

protocol Marshalable {
    init(marshaledKey:String, base:BaseEncoding) throws
    init(marshaledKey:Data) throws
    func marshal() throws -> Data
}

protocol CommonKeyPairInit {
    init(type:LibP2PCrypto.Keys.KeyPairType) throws
}

protocol Signable {
    func sign(message:Data) throws -> Data
}

protocol Verifiable {
    func verfiy(_ signature: Data, for expectedData:Data) throws -> Bool
}

protocol PEMDecodable {
    init(pem:String) throws
}

extension RawPublicKey {
    public func multihash() throws -> Multihash {
        switch self.type {
        case .ed25519:
            return try Multihash(raw: self.marshal(), hashedWith: .identity)
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
            //return try Multihash(raw: self.marshal(), hashedWith: .sha2_256)
        }
    }
    
    /// The keys `rawID` is the SHA-256 multihash of its public key
    /// The public key is a protobuf encoding containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    public func rawID() throws -> [UInt8] {
        return try self.multihash().value
    }
    
    /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
    /// The public key is a protobuf encoding (marshaled) containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    public func id(withMultibasePrefix:Bool = true) throws -> String {
        //let mh = try Multihash(raw: self.marshal(), hashedWith: .sha2_256)
        let mh = try self.multihash()
        return withMultibasePrefix ? mh.asMultibase(.base58btc) : mh.asString(base: .base58btc)
    }
    
    public func asString(base:BaseEncoding, withMultibasePrefix:Bool = false) -> String {
        self.data.asString(base: base, withMultibasePrefix: withMultibasePrefix)
    }
}

extension RawPrivateKey {
    /// The keys `rawID` is the SHA-256 multihash of its public key
    /// The public key is a protobuf encoding containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    public func rawID() throws -> [UInt8] {
        try self.derivePublicKey().rawID()
    }
    
    /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
    /// The public key is a protobuf encoding containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    public func id(withMultibasePrefix:Bool = true) throws -> String {
        try self.derivePublicKey().id(withMultibasePrefix: withMultibasePrefix)
    }
    
    public func asString(base:BaseEncoding, withMultibasePrefix:Bool = false) -> String {
        self.data.asString(base: base, withMultibasePrefix: withMultibasePrefix)
    }
}

extension LibP2PCrypto.Keys.KeyPair {
//    public struct Attributes {
//        public let type:LibP2PCrypto.Keys.KeyPairType
//        public let size:Int
//        public let isPrivate:Bool
//    }
//    public func attributes() -> Attributes? {
//        switch self.keyType {
//        case .rsa:
//            let count = self.publicKey.data.count
//            if count == 140 {
//                return Attributes(type: .RSA(bits: .B1024), size: 1024, isPrivate: (self.privateKey != nil))
//            } else if count == 270 {
//                return Attributes(type: .RSA(bits: .B2048), size: 2048, isPrivate: (self.privateKey != nil))
//            } else if count == 398 {
//                return Attributes(type: .RSA(bits: .B3072), size: 3072, isPrivate: (self.privateKey != nil))
//            } else if count == 560 {
//                return Attributes(type: .RSA(bits: .B4096), size: 4096, isPrivate: (self.privateKey != nil))
//            } else { print("PubKey Data Count: \(count)"); return nil }
//
//        case .ed25519:
//            print("ed25519 PubKey Data Count: \(self.publicKey.data.count)")
//            return Attributes(type: .Ed25519, size: 32, isPrivate: (self.privateKey != nil))
//
//        case .secp256k1:
//            print("secp256k1 PubKey Data Count: \(self.publicKey.data.count)")
//            return Attributes(type: .Secp256k1, size: 32, isPrivate: (self.privateKey != nil))
//
//        }
//    }
    
    /// The keys `rawID` is the SHA-256 multihash of its public key
    /// The public key is a protobuf encoding containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    public func rawID() throws -> [UInt8] {
        try self.publicKey.rawID()
    }
    
    /// The keys `id` is the base58 encoding of the SHA-256 multihash of its public key.
    /// The public key is a protobuf encoding containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    public func id(withMultibasePrefix:Bool = true) throws -> String {
        try self.publicKey.id(withMultibasePrefix: withMultibasePrefix)
    }
    
    public func encrypt(_ data:Data) throws -> Data {
        try self.publicKey.encrypt(data)
    }
    
    public func encrypt(_ message:String) throws -> Data {
        try self.publicKey.encrypt(Data(message.utf8))
    }
    
    public func decrypt(_ data:Data) throws -> Data {
        guard let priv = self.privateKey else {
            throw NSError(domain: "Private Key needs to be present in order to decrypt data", code: 0, userInfo: nil)
        }
        return try priv.decrypt(data)
    }
    
    public func decrypt(_ message:String) throws -> Data {
        guard let priv = self.privateKey else {
            throw NSError(domain: "Private Key needs to be present in order to decrypt data", code: 0, userInfo: nil)
        }
        return try priv.decrypt(Data(message.utf8))
    }
}

extension RawPrivateKey: PublicKeyDerivation {
    func derivePublicKey() throws -> RawPublicKey {
        switch self.type {
        case .ed25519:
            if #available(OSX 10.15, *) {
                let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: self.data.bytes)
                let pubKey = privKey.publicKey
                return RawPublicKey(
                    type: self.type,
                    data: pubKey.rawRepresentation
                )
            } else {
                throw NSError(domain: "Ed25519 Keys are only supported on MacOS 10.15 and greater", code: 0, userInfo: nil)
            }
        
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        }
    }
}

extension RawPrivateKey: Decryptable, Encryptable {
    public func decrypt(_ message: Data) throws -> Data {
        switch self.type {
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        }
    }
    
    public func encrypt(_ message: Data) throws -> Data {
        switch self.type {
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        }
    }
}



/// Ensure these are doing the same thing... (signature(for:) and sign(hash:)
/// Are these equivalent to RSA encrypt?
extension RawPrivateKey:Signable {
    public func sign(message: Data) throws -> Data {
        switch self.type {
        case .ed25519:
            let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: self.data)
            return try privKey.signature(for: message)
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        }
    }
}

extension RawPublicKey:Verifiable {
    public func verfiy(_ signature: Data, for expectedData:Data) throws -> Bool {
        switch self.type {
        case .ed25519:
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: self.data)
            return pubKey.isValidSignature(signature, for: expectedData)
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        }
    }
}

extension RawPublicKey: Encryptable {
    public func encrypt(_ message: Data) throws -> Data {
        
        switch self.type {
        default:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        }
        
    }
}

extension RawPrivateKey: Marshalable {
    public init(marshaledKey: String, base: BaseEncoding) throws {
        let data = try BaseEncoding.decode(marshaledKey, as: base).data
        self.init(try PrivateKey(contiguousBytes: data.bytes))
    }
    
    public init(marshaledKey: Data) throws {
        self.init(try PrivateKey(contiguousBytes: marshaledKey.bytes))
    }
    
    /// For private keys we just marshal the raw representation of the key (no asn1 headers necessary)
    public func marshal() throws -> Data {
        var priv = PrivateKey()
        priv.data = self.data
        priv.type = self.type.toProtoType
        return try priv.serializedData()
    }
}

extension RawPublicKey: Marshalable {
    public init(marshaledKey: String, base: BaseEncoding) throws {
        let data = try BaseEncoding.decode(marshaledKey, as: base).data
        try self.init(PublicKey(contiguousBytes: data.bytes))
    }
    
    public init(marshaledKey: Data) throws {
        try self.init(PublicKey(contiguousBytes: marshaledKey.bytes))
    }
    
    /// For public keys, we need to make sure the data that we're marshaling is the SubjectPublicKeyInfo of the RSA Public Key.... (we normally store the raw representation, which is in DER format without the ASN1 headers)
    public func marshal() throws -> Data {
        switch self.type {
        case .rsa:
            throw NSError(domain: "Unsupported Key Type", code: 0, userInfo: nil)
        default:
            var pubKeyProto = PublicKey()
            pubKeyProto.data = self.data
            pubKeyProto.type = self.type.toProtoType
            return try pubKeyProto.serializedData()
        }
    }
}


extension RawPrivateKey: CommonKeyPairInit {
    public init(type:LibP2PCrypto.Keys.KeyPairType) throws {
        self = try LibP2PCrypto.Keys.generateRawPrivateKey(type)
    }
}

extension RawPublicKey: PEMDecodable {
    public init(pem:String) throws {
        self = try LibP2PCrypto.Keys.parsePem(pem).publicKey
    }
}

extension RawPrivateKey: PEMDecodable {
    public init(pem:String) throws {
        guard let privKey = try LibP2PCrypto.Keys.parsePem(pem).privateKey else {
            throw NSError(domain: "Failed to extract Private key from pem file", code: 0, userInfo: nil)
        }
        self = privKey
    }
}

