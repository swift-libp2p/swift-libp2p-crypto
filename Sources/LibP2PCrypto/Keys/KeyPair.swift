//
//  KeyPair.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import Multihash
import Multibase
import Crypto

extension LibP2PCrypto.Keys {
    public struct KeyPair {
        let keyType:LibP2PCrypto.Keys.GenericKeyType
        let publicKey:CommonPublicKey
        let privateKey:CommonPrivateKey?
        
        public struct Attributes {
            public let type:LibP2PCrypto.Keys.KeyPairType
            public let size:Int
            public let isPrivate:Bool
            
            internal init(type:LibP2PCrypto.Keys.KeyPairType, size:Int, isPrivate:Bool) {
                self.type = type
                self.size = size
                self.isPrivate = isPrivate
            }
        }
        
        /// Initialize a new KeyPair (this generates a private & public key of the specified type)
        public init(_ keyType:LibP2PCrypto.Keys.KeyPairType) throws {
            switch keyType {
            case .Ed25519:
                try self.init(privateKey: Curve25519.Signing.PrivateKey())
            case .Secp256k1:
                try self.init(privateKey: Secp256k1PrivateKey())
            case .RSA(let keySize):
                try self.init(privateKey: RSAPrivateKey(keySize: keySize.bits))
            //default:
            //    throw NSError(domain: "Unsupported Key Type", code: 0)
            }
        }
        
        /// Initialize a KeyPair with a Private Key
        init(privateKey:CommonPrivateKey) throws {
            self.keyType = privateKey.keyType
            self.publicKey = try privateKey.derivePublicKey()
            self.privateKey = privateKey
        }
        
        /// Initialize a KeyPair with a Public Key
        init(publicKey:CommonPublicKey) throws {
            self.keyType = publicKey.keyType
            self.publicKey = publicKey
            self.privateKey = nil
        }
        
        var hasPrivateKey:Bool {
            return privateKey != nil
        }
        
        /// The public keys multihash value
        ///
        /// - Note: The multihash is the SHA-256 Hash of the DER representation of the PublicKey
        public func multihash() throws -> Multihash {
            try self.publicKey.multihash()
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
        
        /// Misc KeyPair Attributes (type, size, isPrivate)
        public func attributes() -> Attributes? {
            switch self.keyType {
            case .rsa:
                let count = self.publicKey.rawRepresentation.count
                switch self.publicKey.rawRepresentation.count {
                case 140, 162:
                    return Attributes(type: .RSA(bits: .B1024), size: 1024, isPrivate: (self.privateKey != nil))
                case 270, 294:
                    return Attributes(type: .RSA(bits: .B2048), size: 2048, isPrivate: (self.privateKey != nil))
                case 398, 422:
                    return Attributes(type: .RSA(bits: .B3072), size: 3072, isPrivate: (self.privateKey != nil))
                case 526, 550, 560:
                    return Attributes(type: .RSA(bits: .B4096), size: 4096, isPrivate: (self.privateKey != nil))
                default:
                    print("PubKey Data Count: \(count)");
                    return nil
                }
        
            case .ed25519:
                return Attributes(type: .Ed25519, size: 32, isPrivate: (self.privateKey != nil))
        
            case .secp256k1:
                return Attributes(type: .Secp256k1, size: 64, isPrivate: (self.privateKey != nil))
            }
        }
        
        //public func asString(base:BaseEncoding, withMultibasePrefix:Bool = false) -> String {
        //    self.data.asString(base: base, withMultibasePrefix: withMultibasePrefix)
        //}
        
        // - MARK: Encryption & Decryption
        
        /// Certain asymmetric keys support encrypting data, use this method to do so.
        func encrypt(data:Data) throws -> Data {
            try self.publicKey.encrypt(data: data)
        }
        
        /// Certain asymmetric keys support decrypting data, use this method to decrypt previously encrypted data.
        func decrypt(data:Data) throws -> Data {
            guard let privateKey = privateKey else {
                throw NSError(domain: "Can't decrypt data without a private key", code: 0)
            }
            return try privateKey.decrypt(data: data)
        }
        
        // - MARK: Signature & Verifications
        
        /// Sign a peice of data for verification by another peer
        ///
        /// - Note: Verify this signature by using the PublicKey and calling `.verify(signature:Data, for:Data) throws -> Bool`
        func sign(message data:Data) throws -> Data {
            guard let privateKey = privateKey else {
                throw NSError(domain: "Can't sign data without a private key", code: 0)
            }
            return try privateKey.sign(message: data)
        }
        
        /// Verify a signature for the expected data
        func verify(signature:Data, for data:Data) throws -> Bool {
            try self.publicKey.verify(signature: signature, for: data)
        }
        
        
        // - MARK: Imports
        
        /// Instantiate a KeyPair from a marshaled public key
        public init(marshaledPublicKey str:String, base:BaseEncoding) throws {
            try self.init(marshaledPublicKey: BaseEncoding.decode(str, as: base).data)
        }
        /// Instantiate a KeyPair from a marshaled public key
        public init(marshaledPublicKey data:Data) throws {
            let proto = try PublicKey(contiguousBytes: data)
            switch proto.type {
            case .rsa:
                try self.init(publicKey: RSAPublicKey(marshaledData: proto.data))
                
            case .ed25519:
                try self.init(publicKey: Curve25519.Signing.PublicKey(marshaledData: proto.data))
                
            case .secp256K1:
                try self.init(publicKey: Secp256k1PublicKey(marshaledData: proto.data))
            }
        }
        
        /// Instantiate a KeyPair from a marshaled private key
        public init(marshaledPrivateKey str:String, base:BaseEncoding) throws {
            try self.init(marshaledPrivateKey: BaseEncoding.decode(str, as: base).data)
        }
        /// Instantiate a KeyPair from a marshaled private key
        public init(marshaledPrivateKey data:Data) throws {
            let proto = try PrivateKey(contiguousBytes: data)
            switch proto.type {
            case .rsa:
                try self.init(privateKey: RSAPrivateKey(marshaledData: proto.data))
                
            case .ed25519:
                try self.init(privateKey: Curve25519.Signing.PrivateKey(marshaledData: proto.data))
                
            case .secp256K1:
                try self.init(privateKey: Secp256k1PrivateKey(marshaledData: proto.data))
            }
        }
        
        // - MARK: Exports
        
        func marshalPublicKey() throws -> Data {
            try publicKey.marshal()
        }
        
        //func marshalPrivateKey() throws -> Data {
        //    guard let privateKey = privateKey else {
        //        throw NSError(domain: "No Private Key", code: 0)
        //    }
        //    return try privateKey.marshal()
        //}
        
        
    }
}

extension LibP2PCrypto.Keys {
    public enum GenericKeyType {
        case rsa
        case ed25519
        case secp256k1
        
        internal var toProtoType:KeyType {
            switch self {
            case .rsa:
                return .rsa
            case .ed25519:
                return .ed25519
            case .secp256k1:
                return .secp256K1
            }
        }
        
        internal init(_ t:KeyType) {
            switch t {
            case .rsa:
                self = .rsa
            case .ed25519:
                self = .ed25519
            case .secp256K1:
                self = .secp256k1
            }
        }
    }
}
