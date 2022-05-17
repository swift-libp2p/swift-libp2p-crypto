//
//  Keys.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import Multibase
import Multihash

import RSAPublicKeyExporter
import RSAPublicKeyImporter

import secp256k1

import Crypto

/// A generic wrapper for libp2p supported Public keys
public struct RawPublicKey {
    let type:LibP2PCrypto.Keys.GenericKeyType
    public let data:Data
    
    internal init(type:LibP2PCrypto.Keys.GenericKeyType, data:Data) {
        self.type = type
        self.data = data
    }
    
    internal init(_ pub:PublicKey) throws {
        // This is the subjectPublicKeyInfo, we need to parse the raw key out...
        switch pub.type {
        case .rsa:
            self.data = try RSAPublicKeyImporter().fromSubjectPublicKeyInfo(pub.data)
        case .ed25519:
            self.data = pub.data
        case .secp256K1:
            self.data = pub.data
        }
        self.type = .init(pub.type)
    }
    
    internal init(_ key:Curve25519.Signing.PublicKey) {
        self.type = .ed25519
        self.data = key.rawRepresentation
    }
    
    internal init(_ key:Secp256k1PublicKey) {
        self.type = .secp256k1
        self.data = Data(key.rawPublicKey)
    }
    
    internal init(_ key:SecKey) throws {
        self.type = .rsa
        guard key.isRSAKey, key.isPublicKey else { throw NSError(domain: "Invalid RSA Public Key", code: 0, userInfo: nil) }
        self.data = try key.rawRepresentation()
    }
}

/// A generic wrapper for libp2p supported Private keys
public struct RawPrivateKey {
    let type:LibP2PCrypto.Keys.GenericKeyType
    public let data:Data
    
    internal init(_ priv:PrivateKey) {
        self.data = priv.data
        self.type = .init(priv.type)
    }
    
    internal init(type:LibP2PCrypto.Keys.GenericKeyType, data:Data) {
        self.type = type
        self.data = data
    }
    
    internal init(_ key:Curve25519.Signing.PrivateKey) {
        self.type = .ed25519
        self.data = key.rawRepresentation
    }
    
    internal init(_ key:Secp256k1PrivateKey) {
        self.type = .secp256k1
        self.data = Data(key.rawPrivateKey)
    }
    
    internal init(_ key:SecKey) throws {
        self.type = .rsa
        guard key.isRSAKey, key.isPublicKey == false else { throw NSError(domain: "Invalid RSA Private Key", code: 0, userInfo: nil) }
        self.data = try key.rawRepresentation()
    }
}

extension LibP2PCrypto {
    public enum Keys {
        public typealias PubKey = SecKey
        public typealias PrivKey = SecKey
        
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
        
        public struct KeyPair {
            /// The key pair type
            public let keyType:GenericKeyType
            
            /// The raw representation of the public key
            public let publicKey:RawPublicKey
            
            /// The raw represenations of the private key
            public let privateKey:RawPrivateKey?
            
            
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
            public func attributes() -> Attributes? {
                switch self.keyType {
                case .rsa:
                    let count = self.publicKey.data.count
                    if count == 140 {
                        return Attributes(type: .RSA(bits: .B1024), size: 1024, isPrivate: (self.privateKey != nil))
                    } else if count == 270 {
                        return Attributes(type: .RSA(bits: .B2048), size: 2048, isPrivate: (self.privateKey != nil))
                    } else if count == 398 {
                        return Attributes(type: .RSA(bits: .B3072), size: 3072, isPrivate: (self.privateKey != nil))
                    } else if count == 560 || count == 526 {
                        return Attributes(type: .RSA(bits: .B4096), size: 4096, isPrivate: (self.privateKey != nil))
                    } else {
                        print("PubKey Data Count: \(count)");
                        return nil
                    }
                    
                case .ed25519:
                    //print("ed25519 PubKey Data Count: \(self.publicKey.data.count)")
                    //print("ed25519 PrivKey Data Count: \(self.privateKey?.data.count ?? 0)")
                    return Attributes(type: .Ed25519, size: 32, isPrivate: (self.privateKey != nil))
                    
                case .secp256k1:
                    //print("secp256k1 PubKey Data Count: \(self.publicKey.data.count)")
                    //print("secp256k1 PrivKey Data Count: \(self.privateKey?.data.count ?? 0)")
                    return Attributes(type: .Secp256k1, size: 64, isPrivate: (self.privateKey != nil))
                }
            }

            /// New
            /// public init(_ type:KeyPairType)
            
            /// Imports
            /// public init(pem:String, password:String? = nil)
            /// public init(jwk:Data)
            public init(marshaledPublicKey str:String, base:BaseEncoding) throws {
                try self.init(marshaledPublicKey: BaseEncoding.decode(str, as: base).data)
            }
            public init(marshaledPublicKey data:Data) throws {
                let pubKey = try RawPublicKey(marshaledKey: data)
                self.init(publicKey: pubKey)
            }
            
            public init(marshaledPrivateKey str:String, base:BaseEncoding) throws {
                try self.init(marshaledPrivateKey: BaseEncoding.decode(str, as: base).data)
            }
            public init(marshaledPrivateKey data:Data) throws {
                let privKey = try RawPrivateKey(marshaledKey: data)
                try self.init(privateKey: privKey)
            }
            
            /// Exports
            /// marshal() -> Data
            /// toJWK() -> Data
            /// toPem() -> String
            
            internal init(keyType:GenericKeyType, publicKey:RawPublicKey, privateKey:RawPrivateKey?) {
                self.keyType = keyType
                self.publicKey = publicKey
                self.privateKey = privateKey
            }
            
            internal init(publicKey:RawPublicKey) {
                self.keyType = publicKey.type
                self.publicKey = publicKey
                self.privateKey = nil
            }
            
            internal init(privateKey:RawPrivateKey) throws {
                self.keyType = privateKey.type
                self.privateKey = privateKey
                self.publicKey = try privateKey.derivePublicKey()
            }
            
            /// Public Ed2559 Key
            internal init(_ pub:Curve25519.Signing.PublicKey) {
                self.keyType = .ed25519
                self.privateKey = nil
                self.publicKey = RawPublicKey(pub)
            }
            /// Private Ed25519 Key
            internal init(_ priv:Curve25519.Signing.PrivateKey) {
                self.keyType = .ed25519
                self.privateKey = RawPrivateKey(priv)
                self.publicKey = RawPublicKey(priv.publicKey)
            }
            
            /// Public Secp256k1 Key
            internal init(_ pub:Secp256k1PublicKey) {
                self.keyType = .secp256k1
                self.privateKey = nil
                self.publicKey = RawPublicKey(pub)
            }
            /// Private Secp256k1 Key
            internal init(_ priv:Secp256k1PrivateKey) {
                self.keyType = .secp256k1
                self.privateKey = RawPrivateKey(priv)
                self.publicKey = RawPublicKey(priv.publicKey)
            }
            
            /// Public RSA SecKey
            internal init(publicSecKey:SecKey) throws {
                self.keyType = .rsa
                self.privateKey = nil
                self.publicKey = try RawPublicKey(publicSecKey)
            }
            /// Private RSA SecKey
            internal init(privateSecKey:SecKey) throws {
                self.keyType = .rsa
                self.privateKey = try RawPrivateKey(privateSecKey)
                self.publicKey = try RawPublicKey(privateSecKey.extractPubKey())
            }
        }
        
//        public struct KeyPair:Encryptable, Decryptable {
//            public let keyType:KeyPairType
//            public let publicKey:PubKey
//            public let privateKey:PrivKey
//
//            public func encrypt(_ data:Data) throws -> Data {
//                try LibP2PCrypto.Keys.encrypt(data, publicKey: self.publicKey)
//            }
//
//            public func encrypt(_ message:String) throws -> Data {
//                try LibP2PCrypto.Keys.encrypt(Data(message.utf8), publicKey: self.publicKey)
//            }
//
//            public func decrypt(_ data:Data) throws -> Data {
//                try LibP2PCrypto.Keys.decrypt(data, privateKey: self.privateKey)
//            }
//
//            public func decrypt(_ message:String) throws -> Data {
//                try LibP2PCrypto.Keys.decrypt(Data(message.utf8), privateKey: self.privateKey)
//            }
//
//            public func id(withMultibasePrefix:Bool = true) throws -> String {
//                /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
//                /// The public key is a protobuf encoding containing a type and the DER encoding
//                /// of the PKCS SubjectPublicKeyInfo.
//                let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(self)
//                let mh = try Multihash(raw: marshaledPubKey, hashedWith: .sha2_256)
//                return withMultibasePrefix ? mh.asMultibase(.base58btc) : mh.asString(base: .base58btc)
//            }
//        }

//        public struct RawKeyPair:CustomStringConvertible {
//            public let keyType:KeyPairType
//            public let publicKey:Data
//            public let privateKey:Data
//
//            public func toKeyPair() throws -> KeyPair {
//                var error:Unmanaged<CFError>? = nil
//                guard let privateSecKey = SecKeyCreateFromData(self.keyType.params! as CFDictionary, self.privateKey as CFData, &error) else {
//                    throw NSError(domain: "Error constructing SecKey from raw key data: \(error.debugDescription)", code: 0, userInfo: nil)
//                }
//                guard let pubKey = SecKeyCopyPublicKey(privateSecKey) else {
//                    throw NSError(domain: "Public Key Extraction Error", code: 0, userInfo: nil)
//                }
//                return KeyPair(keyType: self.keyType, publicKey: pubKey, privateKey: privateSecKey)
//            }
//
//            public var description: String {
//                return """
//                -- \(self.keyType.description) --
//                Pubilc Key: \(self.publicKey.asString(base: .base16))
//                Private Key: \(self.privateKey.asString(base: .base16))
//                """
//            }
//        }
        
        public enum ElipticCurveType {
            case P256
            case P384
            case P521
            
            var bits:Int {
                switch self {
                case .P256:
                    return 256
                case .P384:
                    return 384
                case .P521:
                    return 521
                }
            }
            
            var description:String {
                return "\(bits) Curve"
            }
        }
        
        public enum RSABitLength {
            case B1024
            case B2048
            case B3072
            case B4096
            case custom(bits:Int)
            
            var bits:Int {
                switch self {
                case .B1024:
                    return 1024
                case .B2048:
                    return 2048
                case .B3072:
                    return 3072
                case .B4096:
                    return 4096
                case .custom(let bits):
                    if bits < 1024 { print("‼️ WARNING: RSA Keys less than 1024 are considered insecure! ‼️")}
                    return bits
                }
            }
            
            var description:String {
                return "\(self.bits) Bit"
            }
        }
        
        public enum KeyPairType {
            case RSA(bits:RSABitLength = .B2048)
            case EC(curve:ElipticCurveType = .P256)
            case ECDSA(curve:ElipticCurveType = .P256)
            case ECSECPrimeRandom(curve:ElipticCurveType = .P256)
            case Ed25519
            case Secp256k1
            
            //case DSA(bits:Int)
            //case AES(bits:Int)
            //case DES(bits:Int)
            //case CAST
            //case RC2(bits:Int)
            //case RC4(bits:Int)
            //case ThreeDES
            
            var secKey:CFString {
                switch self {
                case .RSA:              return kSecAttrKeyTypeRSA
                case .EC:               return kSecAttrKeyTypeEC //Deprecated, use ECDSA instead...
                #if os(macOS)
                case .ECDSA:            return kSecAttrKeyTypeECDSA
                #else
                case .ECDSA:            return "" as CFString
                #endif
                case .ECSECPrimeRandom: return kSecAttrKeyTypeECSECPrimeRandom
                case .Ed25519:          return "" as CFString
                case .Secp256k1:        return "" as CFString
                    
                //case .DSA:              return kSecAttrKeyTypeDSA
                //case .AES:              return kSecAttrKeyTypeAES
                //case .DES:              return kSecAttrKeyTypeDES
                //case .CAST:             return kSecAttrKeyTypeCAST
                //case .RC2:              return kSecAttrKeyTypeRC2
                //case .RC4:              return kSecAttrKeyTypeRC4
                //case .ThreeDES:         return kSecAttrKeyType3DES
                }
            }
            
            var bits:Int {
                switch self {
                case .RSA(let type):
                    return type.bits
                case .EC(let curve):
                    return curve.bits
                case .ECDSA(let curve):
                    return curve.bits
                case .ECSECPrimeRandom(let curve):
                    return curve.bits
                case .Ed25519:
                    return 0
                case .Secp256k1:
                    return 0
                    
//                case .RC2(let bits): // unimplemented core routine
//                    return bits
//                case .RC4(let bits): // unimplemented core routine
//                    return bits
//                case .AES(let bits): // error in user parameter list
//                    return bits
//                case .DSA(let bits): // unimplemented core routine
//                    return bits
//                case .DES(let bits): // unimplemented core routine
//                    return bits
//                case .ThreeDES:      // error in user parameter list
//                    return 192 //168
//                default:
//                    return 0
                }
            }
            
            var params:[CFString: Any]? {
                guard self.bits > 0 else { return nil }
                return [
                    kSecAttrKeyType: self.secKey,
                    kSecAttrKeySizeInBits: self.bits
                ]
            }
            
            var toProtoType:KeyType {
                switch self {
                case .RSA, .EC, .ECDSA, .ECSECPrimeRandom:
                    return .rsa
                case .Ed25519:
                    return .ed25519
                case .Secp256k1:
                    return .secp256K1
                }
            }
            
            var toGenericType:GenericKeyType {
                return .init(self.toProtoType)
            }
            
            ///
            /// Gets the ID of the key.
            ///
            /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
            /// The public key is a protobuf encoding containing a type and the DER encoding
            /// of the PKCS SubjectPublicKeyInfo.
            ///
            /// @returns {Promise<String>}
            ///
            /// async id () {
            ///   const hash = await this.public.hash()
            ///   return uint8ArrayToString(hash, 'base58btc')
            /// }
//            var id:String {
//                switch self {
//                case .RSA(let bits):
//                    /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
//                    /// The public key is a protobuf encoding containing a type and the DER encoding
//                    /// of the PKCS SubjectPublicKeyInfo.
//                    return
//                default:
//                    return ""
//                }
//            }
            
            var name:String {
                switch self {
                case .RSA:
                    return "RSA"
                case .EC:
                    return "EC"
                case .ECDSA:
                    return "ECDSA"
                case .ECSECPrimeRandom:
                    return "ECSecPrimeRandom"
                case .Ed25519:
                    return "ED25519"
                case .Secp256k1:
                    return "Secp256k1"
                }
            }
            
            var description:String {
                switch self {
                case .RSA(let bits):
                    return "\(bits.description) RSA"
                case .EC(let curve):
                    return "EC \(curve.description)"
                case .ECDSA(let curve):
                    return "ECDSA \(curve.description)"
                case .ECSECPrimeRandom(let curve):
                    return "ECSecPrimeRandom \(curve.description)"
                case .Ed25519:
                    return "ED25519 Curve"
                case .Secp256k1:
                    return "Secp256k1"
                }
            }
        }
        
        private static func generateEd25519KeyPair() throws -> KeyPair {
            if #available(OSX 10.15, *) {
                return KeyPair(Curve25519.Signing.PrivateKey())
            } else {
                throw NSError(domain: "Ed25519 Keys are only supported on MacOS 10.15 and greater", code: 0, userInfo: nil)
            }
        }
        
        private static func generateSecp256k1KeyPair() throws -> KeyPair {
            return KeyPair(try Secp256k1PrivateKey())
        }
        
        private static func generateSecKeyPair(_ type:KeyPairType) throws -> KeyPair {
            guard let parameters = type.params else {
                throw NSError(domain: "KeyPairGenerationError - Invalid Parameters", code: 0, userInfo: nil)
            }
                    
            var error:Unmanaged<CFError>? = nil
            
            guard let privKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
                print(error.debugDescription)
                throw NSError(domain: "Key Generation Error: \(error.debugDescription)", code: 0, userInfo: nil)
            }
            
            return try KeyPair(privateSecKey: privKey)
            
//            guard let pubKey = SecKeyCopyPublicKey(privKey) else {
//                throw NSError(domain: "Public Key Extraction Error", code: 0, userInfo: nil)
//            }
//
//            return KeyPair(keyType: type.toGenericType, publicKey: pubKey, privateKey: privKey)
        }
        
        /// This does unescesary work by creating both priv and public key then tossing out the public key... Lets have direct methods for only private key generation...
        public static func generateRawPrivateKey(_ type:KeyPairType) throws -> RawPrivateKey {
            if case .Ed25519 = type { return try self.generateEd25519KeyPair().privateKey! }
            
            else if case .Secp256k1 = type { return try self.generateSecp256k1KeyPair().privateKey! }
            
            return try generateSecKeyPair(type).privateKey!
        }
        
        
        public static func generateKeyPair(_ type:KeyPairType) throws -> KeyPair {
            if case .Ed25519 = type { return try self.generateEd25519KeyPair() }
            
            else if case .Secp256k1 = type { return try self.generateSecp256k1KeyPair() }
            
            return try generateSecKeyPair(type)
            
//            let rawPubKey:Data
//            let rawPrivKey:Data
//
//            /// SecKeyCopyExternalRepresentation --> DER Encoded Public Key
//            var pubKeyError:Unmanaged<CFError>?
//            if let cfdata = SecKeyCopyExternalRepresentation(kp.publicKey, &pubKeyError) {
//                rawPubKey = cfdata as Data
//                //rawPubKey = data.asString(base: base, withMultibasePrefix: withPrefix)
//            } else { throw NSError(domain: "RawKeyError: \(pubKeyError.debugDescription)", code: 0, userInfo: nil) }
//
//            var privKeyError:Unmanaged<CFError>?
//            if let cfdata = SecKeyCopyExternalRepresentation(kp.privateKey, &privKeyError) {
//                rawPrivKey = cfdata as Data
//                //rawPrivKey = data.asString(base: base, withMultibasePrefix: withPrefix)
//            } else { throw NSError(domain: "RawKeyError: \(privKeyError.debugDescription)", code: 0, userInfo: nil) }
//
//            return RawKeyPair(keyType: type, publicKey: rawPubKey, privateKey: rawPrivKey)
        }
        
        public static func generateEphemeralKeyPair(curve:ElipticCurveType) throws -> KeyPair {
            return try generateSecKeyPair(.ECDSA(curve: curve))
        }
        
//        public static func generateRawEphemeralKeyPair(curve:ElipticCurveType) throws -> RawKeyPair {
//            return try generateRawKeyPair(.ECDSA(curve: curve))
//        }
        
        
        public static func encrypt(_ data:Data, publicKey:SecKey) throws -> Data {
            var error:Unmanaged<CFError>?
            guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error) else {
                throw NSError(domain: "Error Encrypting Data: \(error.debugDescription)", code: 0, userInfo: nil)
            }
            return encryptedData as Data
        }
        
        public static func decrypt(_ data:Data, privateKey:SecKey) throws -> Data {
            var error:Unmanaged<CFError>?
            guard let decryptedData = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, data as CFData, &error) else {
                throw NSError(domain: "Error Decrypting Data: \(error.debugDescription)", code: 0, userInfo: nil)
            }
            return decryptedData as Data
        }
        
        func keyStretcher(cipherType:String, hashType:String, secret:String) {}
        
        /// Does this make sense?
        public static func marshalPublicKey(raw:String, asKeyType:KeyPairType, fromBase base:BaseEncoding? = nil) throws -> [UInt8] {
            do {
                let decoded:(base:BaseEncoding, data:Data)
                if let b = base {
                    decoded = try BaseEncoding.decode(raw, as: b)
                } else {
                    decoded = try BaseEncoding.decode(raw)
                }
                return try self.marshalPublicKey(raw: decoded.data, keyType: asKeyType)
            } catch {
                print(error)
                throw NSError(domain: "Failed to decode raw public key, unknown base encoding.", code: 0, userInfo: nil)
            }
        }
        
//        public static func marshalPublicKey(_ keyPair:KeyPair) throws -> [UInt8] {
//            try self.marshalPublicKey(raw: keyPair.publicKey.rawRepresentation(), keyType: keyPair.keyType)
//        }
        
        public static func marshalPublicKey(_ secKey:SecKey, keyType:KeyPairType) throws -> [UInt8] {
            //let subjectPublicKeyInfoData = try RSAPublicKeyExporter().toSubjectPublicKeyInfo(secKey.rawRepresentation())
            //print("SubjectPublicKeyInfo:\n\(subjectPublicKeyInfoData.map { "\($0)" }.joined())")
            return try self.marshalPublicKey(raw: secKey.rawRepresentation(), keyType: keyType)
        }
        
        /// Given raw DER public key data, this method will compute the SubjectPublicKeyInfo for the DER and instantitate a PublicKey Protobuf object, then return the serialized data...
        /// Raw Data should be the DER Public Key ( aka the SecKey.rawRepresentation() )
        public static func marshalPublicKey(raw:Data, keyType:KeyPairType) throws -> [UInt8] {
            let subjectPublicKeyInfoData = RSAPublicKeyExporter().toSubjectPublicKeyInfo(raw)
            var pubKeyProto = PublicKey()
            pubKeyProto.data = subjectPublicKeyInfoData
            pubKeyProto.type = keyType.toProtoType
            return Array(try pubKeyProto.serializedData())
        }
        
        /// Converts a protobuf serialized public key into its representative object.
        public static func unmarshalPublicKey(buf:[UInt8], into base:BaseEncoding = .base16) throws -> String {
            let pubKeyProto = try PublicKey(contiguousBytes: buf)
            
            guard !pubKeyProto.data.isEmpty else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }
            switch pubKeyProto.type {
            case .rsa:
                let data = try RSAPublicKeyImporter().fromSubjectPublicKeyInfo( pubKeyProto.data )
                
                return data.asString(base: base)
            case .ed25519:
                return pubKeyProto.data.asString(base: base)
            case .secp256K1:
                return pubKeyProto.data.asString(base: base)
            }
            
        }
        
        /// Converts a raw private key string into a protobuf serialized private key.
        public static func marshalPrivateKey(raw:String, asKeyType:KeyPairType, fromBase base:BaseEncoding? = nil) throws -> [UInt8] {
            do {
                let decoded:(base:BaseEncoding, data:Data)
                if let b = base {
                    decoded = try BaseEncoding.decode(raw, as: b)
                } else {
                    decoded = try BaseEncoding.decode(raw)
                }
                return try self.marshalPrivateKey(raw: decoded.data, keyType: asKeyType)
            } catch {
                print(error)
                throw NSError(domain: "Failed to decode raw private key, unknown base encoding.", code: 0, userInfo: nil)
            }
        }
        
//        public static func marshalPrivateKey(_ keyPair:KeyPair) throws -> [UInt8] {
//            try self.marshalPrivateKey(raw: keyPair.privateKey.rawRepresentation(), keyType: keyPair.keyType)
//        }
        
        public static func marshalPrivateKey(_ secKey:SecKey, keyType:KeyPairType) throws -> [UInt8] {
            try self.marshalPrivateKey(raw: secKey.rawRepresentation(), keyType: keyType)
        }
        
        public static func marshalPrivateKey(raw:Data, keyType:KeyPairType) throws -> [UInt8] {
            //let subjectPublicKeyInfoData = RSAPrivateKeyExporter().toSubjectPublicKeyInfo(raw)
            var privKeyProto = PrivateKey()
            privKeyProto.data = raw
            privKeyProto.type = keyType.toProtoType
            return Array(try privKeyProto.serializedData())
        }
        
        /// Converts a protobuf serialized private key into its representative object.
        public static func unmarshalPrivateKey(buf:[UInt8], into base:BaseEncoding = .base16) throws -> String {
            let privKeyProto = try PrivateKey(contiguousBytes: buf)
            
            let data = privKeyProto.data
            guard !data.isEmpty else { throw NSError(domain: "Unable to Unmarshal PrivateKey", code: 0, userInfo: nil) }
            
            return data.asString(base: base)
        }
        
        func importKey(encryptedKey:String, password:String) {
//            guard let data2 = Data.init(base64Encoded: b64Key) else {
//               return
//            }
//
//            let keyDict:[NSObject:NSObject] = [
//               kSecAttrKeyType: kSecAttrKeyTypeRSA,
//               kSecAttrKeyClass: kSecAttrKeyClassPublic,
//               kSecAttrKeySizeInBits: NSNumber(value: 512),
//               kSecReturnPersistentRef: true as NSObject
//            ]
//
//            guard let publicKey = SecKeyCreateWithData(data2 as CFData, keyDict as CFDictionary, nil) else {
//                return
//            }
        }
        
        public static func importMarshaledPublicKey(_ marshaled:[UInt8]) throws -> PubKey {
            let pubKeyProto = try PublicKey(contiguousBytes: marshaled)
            guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }
            
            print("We Unmarshaled a PublicKey Proto!")
            print(pubKeyProto.type)
            print(pubKeyProto.data.asString(base: .base64))
            
            switch pubKeyProto.type {
            case .rsa:
                //init rsa pub key
                return try LibP2PCrypto.Keys.secKeyFrom(data: pubKeyProto.data, isPrivateKey: false, keyType: .RSA(bits: .B1024))
            default:
                throw NSError(domain: "We dont support exotic public keys yet...", code: 0, userInfo: nil)
            }
        }
        
        public static func importMarshaledPrivateKey(_ marshaled:[UInt8]) throws -> PrivKey {
            let pubKeyProto = try PrivateKey(contiguousBytes: marshaled)
            guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }
            
            switch pubKeyProto.type {
            case .rsa:
                //init rsa pub key
                return try LibP2PCrypto.Keys.secKeyFrom(data: pubKeyProto.data, isPrivateKey: true, keyType: .RSA(bits: .B1024))
            default:
                throw NSError(domain: "We dont support exotic private keys yet...", code: 0, userInfo: nil)
            }
        }
        
        /// Converts a public key object into a protobuf serialized public key.
        /// - TODO: PEM Format
        /// - [PEM](https://developer.apple.com/forums/thread/104753)
        /// - [Example of PEM Format](https://github.com/TakeScoop/SwiftyRSA/blob/master/Source/SwiftyRSA.swift#L44)
        /// - [Stackoverflow Question](https://stackoverflow.com/questions/21322182/how-to-store-ecdsa-private-key-in-go)
        ///
        /// Here is a code sample that demonstrates encoding and decoding of keys in Go. It helps to know that you need to connect couple of steps. Crypto algorithm is the fist step, in this case ECDSA key. Then you need standard encoding, x509 is most commontly used standard. Finally you need a file format, PEM is again commonly used one. This is currently most commonly used combination, but feel free to substitute any other algoriths or encoding.
        /// ```
        /// func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
        ///     x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
        ///     pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

        ///     x509EncodedPub, _ := x509.MarshalPKIXPublicKey(publicKey)
        ///     pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

        ///     return string(pemEncoded), string(pemEncodedPub)
        /// }

        /// func decode(pemEncoded string, pemEncodedPub string) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
        ///     block, _ := pem.Decode([]byte(pemEncoded))
        ///     x509Encoded := block.Bytes
        ///     privateKey, _ := x509.ParseECPrivateKey(x509Encoded)

        ///     blockPub, _ := pem.Decode([]byte(pemEncodedPub))
        ///     x509EncodedPub := blockPub.Bytes
        ///     genericPublicKey, _ := x509.ParsePKIXPublicKey(x509EncodedPub)
        ///     publicKey := genericPublicKey.(*ecdsa.PublicKey)

        ///     return privateKey, publicKey
        /// }

        /// func test() {
        ///     privateKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
        ///     publicKey := &privateKey.PublicKey

        ///     encPriv, encPub := encode(privateKey, publicKey)

        ///     fmt.Println(encPriv)
        ///     fmt.Println(encPub)

        ///     priv2, pub2 := decode(encPriv, encPub)

        ///     if !reflect.DeepEqual(privateKey, priv2) {
        ///         fmt.Println("Private keys do not match.")
        ///     }
        ///     if !reflect.DeepEqual(publicKey, pub2) {
        ///         fmt.Println("Public keys do not match.")
        ///     }
        /// }
        /// ```
        ///
        public enum ExportedKeyType {
            case PEM
            case JWK
        }
        
        func exportKey(key:String, password:String, format:ExportedKeyType) {
            
        }
        
        /// Appends PEM Header and Footer
        /// Base64 encodes DER PubKey
        /// MacOS -> Use <Security/SecImportExport.h>
        /// iOS roll our own
        /// https://github.com/ibm-cloud-security/Swift-JWK-to-PEM
        /// https://github.com/Kitura/OpenSSL
//        private func toDER(keyPair:LibP2PCrypto.Keys.KeyPair) throws -> String {
//
//            // Line length is typically 64 characters, except the last line.
//            // See https://tools.ietf.org/html/rfc7468#page-6 (64base64char)
//            // See https://tools.ietf.org/html/rfc7468#page-11 (example)
//            let keyData = try keyPair.publicKey.rawRepresentation()
//            let chunks = keyData.base64EncodedString().split(intoChunksOfLength: 64)
//
//            let pem = [
//                "-----BEGIN \(keyPair.keyType.name)-----",
//                chunks.joined(separator: "\n"),
//                "-----END \(keyPair.keyType.name)-----"
//            ]
//
//            return pem.joined(separator: "\n")
//        }
        
//        public static func initPubKeyFromPem(_ pem:String, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> PubKey {
//            var pubKey:Data? = nil
//            switch keyType {
//            case .ECDSA(curve: .P256):
//                pubKey = try P256.Signing.PublicKey(pemRepresentation: pem).rawRepresentation
//            case .ECDSA(curve: .P384):
//                pubKey = try P384.Signing.PublicKey(pemRepresentation: pem).rawRepresentation
//            case .ECDSA(curve: .P521):
//                pubKey = try P521.Signing.PublicKey(pemRepresentation: pem).rawRepresentation
//            default:
//                print("Unsupported KeyType")
//            }
//
//            guard let pubKeyData = pubKey else {
//                throw NSError(domain: "Unable to parse PEM into Public Key", code: 0, userInfo: nil)
//            }
//
//            let attributes: [String:Any] = [
//                kSecAttrKeyType as String: keyType.secKey,
//                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
//                kSecAttrKeySizeInBits as String: keyType.bits,
//                kSecAttrIsPermanent as String: false
//            ]
//
//            return try LibP2PCrypto.Keys.secKeyFrom(data: pubKeyData, attributes: attributes)
//        }
        
//        public static func initPrivKeyFromPem(_ pem:String, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> PubKey {
//            var pubKey:Data? = nil
//            switch keyType {
//            case .ECDSA(curve: .P256):
//                pubKey = try P256.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation
//            case .ECDSA(curve: .P384):
//                pubKey = try P384.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation
//            case .ECDSA(curve: .P521):
//                pubKey = try P521.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation
//            default:
//                print("Unsupported KeyType")
//            }
//
//            guard let pubKeyData = pubKey else {
//                throw NSError(domain: "Unable to parse PEM into Private Key", code: 0, userInfo: nil)
//            }
//
//            let attributes: [String:Any] = [
//                kSecAttrKeyType as String: keyType.secKey,
//                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
//                kSecAttrKeySizeInBits as String: keyType.bits,
//                kSecAttrIsPermanent as String: false
//            ]
//
//            return try LibP2PCrypto.Keys.secKeyFrom(data: pubKeyData, attributes: attributes)
//        }
        
        public struct ParsedPem {
            let isPrivate:Bool
            let type:KeyPairType
            let rawKey:Data
        }
        
        /// Parse the pem file into ASN1 bits...
        /// Scan the bits for Object Identifiers and classify the key type
        /// Based on the key type... scan the bits for the key data
        /// Return a ParsedPem struct that we can use to instantiate any of our supported KeyPairTypes...
        public static func parsePem(_ pem:String) throws -> KeyPair {
            let chunks = pem.split(separator: "\n")
            guard chunks.count >= 3,
                  let f = chunks.first, f.hasPrefix("-----BEGIN"),
                  let l = chunks.last, l.hasSuffix("-----") else {
                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
            }
            
            /// If its a DER re route it...
            if f.contains("-----BEGIN RSA PUBLIC") { return try LibP2PCrypto.Keys.importPublicDER(pem) }
            else if f.contains("-----BEGIN RSA PRIVATE") { return try LibP2PCrypto.Keys.importPrivateDER(pem) }
            
            let isPrivate:Bool = f.contains("PRIVATE")
            
            let rawPem = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
            
            return try self.parsePem(rawPem.data, isPrivate: isPrivate)
        }
        
        private static func parsePem(_ rawPem:Data, isPrivate:Bool) throws -> KeyPair {
            var type:KeyPairType? = nil
            let asn = try Asn1ParserECPrivate.parse(data: rawPem)
            
            print("ASN1 Nodes")
            print(asn)
            print("----------")
            
            guard case .sequence(let nodes) = asn else { throw NSError(domain: "Failed to parse PEM", code: 0, userInfo: nil) }
            let ids = objIdsInSequence(nodes)
            
            if ids.contains(where: { (id) -> Bool in
                if case .rsaEncryption = id { return true } else { return false }
            }) {
                type = .RSA(bits: .B1024) //Bit length doesn't matter here, we're just broadly classifying it...
            } else if ids.contains(where: { (id) -> Bool in
                if case .secp256k1 = id { return true } else { return false }
            }) {
                type = .Secp256k1
            } else if ids.contains(where: { (id) -> Bool in
                if case .Ed25519 = id { return true } else { return false }
            }) {
                type = .Ed25519
            } else if ids.contains(where: { (id) -> Bool in
                switch id {
                case .prime256v1, .secp384r1, .secp521r1: return true
                default: return false
                }
            }) {
                type = .EC(curve: .P256) //Curve bits dont matter here, we're just broadly classifying it...
            }
            
            guard let keyType = type else { throw NSError(domain: "Failed to classify key", code: 0, userInfo: nil) }
            
            guard case .sequence(let top) = asn else {
                throw NSError(domain: "Failed to parse Asn1", code: 0, userInfo: nil)
            }
            
            var rawKeyData:Data? = nil
            
            if isPrivate {
                // First Octet
                guard let octet = octetsInSequence(top).first else {
                    throw NSError(domain: "Failed to extract \(keyType.name) \(isPrivate ? "Private" : "Public") key", code: 0, userInfo: nil)
                }
                rawKeyData = octet
            } else {
                // First Bit String...
                guard let bitString = bitStringsInSequence(top).first else {
                    throw NSError(domain: "Failed to extract \(keyType.name) \(isPrivate ? "Private" : "Public") key", code: 0, userInfo: nil)
                }
                rawKeyData = bitString
            }
            
            // ED25519 Private Keys are wrapped in an additional octetString node, lets remove it...
            if isPrivate, case .Ed25519 = keyType, rawKeyData?.count == 34 {
                rawKeyData?.removeFirst(2)
            }

            guard let keyData = rawKeyData else {
                throw NSError(domain: "Failed to extract key data from asn1 nodes", code: 0, userInfo: nil)
            }
            
            //return ParsedPem(isPrivate: isPrivate, type: keyType, rawKey: keyData)
            
            // At this point we know if its a public or private key, the type of key, and the raw bits of the key.
            // We can instantiate the key, ensure it's valid, then create a return a PublicKey or PrivateKey
            switch keyType {
            case .RSA:
                if isPrivate {
                    return try KeyPair(privateSecKey: LibP2PCrypto.Keys.secKeyFrom(data: keyData, isPrivateKey: true, keyType: keyType))
                } else {
                    return try KeyPair(publicSecKey: LibP2PCrypto.Keys.secKeyFrom(data: keyData, isPrivateKey: false, keyType: keyType))
                }
            case .Ed25519:
                if isPrivate {
                    return try KeyPair(Curve25519.Signing.PrivateKey(rawRepresentation: keyData))
                } else {
                    return try KeyPair(Curve25519.Signing.PublicKey(rawRepresentation: keyData))
                }
            case .Secp256k1:
                if isPrivate {
                    return try KeyPair(Secp256k1PrivateKey(keyData.bytes))
                } else {
                    return try KeyPair(Secp256k1PublicKey(keyData.bytes))
                }
            default:
                /// - TODO: Internal Support For EC Keys (without support for marshaling)
                throw NSError(domain: "Unsupported Key Type \(keyType.description)", code: 0, userInfo: nil)
            }
        }
        
        /// Importes an Encrypted PEM Key File
        ///
        /// An ASN1 Node Tree of an Encrypted RSA PEM Key (PBKDF2 and AES_CBC_128)
        /// ```
        /// sequence(nodes: [
        ///     libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///         libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes), //[42,134,72,134,247,13,1,5,13]
        ///         libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
        ///                 libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///                     libp2p_crypto.Asn1Parser.Node.octetString(data: 8 bytes),       //SALT
        ///                     libp2p_crypto.Asn1Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
        ///                 ])
        ///             ]),
        ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
        ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc [96,134,72,1,101,3,4,1,2]
        ///                 libp2p_crypto.Asn1Parser.Node.octetString(data: 16 bytes)           //IV
        ///             ])
        ///         ])
        ///     ]),
        ///     libp2p_crypto.Asn1Parser.Node.octetString(data: 640 bytes)
        /// ])
        /// ```
        static func parseEncryptedPem(_ pem:String, password:String) throws -> KeyPair {
            let chunks = pem.split(separator: "\n")
            guard chunks.count >= 3,
                  let f = chunks.first, f.hasPrefix("-----BEGIN ENCRYPTED"),
                  let l = chunks.last, l.hasSuffix("-----") else {
                throw NSError(domain: "Invalid Encrypted PEM Format", code: 0, userInfo: nil)
            }
            
            let isPrivate:Bool = f.contains("PRIVATE")
            
            let rawPem = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
            
            let asn = try Asn1ParserECPrivate.parse(data: rawPem.data)
            
            print("ASN1 Nodes")
            print(asn)
            print("----------")
            
            var saltData:Data? = nil
            var ivData:Data? = nil
            var itterationsData:Int? = nil
            var ciphertextData:Data? = nil
            
            guard case .sequence(let nodes) = asn else {
                throw NSError(domain: "Failed to parse ASN from PEM", code: 0, userInfo: nil)
            }
            
            /// Octets Should Include our Salt, IV and cipherText...
            /// TODO make this better by actually checking objectIDs to make sure we have the correct data (instead of guessing based on length)
            octetsInSequence(nodes).forEach {
                let count = $0.count
                if count == 16 || count == 32 {
                    ivData = $0
                } else if count > 100 {
                    ciphertextData = $0
                } else {
                     saltData = $0
                }
            }
            
            /// There should be only one integer, the itteration count...
            itterationsData = integersInSequence(nodes).first
            
            guard let salt = saltData, let iv = ivData, let itterations = itterationsData, let ciphertext = ciphertextData else {
                throw NSError(domain: "Failed to parse our pcks#8 key", code: 0, userInfo: nil)
            }

            // Attempt to derive the aes encryption key from the password and salt
            // PBKDF2-SHA1
            guard let key = PBKDF2.SHA1(password: password, salt: salt, keyByteCount: iv.count, rounds: itterations) else {
                throw NSError(domain: "Failed to derive key from password and salt", code: 0, userInfo: nil)
            }

            //print("Key 1 -> \(key.asString(base: .base16))")

            //Create our CBC AES Cipher
            let aes = try AES.createKey(key: key, iv: iv)
            //let aes = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .noPadding)

            // GCM Doesn't work on OPENSSL Encrypted PEM Files but I saw mention of it in libp2p-crypto-js so perhaps we'll need it later...
            //let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .detached), padding: .noPadding)

            let decryptedKey = try aes.decrypt(ciphertext.bytes)
            
            // At this point we have regular unencrypted PEM data rep of a key, lets parse it...
            return try self.parsePem(decryptedKey, isPrivate: isPrivate)
        }
        
        /// Traverses a Node tree and returns all instances of integers
        private static func integersInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Int] {
            var integers:[Int?] = []
            
            nodes.forEach {
                if case .integer(let data) = $0 { integers.append(Int(data.asString(base: .base16), radix: 16)) }
                else if case .sequence(let nodes) = $0 {
                    return integers.append(contentsOf: integersInSequence(nodes) )
                }
            }
            
            return integers.compactMap { $0 }
        }
        
        /// Traverses a Node tree and returns all instances of bitStrings
        private static func bitStringsInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Data] {
            var bitString:[Data] = []
            
            nodes.forEach {
                if case .bitString(let data) = $0 { bitString.append(data) }
                else if case .sequence(let nodes) = $0 {
                    return bitString.append(contentsOf: bitStringsInSequence(nodes) )
                }
            }
            
            return bitString
        }
        
        /// Traverses a Node tree and returns all instances of bitStrings
        private static func octetsInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Data] {
            var octets:[Data] = []
            
            nodes.forEach {
                if case .octetString(let data) = $0 { octets.append(data) }
                else if case .sequence(let nodes) = $0 {
                    return octets.append(contentsOf: octetsInSequence(nodes) )
                }
            }
            
            return octets
        }
        
        /// Traverses a Node tree and returns all instances of objectIds
        private static func objIdsInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Asn1ParserECPrivate.ObjectIdentifier] {
            var objs:[Asn1ParserECPrivate.ObjectIdentifier] = []
            
            nodes.forEach {
                if case .objectIdentifier(let id) = $0 { objs.append(id) }
                else if case .sequence(let nodes) = $0 {
                    return objs.append(contentsOf: objIdsInSequence(nodes) )
                }
            }
            
            return objs
        }
        
        
        public static func secKeyFrom(data:Data, isPrivateKey:Bool, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> SecKey {
            let attributes: [String:Any] = [
                kSecAttrKeyType as String: keyType.secKey,
                kSecAttrKeyClass as String: isPrivateKey ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic,
                kSecAttrKeySizeInBits as String: keyType.bits,
                kSecAttrIsPermanent as String: false
            ]
            
            var error:Unmanaged<CFError>? = nil
            guard let secKey = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, &error) else {
                throw NSError(domain: "Error constructing SecKey from raw key data: \(error.debugDescription)", code: 0, userInfo: nil)
            }
            
            return secKey
        }
        
        /// Expects a PEM Public Key with the x509 header information included (object identifier)
        ///
        /// - Note: Handles RSA and EC Public Keys
        public static func importPublicPem(_ pem:String) throws -> PubKey {
            let chunks = pem.split(separator: "\n")
            guard chunks.count > 3,
                  let f = chunks.first, f.hasPrefix("-----BEGIN"),
                  let l = chunks.last, l.hasSuffix("-----") else {
                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
            }
            
            //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
            //print(raw.data)
            
            //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
            
            let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
            
            guard ans1.isPrivateKey == false else {
                throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
            }
            
            if ans1.objectIdentifier == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
                print("Trying to Init RSA Key")
                return try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .RSA(bits: .B1024))
            } else if ans1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
                print("Trying to Init EC Key")
                return try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .EC(curve: .P256))
            }
            
            throw NSError(domain: "Failed to parse PEM into known key type \(ans1)", code: 0, userInfo: nil)
        }
        
        /// - TODO: Make this better...
//        public static func importRawPublicPem(_ pem:String) throws -> Data {
//            let chunks = pem.split(separator: "\n")
//            guard chunks.count > 3,
//                  let f = chunks.first, f.hasPrefix("-----BEGIN"),
//                  let l = chunks.last, l.hasSuffix("-----") else {
//                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//            }
//
//            //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
//            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//            //print(raw.data)
//
//            //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
//
//            let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
//
//            guard ans1.isPrivateKey == false else {
//                throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
//            }
//
//            if ans1.objectIdentifier == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
//                print("Trying to Init RSA Key")
//                return try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .RSA(bits: .B1024)).rawRepresentation()
//            } else if ans1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
//                print("Trying to Init EC Key")
//                return try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .EC(curve: .P256)).rawRepresentation()
//            } else {
//                do {
//                    let key = try Curve25519.Signing.PublicKey(pem: pem).rawRepresentation
//                    return key
//                } catch {
//                    return try Data(Secp256k1PublicKey(ans1.keyBits.bytes).rawPublicKey)
//                }
//            }
//
//            //throw NSError(domain: "Failed to parse PEM into known key type \(ans1)", code: 0, userInfo: nil)
//        }
        
        /// Expects a PEM Public Key with the x509 header information included (object identifier)
        ///
        /// - Note: Handles RSA and EC Public Keys
        public static func importPublicDER(_ der:String) throws -> KeyPair {
            let chunks = der.split(separator: "\n")
            guard chunks.count > 3,
                  let f = chunks.first, f.hasPrefix("-----BEGIN RSA PUBLIC"),
                  let l = chunks.last, l.hasSuffix("-----") else {
                throw NSError(domain: "Invalid DER Format", code: 0, userInfo: nil)
            }
            
            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
            
            print("Trying to Init RSA DER Key")
            return try KeyPair(publicSecKey: LibP2PCrypto.Keys.secKeyFrom(data: raw.data, isPrivateKey: false, keyType: .RSA(bits: .B1024)))
        }
        
        public static func importPrivateDER(_ der:String) throws -> KeyPair {
            let chunks = der.split(separator: "\n")
            guard chunks.count > 3,
                  let f = chunks.first, f.hasPrefix("-----BEGIN RSA PRIVATE"),
                  let l = chunks.last, l.hasSuffix("-----") else {
                throw NSError(domain: "Invalid DER Format", code: 0, userInfo: nil)
            }
            
            var raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64).data
            
            while raw.count % 4 != 0 {
                raw.insert(0, at: 0)
            }
            
            print("Trying to Init RSA DER Key")
            return try KeyPair(publicSecKey: LibP2PCrypto.Keys.secKeyFrom(data: raw, isPrivateKey: true, keyType: .RSA(bits: .B1024)))
        }
        
        /// Expects a PEM Private Key with the x509 header information included (object identifier)
        ///
        /// - Note: Only handles RSA Pirvate Keys at the moment
        public static func importPrivatePem(_ pem:String) throws -> PrivKey {
            let chunks = pem.split(separator: "\n")
            guard chunks.count > 3,
                  let f = chunks.first, f.hasPrefix("-----BEGIN PRIVATE"),
                  let l = chunks.last, l.hasSuffix("-----") else {
                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
            }
            
            //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
            //print(raw.data)
            
            //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
            
            let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
            
            guard ans1.isPrivateKey == true else {
                throw NSError(domain: "The provided PEM isn't a Private Key. Try importPublicPem() instead...", code: 0, userInfo: nil)
            }
            
            if ans1.objectIdentifier == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
                print("Trying to Init RSA Key")
                return try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .RSA(bits: .B1024))
            } else if ans1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
                print("Trying to Init EC Key")
                return try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .EC(curve: .P256))
            }
            
            throw NSError(domain: "Failed to parse PEM into known key type \(ans1)", code: 0, userInfo: nil)
        }
        
        /// Expects a PEM Private Key with the x509 header information included (object identifier)
        ///
        /// - Note: Only handles RSA Pirvate Keys at the moment
//        public static func importPrivatePemEC(_ pem:String) throws -> PrivKey {
//            let chunks = pem.split(separator: "\n")
//            guard chunks.count > 3,
//                  let f = chunks.first, f.hasPrefix("-----BEGIN PRIVATE"),
//                  let l = chunks.last, l.hasSuffix("-----") else {
//                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//            }
//            
//            //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
//            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//            //print(raw.data)
//                        
//            var octet = try LibP2PCrypto.Keys.parseANS1ECPrivate(pemData: raw.data)
//            
//            let bytes = octet.bytes.count
//            
//            // TODO Create a PublicKey and PrivateKey Protocol that SecKey and these keys can conform to so we can return a common type...
//            if bytes <= 32 { //P256 Pivate Key
//                while octet.bytes.count < 32 { octet.insert(0, at: 0) }
//                try P256.Signing.PrivateKey(rawRepresentation: octet)
//            } else if bytes <= 48 { //P384 Private Key
//                while octet.bytes.count < 48 { octet.insert(0, at: 0) }
//                try P384.Signing.PrivateKey(rawRepresentation: octet)
//            } else if bytes <= 66 { //P521 Private Key
//                while octet.bytes.count < 66 { octet.insert(0, at: 0) }
//                try P521.Signing.PrivateKey(rawRepresentation: octet)
//            }
//            
//            throw NSError(domain: "Failed to parse PEM into known key type \(octet)", code: 0, userInfo: nil)
//        }
        
//        /// Expects a DER Public Key without the x509 header information (object identifier)
//        ///
//        /// - Note: Handles nothing at the moment
//        public static func importPrivateDER(_ der:String) throws -> PrivKey {
//
//            let chunks = der.split(separator: "\n")
//            guard chunks.count > 3,
//                  let f = chunks.first, f.hasPrefix("-----BEGIN"),
//                  let l = chunks.last, l.hasSuffix("-----") else {
//                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//            }
//
//            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//            //let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
//
//            //print(ans1)
//
//            print("Raw Data Count: \(raw.data.count)")
//            print("Is divisible by 4: \(raw.data.count % 4 == 0)")
//            var d = raw.data
//            d.insert(0, at: 0)
//            print("Data Count: \(d.count)")
//            print("Is divisible by 4: \(d.count % 4 == 0)")
//
//            print("Trying to Init RSA DER Key")
////            let attributes: [String: Any] = [
////                        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
////                        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
////                    ]
//            var error: Unmanaged<CFError>?
//            //let privKey = SecKeyCreateWithData(d as CFData, attributes as CFDictionary, &error)
//            let privKey = SecKeyCreateFromData([:] as CFDictionary, d as CFData, &error)
//
//            guard let key = privKey else {
//
//                throw NSError(domain: "Failed to gen priv key... \(error.debugDescription)", code: 0, userInfo: nil)
//            }
//
//            if let pubkey = try? key.extractPubKey() {
//                print("Got the pub key...")
//                print((try? pubkey.asString(base: .base16)) ?? "nil")
//            }
//
//            print(key.attributes)
//
//            print((try? key.rawRepresentation()) ?? "Failed to get raw rep...")
//
//            return key
//
//            //return try LibP2PCrypto.Keys.secKeyFrom(data: d, isPrivateKey: true, keyType: .EC(curve: .P256))
//        }
        
        // 256 objId -> 2a8648ce3d0301
        // 384 objId -> 2a8648ce3d0201
        // 521 objId -> 2a8648ce3d0201
        public struct ANS1Parts {
            let isPrivateKey:Bool
            let keyBits:Data
            let objectIdentifier:Data
        }
        public static func parseANS1(pemData:Data) throws -> ANS1Parts {
            let asn = try Asn1Parser.parse(data: pemData)
            
            var bitString:Data? = nil
            var objId:Data? = nil
            var isPrivate:Bool = false
            if case .sequence(let nodes) = asn {
                nodes.forEach {
                    switch $0 {
                    case .objectIdentifier(let data):
                        if data.first == 0x2a {
                            print("Got our obj id: \(data.asString(base: .base64))")
                            objId = data
                        }
                    case .bitString(let data):
                        print("Got our bit string: \(data.asString(base: .base64))")
                        bitString = data
                    case .sequence(let nodes):
                        nodes.forEach { n in
                            switch n {
                            case .objectIdentifier(let data):
                                if data.first == 0x2a {
                                    print("Got our obj id: \(data.asString(base: .base64))")
                                    objId = data
                                }
                            case .bitString(let data):
                                print("Got our bit string: \(data.asString(base: .base64))")
                                bitString = data
                            case .octetString(let data):
                                //Private Keys trigger
                                bitString = data
                                isPrivate = true
                            default:
                                return
                            }
                        }
                    case .octetString(let data):
                        //Private Keys trigger
                        bitString = data
                        isPrivate = true
                    default:
                        return
                    }
                }
            }
            
            guard let id = objId, let bits = bitString else {
                throw NSError(domain: "Unsupported ans1 format", code: 0, userInfo: nil)
            }
            
            return ANS1Parts(isPrivateKey: isPrivate, keyBits: bits, objectIdentifier: id)
               
        }
        public static func parseANS1ECPrivate(pemData:Data) throws -> Data {
            let asn = try Asn1ParserECPrivate.parse(data: pemData)
            
            var octetString:Data? = nil
            if case .sequence(let nodes) = asn {
                nodes.forEach {
                    switch $0 {
                    case .sequence(let nodes):
                        nodes.forEach { n in
                            switch n {
                            case .octetString(let data):
                                octetString = data
                            default:
                                return
                            }
                        }
                    case .octetString(let data):
                        octetString = data
                    default:
                        return
                    }
                }
            } else if case .octetString(let data) = asn {
                octetString = data
            }
            
            guard let bits = octetString else {
                throw NSError(domain: "Unsupported ans1 format", code: 0, userInfo: nil)
            }
            
            return bits
        }
        
//        public static func importPem(_ str:String) throws -> KeyPair {
//            
//            let pemData = str.data(using: .utf8)
//
//        }
        
//        public static func fromPEM(_ str:String, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> SecKey {
//
//            guard str.hasPrefix("-----BEGIN"), str.hasSuffix("-----") else { throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil) }
//            let chunks = str.split(separator: "\n")
//            guard chunks.count > 3 else { throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil) }
//            //print(chunks)
//            print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
//            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//            print(raw.data)
//            print(keyType.params)
//
//            let key = try stripKeyHeader(keyData: raw.data)
//
//            print("Stripped \(raw.data.count - key.count) Bytes of ANS1 Header")
//            //print(key.toHexString())
//
//            //let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(raw: key, keyType: keyType)
//            //let mh = try Multihash(raw: marshaledPubKey, hashedWith: .sha2_256)
//            //print("ID: \(mh.asString(base: .base58btc))")
//
////            let out:UnsafeMutablePointer<CFArray>?
////            let key = SecItemImport(raw.data as CFData, nil, nil, nil, .pemArmour, nil, nil, out)
////            print(key)
////            print(out)
//            let attributesRSAPriv: [String:Any] = [
//                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
//                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
//                kSecAttrKeySizeInBits as String: keyType.bits,
//                kSecAttrIsPermanent as String: false
//            ]
//
//            var error:Unmanaged<CFError>? = nil
//            guard let secKey = SecKeyCreateWithData(key as CFData, attributesRSAPriv as CFDictionary, &error) else {
//            //guard let secKey = SecKeyCreateFromData(keyType.params! as CFDictionary, key as CFData, &error) else {
//                throw NSError(domain: "Error constructing SecKey from raw key data: \(error.debugDescription)", code: 0, userInfo: nil)
//            }
//
//            return secKey
//        }
        
        
         /// This method strips the x509 header from a provided ASN.1 DER key.
         /// If the key doesn't contain a header, the DER data is returned as is.
         ///
         /// Supported formats are:
         ///
         /// Headerless:
         /// SEQUENCE
         ///    INTEGER (1024 or 2048 bit) -- modulo
         ///    INTEGER -- public exponent
         ///
         /// With x509 header:
         /// SEQUENCE
         ///    SEQUENCE
         ///    OBJECT IDENTIFIER 1.2.840.113549.1.1.1
         ///    NULL
         ///    BIT STRING
         ///    SEQUENCE
         ///    INTEGER (1024 or 2048 bit) -- modulo
         ///    INTEGER -- public exponent
         ///
         /// Example of headerless key:
         ///https://lapo.it/asn1js/#3082010A0282010100C1A0DFA367FBC2A5FD6ED5A071E02A4B0617E19C6B5AD11BB61192E78D212F10A7620084A3CED660894134D4E475BAD7786FA1D40878683FD1B7A1AD9C0542B7A666457A270159DAC40CE25B2EAE7CCD807D31AE725CA394F90FBB5C5BA500545B99C545A9FE08EFF00A5F23457633E1DB84ED5E908EF748A90F8DFCCAFF319CB0334705EA012AF15AA090D17A9330159C9AFC9275C610BB9B7C61317876DC7386C723885C100F774C19830F475AD1E9A9925F9CA9A69CE0181A214DF2EB75FD13E6A546B8C8ED699E33A8521242B7E42711066AEC22D25DD45D56F94D3170D6F2C25164D2DACED31C73963BA885ADCB706F40866B8266433ED5161DC50E4B3B0203010001
         ///
         /// Example of key with X509 header (notice the additional ASN.1 sequence):
         ///https://lapo.it/asn1js/#30819F300D06092A864886F70D010101050003818D0030818902818100D0674615A252ED3D75D2A3073A0A8A445F3188FD3BEB8BA8584F7299E391BDEC3427F287327414174997D147DD8CA62647427D73C9DA5504E0A3EED5274A1D50A1237D688486FADB8B82061675ABFA5E55B624095DB8790C6DBCAE83D6A8588C9A6635D7CF257ED1EDE18F04217D37908FD0CBB86B2C58D5F762E6207FF7B92D0203010001
        public static func stripKeyHeader(keyData: Data) throws -> Data {
            
            let node: Asn1Parser.Node
            do {
                node = try Asn1Parser.parse(data: keyData)
            } catch {
                throw NSError(domain: "asn1ParsingFailed", code: 0, userInfo: nil)
            }
            
            // Ensure the raw data is an ASN1 sequence
            guard case .sequence(let nodes) = node else {
                throw NSError(domain: "invalidAsn1RootNode", code: 0, userInfo: nil)
            }
            
            // Detect whether the sequence only has integers, in which case it's a headerless key
            let onlyHasIntegers = nodes.filter { node -> Bool in
                if case .integer = node {
                    return false
                }
                return true
            }.isEmpty
            
            // Headerless key
            if onlyHasIntegers {
                return keyData
            }
            
            // If last element of the sequence is a bit string, return its data
            if let last = nodes.last, case .bitString(let data) = last {
                return data
            }
            
            // If last element of the sequence is an octet string, return its data
            if let last = nodes.last, case .octetString(let data) = last {
                return data
            }
            
            // Unable to extract bit/octet string or raw integer sequence
            throw NSError(domain: "invalidAsn1Structure", code: 0, userInfo: nil)
        }
    }
}

public extension SecKey {
    func asString(base:BaseEncoding) throws -> String {
        try self.rawRepresentation().asString(base: base)
    }
    
    func extractPubKey() throws -> LibP2PCrypto.Keys.PubKey {
        guard let pubKey = SecKeyCopyPublicKey(self) else {
            throw NSError(domain: "Public Key Extraction Error", code: 0, userInfo: nil)
        }
        return pubKey
    }
    
    /// Returns the DER Encoded representation of the SecKey ( this does not include ANS.1 Headers for SubjectKeyInfo format)
    /// - Note: The method returns data in the PKCS #1 format for an RSA key. For an elliptic curve public key, the format follows the ANSI X9.63 standard using a byte string of 04 || X || Y. For an elliptic curve private key, the output is formatted as the public key concatenated with the big endian encoding of the secret scalar, or 04 || X || Y || K. All of these representations use constant size integers, including leading zeros as needed.
    func rawRepresentation() throws -> Data {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
            return cfdata as Data
        } else { throw NSError(domain: "RawKeyError: \(error.debugDescription)", code: 0, userInfo: nil) }
    }
}

public extension String {
    func split(intoChunksOfLength length: Int) -> [String] {
        return stride(from: 0, to: self.count, by: length).map { index -> String in
            let startIndex = self.index(self.startIndex, offsetBy: index)
            let endIndex = self.index(startIndex, offsetBy: length, limitedBy: self.endIndex) ?? self.endIndex
            return String(self[startIndex..<endIndex])
        }
    }
}


//public extension Crypto.Keys.PubKey {
//
//    /// Gets the ID of the key.
//    ///
//    /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
//    /// The public key is a protobuf encoding containing a type and the DER encoding
//    /// of the PKCS SubjectPublicKeyInfo.
//    func id(keyType: LibP2PCrypto.Keys.KeyPairType, withMultibasePrefix:Bool = true) throws -> String {
//        /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
//        /// The public key is a protobuf encoding containing a type and the DER encoding
//        /// of the PKCS SubjectPublicKeyInfo.
//        let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(self, keyType: keyType)
//        let mh = try Multihash(raw: marshaledPubKey, hashedWith: .sha2_256)
//        return withMultibasePrefix ? mh.asMultibase(.base58btc) : mh.asString(base: .base58btc)
//    }
//}

//public extension LibP2PCrypto.Keys.RawKeyPair {
//    /// Gets the ID of the key.
//    ///
//    /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
//    /// The public key is a protobuf encoding containing a type and the DER encoding
//    /// of the PKCS SubjectPublicKeyInfo.
//    func id(keyType: LibP2PCrypto.Keys.KeyPairType, withMultibasePrefix:Bool = true) throws -> String {
//
//        guard self.publicKey.isEmpty == false else {
//            throw NSError(domain: "Public Key Extraction Error", code: 0, userInfo: nil)
//        }
//
//        /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
//        /// The public key is a protobuf encoding containing a type and the DER encoding
//        /// of the PKCS SubjectPublicKeyInfo.
//        let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(raw: self.publicKey, keyType: keyType)
//        let mh = try Multihash(raw: marshaledPubKey, hashedWith: .sha2_256)
//        return withMultibasePrefix ? mh.asMultibase(.base58btc) : mh.asString(base: .base58btc)
//    }
//}

public extension SecKey {
    
    /// Gets the ID of the key.
    ///
    /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
    /// The public key is a protobuf encoding containing a type and the DER encoding
    /// of the PKCS SubjectPublicKeyInfo.
    func id(keyType: LibP2PCrypto.Keys.KeyPairType, withMultibasePrefix:Bool = true) throws -> String {

        guard let pubKey = SecKeyCopyPublicKey(self) else {
            throw NSError(domain: "Public Key Extraction Error", code: 0, userInfo: nil)
        }

        /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
        /// The public key is a protobuf encoding containing a type and the DER encoding
        /// of the PKCS SubjectPublicKeyInfo.
        let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(pubKey, keyType: keyType)
        let mh = try Multihash(raw: marshaledPubKey, hashedWith: .sha2_256)
        return withMultibasePrefix ? mh.asMultibase(.base58btc) : mh.asString(base: .base58btc)
    }
    
    var attributes:CFDictionary? {
        return SecKeyCopyAttributes(self)
    }
    
    /// Doesn't work
    var isRSAKey:Bool {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any],
            let keyType = attributes[kSecAttrKeyType] as? String else {
                return false
        }

        let isRSA = keyType == (kSecAttrKeyTypeRSA as String)
        return isRSA
    }
    
    /// Doesn't work
    var isPublicKey:Bool {
        guard let attributes = SecKeyCopyAttributes(self) as? [CFString: Any],
            let keyClass = attributes[kSecAttrKeyClass] as? String else {
                return false
        }

        let isPublic = keyClass == (kSecAttrKeyClassPublic as String)
        return isPublic
    }
    
    func subjectKeyInfo() throws -> Data {
        return try RSAPublicKeyExporter().toSubjectPublicKeyInfo(self.rawRepresentation())
    }
}

//extension P256.Signing.PublicKey: CommonPublicKey {
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
//        let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
//
//        guard ans1.isPrivateKey == false else {
//            throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
//        }
//
//        if ans1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
//            print("Trying to Init EC Key")
//            //self = try LibP2PCrypto.Keys.secKeyFrom(data: ans1.keyBits, isPrivateKey: ans1.isPrivateKey, keyType: .EC(curve: .P256))
//            self = try P256.Signing.PublicKey(rawRepresentation: ans1.keyBits)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(ans1)", code: 0, userInfo: nil)
//    }
//
//}

//extension P256.Signing.PrivateKey:CommonPrivateKey {
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
//        var octet = try LibP2PCrypto.Keys.parseANS1ECPrivate(pemData: raw.data)
//
//        let bytes = octet.bytes.count
//
//        // TODO Create a PublicKey and PrivateKey Protocol that SecKey and these keys can conform to so we can return a common type...
//        if bytes <= 32 { //P256 Pivate Key
//            while octet.bytes.count < 32 { octet.insert(0, at: 0) }
//            self = try P256.Signing.PrivateKey(rawRepresentation: octet)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(octet)", code: 0, userInfo: nil)
//    }
//
//    public func derivePublicKey() throws -> CommonPublicKey {
//        self.publicKey
//    }
//
//}


//extension Curve25519.Signing.PublicKey:CommonPublicKey {
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
//        let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
//
//        guard ans1.isPrivateKey == false else {
//            throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
//        }
//
//        if ans1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
//            print("Trying to Init EC Key")
//            self = try Curve25519.Signing.PublicKey(rawRepresentation: ans1.keyBits)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(ans1)", code: 0, userInfo: nil)
//    }
//}

//extension Curve25519.Signing.PrivateKey: CommonPrivateKey {
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
//        var octet = try LibP2PCrypto.Keys.parseANS1ECPrivate(pemData: raw.data)
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
//}

//extension Secp256k1PublicKey:CommonPublicKey {
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
//        let ans1 = try LibP2PCrypto.Keys.parseANS1(pemData: raw.data)
//
//        guard ans1.isPrivateKey == false else {
//            throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
//        }
//
//        if ans1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
//            print("Trying to Init EC Key")
//            self = try Secp256k1PublicKey(publicKey: ans1.keyBits.bytes)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(ans1)", code: 0, userInfo: nil)
//    }
//}
