////
////  PEM.swift
////  
////
////  Created by Brandon Toms on 5/22/22.
////

//import Foundation
//import Multibase
//import Crypto

//extension LibP2PCrypto.Keys {
//    public struct ParsedPem {
//        let isPrivate:Bool
//        let type:KeyPairType
//        let rawKey:Data
//    }
//
//    /// Parse the pem file into ASN1 bits...
//    /// Scan the bits for Object Identifiers and classify the key type
//    /// Based on the key type... scan the bits for the key data
//    /// Return a ParsedPem struct that we can use to instantiate any of our supported KeyPairTypes...
//    public static func parsePem(_ pem:String) throws -> KeyPair {
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count >= 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        /// If its a DER re route it...
//        if f.contains("-----BEGIN RSA PUBLIC") { return try LibP2PCrypto.Keys.importPublicDER(pem) }
//        else if f.contains("-----BEGIN RSA PRIVATE") { return try LibP2PCrypto.Keys.importPrivateDER(pem) }
//
//        let isPrivate:Bool = f.contains("PRIVATE")
//
//        let rawPem = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        return try self.parsePem(rawPem.data, isPrivate: isPrivate)
//    }
//
//    private static func parsePem(_ rawPem:Data, isPrivate:Bool) throws -> KeyPair {
//        var type:KeyPairType? = nil
//        let asn = try Asn1ParserECPrivate.parse(data: rawPem)
//
//        print("ASN1 Nodes")
//        print(asn)
//        print("----------")
//
//        guard case .sequence(let nodes) = asn else { throw NSError(domain: "Failed to parse PEM", code: 0, userInfo: nil) }
//        let ids = objIdsInSequence(nodes)
//
//        if ids.contains(where: { (id) -> Bool in
//            if case .rsaEncryption = id { return true } else { return false }
//        }) {
//            type = .RSA(bits: .B1024) //Bit length doesn't matter here, we're just broadly classifying it...
//        } else if ids.contains(where: { (id) -> Bool in
//            if case .secp256k1 = id { return true } else { return false }
//        }) {
//            type = .Secp256k1
//        } else if ids.contains(where: { (id) -> Bool in
//            if case .Ed25519 = id { return true } else { return false }
//        }) {
//            type = .Ed25519
//        } else if ids.contains(where: { (id) -> Bool in
//            switch id {
//            case .prime256v1, .secp384r1, .secp521r1: return true
//            default: return false
//            }
//        }) {
//            throw NSError(domain: "No EC Key Support Yet", code: 0, userInfo: nil)
//            //type = .EC(curve: .P256) //Curve bits dont matter here, we're just broadly classifying it...
//        }
//
//        guard let keyType = type else { throw NSError(domain: "Failed to classify key", code: 0, userInfo: nil) }
//
//        guard case .sequence(let top) = asn else {
//            throw NSError(domain: "Failed to parse Asn1", code: 0, userInfo: nil)
//        }
//
//        var rawKeyData:Data? = nil
//
//        if isPrivate {
//            // First Octet
//            guard let octet = octetsInSequence(top).first else {
//                throw NSError(domain: "Failed to extract \(keyType.name) \(isPrivate ? "Private" : "Public") key", code: 0, userInfo: nil)
//            }
//            rawKeyData = octet
//        } else {
//            // First Bit String...
//            guard let bitString = bitStringsInSequence(top).first else {
//                throw NSError(domain: "Failed to extract \(keyType.name) \(isPrivate ? "Private" : "Public") key", code: 0, userInfo: nil)
//            }
//            rawKeyData = bitString
//        }
//
//        // ED25519 Private Keys are wrapped in an additional octetString node, lets remove it...
//        if isPrivate, case .Ed25519 = keyType, rawKeyData?.count == 34 {
//            rawKeyData?.removeFirst(2)
//        }
//
//        guard let keyData = rawKeyData else {
//            throw NSError(domain: "Failed to extract key data from asn1 nodes", code: 0, userInfo: nil)
//        }
//
//        //return ParsedPem(isPrivate: isPrivate, type: keyType, rawKey: keyData)
//
//        // At this point we know if its a public or private key, the type of key, and the raw bits of the key.
//        // We can instantiate the key, ensure it's valid, then create a return a PublicKey or PrivateKey
//        switch keyType {
//        case .RSA:
//            if isPrivate {
//                return try KeyPair(privateKey: RSAPrivateKey(rawRepresentation: keyData))
//            } else {
//                return try KeyPair(publicKey: RSAPublicKey(rawRepresentation: keyData))
//            }
//        case .Ed25519:
//            if isPrivate {
//                return try KeyPair(privateKey: Curve25519.Signing.PrivateKey(rawRepresentation: keyData))
//            } else {
//                return try KeyPair(publicKey: Curve25519.Signing.PublicKey(rawRepresentation: keyData))
//            }
//        case .Secp256k1:
//            if isPrivate {
//                return try KeyPair(privateKey: Secp256k1PrivateKey(keyData.bytes))
//            } else {
//                return try KeyPair(publicKey: Secp256k1PublicKey(keyData.bytes))
//            }
//        //default:
//            /// - TODO: Internal Support For EC Keys (without support for marshaling)
//        //    throw NSError(domain: "Unsupported Key Type \(keyType.description)", code: 0, userInfo: nil)
//        }
//    }
//}
//    
//    /// Importes an Encrypted PEM Key File
//    ///
//    /// An ASN1 Node Tree of an Encrypted RSA PEM Key (PBKDF2 and AES_CBC_128)
//    /// ```
//    /// sequence(nodes: [
//    ///     libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//    ///         libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes), //[42,134,72,134,247,13,1,5,13]
//    ///         libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//    ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//    ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
//    ///                 libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//    ///                     libp2p_crypto.Asn1Parser.Node.octetString(data: 8 bytes),       //SALT
//    ///                     libp2p_crypto.Asn1Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
//    ///                 ])
//    ///             ]),
//    ///             libp2p_crypto.Asn1Parser.Node.sequence(nodes: [
//    ///                 libp2p_crypto.Asn1Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc [96,134,72,1,101,3,4,1,2]
//    ///                 libp2p_crypto.Asn1Parser.Node.octetString(data: 16 bytes)           //IV
//    ///             ])
//    ///         ])
//    ///     ]),
//    ///     libp2p_crypto.Asn1Parser.Node.octetString(data: 640 bytes)
//    /// ])
//    /// ```
//    static func parseEncryptedPem(_ pem:String, password:String) throws -> KeyPair {
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count >= 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN ENCRYPTED"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid Encrypted PEM Format", code: 0, userInfo: nil)
//        }
//        
//        let isPrivate:Bool = f.contains("PRIVATE")
//        
//        let rawPem = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//        
//        let asn = try Asn1ParserECPrivate.parse(data: rawPem.data)
//        
//        print("ASN1 Nodes")
//        print(asn)
//        print("----------")
//        
//        var saltData:Data? = nil
//        var ivData:Data? = nil
//        var itterationsData:Int? = nil
//        var ciphertextData:Data? = nil
//        
//        guard case .sequence(let nodes) = asn else {
//            throw NSError(domain: "Failed to parse ASN from PEM", code: 0, userInfo: nil)
//        }
//        
//        /// Octets Should Include our Salt, IV and cipherText...
//        /// TODO make this better by actually checking objectIDs to make sure we have the correct data (instead of guessing based on length)
//        octetsInSequence(nodes).forEach {
//            let count = $0.count
//            if count == 16 || count == 32 {
//                ivData = $0
//            } else if count > 100 {
//                ciphertextData = $0
//            } else {
//                 saltData = $0
//            }
//        }
//        
//        /// There should be only one integer, the itteration count...
//        itterationsData = integersInSequence(nodes).first
//        
//        guard let salt = saltData, let iv = ivData, let itterations = itterationsData, let ciphertext = ciphertextData else {
//            throw NSError(domain: "Failed to parse our pcks#8 key", code: 0, userInfo: nil)
//        }
//
//        // Attempt to derive the aes encryption key from the password and salt
//        // PBKDF2-SHA1
//        guard let key = PBKDF2.SHA1(password: password, salt: salt, keyByteCount: iv.count, rounds: itterations) else {
//            throw NSError(domain: "Failed to derive key from password and salt", code: 0, userInfo: nil)
//        }
//
//        //print("Key 1 -> \(key.asString(base: .base16))")
//
//        //Create our CBC AES Cipher
//        let aes = try LibP2PCrypto.AES.createKey(key: key, iv: iv)
//        //let aes = try AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .noPadding)
//
//        // GCM Doesn't work on OPENSSL Encrypted PEM Files but I saw mention of it in libp2p-crypto-js so perhaps we'll need it later...
//        //let aes = try AES(key: key.bytes, blockMode: GCM(iv: iv.bytes, mode: .detached), padding: .noPadding)
//
//        let decryptedKey = try aes.decrypt(ciphertext.bytes)
//        
//        // At this point we have regular unencrypted PEM data rep of a key, lets parse it...
//        return try self.parsePem(decryptedKey, isPrivate: isPrivate)
//    }
//    
//    /// Traverses a Node tree and returns all instances of integers
//    private static func integersInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Int] {
//        var integers:[Int?] = []
//        
//        nodes.forEach {
//            if case .integer(let data) = $0 { integers.append(Int(data.asString(base: .base16), radix: 16)) }
//            else if case .sequence(let nodes) = $0 {
//                return integers.append(contentsOf: integersInSequence(nodes) )
//            }
//        }
//        
//        return integers.compactMap { $0 }
//    }
//    
//    /// Traverses a Node tree and returns all instances of bitStrings
//    private static func bitStringsInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Data] {
//        var bitString:[Data] = []
//        
//        nodes.forEach {
//            if case .bitString(let data) = $0 { bitString.append(data) }
//            else if case .sequence(let nodes) = $0 {
//                return bitString.append(contentsOf: bitStringsInSequence(nodes) )
//            }
//        }
//        
//        return bitString
//    }
//    
//    /// Traverses a Node tree and returns all instances of bitStrings
//    private static func octetsInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Data] {
//        var octets:[Data] = []
//        
//        nodes.forEach {
//            if case .octetString(let data) = $0 { octets.append(data) }
//            else if case .sequence(let nodes) = $0 {
//                return octets.append(contentsOf: octetsInSequence(nodes) )
//            }
//        }
//        
//        return octets
//    }
//    
//    /// Traverses a Node tree and returns all instances of objectIds
//    private static func objIdsInSequence(_ nodes:[Asn1ParserECPrivate.Node]) -> [Asn1ParserECPrivate.ObjectIdentifier] {
//        var objs:[Asn1ParserECPrivate.ObjectIdentifier] = []
//        
//        nodes.forEach {
//            if case .objectIdentifier(let id) = $0 { objs.append(id) }
//            else if case .sequence(let nodes) = $0 {
//                return objs.append(contentsOf: objIdsInSequence(nodes) )
//            }
//        }
//        
//        return objs
//    }
//    
//    /// Expects a PEM Public Key with the x509 header information included (object identifier)
//    ///
//    /// - Note: Handles RSA Public Keys
//    public static func importPublicPem(_ pem:String) throws -> CommonPublicKey {
//        let chunks = pem.split(separator: "\n")
//        guard chunks.count > 3,
//              let f = chunks.first, f.hasPrefix("-----BEGIN"),
//              let l = chunks.last, l.hasSuffix("-----") else {
//            throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//        }
//
//        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//        //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
//
//        let asn1 = try LibP2PCrypto.Keys.parseASN1(pemData: raw.data)
//
//        guard asn1.isPrivateKey == false else {
//            throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
//        }
//
//        if asn1.objectIdentifier == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
//            print("Trying to Init RSA Key")
//            return try RSAPublicKey(rawRepresentation: asn1.keyBits)
//        } else if asn1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
//            //print("Trying to Init EC Key")
//            //return try LibP2PCrypto.Keys.secKeyFrom(data: asn1.keyBits, isPrivateKey: asn1.isPrivateKey, keyType: .EC(curve: .P256))
//            throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
//        }
//
//        throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
//    }
//    
//    /// - TODO: Make this better...
////        public static func importRawPublicPem(_ pem:String) throws -> Data {
////            let chunks = pem.split(separator: "\n")
////            guard chunks.count > 3,
////                  let f = chunks.first, f.hasPrefix("-----BEGIN"),
////                  let l = chunks.last, l.hasSuffix("-----") else {
////                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
////            }
////
////            //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
////            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
////            //print(raw.data)
////
////            //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
////
////            let asn1 = try LibP2PCrypto.Keys.parseASN1(pemData: raw.data)
////
////            guard asn1.isPrivateKey == false else {
////                throw NSError(domain: "The provided PEM isn't a Public Key. Try importPrivatePem() instead...", code: 0, userInfo: nil)
////            }
////
////            if asn1.objectIdentifier == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
////                print("Trying to Init RSA Key")
////                return try LibP2PCrypto.Keys.secKeyFrom(data: asn1.keyBits, isPrivateKey: asn1.isPrivateKey, keyType: .RSA(bits: .B1024)).rawRepresentation()
////            } else if asn1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
////                print("Trying to Init EC Key")
////                return try LibP2PCrypto.Keys.secKeyFrom(data: asn1.keyBits, isPrivateKey: asn1.isPrivateKey, keyType: .EC(curve: .P256)).rawRepresentation()
////            } else {
////                do {
////                    let key = try Curve25519.Signing.PublicKey(pem: pem).rawRepresentation
////                    return key
////                } catch {
////                    return try Data(Secp256k1PublicKey(asn1.keyBits.bytes).rawPublicKey)
////                }
////            }
////
////            //throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
////        }
//    
//    /// Expects a PEM Private Key with the x509 header information included (object identifier)
//    ///
//    /// - Note: Only handles RSA Pirvate Keys at the moment
//    public static func importPrivatePem(_ pem:String) throws -> CommonPrivateKey {
//        let chunks = pem.split(separator: "\n")
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
//        //let key = try LibP2PCrypto.Keys.stripKeyHeader(keyData: raw.data)
//        
//        let asn1 = try LibP2PCrypto.Keys.parseASN1(pemData: raw.data)
//        
//        guard asn1.isPrivateKey == true else {
//            throw NSError(domain: "The provided PEM isn't a Private Key. Try importPublicPem() instead...", code: 0, userInfo: nil)
//        }
//        
//        if asn1.objectIdentifier == Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) {
//            print("Trying to Init RSA Key")
//            return try RSAPrivateKey(rawRepresentation: asn1.keyBits)
//        } else if asn1.objectIdentifier.prefix(5) == Data([0x2a, 0x86, 0x48, 0xce, 0x3d]) {
//            //print("Trying to Init EC Key")
//            //return try LibP2PCrypto.Keys.secKeyFrom(data: asn1.keyBits, isPrivateKey: asn1.isPrivateKey, keyType: .EC(curve: .P256))
//            throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
//        }
//        
//        throw NSError(domain: "Failed to parse PEM into known key type \(asn1)", code: 0, userInfo: nil)
//    }
//    
//    /// Expects a PEM Private Key with the x509 header information included (object identifier)
//    ///
//    /// - Note: Only handles RSA Pirvate Keys at the moment
////        public static func importPrivatePemEC(_ pem:String) throws -> PrivKey {
////            let chunks = pem.split(separator: "\n")
////            guard chunks.count > 3,
////                  let f = chunks.first, f.hasPrefix("-----BEGIN PRIVATE"),
////                  let l = chunks.last, l.hasSuffix("-----") else {
////                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
////            }
////
////            //print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
////            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
////            //print(raw.data)
////
////            var octet = try LibP2PCrypto.Keys.parseASN1ECPrivate(pemData: raw.data)
////
////            let bytes = octet.bytes.count
////
////            // TODO Create a PublicKey and PrivateKey Protocol that SecKey and these keys can conform to so we can return a common type...
////            if bytes <= 32 { //P256 Pivate Key
////                while octet.bytes.count < 32 { octet.insert(0, at: 0) }
////                try P256.Signing.PrivateKey(rawRepresentation: octet)
////            } else if bytes <= 48 { //P384 Private Key
////                while octet.bytes.count < 48 { octet.insert(0, at: 0) }
////                try P384.Signing.PrivateKey(rawRepresentation: octet)
////            } else if bytes <= 66 { //P521 Private Key
////                while octet.bytes.count < 66 { octet.insert(0, at: 0) }
////                try P521.Signing.PrivateKey(rawRepresentation: octet)
////            }
////
////            throw NSError(domain: "Failed to parse PEM into known key type \(octet)", code: 0, userInfo: nil)
////        }
//    
////        public static func initPubKeyFromPem(_ pem:String, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> PubKey {
////            var pubKey:Data? = nil
////            switch keyType {
////            case .ECDSA(curve: .P256):
////                pubKey = try P256.Signing.PublicKey(pemRepresentation: pem).rawRepresentation
////            case .ECDSA(curve: .P384):
////                pubKey = try P384.Signing.PublicKey(pemRepresentation: pem).rawRepresentation
////            case .ECDSA(curve: .P521):
////                pubKey = try P521.Signing.PublicKey(pemRepresentation: pem).rawRepresentation
////            default:
////                print("Unsupported KeyType")
////            }
////
////            guard let pubKeyData = pubKey else {
////                throw NSError(domain: "Unable to parse PEM into Public Key", code: 0, userInfo: nil)
////            }
////
////            let attributes: [String:Any] = [
////                kSecAttrKeyType as String: keyType.secKey,
////                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
////                kSecAttrKeySizeInBits as String: keyType.bits,
////                kSecAttrIsPermanent as String: false
////            ]
////
////            return try LibP2PCrypto.Keys.secKeyFrom(data: pubKeyData, attributes: attributes)
////        }
//        
////        public static func initPrivKeyFromPem(_ pem:String, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> PubKey {
////            var pubKey:Data? = nil
////            switch keyType {
////            case .ECDSA(curve: .P256):
////                pubKey = try P256.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation
////            case .ECDSA(curve: .P384):
////                pubKey = try P384.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation
////            case .ECDSA(curve: .P521):
////                pubKey = try P521.Signing.PrivateKey(pemRepresentation: pem).rawRepresentation
////            default:
////                print("Unsupported KeyType")
////            }
////
////            guard let pubKeyData = pubKey else {
////                throw NSError(domain: "Unable to parse PEM into Private Key", code: 0, userInfo: nil)
////            }
////
////            let attributes: [String:Any] = [
////                kSecAttrKeyType as String: keyType.secKey,
////                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
////                kSecAttrKeySizeInBits as String: keyType.bits,
////                kSecAttrIsPermanent as String: false
////            ]
////
////            return try LibP2PCrypto.Keys.secKeyFrom(data: pubKeyData, attributes: attributes)
////        }
//        
//        
////        public static func importPem(_ str:String) throws -> KeyPair {
////
////            let pemData = str.data(using: .utf8)
////
////        }
//        
////        public static func fromPEM(_ str:String, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> SecKey {
////
////            guard str.hasPrefix("-----BEGIN"), str.hasSuffix("-----") else { throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil) }
////            let chunks = str.split(separator: "\n")
////            guard chunks.count > 3 else { throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil) }
////            //print(chunks)
////            print("Attempting to decode: \(chunks[1..<chunks.count-1].joined())")
////            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
////            print(raw.data)
////            print(keyType.params)
////
////            let key = try stripKeyHeader(keyData: raw.data)
////
////            print("Stripped \(raw.data.count - key.count) Bytes of ASN1 Header")
////            //print(key.toHexString())
////
////            //let marshaledPubKey = try LibP2PCrypto.Keys.marshalPublicKey(raw: key, keyType: keyType)
////            //let mh = try Multihash(raw: marshaledPubKey, hashedWith: .sha2_256)
////            //print("ID: \(mh.asString(base: .base58btc))")
////
//////            let out:UnsafeMutablePointer<CFArray>?
//////            let key = SecItemImport(raw.data as CFData, nil, nil, nil, .pemArmour, nil, nil, out)
//////            print(key)
//////            print(out)
////            let attributesRSAPriv: [String:Any] = [
////                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
////                kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
////                kSecAttrKeySizeInBits as String: keyType.bits,
////                kSecAttrIsPermanent as String: false
////            ]
////
////            var error:Unmanaged<CFError>? = nil
////            guard let secKey = SecKeyCreateWithData(key as CFData, attributesRSAPriv as CFDictionary, &error) else {
////            //guard let secKey = SecKeyCreateFromData(keyType.params! as CFDictionary, key as CFData, &error) else {
////                throw NSError(domain: "Error constructing SecKey from raw key data: \(error.debugDescription)", code: 0, userInfo: nil)
////            }
////
////            return secKey
////        }
//}
