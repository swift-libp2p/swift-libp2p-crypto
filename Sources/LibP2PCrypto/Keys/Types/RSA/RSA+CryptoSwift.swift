//
//  RSA+CryptoSwift.swift
//  
//
//  Created by Brandon Toms on 5/22/22.
//

#if !canImport(Security)
import Foundation
import CryptoSwift

struct RSAPublicKey:CommonPublicKey {
    static var keyType: LibP2PCrypto.Keys.GenericKeyType { .rsa }
    
    /// RSA Object Identifier Bytes
    private static var RSA_OBJECT_IDENTIFIER = Array<UInt8>(arrayLiteral: 42, 134, 72, 134, 247, 13, 1, 1, 1)
    
    /// The underlying SecKey that backs this struct
    private let key:RSA
    
    fileprivate init(_ rsa:RSA) {
        self.key = rsa
    }
    
    init(rawRepresentation raw: Data) throws {
        let asn1 = try ASN1.Decoder.decode(data: raw)
        
        guard case .sequence(let params) = asn1 else { throw NSError(domain: "Invalid ASN1 Encoding -> \(asn1)", code: 0) }
        
        /// We have an objectID header....
        if case .sequence(let objectID) = params.first {
            guard case .objectIdentifier(let oid) = objectID.first else { throw NSError(domain: "Invalid ASN1 Encoding -> No ObjectID", code: 0) }
            guard oid.bytes == RSAPublicKey.RSA_OBJECT_IDENTIFIER else { throw NSError(domain: "Invalid ASN1 Encoding -> ObjectID != Public RSA Key ID", code: 0) }
            guard case .bitString(let bits) = params.last else { throw NSError(domain: "Invalid ASN1 Encoding -> No BitString", code: 0) }
            
            guard case .sequence(let params2) = try ASN1.Decoder.decode(data: bits) else { throw NSError(domain: "Invalid ASN1 Encoding -> No PubKey Sequence", code: 0) }
            guard case .integer(let n) = params2.first else { throw NSError(domain: "Invalid ASN1 Encoding -> No Modulus", code: 0) }
            guard case .integer(let e) = params2.last else { throw NSError(domain: "Invalid ASN1 Encoding -> No Public Exponent", code: 0) }
            
            self.key = CryptoSwift.RSA(n: n.bytes, e: e.bytes)
        } else if params.count == 2, case .integer = params.first {
            /// We have a direct sequence of integers
            guard case .integer(let n) = params.first else { throw NSError(domain: "Invalid ASN1 Encoding -> No Modulus", code: 0) }
            guard case .integer(let e) = params.last else { throw NSError(domain: "Invalid ASN1 Encoding -> No Public Exponent", code: 0) }
            
            self.key = CryptoSwift.RSA(n: n.bytes, e: e.bytes)
        } else {
            throw NSError(domain: "Invalid RSA rawRepresentation", code: 0)
        }
    }
    
    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }
    
    /// We return the ASN1 Encoded DER Representation of the public key because that's what the rewRepresentation of RSA SecKey return
    var rawRepresentation: Data {
        let mod = key.n.serialize()
        let pubkeyAsnNode:ASN1.Node =
            .sequence(nodes: [
                .integer(data: Data(CryptoSwift.RSA.zeroPad(n: mod.bytes, to: mod.count + 1))),
                .integer(data: key.e.serialize())
            ])
        
        let asnNodes:ASN1.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(RSAPublicKey.RSA_OBJECT_IDENTIFIER)),
                .null
            ]),
            .bitString(data: Data(ASN1.Encoder.encode(pubkeyAsnNode)))
        ])
        
        return Data(ASN1.Encoder.encode(asnNodes))
    }
    
    func encrypt(data: Data) throws -> Data {
        try Data(key.encrypt(data.bytes))
    }
    
    /// Verifies an RSA Signature for an expected block of data
    ///
    /// - Note: We throw on false to match the SecKey implementation
    func verify(signature: Data, for expectedData: Data) throws -> Bool {
        guard try RSA.verify(signature: signature, fromMessage: expectedData, usingKey: self.key) else {
            throw NSError(domain: "Invalid signature for expected data", code: 0)
        }
        return true
    }
    
    public func marshal() throws -> Data {
        var publicKey = PublicKey()
        publicKey.type = .rsa
        publicKey.data = self.rawRepresentation
        return try publicKey.serializedData()
    }
    
}

struct RSAPrivateKey:CommonPrivateKey {
    static var keyType: LibP2PCrypto.Keys.GenericKeyType { .rsa }
    
    /// The underlying CryptoSwift RSA key that backs this struct
    private let key:RSA
    
    fileprivate init(_ rsa:RSA) {
        self.key = rsa
    }
    
    /// Initializes a new RSA key (backed by CryptoSwift) of the specified bit size
    internal init(keySize: Int) throws {
        switch keySize {
        case 1024:
            self.key = CryptoSwift.RSA(keySize: keySize)
        case 2048:
            self.key = CryptoSwift.RSA(keySize: keySize)
        case 3072:
            self.key = CryptoSwift.RSA(keySize: keySize)
        case 4096:
            self.key = CryptoSwift.RSA(keySize: keySize)
        default:
            throw NSError(domain: "Invalid RSA Key Bit Length. (Use one of 2048, 3072 or 4096)", code: 0)
        }
    }
    
    init(keySize: LibP2PCrypto.Keys.RSABitLength) throws {
        try self.init(keySize: keySize.bits)
    }
    
    /// Expects the ASN1 Encoding of the DER formatted RSA Private Key
    init(rawRepresentation raw: Data) throws {
        guard case .sequence(let params) = try ASN1.Decoder.decode(data: raw) else { throw NSError(domain: "Invalid ASN1 Encoding -> No PrivKey Sequence", code: 0) }
        // We check for 4 here because internally we can only marshal the first 4 integers at the moment...
        guard params.count == 4 || params.count == 9 else { throw NSError(domain: "Invalid ASN1 Encoding -> Invalid Private RSA param count. Expected 9 got \(params.count)", code: 0) }
        guard case .integer(let n) = params[1] else { throw NSError(domain: "Invalid ASN1 Encoding -> PrivKey No Modulus", code: 0) }
        guard case .integer(let e) = params[2] else { throw NSError(domain: "Invalid ASN1 Encoding -> PrivKey No Public Exponent", code: 0) }
        guard case .integer(let d) = params[3] else { throw NSError(domain: "Invalid ASN1 Encoding -> PrivKey No Private Exponent", code: 0) }

        self.key = RSA(n: n.bytes, e: e.bytes, d: d.bytes)
    }
    
    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }
    
    var rawRepresentation: Data {
        guard let d = key.d else { /*throw NSError(domain: "Not a valid private RSA Key", code: 0)*/ return Data() }
        let mod = key.n.serialize()
        let privkeyAsnNode:ASN1.Node =
            .sequence(nodes: [
                .integer(data: Data( Array<UInt8>(arrayLiteral: 0x00) )),
                .integer(data: Data(CryptoSwift.RSA.zeroPad(n: mod.bytes, to: mod.count + 1))),
                .integer(data: key.e.serialize()),
                .integer(data: d.serialize())
            ])
        return Data(ASN1.Encoder.encode(privkeyAsnNode))
    }
    
    func derivePublicKey() throws -> CommonPublicKey {
        guard key.d != nil else { throw NSError(domain: "Unable to extract public key", code: 0) }
        return RSAPublicKey(CryptoSwift.RSA(n: key.n, e: key.e))
    }
    
    func decrypt(data: Data) throws -> Data {
        try Data(key.decrypt(data.bytes))
    }
    
    func sign(message: Data) throws -> Data {
        try RSA.sign(message: message, withKey: key)
    }
    
    public func marshal() throws -> Data {
        throw NSError(domain: "CryptoSwift based RSA private keys don't support marshaling", code: 0)
        //var privateKey = PrivateKey()
        //privateKey.type = .rsa
        //privateKey.data = self.rawRepresentation
        //return try privateKey.serializedData()
    }
    
}

extension RSAPublicKey:Equatable {
    static func == (lhs: RSAPublicKey, rhs: RSAPublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension RSAPrivateKey:Equatable {
    static func == (lhs: RSAPrivateKey, rhs: RSAPrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension CryptoSwift.RSA {
    /// Signs a message
    ///
    /// - Note: The signature uses the SHA256 PKCS#1v15 Padding Scheme
    /// - Note: [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2)
    fileprivate static func sign(message:Data, withKey key:RSA) throws -> Data {
        guard let d = key.d else { throw NSError(domain: "Signing data requires a Private RSA key", code: 0) }
        let encodedMessage = try CryptoSwift.RSA.hashedAndPKCSEncoded(message.bytes, modLength: key.n.serialize().count)
        
        let n = BigUInteger(Data(encodedMessage))
        let e = d
        let m = key.n
        let signedData_RsaKey = CryptoSwift.RSA.modPow(n: n, e: e, m: m).serialize()
        return signedData_RsaKey
    }
    
    /// Verifies a signature for the expected data
    ///
    /// - Note: This method assumes the signature was generated using the SHA256 PKCS#1v15 Padding Scheme
    /// - Note: [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2)
    fileprivate static func verify(signature:Data, fromMessage message:Data, usingKey key:RSA) throws -> Bool {
        let modLength = key.n.serialize().count
        /// Step 1: Ensure the signature is the same length as the key's modulus
        guard signature.count == modLength else { throw NSError(domain: "Invalid Signature Length", code: 0) }
        
        /// Step 2: 'Decrypt' the signature
        let n = BigUInteger(signature)
        let e = key.e
        let m = key.n
        let pkcsEncodedSHA256HashedMessage = CryptoSwift.RSA.modPow(n: n, e: e, m: m).serialize()
        
        /// Step 3: Compare the 'decrypted' signature with the prepared / encoded expected message....
        let preparedExpectedMessage = try CryptoSwift.RSA.hashedAndPKCSEncoded(message.bytes, modLength: modLength).dropFirst()

        guard pkcsEncodedSHA256HashedMessage == preparedExpectedMessage else { return false }
        
        return true
    }
    
    /// prepends the data with zero's until it reaches the specified length
    fileprivate static func zeroPad(n:[UInt8], to:Int) -> [UInt8] {
        var modulus = n
        while modulus.count < to {
            modulus.insert(0x00, at: 0)
        }
        return modulus
    }
    
    /// Modular exponentiation
    ///
    /// - Credit: AttaSwift BigInt
    /// - Source: https://rosettacode.org/wiki/Modular_exponentiation#Swift
    fileprivate static func modPow<T: BinaryInteger>(n: T, e: T, m: T) -> T {
        guard e != 0 else {
            return 1
        }
     
        var res = T(1)
        var base = n % m
        var exp = e
     
        while true {
            if exp & 1 == 1 {
                res *= base
                res %= m
            }
     
            if exp == 1 {
                return res
            }
     
            exp /= 2
            base *= base
            base %= m
        }
    }
    
    /// Hashes and Encodes a message for signing and verifying
    ///
    /// - Note: [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2)
    fileprivate static func hashedAndPKCSEncoded(_ message:[UInt8], modLength:Int) throws -> Data {
        /// 1.  Apply the hash function to the message M to produce a hash
        let hashedMessage = SHA2(variant: .sha256).calculate(for: message)
        
        /// 2. Encode the algorithm ID for the hash function and the hash value into an ASN.1 value of type DigestInfo
        /// PKCS#1_15 DER Structure (OID == sha256WithRSAEncryption)
        let asn:ASN1.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01))),
                .null
            ]),
            .octetString(data: Data(hashedMessage))
        ])
        
        let t = ASN1.Encoder.encode(asn)
                
        /// 3.  If emLen < tLen + 11, output "intended encoded message lengthtoo short" and stop
        if modLength < t.count + 11 { throw NSError(domain: "intended encoded message length too short", code: 0) }
        
        /// 4.  Generate an octet string PS consisting of emLen - tLen - 3
        /// octets with hexadecimal value 0xff. The length of PS will be
        /// at least 8 octets.
        let r = modLength - t.count - 3
        let padding = [0x00, 0x01] + Array<UInt8>(repeating: 0xFF, count: r) + [0x00]
        
        /// 5.  Concatenate PS, the DER encoding T, and other padding to form
        /// the encoded message EM as EM = 0x00 || 0x01 || PS || 0x00 || T.
        return Data(padding + t)
    }
}

#endif
