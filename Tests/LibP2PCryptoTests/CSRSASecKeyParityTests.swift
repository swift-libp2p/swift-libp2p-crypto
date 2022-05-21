//
//  CSRSASecKeyParityTests.swift
//  
//
//  Created by Brandon Toms on 5/21/22.
//

import XCTest
@testable import LibP2PCrypto
import Multibase
import Crypto
import Multihash
import CryptoSwift

#if canImport(Security)
class CSRSASecKeyParityTests: XCTestCase {
    
    // - MARK: Marshaling
    
    // Manual
    // This the ASN1 encoding of the modulus (n) and public exponent (e) for a public RSA key...
    // Given n: 00b648aa3f1cc1597819a5d401775e28f3af1adf417749ce378f05901b771a8a47531cea3b911d78a3e875d83e3940934d41845d52dcb9782f08b47001e18207f8e7bb0c839e545b278629e52fd2e720bc2a41c25479710d36d22d0c8338cf58e2d6ab5aedbd26cd7008b6644567ebe43611c1e8df052f591b4b78acfe0d94997f0d8f1030be0c63c93e5edff20ef3979e98ca69a6cc7f658992cdaf383faa2768914bf9bb5a5d1ab7292ee3cd79338393472a281f8e51bb8a8fd1928581020848dac9b24397ddbbea86a52fd82106d49e12fdb492e81ab53bd8cb9f74c05949924bf297e9cfc481f410460c28af5745696ef57627a127dba22c1cbfc3374a5b23
    // And e: 010001
    // We need to get this bitString
    // bitString: 3082010a02820101 00b648aa3f1cc1597819a5d401775e28f3af1adf417749ce378f05901b771a8a47531cea3b911d78a3e875d83e3940934d41845d52dcb9782f08b47001e18207f8e7bb0c839e545b278629e52fd2e720bc2a41c25479710d36d22d0c8338cf58e2d6ab5aedbd26cd7008b6644567ebe43611c1e8df052f591b4b78acfe0d94997f0d8f1030be0c63c93e5edff20ef3979e98ca69a6cc7f658992cdaf383faa2768914bf9bb5a5d1ab7292ee3cd79338393472a281f8e51bb8a8fd1928581020848dac9b24397ddbbea86a52fd82106d49e12fdb492e81ab53bd8cb9f74c05949924bf297e9cfc481f410460c28af5745696ef57627a127dba22c1cbfc3374a5b23 0203 010001
    func testImportFromMarshalledPublicKey_Manual_CryptoSwift() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_2048, as: .base64Pad)
//        let pubKey = try LibP2PCrypto.Keys.importMarshaledPublicKey(marshaledData.data.bytes)
        print(marshaledData.data.count)

        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }

        print("We Unmarshaled a PublicKey Proto!")
        print(pubKeyProto.type)
        print(pubKeyProto.data.asString(base: .base64))

        //let data = try RSAPublicKeyImporter().fromSubjectPublicKeyInfo(pubKeyProto.data)
        //print(data.count)
        let data = pubKeyProto.data

        let asn1 = try Asn1Parser.parse(data: data)
        printNode(asn1, level: 0)
        guard case .sequence(let params) = asn1 else { return XCTFail("ASN1 Parse Error") }
        print(params.count)
        guard case .bitString(let bits) = params.last else { return XCTFail("No bits") }
        //guard case .integer(let e) = params.last else { return XCTFail("No Exponent") }

        let asn1_2 = try Asn1Parser.parse(data: bits)
        printNode(asn1_2, level: 0)
        guard case .sequence(let params2) = asn1_2 else { return XCTFail("ASN1 Parse Error") }
        print(params.count)
        guard case .integer(let n) = params2.first else { return XCTFail("No Exponent") }
        guard case .integer(let e) = params2.last else { return XCTFail("No Exponent") }

        print("BitString: \(bits.count) bytes")

        print(n.asString(base: .base16))
        print(e.asString(base: .base16))

        let rsa = RSA(n: n.bytes, e: e.bytes)
        print(rsa)
        print(rsa.n)
        print(rsa.e)
        //print(rsa.d)

        // CryptoSwift.RSA drops the leading 0 byte
        //XCTAssertEqual(rsa.n.serialize(), n)

        //let marshaledKey = try LibP2PCrypto.Keys.marshalPublicKey(raw: rsa.rawRepresentation, keyType: .RSA(bits: .B1024))

        //XCTAssertEqual(Data(marshaledKey), marshaledData.data)

        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: false, keyType: .RSA(bits: .B1024))
        print(secKey)

        print("--- Encryption ---")

        /// rsa.encrypt acts on the raw data (no data padding)
        /// the rsa encrypt we were using with SecKeys used PKCS1 data padding
        let rsaEncrypted = try rsa.encrypt("Hello".bytes)
        print(rsaEncrypted.asString(base: .base16))

        let secKeyEncrypted = try encryptRaw(Data("Hello".bytes), publicKey: secKey)
        print(secKeyEncrypted.asString(base: .base16))

        XCTAssertEqual(Data(rsaEncrypted), secKeyEncrypted)



        /// Now we need to go from CryptoSwift.RSA raw key to the ASN1 Encodeded (DER) struct
        /// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkiqPxzBWXgZpdQBd14o868a30F3Sc43jwWQG3caikdTHOo7kR14o
        /// which is the pubKeyProto.data.asString(base: .base64) above
        /// RSAPublicKey ::= SEQUENCE {
        ///   version           Version,
        ///   modulus           INTEGER,  -- n
        ///   publicExponent    INTEGER,  -- e
        /// }
        /// Which is decoded into an
        /// {
        /// objectID: [42,134,72,134,247,13,1,1,1]
        /// bitString: { //which is actually just more asn1 nodes...
        ///   integer: n
        ///   integer: e
        /// }


        var asn1Encoded:[UInt8] = []
        let modulus = zeroPad(n: rsa.n.serialize().bytes, to: 257)
        let asn_n = [0x02] + asn1LengthPrefix(modulus) + modulus
        let asn_e = [0x02] + asn1LengthPrefix(rsa.e.serialize().bytes) + rsa.e.serialize()
        let asn_bitStringData = [0x30] + asn1LengthPrefix(asn_n + asn_e) + asn_n + asn_e

        XCTAssertEqual((asn_bitStringData).asString(base: .base16), "3082010a0282010100b648aa3f1cc1597819a5d401775e28f3af1adf417749ce378f05901b771a8a47531cea3b911d78a3e875d83e3940934d41845d52dcb9782f08b47001e18207f8e7bb0c839e545b278629e52fd2e720bc2a41c25479710d36d22d0c8338cf58e2d6ab5aedbd26cd7008b6644567ebe43611c1e8df052f591b4b78acfe0d94997f0d8f1030be0c63c93e5edff20ef3979e98ca69a6cc7f658992cdaf383faa2768914bf9bb5a5d1ab7292ee3cd79338393472a281f8e51bb8a8fd1928581020848dac9b24397ddbbea86a52fd82106d49e12fdb492e81ab53bd8cb9f74c05949924bf297e9cfc481f410460c28af5745696ef57627a127dba22c1cbfc3374a5b230203010001")


        // Where we're trying to get to..
        //30820122 - top level sequence with length prefix
        //  300d - second level sequence with length prefix (houses the object id and null)
        //    06092a864886f70d010101 - RSA Public Key Object Identifier
        //    0500 - Null
        //  0382010f00 - bitString that houses another node sequence
        //    3082010a - node sequence with length prefix (houses the rsa modulus and public exponent as Integers)
        //      02820101 - Integer (with length prefix)
        //        00b648...4a5b23 - RSA Modulus
        //      0203 - Integer (with length prefix)
        //        010001 - RSA Public Exponent

        let oid = Array<UInt8>(arrayLiteral: 42, 134, 72, 134, 247, 13, 1, 1, 1)
        let objectID = [0x06] + asn1LengthPrefix(oid) + oid
        let asn_bitString = [0x03] + asn1LengthPrefix([0x00] + asn_bitStringData) + [0x00] + asn_bitStringData
        let objectIDSequence = [0x30] + asn1LengthPrefix(objectID + [0x05, 0x00]) + objectID + [0x05, 0x00]
        asn1Encoded = [0x30] + asn1LengthPrefix(objectIDSequence + asn_bitString) + objectIDSequence + asn_bitString

        XCTAssertEqual(asn1Encoded.asString(base: .base16), pubKeyProto.data.asString(base: .base16))
        XCTAssertEqual(asn1Encoded, pubKeyProto.data.bytes)

        var reMarshaledKey = PublicKey()
        reMarshaledKey.type = .rsa
        reMarshaledKey.data = Data(asn1Encoded)

        let serialized = try reMarshaledKey.serializedData()

        XCTAssertEqual(serialized, marshaledData.data)


        let pubkeyAsnNode:Asn1Parser.Node =
            .sequence(nodes: [
                .integer(data: Data(zeroPad(n: rsa.n.serialize().bytes, to: 257))),
                .integer(data: rsa.e.serialize())
            ])


        let asnNodes:Asn1Parser.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(oid)),
                .null
            ]),
            .bitString(data: Data(encoded(pubkeyAsnNode)))
        ])


        // Where we're at now
        // 30820122
        //   300d
        //     06092a864886f70d010101
        //     0500
        //   0382010f
        //     003082010a
        //       02820101
        //         00b648...4a5b23
        //       0203
        //         010001
        //

        // Where we're trying to get to..
        // 30820122 - top level sequence with length prefix
        //  300d - second level sequence with length prefix (houses the object id and null)
        //    06092a864886f70d010101 - RSA Public Key Object Identifier
        //    0500 - Null
        //  0382010f - bitString that houses another node sequence
        //    003082010a - node sequence with length prefix (houses the rsa modulus and public exponent as Integers)
        //      02820101 - Integer (with length prefix)
        //        00b648...4a5b23 - RSA Modulus
        //      0203 - Integer (with length prefix)
        //        010001 - RSA Public Exponent

        let asn1AutoEncoded = encoded(asnNodes)
        print(asn1AutoEncoded.asString(base: .base16))

        XCTAssertEqual(asn1Encoded, asn1AutoEncoded)
        XCTAssertEqual(asn1AutoEncoded, pubKeyProto.data.bytes)


        //XCTAssertEqual(Data(asn1Encoded).base64Encoded(), "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkiqPxzBWXgZpdQBd14o868a30F3Sc43jwWQG3caikdTHOo7kR14o")
    }
    
    /// Integer: 00
    /// Integer: 00baff9a3e5674aa277be1b6380e5c898dca21b43acd9de40d514a6d1cb91a2c3c65581fba0c9679933d050157fb66ee5eebd6a29ce3efc02eeff5a6c51a5823a294539eff751b337c0e8102d44ff174cdb06c27f770a3704defdd3373a80ceb0ac63c5d67643cb38c22abd960963d7c10689bdba2395f270db5c68f1559b07e55
    /// Integer: 010001
    /// Integer: 39e5979903659da519eaf96303b74cf37488d8e777f011c2b9cf8456e74c9e3398e11ef9989a224c1f1164a81bf3738c3a12bb483e1e65ef6266395b3f5bd8b41e3b77c66ad7a741ad5bc4caa2dc0ce31211e7decba79fb28c14c98a72ef63d2df778bfef3be00fe84ac5b885e5f694417a2fc06ba11eeb8364c7e2dbc915fe5
    /// Integer: 00f5887f438601bf47134b2ae50727732599c77236e3316587d2d2c155d34e627f67c17610ff33eaff48f1d59a055ada0aca73daa7bb920f17b1b49acc8a118d53
    /// Integer: 00c2f850e06679a72919f9e6a3ee486371ed395510482021bbcf01037134ff3efffaa41728fa93d1ddfdaf5d2765f45025c73f3c23fc52b10f3f9f97c72142a8b7
    /// Integer: 0088e67376f5b7f1abb2813dc87745b2b92b55fe43c6475b81f0b59c20bb71c00fa38d45c45256e3573597c96e584000c4f57ec552b28dcca67c69e3c9d9cdd18b
    /// Integer: 00c1b012187b750b5d4792fd4f899e9c3c47a09722cfa42c1ef96c5651168723bd04f0129a0124ec6e8e60b2383b8ed43853923c5abb8622a3b55f04572c719e4d
    /// Integer: 00cadd324267fe5f2f7d098999c258f3db426dc56d8c8a3967406381e5a81cc36e2cc7deb8bdde44b74796750d9bb4dbf29bd809a503bf13c753ed1de7d9f9be12
    func testSecKeyRSAPrivateASN1() throws {
        let seckey = try genSecKey(bits: .B1024)
        let raw = try seckey.rawRepresentation()
        
        let asn = try Asn1Parser.parse(data: raw)
        
        printNode(asn, level: 0)
    }
    
    private func rsaFromMarshaledPublicKey(_ data:Data) throws -> CryptoSwift.RSA {
        let asn1 = try Asn1Parser.parse(data: data)
        
        guard case .sequence(let params) = asn1 else { throw NSError(domain: "Invalid ASN1 Encoding", code: 0) }
        guard case .sequence(let objectID) = params.first else { throw NSError(domain: "Invalid ASN1 Encoding -> No ObjectID Sequence Node", code: 0) }
        guard case .objectIdentifier(let oid) = objectID.first else { throw NSError(domain: "Invalid ASN1 Encoding -> No ObjectID", code: 0) }
        guard oid.bytes == Array<UInt8>(arrayLiteral: 42, 134, 72, 134, 247, 13, 1, 1, 1) else { throw NSError(domain: "Invalid ASN1 Encoding -> ObjectID != Public RSA Key ID", code: 0) }
        guard case .bitString(let bits) = params.last else { throw NSError(domain: "Invalid ASN1 Encoding -> No BitString", code: 0) }
        
        guard case .sequence(let params2) = try Asn1Parser.parse(data: bits) else { throw NSError(domain: "Invalid ASN1 Encoding -> No PubKey Sequence", code: 0) }
        guard case .integer(let n) = params2.first else { throw NSError(domain: "Invalid ASN1 Encoding -> No Modulus", code: 0) }
        guard case .integer(let e) = params2.last else { throw NSError(domain: "Invalid ASN1 Encoding -> No Public Exponent", code: 0) }
        
        return RSA(n: n.bytes, e: e.bytes)
    }
    
    private func marshaledDataFromRSAPublicKey(_ key:RSA) throws -> Data {
        let mod = key.n.serialize()
        let pubkeyAsnNode:Asn1Parser.Node =
            .sequence(nodes: [
                .integer(data: Data(zeroPad(n: mod.bytes, to: mod.count + 1))),
                .integer(data: key.e.serialize())
            ])
        
        let asnNodes:Asn1Parser.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Array<UInt8>(arrayLiteral: 42, 134, 72, 134, 247, 13, 1, 1, 1))),
                .null
            ]),
            .bitString(data: Data(encoded(pubkeyAsnNode)))
        ])
        
        return Data(encoded(asnNodes))
    }
    
    private func zeroPad(n:[UInt8], to:Int) -> [UInt8] {
        var modulus = n
        while modulus.count < to {
            modulus.insert(0x00, at: 0)
        }
        return modulus
    }
    
    private func asn1LengthPrefix(_ bytes:[UInt8]) -> [UInt8] {
        if bytes.count > 0x80 {
            var lengthAsBytes = withUnsafeBytes(of: bytes.count.bigEndian, Array<UInt8>.init)
            while lengthAsBytes.first == 0 {
                lengthAsBytes.removeFirst()
            }
            print("Data Length: \(bytes.count) bytes")
            print("As bytes: \(lengthAsBytes)")
            print([(0x80 + UInt8(lengthAsBytes.count))] + lengthAsBytes)
            return [(0x80 + UInt8(lengthAsBytes.count))] + lengthAsBytes
        } else {
            return [UInt8(bytes.count)]
        }
    }
    
    private func asn1LengthPrefixed(_ bytes:[UInt8]) -> [UInt8] {
        if bytes.count >= 0x80 {
            var lengthAsBytes = withUnsafeBytes(of: bytes.count.bigEndian, Array<UInt8>.init)
            while lengthAsBytes.first == 0 { lengthAsBytes.removeFirst() }
            return [(0x80 + UInt8(lengthAsBytes.count))] + lengthAsBytes + bytes
        } else {
            return [UInt8(bytes.count)] + bytes
        }
    }
    
    private func encoded(_ node:Asn1Parser.Node) -> [UInt8] {
        switch node {
        case .integer(let integer):
            return [0x02] + asn1LengthPrefixed(integer.bytes)
        case .bitString(let bits):
            return [0x03] + asn1LengthPrefixed([0x00] + bits.bytes)
        case .octetString(let octet):
            return [0x04] + asn1LengthPrefixed(octet.bytes)
        case .null:
            return [0x05, 0x00]
        case .objectIdentifier(let oid):
            return [0x06] + asn1LengthPrefixed(oid.bytes)
        case .sequence(let nodes):
            return [0x30] + asn1LengthPrefixed( nodes.reduce(into: Array<UInt8>(), { partialResult, node in
                partialResult += encoded(node)
            }) )
        }
    }
        
    func testImportFromMarshalledPublicKey_Manual_CryptoSwift_1024() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_1024, as: .base64Pad)
//        let pubKey = try LibP2PCrypto.Keys.importMarshaledPublicKey(marshaledData.data.bytes)
        print(marshaledData.data.count)

        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }

        print("We Unmarshaled a PublicKey Proto!")
        print(pubKeyProto.type)
        print(pubKeyProto.data.asString(base: .base64))

        let rsaKey = try rsaFromMarshaledPublicKey(pubKeyProto.data)

        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: false, keyType: .RSA(bits: .B1024))
        print(secKey)

        print("--- Encryption ---")

        /// rsa.encrypt acts on the raw data (no data padding)
        /// the rsa encrypt we were using with SecKeys used PKCS1 data padding
        let rsaEncrypted = try rsaKey.encrypt("Hello".bytes)
        print(rsaEncrypted.asString(base: .base16))

        let secKeyEncrypted = try encryptRaw(Data("Hello".bytes), publicKey: secKey)
        print(secKeyEncrypted.asString(base: .base16))

        /// Ensure we have the same keys by encrypting the same message with both SecKey and RSAKey and assert they're equal
        XCTAssertEqual(Data(rsaEncrypted), secKeyEncrypted)

        var pubKey = PublicKey()
        pubKey.type = .rsa
        pubKey.data = try marshaledDataFromRSAPublicKey(rsaKey)
        let remarshalledData = try pubKey.serializedData()

        XCTAssertEqual(remarshalledData, marshaledData.data)
    }
    
    func testImportFromMarshalledPublicKey_Manual_CryptoSwift_2048() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_2048, as: .base64Pad)
//        let pubKey = try LibP2PCrypto.Keys.importMarshaledPublicKey(marshaledData.data.bytes)
        print(marshaledData.data.count)

        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }

        print("We Unmarshaled a PublicKey Proto!")
        print(pubKeyProto.type)
        print(pubKeyProto.data.asString(base: .base64))

        let rsaKey = try rsaFromMarshaledPublicKey(pubKeyProto.data)

        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: false, keyType: .RSA(bits: .B1024))
        print(secKey)

        print("--- Encryption ---")

        /// rsa.encrypt acts on the raw data (no data padding)
        /// the rsa encrypt we were using with SecKeys used PKCS1 data padding
        let rsaEncrypted = try rsaKey.encrypt("Hello".bytes)
        print(rsaEncrypted.asString(base: .base16))

        let secKeyEncrypted = try encryptRaw(Data("Hello".bytes), publicKey: secKey)
        print(secKeyEncrypted.asString(base: .base16))

        /// Ensure we have the same keys by encrypting the same message with both SecKey and RSAKey and assert they're equal
        XCTAssertEqual(Data(rsaEncrypted), secKeyEncrypted)

        var pubKey = PublicKey()
        pubKey.type = .rsa
        pubKey.data = try marshaledDataFromRSAPublicKey(rsaKey)
        let remarshalledData = try pubKey.serializedData()

        XCTAssertEqual(remarshalledData, marshaledData.data)
    }
    
    func testImportFromMarshalledPublicKey_Manual_CryptoSwift_3072() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_3072, as: .base64Pad)
//        let pubKey = try LibP2PCrypto.Keys.importMarshaledPublicKey(marshaledData.data.bytes)
        print(marshaledData.data.count)

        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }

        print("We Unmarshaled a PublicKey Proto!")
        print(pubKeyProto.type)
        print(pubKeyProto.data.asString(base: .base64))

        let rsaKey = try rsaFromMarshaledPublicKey(pubKeyProto.data)

        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: false, keyType: .RSA(bits: .B1024))
        print(secKey)

        print("--- Encryption ---")

        /// rsa.encrypt acts on the raw data (no data padding)
        /// the rsa encrypt we were using with SecKeys used PKCS1 data padding
        let rsaEncrypted = try rsaKey.encrypt("Hello".bytes)
        print(rsaEncrypted.asString(base: .base16))

        let secKeyEncrypted = try encryptRaw(Data("Hello".bytes), publicKey: secKey)
        print(secKeyEncrypted.asString(base: .base16))

        /// Ensure we have the same keys by encrypting the same message with both SecKey and RSAKey and assert they're equal
        XCTAssertEqual(Data(rsaEncrypted), secKeyEncrypted)

        var pubKey = PublicKey()
        pubKey.type = .rsa
        pubKey.data = try marshaledDataFromRSAPublicKey(rsaKey)
        let remarshalledData = try pubKey.serializedData()

        XCTAssertEqual(remarshalledData, marshaledData.data)
    }
    
    func testImportFromMarshalledPublicKey_Manual_CryptoSwift_4096() throws {
        let marshaledData = try BaseEncoding.decode(MarshaledData.PUBLIC_RSA_KEY_4096, as: .base64Pad)
//        let pubKey = try LibP2PCrypto.Keys.importMarshaledPublicKey(marshaledData.data.bytes)
        print(marshaledData.data.count)

        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        guard pubKeyProto.data.isEmpty == false else { throw NSError(domain: "Unable to Unmarshal PublicKey", code: 0, userInfo: nil) }

        print("We Unmarshaled a PublicKey Proto!")
        print(pubKeyProto.type)
        print(pubKeyProto.data.asString(base: .base64))

        let rsaKey = try rsaFromMarshaledPublicKey(pubKeyProto.data)

        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: false, keyType: .RSA(bits: .B1024))
        print(secKey)

        print("--- Encryption ---")

        /// rsa.encrypt acts on the raw data (no data padding)
        /// the rsa encrypt we were using with SecKeys used PKCS1 data padding
        let rsaEncrypted = try rsaKey.encrypt("Hello".bytes)
        print(rsaEncrypted.asString(base: .base16))

        let secKeyEncrypted = try encryptRaw(Data("Hello".bytes), publicKey: secKey)
        print(secKeyEncrypted.asString(base: .base16))

        /// Ensure we have the same keys by encrypting the same message with both SecKey and RSAKey and assert they're equal
        XCTAssertEqual(Data(rsaEncrypted), secKeyEncrypted)

        var pubKey = PublicKey()
        pubKey.type = .rsa
        pubKey.data = try marshaledDataFromRSAPublicKey(rsaKey)
        let remarshalledData = try pubKey.serializedData()

        XCTAssertEqual(remarshalledData, marshaledData.data)
    }
    
    /// TODO for tomorrow
    /// - Unmarshal test RSA Key
    /// - Run it through the ASN.1 Parser
    /// - Grab the mod (n) and exp (e) values
    /// - Init CryptoSwift.RSA key RSA(n: n, e: e)
    /// - Encrypt "Hello"
    /// - Instantiate SecKey from unmarshaled RSA Key
    /// - Encrypt "Hello"
    /// - Compare the encrpytions...
    
//    func testSecKeyVsCryptoSwift_Public() throws {
//        let rsa = CryptoSwift.RSA(keySize: 1024)
//
//        //let padded = Padding.pkcs5.add(to: rsa.rawRepresentation.bytes, blockSize: 64)
////        let asc1 =
//
//        let sec = try genSecKey(bits: .B1024).extractPubKey()
//        let asn = try Asn1Parser.parse(data: sec.rawRepresentation())
//
//        printNode(asn, level: 0)
//
//        print("--- CS Raw RSA ---")
//        print("\(rsa.rawRepresentation.count) bytes")
//        print(rsa.rawRepresentation.asString(base: .base16))
//        print("")
//        print("--- SC Raw RSA ---")
//        print(try sec.rawRepresentation().asString(base: .base16))
//    }
//
//    func testSecKeyVsCryptoSwift_Private() throws {
//        let rsa = CryptoSwift.RSA(keySize: 1024)
//
//        //let padded = Padding.pkcs5.add(to: rsa.rawRepresentation.bytes, blockSize: 64)
////        let asc1 =
//
//        let sec = try genSecKey(bits: .B1024)
//        let asn = try Asn1Parser.parse(data: sec.rawRepresentation())
//
//        printNode(asn, level: 0)
//
//        print("--- CS Raw RSA ---")
//        print("\(rsa.rawRepresentation.count) bytes")
//        print(rsa.rawRepresentation.asString(base: .base16))
//        print("")
//        print("--- SC Raw RSA ---")
//        print(try sec.rawRepresentation().asString(base: .base16))
//    }
    
    /// RSA_1024_SecKey == 3143f76d4f5e253b71115bcee78d0a0767b103594fefc5bc9e00bc8e10f31bc31f9095d634f58008c5fd40d1bafd60d2d7ce455aea914fa2f5faa59cdc8c57993ab7529828a504157c00abef12b21332c61b3e78cc2b90ebd0ae6d3295959a3d3446ca94de40fb4591053a6fa7800a9d475737bc88e160a3535c139233cc2126
    func testRSAMessageSignatureAndVerify() throws {
        let message = "Hello, swift-libp2p-crypto!".bytes
        //let message = Data(SHA2(variant: .sha256).calculate(for: "Hello, swift-libp2p-crypto!".bytes))
        
        let marshaledData = try BaseEncoding.decode(MarshaledData.PRIVATE_RSA_KEY_1024, as: .base64Pad)
        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        /// Sec Key
        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: true, keyType: .RSA(bits: .B1024))
        /// CryptoSwift
        let rsa = try LibP2PCrypto.Keys.rsaKeyFromData(data: pubKeyProto.data, isPrivateKey: true)
        
        let signedData_SecKey = try signRaw(message: Data(message), key: secKey)
        //let signedData_SecKey = try encryptRaw(Data(message), publicKey: secKey.extractPubKey())
        
        //let signedData_RsaKey = try rsa.encrypt( message )
        //let n = BigUInteger(Data(SHA2(variant: .sha256).calculate(for: message)))
        let n = BigUInteger(Data(message))
        let e = rsa.d!
        let m = rsa.n
        let signedData_RsaKey = modPow(n: n, e: e, m: m).serialize()
        
        print(signedData_SecKey.asString(base: .base16))
        print(signedData_RsaKey.asString(base: .base16))
        
        XCTAssertEqual(signedData_RsaKey, signedData_SecKey)
        
        
        /// Verify
        XCTAssertTrue(try verifyRaw(signature: signedData_SecKey, forExpectedData: Data(message), usingKey: secKey.extractPubKey()))
        XCTAssertTrue(try verifyRaw(signature: signedData_RsaKey, forExpectedData: Data(message), usingKey: secKey.extractPubKey()))
        
        let _n = BigUInteger(Data(signedData_RsaKey))
        let _e = rsa.e
        let _m = rsa.n
        let _fromSignedData = modPow(n: _n, e: _e, m: _m).serialize()
        
        if _fromSignedData == Data(message) {
            print("Verified")
        } else {
            print("Incorrect")
        }
    }
    
    /// https://datatracker.ietf.org/doc/html/rfc8017#section-8.2
    /// v1.5 - https://datatracker.ietf.org/doc/html/rfc2313
    /// OID - https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.2.4
    func testPKCS1v15Padding() throws {
        let message = "Hello, swift-libp2p-crypto!".bytes
        //let message = Data(SHA2(variant: .sha256).calculate(for: "Hello, swift-libp2p-crypto!".bytes))
        
        let marshaledData = try BaseEncoding.decode(MarshaledData.PRIVATE_RSA_KEY_1024, as: .base64Pad)
        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        /// Sec Key
        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: true, keyType: .RSA(bits: .B1024))
        /// CryptoSwift
        let rsa = try LibP2PCrypto.Keys.rsaKeyFromData(data: pubKeyProto.data, isPrivateKey: true)
        
        let signedData_SecKey = try sign(message: Data(message), key: secKey)
        
        // We have a signed message via SecKey, we're going to attempt to verify with the CryptoSwift.RSA key...
        print(signedData_SecKey.asString(base: .base16))
        
        
        let hashedMessage = SHA2(variant: .sha256).calculate(for: message)
        
        /// PKCS#1_15 DER Structure (OID == sha256WithRSAEncryption)
        let asn:Asn1Parser.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01))),
                .null
            ]),
            .octetString(data: Data(hashedMessage))
        ])
        
        let t = encoded(asn)
        
        //let t = encoded(asn)
        //let t = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20] + hashedMessage
        
        let r = rsa.n.serialize().count - t.count - 3
        print(r)
        let paddedMessage = [0x00, 0x01] + Array<UInt8>(repeating: 0xFF, count: r) + [0x00] + t
        
        XCTAssertEqual(paddedMessage.count, rsa.n.serialize().count)
        
        //print(paddedMessage.asString(base: .base16))
        
        let n = BigUInteger(Data(paddedMessage))
        let e = rsa.d!
        let m = rsa.n
        let signedData_RsaKey_Manual = modPow(n: n, e: e, m: m).serialize()
        print(signedData_RsaKey_Manual.asString(base: .base16))
        
        let signedData_RsaKey_Auto = try rsa.sign(message: Data(message))
        
        //print(try RSA.verify(signedData: signedData_SecKey, expectedData: Data(paddedMessage), usingPublicKey: rsa.publicKey()))
        print(try verify(signature: signedData_SecKey, forExpectedData: Data(message), usingKey: secKey.extractPubKey()))
        
        XCTAssertEqual(signedData_RsaKey_Manual, signedData_SecKey)
        XCTAssertEqual(signedData_RsaKey_Auto, signedData_SecKey)
    }
    
    func testPKCS1v15PaddingMessageVerification() throws {
        let message = "Hello, swift-libp2p-crypto!".bytes
        //let message = Data(SHA2(variant: .sha256).calculate(for: "Hello, swift-libp2p-crypto!".bytes))
        
        let marshaledData = try BaseEncoding.decode(MarshaledData.PRIVATE_RSA_KEY_1024, as: .base64Pad)
        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
        /// Sec Key
        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: true, keyType: .RSA(bits: .B1024))
        /// CryptoSwift
        let rsa = try LibP2PCrypto.Keys.rsaKeyFromData(data: pubKeyProto.data, isPrivateKey: true)
        
        let signedData_SecKey = try sign(message: Data(message), key: secKey)
        let signedData_RsaKey = try rsa.sign(message: Data(message))
        
        /// Ensure our signatures are the same!
        XCTAssertEqual(signedData_RsaKey, signedData_SecKey)
        /// Ensure that it's a valid signature
        XCTAssertTrue(try verify(signature: signedData_SecKey, forExpectedData: Data(message), usingKey: secKey.extractPubKey()))
        
        /// Attempt to verify the signature using CryptoSwift.RSA key
        
        /// Get the public key of our RSA...
        let publicRSAKey = try rsa.publicKey()
        
        /// Step 1: Ensure the signature is the same length as the key's modulus
        guard signedData_RsaKey.count == publicRSAKey.n.serialize().count else { return XCTFail("Invalid Signature Length") }
        
        /// Step 2: 'Decrypt' the signature
        let n = BigUInteger(signedData_RsaKey)
        let e = publicRSAKey.e
        let m = publicRSAKey.n
        let pkcsEncodedSHA256HashedMessage = modPow(n: n, e: e, m: m).serialize()
        
        /// Step 3: Compare the 'decrypted' signature with the prepared / encoded expected message....
        let preparedExpectedMessage = hashedAndPKCSEncoded(message, modLength: publicRSAKey.n.serialize().count).dropFirst()

        print(pkcsEncodedSHA256HashedMessage.asString(base: .base16))
        print(preparedExpectedMessage.asString(base: .base16))
        
        if pkcsEncodedSHA256HashedMessage == preparedExpectedMessage {
            print("Valid")
        } else {
            print("Invalid")
        }
        
        // Auto instance member
        XCTAssertTrue(try publicRSAKey.verify(signature: signedData_SecKey, fromMessage: Data(message)))
        XCTAssertTrue(try publicRSAKey.verify(signature: signedData_RsaKey, fromMessage: Data(message)))
        // Auto static method
        XCTAssertTrue(try RSA.verify(signature: signedData_SecKey, fromMessage: Data(message), usingKey: publicRSAKey))
        XCTAssertTrue(try RSA.verify(signature: signedData_RsaKey, fromMessage: Data(message), usingKey: publicRSAKey))
        
        let messageAltered = "Hello, swift-libp2p-crypto?".bytes
        // Auto instance member
        XCTAssertFalse(try publicRSAKey.verify(signature: signedData_SecKey, fromMessage: Data(messageAltered)))
        XCTAssertFalse(try publicRSAKey.verify(signature: signedData_RsaKey, fromMessage: Data(messageAltered)))
        // Auto static method
        XCTAssertFalse(try RSA.verify(signature: signedData_SecKey, fromMessage: Data(messageAltered), usingKey: publicRSAKey))
        XCTAssertFalse(try RSA.verify(signature: signedData_RsaKey, fromMessage: Data(messageAltered), usingKey: publicRSAKey))
    }
    
    
    
    func testOID() throws {
        let num:BigInteger = 840
        print(num.serialize().asString(base: .base16))
        
        print((num & 0x7F))
        print((num >> 7) & 0x7F | 0x80)
        print((num >> 14) & 0x7F | 0x80)
        print((num >> 21) & 0x7F | 0x80)
        print((num >> 28) & 0x7F | 0x80)
        
        let message = "Hello, swift-libp2p-crypto!".bytes
        let hashedMessage = SHA2(variant: .sha256).calculate(for: message)
        
        let asn:Asn1Parser.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01))),
                .null
            ]),
            .octetString(data: Data(hashedMessage))
        ])
        
        let t_encoded = encoded(asn)
        let t_static:[UInt8] = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20] + hashedMessage
        
        print(t_encoded.asString(base: .base16))
        print(t_static.asString(base: .base16))
        
        XCTAssertEqual(t_encoded, t_static)
        //[48, 50, 48, 14, 6, 10, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]
        //[48, 49, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 5, 0, 4, 32]
    }
    
    /// RSAPrivateKey ::= SEQUENCE {
    ///   version           Version,
    ///   modulus           INTEGER,  -- n
    ///   publicExponent    INTEGER,  -- e
    ///   privateExponent   INTEGER,  -- d
    ///   prime1            INTEGER,  -- p
    ///   prime2            INTEGER,  -- q
    ///   exponent1         INTEGER,  -- d mod (p-1)
    ///   exponent2         INTEGER,  -- d mod (q-1)
    ///   coefficient       INTEGER,  -- (inverse of q) mod p
    ///   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    /// }
//    func testMarshalPrivateRSAKey() throws {
//        let marshaledData = try BaseEncoding.decode(MarshaledData.PRIVATE_RSA_KEY_1024, as: .base64Pad)
//        let pubKeyProto = try PublicKey(contiguousBytes: marshaledData.data)
//        /// Sec Key
//        let secKey = try secKeyFrom(data: pubKeyProto.data, isPrivateKey: true, keyType: .RSA(bits: .B1024))
//
//        let rawRep = try secKey.rawRepresentation()
//
//        let asn = try Asn1Parser.parse(data: rawRep)
//        printNode(asn, level: 0)
//        guard case .sequence(let params) = asn else { return XCTFail("No ASN sequence...") }
//
//        guard case .integer(let version)         = params[0] else { return XCTFail("Invalid ASN...") }
//        guard case .integer(let modulus)         = params[1] else { return XCTFail("Invalid ASN...") }
//        guard case .integer(let publicExponent)  = params[2] else { return XCTFail("Invalid ASN...") }
//        guard case .integer(let privateExponent) = params[3] else { return XCTFail("Invalid ASN...") }
//        //guard case .integer(let prime1)          = params[4] else { return XCTFail("Invalid ASN...") }
//        //guard case .integer(let prime2)          = params[5] else { return XCTFail("Invalid ASN...") }
//        //guard case .integer(let exponent1)       = params[6] else { return XCTFail("Invalid ASN...") }
//        //guard case .integer(let exponent2)       = params[7] else { return XCTFail("Invalid ASN...") }
//        //guard case .integer(let coefficient)     = params[8] else { return XCTFail("Invalid ASN...") }
//
//        let rsa = try LibP2PCrypto.Keys.rsaKeyFromData(data: pubKeyProto.data, isPrivateKey: true)
//
//        //3082010e
//        //  0201
//        //    00
//        //028181
//        //  006d...55d3
//        //0203
//        //  010001
//        //0280
//        // 344e...ec41
//        let mod = rsa.n.serialize()
//        let pubkeyAsnNode:Asn1Parser.Node =
//            .sequence(nodes: [
//                .integer(data: Data( Array<UInt8>(arrayLiteral: 0x00) )),
//                .integer(data: Data(RSA.zeroPad(n: mod.bytes, to: mod.count + 1))),
//                .integer(data: rsa.e.serialize()),
//                .integer(data: rsa.d!.serialize())
//            ])
//
//        printNode(pubkeyAsnNode, level: 0)
//
//        let encoded = encoded(pubkeyAsnNode)
//
//        print(rawRep.asString(base: .base16))
//        print(encoded.asString(base: .base16))
//
//        let asn2 = try Asn1Parser.parse(data: Data(encoded))
//        printNode(asn2, level: 0)
//    }

}

/// RSA Mod Pow Method
extension CSRSASecKeyParityTests {
    /// Modular exponentiation
    ///
    /// - Credit: AttaSwift BigInt
    /// - Source: https://rosettacode.org/wiki/Modular_exponentiation#Swift
    func modPow<T: BinaryInteger>(n: T, e: T, m: T) -> T {
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
}

/// ASN Helper Methods
extension CSRSASecKeyParityTests {
    /// RSAPrivateKey ::= SEQUENCE {
    ///   version           Version,
    ///   modulus           INTEGER,  -- n
    ///   publicExponent    INTEGER,  -- e
    ///   privateExponent   INTEGER,  -- d
    ///   prime1            INTEGER,  -- p
    ///   prime2            INTEGER,  -- q
    ///   exponent1         INTEGER,  -- d mod (p-1)
    ///   exponent2         INTEGER,  -- d mod (q-1)
    ///   coefficient       INTEGER,  -- (inverse of q) mod p
    ///   otherPrimeInfos   OtherPrimeInfos OPTIONAL
    /// }
    ///
    /// version         - Integer: 00
    /// modulus         - Integer: 00e12a47ac3cfc3db5028442ebe4b320da8ae9cf5663e6ff16c1968da1fd4edf98a4eb0819f283d8e00973a56321b82e6a589f2bb047ead259fe76c8ccaae9bddda806d00fd287307d1993ded260116bdb910f908bea30f2ae616aefceec03182693f26037ca387f6f781a148363e9b258aa4ee83520097403bf5124724509de89
    /// publicExponent  - Integer: 010001
    /// privateExponent - Integer: 1d7d130beca4c0541f7340ec71f43fbe3f69259d53d221e052142c92658159e93cd8072496cd4baef3adf0a00dff781cb764892d3a0df7e48f5df12854cdedee85b45e88d2e45d51de419b7825993aac6d4fadcbe82b04e9eeb8424dbb4e910d00ecec2ad7f64f59694afde22ea3437866f31cc59f285a740a8242a671f1b771
    /// prime1          - Integer: 00f70aeecca06fada31bfc4998700b3b551912ff514af08557e94ae9aeb640335d9b9588574b222e94c03c12ecd26b25ad8a0c2d8df99fc2ae04a9739c56d01d4d
    /// prime2          - Integer: 00e954473bb24f56fff142776fe43b45bdf9e09de342f892a6ec0657bb2b765935d6553c19c25ef6b28d806f7e462b5c452ab6e1a4db0330e4008f238e89cb982d
    /// exponent1       - Integer: 3e7030f2df09dae502c9bd001e3178898590db9efc45d62de5f4dd231f4512b6720055395af004bdebe84310400e7cb363d4b81ece1ca6e3bca1e76a78369971
    /// exponent2       - Integer: 4d10c70e52909dfd9f2402eaf40917b9eda460c1c546f0b92d4fd2fe4116afd4765c64a3656d9431d946c88c7e84a7cf38927ae8c665c16a2d3d19d36473d869
    /// coefficient     - Integer: 603cca022b9fae65b551bbf49f2211ac224db930447cb0a6d86beb6dda370986557bf416b38318c4d2e9678b61e787d0f0d0db8f2234316b7637fc7b72ba9505
    private func printNode(_ node:Asn1Parser.Node, level:Int) {
        let prefix = String(repeating: "\t", count: level)
        switch node {
        case .integer(let int):
            print("\(prefix)Integer: \(int.asString(base: .base16))")
        case .bitString(let bs):
            print("\(prefix)BitString: \(bs.asString(base: .base16))")
        case .null:
            print("\(prefix)NULL")
        case .objectIdentifier(let oid):
            print("\(prefix)ObjectID: \(oid.asString(base: .base16))")
        case .octetString(let os):
            print("\(prefix)OctetString: \(os.asString(base: .base16))")
        case .sequence(let nodes):
            nodes.forEach { printNode($0, level: level + 1) }
        }
    }
    
    private func hashedAndPKCSEncoded(_ message:[UInt8], modLength:Int) -> Data {
        let hashedMessage = SHA2(variant: .sha256).calculate(for: message)
        
        /// PKCS#1_15 DER Structure (OID == sha256WithRSAEncryption)
        let asn:Asn1Parser.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Array<UInt8>(arrayLiteral: 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01))),
                .null
            ]),
            .octetString(data: Data(hashedMessage))
        ])
        
        let t = encoded(asn)
        let r = modLength - t.count - 3
        let paddedMessage = [0x00, 0x01] + Array<UInt8>(repeating: 0xFF, count: r) + [0x00] + t
        
        return Data(paddedMessage)
    }
}

/// SecKey Helper Methods
extension CSRSASecKeyParityTests {
    private func genSecKey(bits:LibP2PCrypto.Keys.RSABitLength) throws -> SecKey {
        let parameters = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: bits.bits
        ] as [CFString : Any]

        var error:Unmanaged<CFError>? = nil

        guard let privKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
            print(error.debugDescription)
            throw NSError(domain: "Key Generation Error: \(error.debugDescription)", code: 0, userInfo: nil)
        }

        return privKey
    }

    private func secKeyFrom(data:Data, isPrivateKey:Bool, keyType:LibP2PCrypto.Keys.KeyPairType) throws -> SecKey {
        let attributes: [String:Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
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

    private func encryptPKCS1(_ data:Data, publicKey:SecKey) throws -> Data {
        var error:Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionPKCS1, data as CFData, &error) else {
            throw NSError(domain: "Error Encrypting Data: \(error.debugDescription)", code: 0, userInfo: nil)
        }
        return encryptedData as Data
    }

    private func encryptRaw(_ data:Data, publicKey:SecKey) throws -> Data {
        var error:Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionRaw, data as CFData, &error) else {
            throw NSError(domain: "Error Encrypting Data: \(error.debugDescription)", code: 0, userInfo: nil)
        }
        return encryptedData as Data
    }
    
    private func signRaw(message:Data, key:SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key,
            .rsaSignatureRaw, //.rsaSignatureMessagePKCS1v15SHA256,
            message as CFData,
            &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return signature
    }
    
    private func verifyRaw(signature:Data, forExpectedData expected:Data, usingKey key:SecKey) throws -> Bool {
        var error:Unmanaged<CFError>?
        guard SecKeyVerifySignature(key,
            .rsaSignatureRaw, //.rsaSignatureMessagePKCS1v15SHA256,
            expected as CFData,
            signature as CFData,
            &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return true
    }
    
    private func sign(message:Data, key:SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key,
            .rsaSignatureMessagePKCS1v15SHA256,
            message as CFData,
            &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        return signature
    }
    
    private func verify(signature:Data, forExpectedData expected:Data, usingKey key:SecKey) throws -> Bool {
        var error:Unmanaged<CFError>?
        guard SecKeyVerifySignature(key,
            .rsaSignatureMessagePKCS1v15SHA256,
            expected as CFData,
            signature as CFData,
            &error) else {
            throw error!.takeRetainedValue() as Error
        }
        return true
    }
}

extension SecKey {
    /// Returns the RSA Key in the PKCS #1 format
    /// https://stackoverflow.com/questions/48958304/pkcs1-and-pkcs8-format-for-rsa-private-key
    func rawRepresentation() throws -> Data {
        var error:Unmanaged<CFError>?
        if let cfdata = SecKeyCopyExternalRepresentation(self, &error) {
            return cfdata as Data
        } else { throw NSError(domain: "RawKeyError: \(error.debugDescription)", code: 0, userInfo: nil) }
    }
    
    func extractPubKey() throws -> SecKey {
        guard let pubKey = SecKeyCopyPublicKey(self) else {
            throw NSError(domain: "Public Key Extraction Error", code: 0, userInfo: nil)
        }
        return pubKey
    }
}

#endif
