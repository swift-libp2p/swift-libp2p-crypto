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

#if !canImport(Security)
import Foundation
@preconcurrency import CryptoSwift

struct RSAPublicKey: CommonPublicKey {
    static var keyType: LibP2PCrypto.Keys.GenericKeyType { .rsa }

    /// RSA Object Identifier Bytes
    private static let RSA_OBJECT_IDENTIFIER = [UInt8](arrayLiteral: 42, 134, 72, 134, 247, 13, 1, 1, 1)

    /// The underlying CryptoSwift RSA Key that backs this struct
    private let key: RSA

    /// The PKCS#1 DER (`externalRepresentation()`) captured at init time so that the
    /// non-throwing `rawRepresentation` accessor can never crash or silently return empty data.
    private let externalRepresentationBytes: Data

    fileprivate init(_ rsa: RSA) throws {
        self.key = rsa
        self.externalRepresentationBytes = try rsa.externalRepresentation()
    }

    init(rawRepresentation raw: Data) throws {
        let asn1 = try ASN1.Decoder.decode(data: raw)

        guard case .sequence(let params) = asn1 else {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("RSA public key: not an ASN.1 sequence")
        }

        /// We have an objectID header....
        if case .sequence(let objectID) = params.first {
            guard case .objectIdentifier(let oid) = objectID.first else {
                throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("RSA public key: missing object identifier")
            }
            guard oid.byteArray == RSAPublicKey.RSA_OBJECT_IDENTIFIER else {
                throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("RSA public key: unexpected object identifier")
            }
            guard case .bitString(let bits) = params.last else {
                throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("RSA public key: missing key bit string")
            }

            self.key = try CryptoSwift.RSA(rawRepresentation: bits)
        } else if params.count == 2, case .integer = params.first {
            /// We have a direct sequence of integers
            guard case .integer(let n) = params.first else {
                throw NSError(domain: "Invalid ASN1 Encoding -> No Modulus", code: 0)
            }
            guard case .integer(let e) = params.last else {
                throw NSError(domain: "Invalid ASN1 Encoding -> No Public Exponent", code: 0)
            }

            self.key = CryptoSwift.RSA(n: n.byteArray, e: e.byteArray)
        } else {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("RSA public key: unrecognized structure")
        }
    }

    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }

    /// We return the ASN1 Encoded DER Representation of the public key because that's what the rawRepresentation of RSA SecKey return
    var rawRepresentation: Data {
        let asnNodes: ASN1.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(RSAPublicKey.primaryObjectIdentifier)),
                .null,
            ]),
            .bitString(data: externalRepresentationBytes),
        ])

        return Data(ASN1.Encoder.encode(asnNodes))
    }

    func encrypt(data: Data) throws -> Data {
        try Data(key.encrypt(data.byteArray))
    }

    /// Verifies an RSA Signature for an expected block of data
    ///
    /// - Note: We throw on false to match the SecKey implementation
    func verify(signature: Data, for expectedData: Data) throws -> Bool {
        guard try RSA.verify(signature: signature, fromMessage: expectedData, usingKey: self.key) else {
            throw LibP2PCrypto.Keys.KeyError.signatureFailed("RSA: invalid signature for expected data")
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

struct RSAPrivateKey: CommonPrivateKey {
    static var keyType: LibP2PCrypto.Keys.GenericKeyType { .rsa }

    /// The underlying CryptoSwift RSA key that backs this struct
    private let key: RSA

    /// The PKCS#1 DER (`externalRepresentation()`) captured at init time so that the
    /// non-throwing `rawRepresentation` accessor can never crash or silently return empty data.
    private let externalRepresentationBytes: Data

    fileprivate init(_ rsa: RSA) throws {
        self.key = rsa
        self.externalRepresentationBytes = try rsa.externalRepresentation()
    }

    /// Initializes a new RSA key (backed by CryptoSwift) of the specified bit size
    internal init(keySize: Int) throws {
        switch keySize {
        case 1024:
            self.key = try CryptoSwift.RSA(keySize: keySize)
        case 2048:
            self.key = try CryptoSwift.RSA(keySize: keySize)
        case 3072:
            self.key = try CryptoSwift.RSA(keySize: keySize)
        case 4096:
            self.key = try CryptoSwift.RSA(keySize: keySize)
        default:
            throw LibP2PCrypto.Keys.KeyError.invalidParameters(
                "Invalid RSA key bit length (use 2048, 3072 or 4096), got \(keySize)"
            )
        }
    }

    init(keySize: LibP2PCrypto.Keys.RSABitLength) throws {
        try self.init(keySize: keySize.bits)
    }

    /// Expects the ASN1 Encoding of the DER formatted RSA Private Key
    init(rawRepresentation raw: Data) throws {
        let rsaKey = try RSA(rawRepresentation: raw)
        guard rsaKey.d != nil else {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding("RSA: missing private exponent")
        }
        try self.init(rsaKey)
    }

    init(marshaledData data: Data) throws {
        try self.init(rawRepresentation: data)
    }

    var rawRepresentation: Data {
        externalRepresentationBytes
    }

    func derivePublicKey() throws -> CommonPublicKey {
        guard key.d != nil else {
            throw LibP2PCrypto.Keys.KeyError.publicKeyDerivationFailed("RSA: no private exponent")
        }
        return try RSAPublicKey(CryptoSwift.RSA(n: key.n, e: key.e))
    }

    func decrypt(data: Data) throws -> Data {
        try Data(key.decrypt(data.byteArray))
    }

    func sign(message: Data) throws -> Data {
        try RSA.sign(message: message, withKey: key)
    }

    public func marshal() throws -> Data {
        var privateKey = PrivateKey()
        privateKey.type = .rsa
        privateKey.data = self.rawRepresentation
        return try privateKey.serializedData()
    }

}

extension RSAPublicKey: Equatable {
    static func == (lhs: RSAPublicKey, rhs: RSAPublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension RSAPrivateKey: Equatable {
    static func == (lhs: RSAPrivateKey, rhs: RSAPrivateKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
}

extension CryptoSwift.RSA {
    /// Signs a message
    ///
    /// - Note: The signature uses the SHA256 PKCS#1v15 Padding Scheme
    /// - Note: [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2)
    fileprivate static func sign(message: Data, withKey key: RSA) throws -> Data {
        try Data(key.sign(message.byteArray, variant: .message_pkcs1v15_SHA256))
    }

    /// Verifies a signature for the expected data
    ///
    /// - Note: This method assumes the signature was generated using the SHA256 PKCS#1v15 Padding Scheme
    /// - Note: [EMSA-PKCS1-v1_5](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2)
    fileprivate static func verify(signature: Data, fromMessage message: Data, usingKey key: RSA) throws -> Bool {
        try key.verify(signature: signature.byteArray, for: message.byteArray, variant: .message_pkcs1v15_SHA256)
    }
}

#endif
