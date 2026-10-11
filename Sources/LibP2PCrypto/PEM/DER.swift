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

import CryptoSwift
import Foundation
import SwiftASN1

/// Conform to this protocol if your type can be instantiated from a ASN1 DER representation
public protocol DERDecodable {
    /// The keys ASN1 object identifier (ex: RSA --> rsaEncryption --> 1.2.840.113549.1.1.1)
    static var primaryObjectIdentifier: ASN1ObjectIdentifier { get }
    /// The keys secondary ASN1 object identifier, if any (ex: Secp256k1 public key --> secp256k1 --> 1.3.132.0.10)
    static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { get }
    /// Instantiates an instance of your Public Key when given a DER representation of your Public Key
    init(publicDER: [UInt8]) throws
    /// Instantiates an instance of your Private Key when given a DER representation of your Private Key
    init(privateDER: [UInt8]) throws
    /// Instantiates a DERDecodable Key from a PEM string
    init<Key: DERDecodable>(pem: String, password: String?, asType: Key.Type) throws
    /// Instantiates a DERDecodable Key from ut8 decoded PEM data
    init<Key: DERDecodable>(pem: Data, password: String?, asType: Key.Type) throws
}

extension DERDecodable {
    /// Instantiates a DERDecodable Key from a PEM string
    /// - Parameters:
    ///   - pem: The PEM file to import
    ///   - password: A password to use to decrypt an encrypted PEM file
    ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
    public init<Key: DERDecodable>(pem: String, password: String? = nil, asType: Key.Type = Key.self) throws {
        try self.init(pem: pem.bytes, password: password, asType: Key.self)
    }

    /// Instantiates a DERDecodable Key from ut8 decoded PEM data
    /// - Parameters:
    ///   - pem: The PEM file to import
    ///   - password: A password to use to decrypt an encrypted PEM file
    ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
    public init<Key: DERDecodable>(pem: Data, password: String? = nil, asType: Key.Type = Key.self) throws {
        try self.init(pem: pem.byteArray, password: password, asType: Key.self)
    }

    /// Instantiates a DERDecodable Key from ut8 decoded PEM bytes
    /// - Parameters:
    ///   - pem: The PEM file to import
    ///   - password: A password to use to decrypt an encrypted PEM file
    ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
    public init<Key: DERDecodable>(pem: [UInt8], password: String? = nil, asType: Key.Type = Key.self) throws {
        let (type, bytes, _) = try LibP2PCrypto.PEM.pemToData(pem)

        if password != nil {
            guard type == .encryptedPrivateKey else { throw LibP2PCrypto.PEM.Error.invalidParameters }
        }

        switch type {
        case .publicRSAKeyDER:
            // Ensure the objectIdentifier is rsaEncryption
            try self.init(publicDER: bytes)
        case .privateRSAKeyDER:
            // Ensure the objectIdentifier is rsaEncryption
            try self.init(privateDER: bytes)
        case .publicKey:
            let der = try LibP2PCrypto.PEM.decodePublicKeyPEM(
                Data(bytes),
                expectedPrimaryObjectIdentifier: Key.primaryObjectIdentifier,
                expectedSecondaryObjectIdentifier: Key.secondaryObjectIdentifier
            )
            try self.init(publicDER: der)
        case .privateKey, .ecPrivateKey:
            let der = try LibP2PCrypto.PEM.decodePrivateKeyPEM(
                Data(bytes),
                expectedPrimaryObjectIdentifier: Key.primaryObjectIdentifier,
                expectedSecondaryObjectIdentifier: Key.secondaryObjectIdentifier
            )
            try self.init(privateDER: der)
        case .encryptedPrivateKey:
            // Decrypt the encrypted PEM and attempt to instantiate it again...

            // Ensure we were provided a password
            guard let password = password else { throw LibP2PCrypto.PEM.Error.invalidParameters }

            // Parse out Encryption Strategy and CipherText
            let decryptionStategy = try LibP2PCrypto.PEM.decodeEncryptedPEM(Data(bytes))

            // Derive Encryption Key from Password
            let key = try decryptionStategy.pbkdfAlgorithm.deriveKey(
                password: password,
                ofLength: decryptionStategy.cipherAlgorithm.desiredKeyLength
            )

            // Decrypt CipherText
            let decryptedPEM = try decryptionStategy.cipherAlgorithm.decrypt(
                bytes: decryptionStategy.ciphertext,
                withKey: key
            )

            // Proceed with the unencrypted PEM (can public PEM keys be encrypted as well, wouldn't really make sense but idk if we should support it)?
            let der = try LibP2PCrypto.PEM.decodePrivateKeyPEM(
                Data(decryptedPEM),
                expectedPrimaryObjectIdentifier: Key.primaryObjectIdentifier,
                expectedSecondaryObjectIdentifier: Key.secondaryObjectIdentifier
            )

            try self.init(privateDER: der)
        }
    }
}

/// Conform to this protocol if your type can be described in an ASN1 DER representation
public protocol DEREncodable {
    /// The keys ASN1 object identifier (ex: RSA --> rsaEncryption --> 1.2.840.113549.1.1.1)
    static var primaryObjectIdentifier: ASN1ObjectIdentifier { get }
    /// The keys secondary ASN1 object identifier, if any (ex: RSA --> nil)
    static var secondaryObjectIdentifier: ASN1ObjectIdentifier? { get }

    func publicKeyDER() throws -> [UInt8]
    func privateKeyDER() throws -> [UInt8]

    /// The raw ASN1 Encoded PEM data without headers, footers and line breaks
    func exportPrivateKeyPEMRaw() throws -> [UInt8]

    /// PublicKey PEM Export Functions
    func exportPublicKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8]
    func exportPublicKeyPEMString(withHeaderAndFooter: Bool) throws -> String

    /// PrivateKey PEM Export Functions
    func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8]
    func exportPrivateKeyPEMString(withHeaderAndFooter: Bool) throws -> String
}

extension DEREncodable {

    /// The DER encoded SubjectPublicKeyInfo for this key
    internal func exportPublicKeyPEMRaw() throws -> [UInt8] {
        let parameters: AlgorithmIdentifier.Parameters?
        if Self.primaryObjectIdentifier == ASN1ObjectIdentifier.LibP2P.rsaEncryption {
            // RSA requires an explicit NULL parameter (RFC 3279 §2.3.1)
            parameters = .null
        } else {
            parameters = Self.secondaryObjectIdentifier.map { .objectIdentifier($0) }
        }

        return try SubjectPublicKeyInfo(
            algorithmIdentifier: AlgorithmIdentifier(algorithm: Self.primaryObjectIdentifier, parameters: parameters),
            key: self.publicKeyDER()
        ).serializedDERBytes()
    }

    public func exportPublicKeyPEM(withHeaderAndFooter: Bool = true) throws -> [UInt8] {
        try LibP2PCrypto.PEM.armor(
            self.exportPublicKeyPEMRaw(),
            as: .publicKey,
            withHeaderAndFooter: withHeaderAndFooter
        )
    }

    public func exportPublicKeyPEMString(withHeaderAndFooter: Bool = true) throws -> String {
        let publicPEMData = try exportPublicKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
        guard let pemAsString = String(data: Data(publicPEMData), encoding: .utf8) else {
            throw LibP2PCrypto.PEM.Error.encodingError
        }
        return pemAsString
    }

    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        try PrivateKeyInfo(
            algorithmIdentifier: AlgorithmIdentifier(algorithm: Self.primaryObjectIdentifier),
            privateKey: self.privateKeyDER()
        ).serializedDERBytes()
    }

    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool = true) throws -> [UInt8] {
        try LibP2PCrypto.PEM.armor(
            self.exportPrivateKeyPEMRaw(),
            as: .privateKey,
            withHeaderAndFooter: withHeaderAndFooter
        )
    }

    public func exportPrivateKeyPEMString(withHeaderAndFooter: Bool = true) throws -> String {
        let privatePEMData = try exportPrivateKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
        guard let pemAsString = String(data: Data(privatePEMData), encoding: .utf8) else {
            throw LibP2PCrypto.PEM.Error.encodingError
        }
        return pemAsString
    }
}

/// Conform to this protocol if your type can both be instantiated and expressed as an ASN1 DER representation.
public protocol DERCodable: DERDecodable, DEREncodable {}
