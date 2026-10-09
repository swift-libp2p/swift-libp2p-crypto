//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2026 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftASN1

// MARK: Object Identifiers

extension ASN1ObjectIdentifier {

    /// Object identifiers used by the key and PEM encodings supported by LibP2PCrypto
    public enum LibP2P {

        /// rsaEncryption (1.2.840.113549.1.1.1)
        public static let rsaEncryption: ASN1ObjectIdentifier = ASN1ObjectIdentifier.AlgorithmIdentifier.rsaEncryption

        /// id-ecPublicKey (1.2.840.10045.2.1)
        public static let idEcPublicKey: ASN1ObjectIdentifier = ASN1ObjectIdentifier.AlgorithmIdentifier.idEcPublicKey

        /// id-Ed25519 (1.3.101.112) [RFC 8410]
        public static let ed25519: ASN1ObjectIdentifier = [1, 3, 101, 112]

        /// secp256k1 named curve (1.3.132.0.10) [SEC 2]
        public static let secp256k1: ASN1ObjectIdentifier = [1, 3, 132, 0, 10]

        /// id-PBES2 (1.2.840.113549.1.5.13) [RFC 8018]
        public static let pbes2: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 5, 13]

        /// id-PBKDF2 (1.2.840.113549.1.5.12) [RFC 8018]
        public static let pbkdf2: ASN1ObjectIdentifier = [1, 2, 840, 113_549, 1, 5, 12]

        /// aes128-CBC-PAD (2.16.840.1.101.3.4.1.2)
        public static let aes128CBC: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 2]

        /// aes256-CBC-PAD (2.16.840.1.101.3.4.1.42)
        public static let aes256CBC: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 42]
    }
}

extension DERSerializable {

    /// Returns the DER encoding of this value
    func serializedDERBytes() throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(self)
        return serializer.serializedBytes
    }
}

// MARK: AlgorithmIdentifier

/// ```
/// AlgorithmIdentifier ::= SEQUENCE {
///     algorithm   OBJECT IDENTIFIER,
///     parameters  ANY DEFINED BY algorithm OPTIONAL
/// }
/// ```
///
/// Only the parameter forms used by the supported key types are modeled:
/// `NULL` (RSA), a named curve `OBJECT IDENTIFIER` (EC) or absent (Ed25519).
struct AlgorithmIdentifier: DERImplicitlyTaggable, Hashable {
    enum Parameters: Hashable {
        case null
        case objectIdentifier(ASN1ObjectIdentifier)
    }

    static var defaultIdentifier: ASN1Identifier { .sequence }

    /// rsaEncryption with its required NULL parameter (RFC 3279 §2.3.1)
    static let rsaEncryption = AlgorithmIdentifier(
        algorithm: ASN1ObjectIdentifier.LibP2P.rsaEncryption,
        parameters: .null
    )

    var algorithm: ASN1ObjectIdentifier
    var parameters: Parameters?

    init(algorithm: ASN1ObjectIdentifier, parameters: Parameters? = nil) {
        self.algorithm = algorithm
        self.parameters = parameters
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let parameters: Parameters?
            switch nodes.next() {
            case .none:
                parameters = nil
            case .some(let node) where node.identifier == .null:
                _ = try ASN1Null(derEncoded: node)
                parameters = .null
            case .some(let node) where node.identifier == .objectIdentifier:
                parameters = .objectIdentifier(try ASN1ObjectIdentifier(derEncoded: node))
            case .some(let node):
                throw ASN1Error.unexpectedFieldType(node.identifier)
            }
            return AlgorithmIdentifier(algorithm: algorithm, parameters: parameters)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            switch self.parameters {
            case .none:
                break
            case .null:
                try coder.serialize(ASN1Null())
            case .objectIdentifier(let oid):
                try coder.serialize(oid)
            }
        }
    }
}

// MARK: SubjectPublicKeyInfo

/// ```
/// SubjectPublicKeyInfo ::= SEQUENCE {
///     algorithm         AlgorithmIdentifier,
///     subjectPublicKey  BIT STRING
/// }
/// ```
/// [RFC 5280 §4.1](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1)
struct SubjectPublicKeyInfo: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    var algorithmIdentifier: AlgorithmIdentifier
    var key: ASN1BitString

    init(algorithmIdentifier: AlgorithmIdentifier, key: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = ASN1BitString(bytes: key[...])
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try AlgorithmIdentifier(derEncoded: &nodes)
            let key = try ASN1BitString(derEncoded: &nodes)
            guard key.paddingBits == 0 else {
                throw ASN1Error.invalidASN1Object(reason: "SubjectPublicKeyInfo key is not octet aligned")
            }
            return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: Array(key.bytes))
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.key)
        }
    }
}

// MARK: PrivateKeyInfo (PKCS #8)

/// ```
/// PrivateKeyInfo ::= SEQUENCE {
///     version              INTEGER (v1(0)),
///     privateKeyAlgorithm  AlgorithmIdentifier,
///     privateKey           OCTET STRING
/// }
/// ```
/// [RFC 5208 §5](https://datatracker.ietf.org/doc/html/rfc5208#section-5)
struct PrivateKeyInfo: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    static let version = 0

    var algorithmIdentifier: AlgorithmIdentifier
    var privateKey: ASN1OctetString

    init(algorithmIdentifier: AlgorithmIdentifier, privateKey: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == Self.version else {
                throw ASN1Error.invalidASN1Object(reason: "Unsupported PrivateKeyInfo version \(version)")
            }
            let algorithmIdentifier = try AlgorithmIdentifier(derEncoded: &nodes)
            let privateKey = try ASN1OctetString(derEncoded: &nodes)
            return PrivateKeyInfo(algorithmIdentifier: algorithmIdentifier, privateKey: Array(privateKey.bytes))
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(Self.version)
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.privateKey)
        }
    }
}

// MARK: ECPrivateKey (RFC 5915)

/// ```
/// ECPrivateKey ::= SEQUENCE {
///     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
///     privateKey     OCTET STRING,
///     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
///     publicKey  [1] BIT STRING OPTIONAL
/// }
/// ```
/// [RFC 5915 §3](https://datatracker.ietf.org/doc/html/rfc5915#section-3)
struct ECPrivateKey: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    static let version = 1

    var privateKey: ASN1OctetString
    var namedCurve: ASN1ObjectIdentifier?
    var publicKey: ASN1BitString?

    init(privateKey: [UInt8], namedCurve: ASN1ObjectIdentifier?, publicKey: [UInt8]?) {
        self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        self.namedCurve = namedCurve
        self.publicKey = publicKey.map { ASN1BitString(bytes: $0[...]) }
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == Self.version else {
                throw ASN1Error.invalidASN1Object(reason: "Unsupported ECPrivateKey version \(version)")
            }
            let privateKey = try ASN1OctetString(derEncoded: &nodes)
            let namedCurve = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                try ASN1ObjectIdentifier(derEncoded: $0)
            }
            let publicKey = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                try ASN1BitString(derEncoded: $0)
            }
            return ECPrivateKey(
                privateKey: Array(privateKey.bytes),
                namedCurve: namedCurve,
                publicKey: publicKey.map { Array($0.bytes) }
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(Self.version)
            try coder.serialize(self.privateKey)
            if let namedCurve = self.namedCurve {
                try coder.serialize(namedCurve, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let publicKey = self.publicKey {
                try coder.serialize(publicKey, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
        }
    }
}

// MARK: RSAPublicKey (PKCS #1)

/// ```
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
/// [RFC 8017 §A.1.1](https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1)
///
/// The integers are exposed as unsigned big-endian magnitudes (no DER sign byte).
struct RSAPublicKeyPKCS1: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    var modulus: ArraySlice<UInt8>
    var publicExponent: ArraySlice<UInt8>

    init(modulus: ArraySlice<UInt8>, publicExponent: ArraySlice<UInt8>) {
        self.modulus = modulus
        self.publicExponent = publicExponent
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let modulus = try ArraySlice<UInt8>(derEncoded: &nodes)
            let publicExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            return RSAPublicKeyPKCS1(modulus: modulus, publicExponent: publicExponent)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.modulus)
            try coder.serialize(self.publicExponent)
        }
    }
}

// MARK: Encrypted Private Keys (PKCS #8 / PKCS #5 v2)

/// ```
/// EncryptedPrivateKeyInfo ::= SEQUENCE {
///     encryptionAlgorithm  SEQUENCE {
///         algorithm   OBJECT IDENTIFIER,  -- id-PBES2
///         parameters  PBES2-params
///     },
///     encryptedData        OCTET STRING
/// }
///
/// PBES2-params ::= SEQUENCE {
///     keyDerivationFunc  AlgorithmIdentifier {{PBES2-KDFs}},
///     encryptionScheme   AlgorithmIdentifier {{PBES2-Encs}}
/// }
/// ```
/// [RFC 5208 §6](https://datatracker.ietf.org/doc/html/rfc5208#section-6),
/// [RFC 8018 §A.4](https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.4)
struct EncryptedPrivateKeyInfo: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    var encryptionAlgorithm: ASN1ObjectIdentifier
    var keyDerivationFunction: PBKDF2AlgorithmIdentifier
    var encryptionScheme: CipherAlgorithmIdentifier
    var encryptedData: ASN1OctetString

    init(
        encryptionAlgorithm: ASN1ObjectIdentifier = ASN1ObjectIdentifier.LibP2P.pbes2,
        keyDerivationFunction: PBKDF2AlgorithmIdentifier,
        encryptionScheme: CipherAlgorithmIdentifier,
        encryptedData: [UInt8]
    ) {
        self.encryptionAlgorithm = encryptionAlgorithm
        self.keyDerivationFunction = keyDerivationFunction
        self.encryptionScheme = encryptionScheme
        self.encryptedData = ASN1OctetString(contentBytes: encryptedData[...])
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            guard let encryptionAlgorithmNode = nodes.next() else {
                throw ASN1Error.invalidASN1Object(reason: "EncryptedPrivateKeyInfo missing encryptionAlgorithm")
            }
            let (encryptionAlgorithm, kdf, scheme) = try DER.sequence(
                encryptionAlgorithmNode,
                identifier: .sequence
            ) { nodes in
                let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
                guard let parametersNode = nodes.next() else {
                    throw ASN1Error.invalidASN1Object(reason: "EncryptedPrivateKeyInfo missing PBES2 parameters")
                }
                let (kdf, scheme) = try DER.sequence(parametersNode, identifier: .sequence) { nodes in
                    (
                        try PBKDF2AlgorithmIdentifier(derEncoded: &nodes),
                        try CipherAlgorithmIdentifier(derEncoded: &nodes)
                    )
                }
                return (algorithm, kdf, scheme)
            }
            let encryptedData = try ASN1OctetString(derEncoded: &nodes)
            return EncryptedPrivateKeyInfo(
                encryptionAlgorithm: encryptionAlgorithm,
                keyDerivationFunction: kdf,
                encryptionScheme: scheme,
                encryptedData: Array(encryptedData.bytes)
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(self.encryptionAlgorithm)
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(self.keyDerivationFunction)
                    try coder.serialize(self.encryptionScheme)
                }
            }
            try coder.serialize(self.encryptedData)
        }
    }
}

/// ```
/// SEQUENCE {
///     algorithm   OBJECT IDENTIFIER,  -- id-PBKDF2
///     parameters  PBKDF2-params ::= SEQUENCE {
///         salt            OCTET STRING,
///         iterationCount  INTEGER (1..MAX)
///     }
/// }
/// ```
/// [RFC 8018 §A.2](https://datatracker.ietf.org/doc/html/rfc8018#appendix-A.2)
///
/// - Note: The optional `keyLength` and `prf` fields are not supported (the PRF is always HMAC-SHA1).
struct PBKDF2AlgorithmIdentifier: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    var algorithm: ASN1ObjectIdentifier
    var salt: ASN1OctetString
    var iterationCount: Int

    init(algorithm: ASN1ObjectIdentifier, salt: [UInt8], iterationCount: Int) {
        self.algorithm = algorithm
        self.salt = ASN1OctetString(contentBytes: salt[...])
        self.iterationCount = iterationCount
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
            guard let parametersNode = nodes.next() else {
                throw ASN1Error.invalidASN1Object(reason: "PBKDF2 missing parameters")
            }
            let (salt, iterationCount) = try DER.sequence(parametersNode, identifier: .sequence) { nodes in
                (try ASN1OctetString(derEncoded: &nodes), try Int(derEncoded: &nodes))
            }
            return PBKDF2AlgorithmIdentifier(
                algorithm: algorithm,
                salt: Array(salt.bytes),
                iterationCount: iterationCount
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(self.salt)
                try coder.serialize(self.iterationCount)
            }
        }
    }
}

/// ```
/// SEQUENCE {
///     algorithm   OBJECT IDENTIFIER,  -- ex: aes128-CBC-PAD
///     parameters  OCTET STRING        -- the initialization vector
/// }
/// ```
struct CipherAlgorithmIdentifier: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier { .sequence }

    var algorithm: ASN1ObjectIdentifier
    var iv: ASN1OctetString

    init(algorithm: ASN1ObjectIdentifier, iv: [UInt8]) {
        self.algorithm = algorithm
        self.iv = ASN1OctetString(contentBytes: iv[...])
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithm = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let iv = try ASN1OctetString(derEncoded: &nodes)
            return CipherAlgorithmIdentifier(algorithm: algorithm, iv: Array(iv.bytes))
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            try coder.serialize(self.iv)
        }
    }
}

// MARK: Node Traversal

extension ASN1Node {
    /// Recursively collects every OBJECT IDENTIFIER contained in this node tree
    /// (including those nested inside explicitly tagged / context specific nodes).
    var containedObjectIdentifiers: [ASN1ObjectIdentifier] {
        switch self.content {
        case .primitive:
            guard self.identifier == .objectIdentifier,
                let oid = try? ASN1ObjectIdentifier(derEncoded: self)
            else { return [] }
            return [oid]
        case .constructed(let children):
            return children.flatMap { $0.containedObjectIdentifiers }
        }
    }
}
