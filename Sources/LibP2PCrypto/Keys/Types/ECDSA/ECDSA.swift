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
//
//  ECDSA (NIST P-256 / P-384 / P-521) key support, as specified by the libp2p peer-id spec
//  and implemented by go-libp2p (core/crypto/ecdsa.go):
//  - Public keys are marshaled as DER encoded PKIX SubjectPublicKeyInfo structures
//  - Private keys are marshaled as DER encoded SEC1 ECPrivateKey structures (RFC 5915)
//  - Messages are hashed with SHA-256 (regardless of the curve) and signatures are DER encoded
//    `SEQUENCE { r INTEGER, s INTEGER }` structures
//
//  - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#ecdsa

import Crypto
import Foundation
import SwiftASN1
import SwiftProtobuf

// MARK: - Backing protocols

/// Unifies the swift-crypto `P256/P384/P521.Signing.ECDSASignature` APIs
protocol ECDSASignatureBacking {
    init<D: DataProtocol>(derRepresentation: D) throws
    var derRepresentation: Data { get }
}

/// Unifies the swift-crypto `P256/P384/P521.Signing.PublicKey` APIs so their libp2p conformances can share a single implementation
protocol ECDSAPublicKeyBacking: CommonPublicKey {
    associatedtype ECDSASignature: ECDSASignatureBacking

    /// The curve this key type belongs to
    static var curve: LibP2PCrypto.Keys.ElipticCurveType { get }

    init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8
    init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws
    init<Bytes: ContiguousBytes>(compressedRepresentation: Bytes) throws

    /// The DER encoded SubjectPublicKeyInfo
    var derRepresentation: Data { get }
    /// The uncompressed `0x04 || X || Y` point
    var x963Representation: Data { get }

    func isValidSignature<D: Digest>(_ signature: ECDSASignature, for digest: D) -> Bool
}

/// Unifies the swift-crypto `P256/P384/P521.Signing.PrivateKey` APIs so their libp2p conformances can share a single implementation
protocol ECDSAPrivateKeyBacking: CommonPrivateKey {
    associatedtype ECDSAPublicKey: ECDSAPublicKeyBacking

    var publicKey: ECDSAPublicKey { get }

    /// The DER encoded PKCS #8 PrivateKeyInfo
    var derRepresentation: Data { get }

    func signature<D: Digest>(for digest: D) throws -> ECDSAPublicKey.ECDSASignature
}

extension P256.Signing.ECDSASignature: ECDSASignatureBacking {}
extension P384.Signing.ECDSASignature: ECDSASignatureBacking {}
extension P521.Signing.ECDSASignature: ECDSASignatureBacking {}

// MARK: - Curves

extension LibP2PCrypto.Keys.ElipticCurveType {
    /// The curve's named curve object identifier
    var objectIdentifier: ASN1ObjectIdentifier {
        switch self {
        case .P256: return ASN1ObjectIdentifier.LibP2P.prime256v1
        case .P384: return ASN1ObjectIdentifier.LibP2P.secp384r1
        case .P521: return ASN1ObjectIdentifier.LibP2P.secp521r1
        }
    }

    /// The byte length of a private key scalar on this curve
    var privateKeyByteCount: Int {
        (self.bits + 7) / 8
    }

    init?(objectIdentifier: ASN1ObjectIdentifier) {
        guard let curve = Self.allCases.first(where: { $0.objectIdentifier == objectIdentifier }) else {
            return nil
        }
        self = curve
    }
}

// MARK: - Shared Implementation

enum ECDSAKeys {

    // MARK: Signatures

    /// Signs the SHA-256 hash of `message` and returns the DER encoded signature
    static func sign<Key: ECDSAPrivateKeyBacking>(_ message: Data, with key: Key) throws -> Data {
        try key.signature(for: Crypto.SHA256.hash(data: message)).derRepresentation
    }

    /// Verifies a DER encoded signature against the SHA-256 hash of `message`
    /// - Throws: if the signature isn't valid DER
    static func verify<Key: ECDSAPublicKeyBacking>(_ signature: Data, for message: Data, with key: Key) throws -> Bool {
        let sig: Key.ECDSASignature
        do {
            sig = try Key.ECDSASignature(derRepresentation: signature)
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("ECDSA: signature is not a valid DER encoded signature")
        }
        return key.isValidSignature(sig, for: Crypto.SHA256.hash(data: message))
    }

    // MARK: Marshaling

    /// Protobuf marshals the public key as a DER encoded SubjectPublicKeyInfo
    static func marshal<Key: ECDSAPublicKeyBacking>(publicKey key: Key) throws -> Data {
        var publicKey = PublicKey()
        publicKey.type = .ecdsa
        publicKey.data = key.derRepresentation
        return try publicKey.serializedData()
    }

    /// Protobuf marshals the private key as a DER encoded SEC1 ECPrivateKey
    static func marshal<Key: ECDSAPrivateKeyBacking>(privateKey key: Key) throws -> Data {
        var privateKey = PrivateKey()
        privateKey.type = .ecdsa
        privateKey.data = try Data(self.sec1DER(for: key))
        return try privateKey.serializedData()
    }

    /// The DER encoded SEC1 ECPrivateKey (including the named curve and public key), equivalent to go's `x509.MarshalECPrivateKey`
    static func sec1DER<Key: ECDSAPrivateKeyBacking>(for key: Key) throws -> [UInt8] {
        try ECPrivateKey(
            privateKey: [UInt8](key.rawRepresentation),
            namedCurve: Key.ECDSAPublicKey.curve.objectIdentifier,
            publicKey: [UInt8](key.publicKey.x963Representation)
        ).serializedDERBytes()
    }

    // MARK: Unmarshaling

    /// Instantiates a public key from a DER encoded SubjectPublicKeyInfo, ensuring the named curve matches `Key`
    static func publicKey<Key: ECDSAPublicKeyBacking>(fromSPKI spki: Data, as: Key.Type = Key.self) throws -> Key {
        let curve = try self.curve(ofSPKI: spki)
        guard curve == Key.curve else {
            throw LibP2PCrypto.PEM.Error.objectIdentifierMismatch(
                got: curve.objectIdentifier,
                expected: Key.curve.objectIdentifier
            )
        }
        do {
            return try Key(derRepresentation: Array(spki))
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidMarshaledData("ECDSA: invalid \(Key.curve) public key")
        }
    }

    /// Instantiates a private key from a DER encoded SEC1 ECPrivateKey, ensuring the named curve matches `Key`
    ///
    /// - Note: Like go's `x509.ParseECPrivateKey`, the named curve parameter is required.
    static func privateKey<Key: ECDSAPrivateKeyBacking>(fromSEC1 der: Data, as: Key.Type = Key.self) throws -> Key {
        let ecPrivateKey = try self.parseSEC1(der)
        guard let namedCurve = ecPrivateKey.namedCurve else {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding("ECDSA: missing named curve parameter")
        }
        return try self.privateKey(from: ecPrivateKey, namedCurve: namedCurve)
    }

    /// Instantiates the appropriate P256 / P384 / P521 public key from a DER encoded SubjectPublicKeyInfo
    static func anyPublicKey(fromSPKI spki: Data) throws -> CommonPublicKey {
        switch try self.curve(ofSPKI: spki) {
        case .P256: return try self.publicKey(fromSPKI: spki, as: P256.Signing.PublicKey.self)
        case .P384: return try self.publicKey(fromSPKI: spki, as: P384.Signing.PublicKey.self)
        case .P521: return try self.publicKey(fromSPKI: spki, as: P521.Signing.PublicKey.self)
        }
    }

    /// Instantiates the appropriate P256 / P384 / P521 private key from a DER encoded SEC1 ECPrivateKey
    static func anyPrivateKey(fromSEC1 der: Data) throws -> CommonPrivateKey {
        let ecPrivateKey = try self.parseSEC1(der)
        guard let namedCurve = ecPrivateKey.namedCurve else {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding("ECDSA: missing named curve parameter")
        }
        guard let curve = LibP2PCrypto.Keys.ElipticCurveType(objectIdentifier: namedCurve) else {
            throw LibP2PCrypto.Keys.KeyError.unsupportedKeyType("ECDSA: unsupported named curve \(namedCurve)")
        }
        switch curve {
        case .P256: return try self.privateKey(from: ecPrivateKey, namedCurve: namedCurve) as P256.Signing.PrivateKey
        case .P384: return try self.privateKey(from: ecPrivateKey, namedCurve: namedCurve) as P384.Signing.PrivateKey
        case .P521: return try self.privateKey(from: ecPrivateKey, namedCurve: namedCurve) as P521.Signing.PrivateKey
        }
    }

    // MARK: DER (PEM)

    /// Instantiates a public key from the SubjectPublicKeyInfo's BIT STRING contents (a compressed or uncompressed EC point)
    static func publicKey<Key: ECDSAPublicKeyBacking>(fromPoint point: [UInt8], as: Key.Type = Key.self) throws -> Key {
        do {
            if point.first == 0x04 {
                return try Key(x963Representation: point)
            } else {
                return try Key(compressedRepresentation: point)
            }
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidRawRepresentation("ECDSA: invalid \(Key.curve) public key point")
        }
    }

    /// Instantiates a private key from either the raw private key scalar or a DER encoded SEC1 ECPrivateKey (where the named curve parameter is optional, as is the case when nested in a PKCS #8 PrivateKeyInfo)
    ///
    /// - Note: A SEC1 ECPrivateKey is always longer than the curve's scalar, while the scalar itself may be shorter
    ///   than the curve's size when an encoder strips leading zeros (ex: OpenSSL encodes some P-521 keys as 65 bytes)
    static func privateKey<Key: ECDSAPrivateKeyBacking>(
        fromPrivateDER der: [UInt8],
        as: Key.Type = Key.self
    ) throws -> Key {
        if der.count <= Key.ECDSAPublicKey.curve.privateKeyByteCount {
            return try self.privateKey(fromScalar: der)
        }
        let ecPrivateKey = try self.parseSEC1(Data(der))
        return try self.privateKey(
            from: ecPrivateKey,
            namedCurve: ecPrivateKey.namedCurve ?? Key.ECDSAPublicKey.curve.objectIdentifier
        )
    }

    // MARK: Helpers

    /// Extracts and validates the named curve of a DER encoded EC SubjectPublicKeyInfo
    private static func curve(ofSPKI spki: Data) throws -> LibP2PCrypto.Keys.ElipticCurveType {
        let info: SubjectPublicKeyInfo
        do {
            info = try SubjectPublicKeyInfo(derEncoded: Array(spki))
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidMarshaledData(
                "ECDSA: public key is not a valid SubjectPublicKeyInfo"
            )
        }
        guard info.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.idEcPublicKey else {
            throw LibP2PCrypto.PEM.Error.objectIdentifierMismatch(
                got: info.algorithmIdentifier.algorithm,
                expected: ASN1ObjectIdentifier.LibP2P.idEcPublicKey
            )
        }
        guard case .objectIdentifier(let namedCurve) = info.algorithmIdentifier.parameters else {
            throw LibP2PCrypto.Keys.KeyError.invalidMarshaledData("ECDSA: missing named curve parameter")
        }
        guard let curve = LibP2PCrypto.Keys.ElipticCurveType(objectIdentifier: namedCurve) else {
            throw LibP2PCrypto.Keys.KeyError.unsupportedKeyType("ECDSA: unsupported named curve \(namedCurve)")
        }
        return curve
    }

    private static func parseSEC1(_ der: Data) throws -> ECPrivateKey {
        do {
            return try ECPrivateKey(derEncoded: Array(der))
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding("ECDSA: private key is not a valid ECPrivateKey")
        }
    }

    /// Instantiates a private key from a parsed SEC1 ECPrivateKey, ensuring the curve and the (optional) attached public key match
    private static func privateKey<Key: ECDSAPrivateKeyBacking>(
        from ecPrivateKey: ECPrivateKey,
        namedCurve: ASN1ObjectIdentifier
    ) throws -> Key {
        let expected = Key.ECDSAPublicKey.curve.objectIdentifier
        guard namedCurve == expected else {
            throw LibP2PCrypto.PEM.Error.objectIdentifierMismatch(got: namedCurve, expected: expected)
        }

        let key: Key = try self.privateKey(fromScalar: Array(ecPrivateKey.privateKey.bytes))

        if let attachedPublicKey = ecPrivateKey.publicKey {
            guard key.publicKey.x963Representation == Data(attachedPublicKey.bytes) else {
                throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                    "ECDSA: unable to validate attached public key"
                )
            }
        }

        return key
    }

    /// Instantiates a private key from its scalar, left padding it to the curve's size (some encoders strip leading zeros)
    private static func privateKey<Key: ECDSAPrivateKeyBacking>(fromScalar scalar: [UInt8]) throws -> Key {
        let byteCount = Key.ECDSAPublicKey.curve.privateKeyByteCount
        guard !scalar.isEmpty, scalar.count <= byteCount else {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                "ECDSA: invalid \(Key.ECDSAPublicKey.curve) private key length \(scalar.count)"
            )
        }
        let padded = [UInt8](repeating: 0, count: byteCount - scalar.count) + scalar
        do {
            return try Key(rawRepresentation: Data(padded))
        } catch {
            throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                "ECDSA: invalid \(Key.ECDSAPublicKey.curve) private key"
            )
        }
    }
}
