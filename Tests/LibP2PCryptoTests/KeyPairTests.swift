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
import Multibase
import Multicodec
import Multihash
import SwiftProtobuf
import Testing

@testable import LibP2PCrypto

/// Behavior every key type must share, run against each supported key type
@Suite("Key Pair Tests")
struct KeyPairTests {
    typealias KeyPair = LibP2PCrypto.Keys.KeyPair
    typealias KeyPairType = LibP2PCrypto.Keys.KeyPairType

    static let keyPairTypes: [KeyPairType] = [
        .rsa(bits: .b2048),
        .ed25519,
        .secp256k1,
        .ecdsa(curve: .p256),
        .ecdsa(curve: .p384),
        .ecdsa(curve: .p521),
    ]

    /// The key size (in bits) `attributes()` should report
    static func expectedBits(of keyPairType: KeyPairType) -> Int {
        switch keyPairType {
        case .rsa(let bits): return bits.bits
        case .ed25519, .secp256k1: return 256
        case .ecdsa(let curve): return curve.bits
        }
    }

    // MARK: Generation

    @Test(arguments: keyPairTypes)
    func generation(keyPairType: KeyPairType) throws {
        let keyPair = try KeyPair(keyPairType)

        #expect(keyPair.keyType == keyPairType.keyType)
        #expect(keyPair.publicKey.keyType == keyPairType.keyType)
        #expect(keyPair.privateKey?.keyType == keyPairType.keyType)
        #expect(keyPair.hasPrivateKey)

        let attributes = try #require(keyPair.attributes())
        #expect(attributes.type == keyPairType)
        #expect(attributes.size == Self.expectedBits(of: keyPairType))
        #expect(attributes.isPrivate)

        let publicOnly = try KeyPair(publicKey: keyPair.publicKey)
        #expect(publicOnly.hasPrivateKey == false)
        #expect(publicOnly.attributes()?.type == keyPairType)
        #expect(publicOnly.attributes()?.isPrivate == false)

        // Freshly generated keys are unique
        #expect(try KeyPair(keyPairType) != keyPair)
    }

    // MARK: Raw Representation

    /// `T(rawRepresentation: key.rawRepresentation) == key` for every public and private key type
    @Test(arguments: keyPairTypes)
    func rawRepresentationRoundTrip(keyPairType: KeyPairType) throws {
        let keyPair = try KeyPair(keyPairType)
        let privateKey = try #require(keyPair.privateKey)

        let restoredPublicKey = try type(of: keyPair.publicKey).init(
            rawRepresentation: keyPair.publicKey.rawRepresentation
        )
        #expect(restoredPublicKey.rawRepresentation == keyPair.publicKey.rawRepresentation)

        let restoredPrivateKey = try type(of: privateKey).init(rawRepresentation: privateKey.rawRepresentation)
        #expect(restoredPrivateKey.rawRepresentation == privateKey.rawRepresentation)

        #expect(try KeyPair(privateKey: restoredPrivateKey) == keyPair)
        #expect(try KeyPair(publicKey: restoredPublicKey) == KeyPair(publicKey: keyPair.publicKey))
    }

    // MARK: Marshaling

    @Test(arguments: keyPairTypes)
    func marshalingRoundTrip(keyPairType: KeyPairType) throws {
        let keyPair = try KeyPair(keyPairType)
        let privateKey = try #require(keyPair.privateKey)
        let marshaledPublicKey = try keyPair.marshalPublicKey()
        let marshaledPrivateKey = try keyPair.marshalPrivateKey()

        // The protobuf carries the key type
        let publicProto = try ProtoPublicKey(serializedBytes: marshaledPublicKey)
        let privateProto = try ProtoPrivateKey(serializedBytes: marshaledPrivateKey)
        #expect(LibP2PCrypto.Keys.KeyType(publicProto.type) == keyPairType.keyType)
        #expect(LibP2PCrypto.Keys.KeyType(privateProto.type) == keyPairType.keyType)

        // Each key type can be instantiated from its protobuf's data field
        let publicKey = try type(of: keyPair.publicKey).init(marshaledData: publicProto.data)
        #expect(publicKey.rawRepresentation == keyPair.publicKey.rawRepresentation)
        let restoredPrivateKey = try type(of: privateKey).init(marshaledData: privateProto.data)
        #expect(restoredPrivateKey.rawRepresentation == privateKey.rawRepresentation)

        // KeyPairs round trip, and re-marshal to the exact same bytes
        let restoredPublicOnly = try KeyPair(marshaledPublicKey: marshaledPublicKey)
        let restored = try KeyPair(marshaledPrivateKey: marshaledPrivateKey)
        #expect(try restoredPublicOnly == KeyPair(publicKey: keyPair.publicKey))
        #expect(restored == keyPair)
        #expect(try restoredPublicOnly.marshalPublicKey() == marshaledPublicKey)
        #expect(try restored.marshalPrivateKey() == marshaledPrivateKey)

        // Base encoded marshaled keys
        #expect(
            try KeyPair(marshaledPublicKey: marshaledPublicKey.asString(base: .base64Pad), base: .base64Pad)
                == restoredPublicOnly
        )
        #expect(
            try KeyPair(marshaledPrivateKey: marshaledPrivateKey.asString(base: .base64Pad), base: .base64Pad)
                == restored
        )

        // The (un)marshaling helpers agree with the protobufs
        #expect(
            try LibP2PCrypto.Keys.unmarshalPublicKey(buf: Array(marshaledPublicKey))
                == publicProto.data.asString(base: .base16)
        )
        #expect(
            try LibP2PCrypto.Keys.unmarshalPrivateKey(buf: Array(marshaledPrivateKey))
                == privateProto.data.asString(base: .base16)
        )
        #expect(
            try LibP2PCrypto.Keys.marshalPrivateKey(raw: privateProto.data, keyType: keyPairType.keyType)
                == Array(marshaledPrivateKey)
        )
    }

    // MARK: Peer IDs

    /// Marshaled public keys of 42 bytes or less are inlined (`identity`), larger keys are `sha2-256` hashed
    @Test(arguments: keyPairTypes)
    func peerIDs(keyPairType: KeyPairType) throws {
        let keyPair = try KeyPair(keyPairType)
        let privateKey = try #require(keyPair.privateKey)
        let marshaled = try keyPair.marshalPublicKey()

        let inlined = marshaled.count <= 42
        #expect(inlined == [.ed25519, .secp256k1].contains(keyPairType.keyType))

        let expected =
            inlined
            ? try Multihash(hashing: marshaled, codec: .identity)
            : try Multihash(hashing: marshaled, codec: .sha2_256)
        #expect(try keyPair.multihash().value == expected.value)
        #expect(try keyPair.rawID() == expected.value)

        // The key pair, its public key and its private key all share the same id
        #expect(try keyPair.publicKey.id() == keyPair.id())
        #expect(try privateKey.id() == keyPair.id())
        #expect(try privateKey.rawID() == keyPair.rawID())
        #expect(try keyPair.id(withMultibasePrefix: false) == expected.asString(base: .base58btc))
    }

    // MARK: Signatures

    @Test(arguments: keyPairTypes)
    func signAndVerify(keyPairType: KeyPairType) throws {
        let message = Data("Hello, swift-libp2p-crypto!".utf8)
        let keyPair = try KeyPair(keyPairType)
        let signature = try keyPair.sign(message: message)

        #expect(signature != message)
        #expect(try keyPair.verify(signature: signature, for: message))

        // A public only key pair can verify, but not sign
        let publicOnly = try KeyPair(publicKey: keyPair.publicKey)
        #expect(try publicOnly.verify(signature: signature, for: message))
        #expect(throws: LibP2PCrypto.Keys.KeyError.noPrivateKey) { try publicOnly.sign(message: message) }

        // A tweaked message is rejected
        #expect(try keyPair.verify(signature: signature, for: Data(message.reversed())) == false)
        #expect(try keyPair.verify(signature: signature, for: Data(message.dropLast())) == false)

        // A tweaked signature is rejected (`false`), while a malformed one may throw instead
        var tampered = signature
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
        #expect(try keyPair.verify(signature: tampered, for: message) == false)
        #expect((try? keyPair.verify(signature: Data(signature.dropLast()), for: message)) != true)
        #expect((try? keyPair.verify(signature: Data(), for: message)) != true)

        // Another key's signature is rejected
        #expect(try KeyPair(keyPairType).verify(signature: signature, for: message) == false)
    }

    // MARK: PEM

    @Test(arguments: keyPairTypes)
    func pemRoundTrip(keyPairType: KeyPairType) throws {
        let keyPair = try KeyPair(keyPairType)
        let privateKey = try #require(keyPair.privateKey)

        let publicPEM = try keyPair.exportPublicPEMString()
        #expect(publicPEM.hasPrefix("-----BEGIN PUBLIC KEY-----\n"))
        #expect(try KeyPair(pem: publicPEM) == KeyPair(publicKey: keyPair.publicKey))
        #expect(try Self.importPublicKey(publicPEM, like: keyPair.publicKey) == keyPair.publicKey.rawRepresentation)

        let privatePEM = try keyPair.exportPrivatePEMString()
        #expect(try KeyPair(pem: privatePEM) == keyPair)
        #expect(try Self.importPrivateKey(privatePEM, like: privateKey) == privateKey.rawRepresentation)

        let password = "correct horse battery staple"
        let encryptedPEM = try keyPair.exportEncryptedPrivatePEMString(
            withPassword: password,
            usingPBKDF: .pbkdf2(
                salt: LibP2PCrypto.randomBytes(length: 16),
                iterations: 2048,
                prf: .hmacWithSHA256
            )
        )
        #expect(encryptedPEM.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"))
        #expect(try KeyPair(pem: encryptedPEM, password: password) == keyPair)
        #expect(
            try Self.importPrivateKey(encryptedPEM, password: password, like: privateKey)
                == privateKey.rawRepresentation
        )
        #expect(throws: (any Error).self) { try KeyPair(pem: encryptedPEM, password: "wrong password") }
        #expect(throws: (any Error).self) { try KeyPair(pem: encryptedPEM) }
    }

    /// Imports a PEM directly into the same key type as `like`, returning its raw representation
    private static func importPublicKey<Key: CommonPublicKey>(_ pem: String, like _: Key) throws -> Data {
        try Key(pem: pem).rawRepresentation
    }

    /// Imports a PEM directly into the same key type as `like`, returning its raw representation
    private static func importPrivateKey<Key: CommonPrivateKey>(
        _ pem: String,
        password: String? = nil,
        like _: Key
    ) throws -> Data {
        try Key(pem: pem, password: password).rawRepresentation
    }
}
