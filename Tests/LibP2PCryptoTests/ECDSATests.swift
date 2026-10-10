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

import Crypto
import CryptoSwift
import Foundation
import Multicodec
import Multihash
import SwiftASN1
import SwiftProtobuf
import Testing

@testable import LibP2PCrypto

typealias ECCurve = LibP2PCrypto.Keys.ElipticCurveType

// MARK: - ECDSA Tests

@Suite("ECDSA Tests")
struct ECDSATests {

    // MARK: Generation

    @Test(arguments: ECCurve.allCases)
    func generateKeyPair(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.ECDSA(curve: curve))

        #expect(keyPair.keyType == .ecdsa)
        #expect(keyPair.keyType == .ECDSA(curve: curve))
        #expect(keyPair.hasPrivateKey)
        #expect(ECDSATests.curveOf(keyPair) == curve)

        let attributes = try #require(keyPair.attributes())
        #expect(attributes.size == curve.bits)
        #expect(attributes.isPrivate)
        guard case .ECDSA(let attributeCurve) = attributes.type else {
            Issue.record("Expected an ECDSA KeyPairType, got \(attributes.type)")
            return
        }
        #expect(attributeCurve == curve)

        // Public only key pairs report the same attributes, minus the private flag
        let publicOnly = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: keyPair.marshalPublicKey())
        #expect(publicOnly.attributes()?.size == curve.bits)
        #expect(publicOnly.attributes()?.isPrivate == false)
    }

    @Test func defaultCurveIsP256() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA())
        #expect(ECDSATests.curveOf(keyPair) == .P256)
    }

    @Test func asyncKeyGeneration() async throws {
        let keyPair = try await LibP2PCrypto.Keys.generateKeyPair(.ECDSA(curve: .P384))
        #expect(ECDSATests.curveOf(keyPair) == .P384)
        let signature = try keyPair.sign(message: ECDSAFixtures.opensslMessage)
        #expect(try keyPair.verify(signature: signature, for: ECDSAFixtures.opensslMessage))
    }

    @Test(arguments: ECCurve.allCases)
    func generatedKeysAreUnique(curve: ECCurve) throws {
        let a = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let b = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        #expect(a.privateKey?.rawRepresentation != b.privateKey?.rawRepresentation)
        #expect(try a.id() != b.id())
    }

    // MARK: Raw Representation

    @Test(arguments: ECCurve.allCases)
    func rawRepresentationRoundTrip(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let rawPublicKey = keyPair.publicKey.rawRepresentation
        let rawPrivateKey = try #require(keyPair.privateKey?.rawRepresentation)

        // X || Y and the private scalar
        #expect(rawPublicKey.count == 2 * curve.privateKeyByteCount)
        #expect(rawPrivateKey.count == curve.privateKeyByteCount)

        let recoveredPublicKeyPair = try LibP2PCrypto.Keys.KeyPair(
            publicKey: publicKey(rawRepresentation: rawPublicKey, curve: curve)
        )
        let recoveredPrivateKeyPair = try LibP2PCrypto.Keys.KeyPair(
            privateKey: privateKey(rawRepresentation: rawPrivateKey, curve: curve)
        )

        #expect(try keyPair.rawID() == recoveredPublicKeyPair.rawID())
        #expect(try keyPair.rawID() == recoveredPrivateKeyPair.rawID())
        #expect(recoveredPrivateKeyPair.privateKey?.rawRepresentation == rawPrivateKey)
    }

    // MARK: Marshaling

    @Test(arguments: ECCurve.allCases)
    func marshaledPublicKeyRoundTrip(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let marshaled = try keyPair.marshalPublicKey()

        // The protobuf carries the ECDSA type and a DER encoded SubjectPublicKeyInfo
        let proto = try PublicKey(serializedBytes: marshaled)
        #expect(proto.type == .ecdsa)
        let spki = try SubjectPublicKeyInfo(derEncoded: proto.data.byteArray)
        #expect(spki.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.idEcPublicKey)
        #expect(spki.algorithmIdentifier.parameters == .objectIdentifier(curve.objectIdentifier))
        #expect(Array(spki.key.bytes) == [0x04] + keyPair.publicKey.rawRepresentation.byteArray)

        let recovered = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaled)
        #expect(recovered.keyType == .ecdsa)
        #expect(recovered.hasPrivateKey == false)
        #expect(ECDSATests.curveOf(recovered) == curve)
        #expect(recovered.publicKey.rawRepresentation == keyPair.publicKey.rawRepresentation)
        #expect(try recovered.id() == keyPair.id())
        #expect(try recovered.marshalPublicKey() == marshaled)
    }

    @Test(arguments: ECCurve.allCases)
    func marshaledPrivateKeyRoundTrip(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let marshaled = try keyPair.marshalPrivateKey()

        // The protobuf carries the ECDSA type and a DER encoded SEC1 ECPrivateKey (with the named curve and public key)
        let proto = try PrivateKey(serializedBytes: marshaled)
        #expect(proto.type == .ecdsa)
        let ecPrivateKey = try ECPrivateKey(derEncoded: proto.data.byteArray)
        #expect(Data(ecPrivateKey.privateKey.bytes) == keyPair.privateKey?.rawRepresentation)
        #expect(ecPrivateKey.namedCurve == curve.objectIdentifier)
        #expect(
            ecPrivateKey.publicKey.map { Array($0.bytes) } == [0x04] + keyPair.publicKey.rawRepresentation.byteArray
        )

        let recovered = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaled)
        #expect(recovered.keyType == .ecdsa)
        #expect(recovered.hasPrivateKey)
        #expect(ECDSATests.curveOf(recovered) == curve)
        #expect(recovered.privateKey?.rawRepresentation == keyPair.privateKey?.rawRepresentation)
        #expect(recovered.publicKey.rawRepresentation == keyPair.publicKey.rawRepresentation)
        #expect(try recovered.marshalPrivateKey() == marshaled)
    }

    /// Marshaled ECDSA public keys exceed the 42 byte inline limit, so their peer IDs are sha2-256 multihashes
    @Test(arguments: ECCurve.allCases)
    func peerIDUsesSHA256Multihash(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let marshaled = try keyPair.marshalPublicKey()
        #expect(marshaled.count > 42)
        #expect(try keyPair.multihash().value == Multihash(hashing: marshaled, codec: .sha2_256).value)
        #expect(try keyPair.id(withMultibasePrefix: false).hasPrefix("Qm"))
        #expect(try keyPair.privateKey?.id() == keyPair.id())
    }

    // MARK: Signatures

    @Test(arguments: ECCurve.allCases)
    func signAndVerify(curve: ECCurve) throws {
        let message = ECDSAFixtures.opensslMessage
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))

        let signature = try keyPair.sign(message: message)

        // DER encoded `SEQUENCE { r INTEGER, s INTEGER }`
        let node = try DER.parse(signature.byteArray)
        #expect(node.identifier == .sequence)
        guard case .constructed(let children) = node.content else {
            Issue.record("Signature isn't a constructed ASN1 sequence")
            return
        }
        #expect(Array(children).count == 2)
        #expect(Array(children).allSatisfy { $0.identifier == .integer })

        #expect(try keyPair.verify(signature: signature, for: message))
        #expect(try keyPair.publicKey.verify(signature: signature, for: message))

        // Altered messages
        #expect(try keyPair.verify(signature: signature, for: Data(message.dropFirst())) == false)
        #expect(try keyPair.verify(signature: signature, for: Data(message.dropLast())) == false)
        #expect(try keyPair.verify(signature: signature, for: message + Data([0x00])) == false)

        // Altered signature (flip the lowest bit of `s`)
        var alteredSignature = signature
        alteredSignature[alteredSignature.count - 1] ^= 0x01
        #expect(try keyPair.verify(signature: alteredSignature, for: message) == false)

        // Malformed signatures throw
        #expect(throws: Error.self) { try keyPair.verify(signature: Data(signature.dropLast()), for: message) }
        #expect(throws: Error.self) { try keyPair.verify(signature: Data(signature.dropFirst()), for: message) }
        #expect(throws: Error.self) { try keyPair.verify(signature: Data(), for: message) }

        // Signatures from a different key on the same curve
        let otherKeyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        #expect(try otherKeyPair.verify(signature: signature, for: message) == false)
    }

    @Test func signaturesDontVerifyAcrossCurves() throws {
        let message = ECDSAFixtures.opensslMessage
        for signingCurve in ECCurve.allCases {
            let signer = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: signingCurve))
            let signature = try signer.sign(message: message)
            for verifyingCurve in ECCurve.allCases where verifyingCurve != signingCurve {
                let verifier = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: verifyingCurve))
                // Depending on the curves the signature might not even parse, either way it can't verify
                #expect((try? verifier.verify(signature: signature, for: message)) != true)
            }
        }
    }

    /// OpenSSL signatures over the SHA-256 hash (`openssl dgst -sha256 -sign`) verify on every curve,
    /// ensuring we interoperate with external implementations and always use SHA-256 (even for P-384 and P-521).
    @Test(arguments: ECCurve.allCases)
    func verifyOpenSSLSignature(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: ECDSAFixtures.privatePEM(for: curve))
        let signature = ECDSAFixtures.opensslSignature(for: curve)

        #expect(try keyPair.verify(signature: signature, for: ECDSAFixtures.opensslMessage))
        #expect(try keyPair.verify(signature: signature, for: ECDSAFixtures.goMessage) == false)

        // Verify with the public key alone (imported from the OpenSSL derived public key PEM)
        let publicKeyPair = try LibP2PCrypto.Keys.KeyPair(pem: ECDSAFixtures.derivedPublicPEM(for: curve))
        #expect(try publicKeyPair.verify(signature: signature, for: ECDSAFixtures.opensslMessage))
    }

    // MARK: PEM

    @Test(arguments: ECCurve.allCases)
    func importPublicKeyPEMFixtures(curve: ECCurve) throws {
        let pem = ECDSAFixtures.publicPEM(for: curve)

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)
        #expect(keyPair.keyType == .ecdsa)
        #expect(keyPair.hasPrivateKey == false)
        #expect(ECDSATests.curveOf(keyPair) == curve)

        let typed = try publicKey(pem: pem, curve: curve)
        #expect(typed.rawRepresentation == keyPair.publicKey.rawRepresentation)

        // Re-exporting yields the original PEM
        #expect(try keyPair.exportPublicPEMString() == pem)
    }

    @Test(arguments: ECCurve.allCases)
    func importPrivateKeyPEMFixtures(curve: ECCurve) throws {
        // The fixtures are `-----BEGIN EC PRIVATE KEY-----` SEC1 encodings
        let pem = ECDSAFixtures.privatePEM(for: curve)

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)
        #expect(keyPair.keyType == .ecdsa)
        #expect(keyPair.hasPrivateKey)
        #expect(ECDSATests.curveOf(keyPair) == curve)

        let typed = try privateKey(pem: pem, curve: curve)
        #expect(typed.rawRepresentation == keyPair.privateKey?.rawRepresentation)

        // The derived public key matches the one OpenSSL derives
        #expect(try keyPair.exportPublicPEMString() == ECDSAFixtures.derivedPublicPEM(for: curve))
    }

    @Test(arguments: ECCurve.allCases)
    func pemExportRoundTrip(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))

        let publicPEM = try keyPair.exportPublicPEMString()
        let privatePEM = try keyPair.exportPrivatePEMString()
        #expect(publicPEM.hasPrefix("-----BEGIN PUBLIC KEY-----\n"))
        #expect(privatePEM.hasPrefix("-----BEGIN PRIVATE KEY-----\n"))

        // Our exports match swift-crypto's own (SPKI and PKCS #8) PEM encodings
        let swiftCrypto = try #require(swiftCryptoPEMs(of: keyPair))
        #expect(publicPEM == swiftCrypto.public)
        #expect(privatePEM == swiftCrypto.private)

        let recoveredPublic = try LibP2PCrypto.Keys.KeyPair(pem: publicPEM)
        #expect(recoveredPublic.keyType == .ecdsa)
        #expect(recoveredPublic.publicKey.rawRepresentation == keyPair.publicKey.rawRepresentation)

        let recoveredPrivate = try LibP2PCrypto.Keys.KeyPair(pem: privatePEM)
        #expect(recoveredPrivate.keyType == .ecdsa)
        #expect(recoveredPrivate.privateKey?.rawRepresentation == keyPair.privateKey?.rawRepresentation)
        #expect(try recoveredPrivate.id() == keyPair.id())
    }

    @Test(arguments: ECCurve.allCases)
    func exportedDERStructures(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let privateKey = try #require(keyPair.privateKey)
        let point = [0x04] + keyPair.publicKey.rawRepresentation.byteArray

        // Public: SubjectPublicKeyInfo { id-ecPublicKey, namedCurve } BIT STRING point
        let spki = try SubjectPublicKeyInfo(derEncoded: keyPair.publicKey.exportPublicKeyPEMRaw())
        #expect(spki.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.idEcPublicKey)
        #expect(spki.algorithmIdentifier.parameters == .objectIdentifier(curve.objectIdentifier))
        #expect(Array(spki.key.bytes) == point)
        #expect(try keyPair.publicKey.publicKeyDER() == point)

        // Private: PrivateKeyInfo { 0, { id-ecPublicKey, namedCurve }, OCTET STRING ECPrivateKey }
        let privateKeyInfo = try PrivateKeyInfo(derEncoded: privateKey.exportPrivateKeyPEMRaw())
        #expect(privateKeyInfo.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.idEcPublicKey)
        #expect(privateKeyInfo.algorithmIdentifier.parameters == .objectIdentifier(curve.objectIdentifier))
        let nested = try ECPrivateKey(derEncoded: Array(privateKeyInfo.privateKey.bytes))
        #expect(Data(nested.privateKey.bytes) == privateKey.rawRepresentation)

        // privateKeyDER is the SEC1 ECPrivateKey
        let sec1 = try ECPrivateKey(derEncoded: privateKey.privateKeyDER())
        #expect(Data(sec1.privateKey.bytes) == privateKey.rawRepresentation)
        #expect(sec1.namedCurve == curve.objectIdentifier)
        #expect(sec1.publicKey.map { Array($0.bytes) } == point)
    }

    @Test(arguments: ECCurve.allCases)
    func privateDERVariants(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        let raw = try #require(keyPair.privateKey?.rawRepresentation).byteArray
        let point = [0x04] + keyPair.publicKey.rawRepresentation.byteArray

        let variants: [String: [UInt8]] = [
            "raw scalar": raw,
            "SEC1 with curve and public key": try ECPrivateKey(
                privateKey: raw,
                namedCurve: curve.objectIdentifier,
                publicKey: point
            ).serializedDERBytes(),
            "SEC1 with curve only": try ECPrivateKey(
                privateKey: raw,
                namedCurve: curve.objectIdentifier,
                publicKey: nil
            )
            .serializedDERBytes(),
            "SEC1 without parameters": try ECPrivateKey(privateKey: raw, namedCurve: nil, publicKey: nil)
                .serializedDERBytes(),
        ]

        for (name, der) in variants {
            let key = try privateKey(privateDER: der, curve: curve)
            #expect(key.rawRepresentation.byteArray == raw, "\(name)")
        }

        // A SEC1 PEM without curve parameters can still be imported when the key type is known
        let sec1PEM = pem(variants["SEC1 without parameters"]!, type: "EC PRIVATE KEY")
        #expect(try privateKey(pem: sec1PEM, curve: curve).rawRepresentation.byteArray == raw)

        // A PKCS #8 PEM produced by swift-crypto
        let pkcs8PEM = try #require(swiftCryptoPEMs(of: keyPair)).private
        #expect(try privateKey(pem: pkcs8PEM, curve: curve).rawRepresentation.byteArray == raw)
    }

    @Test(arguments: ECCurve.allCases)
    func encryptedPEMRoundTrip(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))

        let encryptedPEM = try keyPair.exportEncryptedPrivatePEMString(
            withPassword: "mypassword",
            usingPBKDF: .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 16), iterations: testPBKDF2Iterations)
        )
        #expect(encryptedPEM.hasPrefix("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"))

        let recovered = try LibP2PCrypto.Keys.KeyPair(pem: encryptedPEM, password: "mypassword")
        #expect(recovered.keyType == .ecdsa)
        #expect(ECDSATests.curveOf(recovered) == curve)
        #expect(recovered.privateKey?.rawRepresentation == keyPair.privateKey?.rawRepresentation)
        #expect(try recovered.id() == keyPair.id())

        #expect(throws: Error.self) { try LibP2PCrypto.Keys.KeyPair(pem: encryptedPEM, password: "wrongpassword") }
    }

    // MARK: Rejections

    @Test func pemCurveMismatchesThrow() throws {
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            try P256.Signing.PublicKey(pem: TestPEMKeys.EC_384_PUBLIC, asType: P256.Signing.PublicKey.self)
        }
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            try P521.Signing.PublicKey(pem: TestPEMKeys.EC_256_PUBLIC, asType: P521.Signing.PublicKey.self)
        }
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            try P256.Signing.PrivateKey(pem: TestPEMKeys.EC_384_PRIVATE, asType: P256.Signing.PrivateKey.self)
        }
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            try P384.Signing.PrivateKey(pem: TestPEMKeys.EC_521_PRIVATE, asType: P384.Signing.PrivateKey.self)
        }
        // Secp256k1 keys share the id-ecPublicKey algorithm but aren't ECDSA (NIST) keys
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            try P256.Signing.PublicKey(pem: TestPEMKeys.SECP256k1_KeyPair.PUBLIC, asType: P256.Signing.PublicKey.self)
        }
    }

    /// EC PEMs are routed to the correct key type based on their named curve
    @Test func pemRoutingByNamedCurve() throws {
        #expect(try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.SECP256k1_KeyPair.PUBLIC).keyType == .secp256k1)
        #expect(try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.SECP256k1_KeyPair.PRIVATE).keyType == .secp256k1)
        for curve in ECCurve.allCases {
            #expect(try LibP2PCrypto.Keys.KeyPair(pem: ECDSAFixtures.publicPEM(for: curve)).keyType == .ecdsa)
            #expect(try LibP2PCrypto.Keys.KeyPair(pem: ECDSAFixtures.privatePEM(for: curve)).keyType == .ecdsa)
        }
    }

    @Test func marshaledKeysWithUnsupportedCurvesThrow() throws {
        // An ECDSA typed public key carrying a secp256k1 SubjectPublicKeyInfo
        let secp256k1 = try LibP2PCrypto.Keys.KeyPair(.Secp256k1)
        let secp256k1SPKI = try secp256k1.publicKey.exportPublicKeyPEMRaw()
        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKey(type: .ecdsa, data: secp256k1SPKI))
        }

        // An ECDSA typed private key carrying a secp256k1 ECPrivateKey
        let secp256k1SEC1 = try ECPrivateKey(
            privateKey: secp256k1.privateKey!.rawRepresentation.byteArray,
            namedCurve: ASN1ObjectIdentifier.LibP2P.secp256k1,
            publicKey: nil
        ).serializedDERBytes()
        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey(type: .ecdsa, data: secp256k1SEC1))
        }

        // An Ed25519 SubjectPublicKeyInfo
        let ed25519SPKI = try LibP2PCrypto.Keys.KeyPair(.Ed25519).publicKey.exportPublicKeyPEMRaw()
        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKey(type: .ecdsa, data: ed25519SPKI))
        }

        // Garbage
        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKey(type: .ecdsa, data: [0x30, 0x00]))
        }
        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey(type: .ecdsa, data: [0x01, 0x02]))
        }
    }

    /// Like go's `x509.ParseECPrivateKey`, marshaled private keys must specify their named curve
    @Test func marshaledPrivateKeyRequiresNamedCurve() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: .P256))
        let sec1 = try ECPrivateKey(
            privateKey: keyPair.privateKey!.rawRepresentation.byteArray,
            namedCurve: nil,
            publicKey: nil
        ).serializedDERBytes()
        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey(type: .ecdsa, data: sec1))
        }
    }

    @Test func mismatchedAttachedPublicKeyThrows() throws {
        let a = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: .P256))
        let b = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: .P256))
        let sec1 = try ECPrivateKey(
            privateKey: a.privateKey!.rawRepresentation.byteArray,
            namedCurve: ECCurve.P256.objectIdentifier,
            publicKey: [0x04] + b.publicKey.rawRepresentation.byteArray
        ).serializedDERBytes()

        #expect(throws: Error.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey(type: .ecdsa, data: sec1))
        }
        #expect(throws: Error.self) { try P256.Signing.PrivateKey(privateDER: sec1) }
    }

    @Test func typedUnmarshalingRejectsOtherCurves() throws {
        let p384 = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: .P384))
        let spki = try PublicKey(serializedBytes: p384.marshalPublicKey()).data
        let sec1 = try PrivateKey(serializedBytes: p384.marshalPrivateKey()).data

        #expect(throws: Error.self) { try P256.Signing.PublicKey(marshaledData: spki) }
        #expect(throws: Error.self) { try P521.Signing.PublicKey(marshaledData: spki) }
        #expect(throws: Error.self) { try P256.Signing.PrivateKey(marshaledData: sec1) }
        #expect(throws: Error.self) { try P521.Signing.PrivateKey(marshaledData: sec1) }
        #expect(try P384.Signing.PublicKey(marshaledData: spki).rawRepresentation == p384.publicKey.rawRepresentation)
    }

    @Test(arguments: ECCurve.allCases)
    func invalidPrivateKeyScalarsThrow(curve: ECCurve) throws {
        // Zero isn't a valid private key
        #expect(throws: Error.self) {
            try privateKey(privateDER: [UInt8](repeating: 0, count: curve.privateKeyByteCount), curve: curve)
        }
        // Longer than the curve's scalar
        let tooLong = try ECPrivateKey(
            privateKey: [UInt8](repeating: 1, count: curve.privateKeyByteCount + 1),
            namedCurve: curve.objectIdentifier,
            publicKey: nil
        ).serializedDERBytes()
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) { try privateKey(privateDER: tooLong, curve: curve) }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey(type: .ecdsa, data: tooLong))
        }
    }

    // MARK: Misc

    @Test(arguments: ECCurve.allCases)
    func encryptionIsUnsupported(curve: ECCurve) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ECDSA(curve: curve))
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) { try keyPair.encrypt(data: Data("hello".utf8)) }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) { try keyPair.decrypt(data: Data("hello".utf8)) }
    }

    @Test func equatable() throws {
        let key = P256.Signing.PrivateKey()
        let sameKey = try P256.Signing.PrivateKey(rawRepresentation: key.rawRepresentation)
        let otherKey = P256.Signing.PrivateKey()

        #expect(key == sameKey)
        #expect(key != otherKey)
        #expect(key.publicKey == sameKey.publicKey)
        #expect(key.publicKey != otherKey.publicKey)
    }

    private static func curveOf(_ keyPair: LibP2PCrypto.Keys.KeyPair) -> ECCurve? {
        curve(of: keyPair.publicKey)
    }
}

// MARK: - go-libp2p Interop

/// Ensures we interoperate byte for byte with go-libp2p's key fixtures (`core/crypto/test_data`)
@Suite("go-libp2p Fixture Tests")
struct GoLibP2PFixtureTests {

    @Test func ecdsaFixtures() throws {
        let marshaledPrivateKey = Data(hex: ECDSAFixtures.goPrivateKey)
        let marshaledPublicKey = Data(hex: ECDSAFixtures.goPublicKey)
        let signature = Data(hex: ECDSAFixtures.goSignature)

        let privateKeyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey)
        let publicKeyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKey)

        #expect(privateKeyPair.keyType == .ecdsa)
        #expect(publicKeyPair.keyType == .ecdsa)
        #expect(curve(of: privateKeyPair.publicKey) == .P256)

        // Re-marshaling reproduces go's encodings exactly
        #expect(try privateKeyPair.marshalPrivateKey() == marshaledPrivateKey)
        #expect(try privateKeyPair.marshalPublicKey() == marshaledPublicKey)
        #expect(try publicKeyPair.marshalPublicKey() == marshaledPublicKey)

        // go's signature verifies (it's a non-canonical high-S signature, which go accepts and so must we)
        #expect(try privateKeyPair.verify(signature: signature, for: ECDSAFixtures.goMessage))
        #expect(try publicKeyPair.verify(signature: signature, for: ECDSAFixtures.goMessage))
        #expect(try publicKeyPair.verify(signature: signature, for: ECDSAFixtures.opensslMessage) == false)

        // ECDSA signatures are randomized, but ours must verify too
        let ourSignature = try privateKeyPair.sign(message: ECDSAFixtures.goMessage)
        #expect(try publicKeyPair.verify(signature: ourSignature, for: ECDSAFixtures.goMessage))

        // Peer ID
        #expect(try publicKeyPair.id(withMultibasePrefix: false) == ECDSAFixtures.goPeerID)
        #expect(try privateKeyPair.id(withMultibasePrefix: false) == ECDSAFixtures.goPeerID)
    }

    @Test func secp256k1Fixtures() throws {
        let marshaledPrivateKey = Data(hex: ECDSAFixtures.goSecp256k1PrivateKey)
        let marshaledPublicKey = Data(hex: ECDSAFixtures.goSecp256k1PublicKey)
        let signature = Data(hex: ECDSAFixtures.goSecp256k1Signature)

        let privateKeyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: marshaledPrivateKey)
        let publicKeyPair = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPublicKey)

        #expect(privateKeyPair.keyType == .secp256k1)
        #expect(try privateKeyPair.marshalPrivateKey() == marshaledPrivateKey)
        #expect(try privateKeyPair.marshalPublicKey() == marshaledPublicKey)

        #expect(try publicKeyPair.verify(signature: signature, for: ECDSAFixtures.goMessage))

        // Secp256k1 signatures are deterministic (RFC6979), so we must produce go's exact signature
        #expect(try privateKeyPair.sign(message: ECDSAFixtures.goMessage) == signature)
    }
}

// MARK: - Fixtures

enum ECDSAFixtures {

    /// The message signed by go-libp2p's `core/crypto/fixture_test.go`
    static let goMessage = "Libp2p is the _best_!".data(using: .utf8)!

    /// go-libp2p `core/crypto/test_data/3.priv` (marshaled ECDSA P-256 private key, SEC1 ECPrivateKey)
    static let goPrivateKey =
        "08031279307702010104201fc05449e3a3423bb8b59447a43c3e23ad4095ac4f9fbb75457acef34b68949fa00a06082a8648ce3d030107a14403420004e29a8674f3614e0ccb72406bfe2137e9f8c5f7d62d137f0a2edd233e35374777fd1f9aed4d2cfa7371caafc6ef02db83b81f77cfe1bcd8c715acf0b9a2778ea9"

    /// go-libp2p `core/crypto/test_data/3.pub` (marshaled ECDSA P-256 public key, SubjectPublicKeyInfo)
    static let goPublicKey =
        "0803125b3059301306072a8648ce3d020106082a8648ce3d03010703420004e29a8674f3614e0ccb72406bfe2137e9f8c5f7d62d137f0a2edd233e35374777fd1f9aed4d2cfa7371caafc6ef02db83b81f77cfe1bcd8c715acf0b9a2778ea9"

    /// go-libp2p `core/crypto/test_data/3.sig` (DER signature of `goMessage`, note: `s` is high-S)
    static let goSignature =
        "3046022100846a6685b9e72b560cb2fc4a75f9cbc38a90aaeaa7f3f25ee719832db7b93a65022100cd992bb7bd2bcc28c7db04987d10adc490fe348270954f7696cb0dffff0dfc3d"

    /// base58btc( 0x12 0x20 || sha256(3.pub) ), computed independently of this library
    static let goPeerID = "QmYod9tQDX9rLCrs7au5um1aDrBXTnaHGbh1W6bxNGeEut"

    /// go-libp2p `core/crypto/test_data/2.priv` (marshaled Secp256k1 private key)
    static let goSecp256k1PrivateKey = "080212203141bd606a504c44f23494d8f3174ef25b1fb9b52daa07d058be83b6e046b158"

    /// go-libp2p `core/crypto/test_data/2.pub` (marshaled Secp256k1 public key)
    static let goSecp256k1PublicKey = "08021221023540ad842af8a43551a94d8383a555a99226506b88f953d2e70316a3a1b3d6a2"

    /// go-libp2p `core/crypto/test_data/2.sig` (deterministic, RFC6979, DER signature of `goMessage`)
    static let goSecp256k1Signature =
        "3044022031a7d633c2f3e45a16128d43751afaa8dc9ba24092c5f5b3cad2c8fe4cf388f2022049ea8d219f458683d24775d543ea8fb290704347fb35493c403bc2c259b29d9e"

    /// The message signed by OpenSSL for the `opensslSignature(for:)` fixtures
    static let opensslMessage = "Hello, swift-libp2p-crypto!".data(using: .utf8)!

    /// `openssl dgst -sha256 -sign ec_priv_<curve>.pem` signatures of `opensslMessage` using the `TestPEMKeys.EC_<curve>_PRIVATE` fixtures
    static func opensslSignature(for curve: ECCurve) -> Data {
        switch curve {
        case .P256:
            return Data(
                hex:
                    "3045022100a430b4b2288d0d528d290e3c9ee480dc0a5c4fd11461a509ce8deb7ce22ff957022078e6efea71beb71afa8ecd1b3ae12a177551826b1590e3336d8c4ba2d955167e"
            )
        case .P384:
            return Data(
                hex:
                    "3065023100850ccf2b633ca9f231ad967d480534f9ba2a57755f186ead8feee83379c8db87a2a2df72933ff6653580f581ec79abb0023057746a61511367f7d6ef47c6e7f8ff21b765a54e008460bdedf90f2d7ab82a8eba85b6b578003b1f0023f84e8147a490"
            )
        case .P521:
            return Data(
                hex:
                    "30818802420085f8613754847ae3ab449fb8415629bfd85a931fc6e47cbecd139cb59dd5fe35ca6a6be133749026ea9d3d7c1a840b269cd1e4c2f309dcffce21c21a1bfed79d5d02420173eec3c20fe613dc0e7b70ca92bce14602bb1ba03beeaf27f1babf022ecfeec1a3583a04afa70ab32abea3bcb0dc745521d44a447789e58bab4334e8c658a41d81"
            )
        }
    }

    static func privatePEM(for curve: ECCurve) -> String {
        switch curve {
        case .P256: return TestPEMKeys.EC_256_PRIVATE
        case .P384: return TestPEMKeys.EC_384_PRIVATE
        case .P521: return TestPEMKeys.EC_521_PRIVATE
        }
    }

    static func publicPEM(for curve: ECCurve) -> String {
        switch curve {
        case .P256: return TestPEMKeys.EC_256_PUBLIC
        case .P384: return TestPEMKeys.EC_384_PUBLIC
        case .P521: return TestPEMKeys.EC_521_PUBLIC
        }
    }

    /// `openssl ec -in ec_priv_<curve>.pem -pubout` (the public key belonging to the `privatePEM(for:)` fixture)
    static func derivedPublicPEM(for curve: ECCurve) -> String {
        switch curve {
        case .P256:
            return """
                -----BEGIN PUBLIC KEY-----
                MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE79HvsMQC9IyhZ7yCCYKmgz9zewM4
                KziWoVMXKN+7Cd5Ds+jK8V5qhD6YVbbo/v1udmM5DfhHJiUW3Ww5++suRg==
                -----END PUBLIC KEY-----
                """
        case .P384:
            return """
                -----BEGIN PUBLIC KEY-----
                MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEK0Yms7RqSJ2KNV6jJzaJFmOoNU3IDLs4
                KlIOi8xUGwgKgq3JzPfnPWeP+t3QtOrpS/ymy0IE4Y0oqkc4G875jrwdDs5aV9cH
                irrBaxeD4tAfaSj5lQgJUs2sVRJkbG5s
                -----END PUBLIC KEY-----
                """
        case .P521:
            return """
                -----BEGIN PUBLIC KEY-----
                MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBkyGgNGcYB5F65ziwoSrd/Oc/Ws9n
                hAN3Ck1/FBs8t7SvODh+T4noE+XJCzvhF8e1fGIc6IvcZkkvOj+k9uL3rPsAbUAQ
                AEdYJyaL+5yUayODTA24q5YfBjxska8dkgG136nHn4vovTCD3e4zLejacwQl3TWf
                Xwsa+N2XcZS+CraRdA0=
                -----END PUBLIC KEY-----
                """
        }
    }
}

// MARK: - Helpers

/// The curve of an ECDSA key (nil if the key isn't an ECDSA key)
private func curve(of key: CommonPublicKey) -> ECCurve? {
    (key as? any ECDSAPublicKeyBacking).map { type(of: $0).curve }
}

private func publicKey(rawRepresentation raw: Data, curve: ECCurve) throws -> CommonPublicKey {
    switch curve {
    case .P256: return try P256.Signing.PublicKey(rawRepresentation: raw)
    case .P384: return try P384.Signing.PublicKey(rawRepresentation: raw)
    case .P521: return try P521.Signing.PublicKey(rawRepresentation: raw)
    }
}

private func privateKey(rawRepresentation raw: Data, curve: ECCurve) throws -> CommonPrivateKey {
    switch curve {
    case .P256: return try P256.Signing.PrivateKey(rawRepresentation: raw)
    case .P384: return try P384.Signing.PrivateKey(rawRepresentation: raw)
    case .P521: return try P521.Signing.PrivateKey(rawRepresentation: raw)
    }
}

private func publicKey(pem: String, curve: ECCurve) throws -> CommonPublicKey {
    switch curve {
    case .P256: return try P256.Signing.PublicKey(pem: pem, asType: P256.Signing.PublicKey.self)
    case .P384: return try P384.Signing.PublicKey(pem: pem, asType: P384.Signing.PublicKey.self)
    case .P521: return try P521.Signing.PublicKey(pem: pem, asType: P521.Signing.PublicKey.self)
    }
}

private func privateKey(pem: String, curve: ECCurve) throws -> CommonPrivateKey {
    switch curve {
    case .P256: return try P256.Signing.PrivateKey(pem: pem, asType: P256.Signing.PrivateKey.self)
    case .P384: return try P384.Signing.PrivateKey(pem: pem, asType: P384.Signing.PrivateKey.self)
    case .P521: return try P521.Signing.PrivateKey(pem: pem, asType: P521.Signing.PrivateKey.self)
    }
}

private func privateKey(privateDER der: [UInt8], curve: ECCurve) throws -> CommonPrivateKey {
    switch curve {
    case .P256: return try P256.Signing.PrivateKey(privateDER: der)
    case .P384: return try P384.Signing.PrivateKey(privateDER: der)
    case .P521: return try P521.Signing.PrivateKey(privateDER: der)
    }
}

/// swift-crypto's own PEM encodings of the key pair (used to cross check our PEM exports)
private func swiftCryptoPEMs(of keyPair: LibP2PCrypto.Keys.KeyPair) -> (public: String, private: String)? {
    switch keyPair.privateKey {
    case let key as P256.Signing.PrivateKey: return (key.publicKey.pemRepresentation, key.pemRepresentation)
    case let key as P384.Signing.PrivateKey: return (key.publicKey.pemRepresentation, key.pemRepresentation)
    case let key as P521.Signing.PrivateKey: return (key.publicKey.pemRepresentation, key.pemRepresentation)
    default: return nil
    }
}

/// Wraps DER bytes in a PEM envelope
private func pem(_ der: [UInt8], type: String) -> String {
    let body = Data(der).base64EncodedString().chunks(ofCount: 64).joined(separator: "\n")
    return "-----BEGIN \(type)-----\n\(body)\n-----END \(type)-----"
}

private func marshaledPublicKey(type: KeyType, data: [UInt8]) throws -> Data {
    var proto = PublicKey()
    proto.type = type
    proto.data = Data(data)
    return try proto.serializedData()
}

private func marshaledPrivateKey(type: KeyType, data: [UInt8]) throws -> Data {
    var proto = PrivateKey()
    proto.type = type
    proto.data = Data(data)
    return try proto.serializedData()
}
