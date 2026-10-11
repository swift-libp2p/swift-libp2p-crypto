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
import CryptoExtras
import Foundation
import Multibase
import Multihash
import SwiftProtobuf
import Testing

@testable import LibP2PCrypto

/// Secp - https://techdocs.akamai.com/iot-token-access-control/docs/generate-ecdsa-keys
/// JWT - https://techdocs.akamai.com/iot-token-access-control/docs/generate-jwt-ecdsa-keys
/// Fixtures - http://cryptomanager.com/tv.html
/// RSA (Sign+Verify) - https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
/// PEM+DER (PKCS1&8) - https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
@Suite("LibP2P Crypto Tests")
struct Libp2pCryptoTests {

    @Test func keyPairTypeExposesItsKeyType() {
        #expect(LibP2PCrypto.Keys.KeyPairType.rsa(bits: .b4096).keyType == .rsa)
        #expect(LibP2PCrypto.Keys.KeyPairType.ed25519.keyType == .ed25519)
        #expect(LibP2PCrypto.Keys.KeyPairType.secp256k1.keyType == .secp256k1)
        #expect(LibP2PCrypto.Keys.KeyPairType.ecdsa(curve: .p521).keyType == .ecdsa)
        #expect(LibP2PCrypto.Keys.RSABitLength.b3072.bits == 3072)
    }

    @Test func keyPairTypeDescriptions() throws {
        #expect(LibP2PCrypto.Keys.KeyType.secp256k1.description == "Secp256k1")
        #expect(LibP2PCrypto.Keys.EllipticCurve.p384.description == "P-384")
        #expect(LibP2PCrypto.Keys.KeyPairType.rsa(bits: .b2048).description == "RSA (2048 bit)")
        #expect(LibP2PCrypto.Keys.KeyPairType.ecdsa(curve: .p256).description == "ECDSA (P-256)")

        let attributes = try #require(LibP2PCrypto.Keys.KeyPair(.ed25519).attributes())
        #expect(attributes.description == "Ed25519 private key (256 bits)")

        #expect(LibP2PCrypto.PEM.CipherAlgorithm.aes256CBC(iv: []).description == "AES-256-CBC")
        #expect(
            LibP2PCrypto.PEM.PBKDFAlgorithm.pbkdf2(salt: [], iterations: 2048, prf: .hmacWithSHA256).description
                == "PBKDF2 (HMAC-SHA256, 2048 iterations)"
        )
        #expect(LibP2PCrypto.PEM.Error.invalidPEMFormat("bad").description == "Invalid PEM format: bad")
    }

    @Test func keyPairEquality() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.ed25519)
        let publicOnly = try LibP2PCrypto.Keys.KeyPair(publicKey: keyPair.publicKey)
        let restored = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: keyPair.marshalPrivateKey())

        #expect(keyPair == restored)
        #expect(keyPair != publicOnly)
        #expect(try publicOnly == LibP2PCrypto.Keys.KeyPair(publicKey: restored.publicKey))
        #expect(try keyPair != LibP2PCrypto.Keys.KeyPair(.ed25519))
    }

    @Test func privateKeyEqualityForOurOwnTypes() throws {
        let secp = try Secp256k1PrivateKey()
        #expect(try secp == Secp256k1PrivateKey(rawRepresentation: secp.rawRepresentation))
        #expect(try secp != Secp256k1PrivateKey())

        let rsa = try RSAPrivateKey(keySize: .b2048)
        #expect(try rsa == RSAPrivateKey(rawRepresentation: rsa.rawRepresentation))
    }

    /// RSA keys smaller than 2048 bits can be neither generated nor imported
    @Test func testRSAUnder2048BitsIsRejected() throws {
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .custom(bits: 1024)))
        }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: MarshaledData.PUBLIC_RSA_KEY_1024, base: .base64Pad)
        }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: MarshaledData.PRIVATE_RSA_KEY_1024, base: .base64Pad)
        }
        #expect(throws: (any Error).self) { try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_1024_PUBLIC) }
        #expect(throws: (any Error).self) { try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_1024_PRIVATE) }
    }

    /// RSA keys larger than 8192 bits can be neither generated nor imported
    @Test func testRSAOver8192BitsIsRejected() throws {
        #expect(LibP2PCrypto.Keys.RSABitLength.supportedBitRange == 2048...8192)

        // Generation is rejected up front, rather than after spending seconds generating the key
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
                try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .custom(bits: 9216)))
            }
        }
        #expect(elapsed < .seconds(1))

        // A PKCS#1 RSAPublicKey with a 9216 bit modulus (primality isn't checked when parsing a public key)
        var modulus: [UInt8] = [0x00, 0xC0] + [UInt8](repeating: 0xAB, count: 9216 / 8 - 1)
        modulus[modulus.count - 1] = 0x01
        var serializer = DER.Serializer()
        try serializer.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(ArraySlice(modulus))
            try coder.serialize(ArraySlice<UInt8>([0x01, 0x00, 0x01]))
        }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try RSAPublicKey(rawRepresentation: Data(serializer.serializedBytes))
        }
    }

    @Test func testRSA3072() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .b3072))
        print(keyPair)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.privateKey != nil)
        //#expect(keyPair.publicKey.data.count == 398)
        //#expect(keyPair.privateKey!.data.count >= 1768)
        //#expect(keyPair.privateKey!.data.count <= 1768)

        let attributes = keyPair.attributes()
        #expect(attributes?.size == 3072)
        #expect(attributes?.isPrivate == true)
    }

    @Test func testRSA4096() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .b4096))
        print(keyPair)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.privateKey != nil)
        //#expect(keyPair.publicKey.data.count == 526)
        //#expect(keyPair.privateKey!.data.count >= 2349)
        //#expect(keyPair.privateKey!.data.count <= 2349)

        let attributes = keyPair.attributes()
        #expect(attributes?.size == 4096)
        #expect(attributes?.isPrivate == true)
    }

    @Test func testSecp256k1MarshallingRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)

        print("Public Key: \(keyPair.publicKey.asString(base: .base16))")

        let marshaledPubKey = try keyPair.publicKey.marshal()
        print("Marshaled PubKey Bytes: \(marshaledPubKey.asString(base: .base16))")

        let unmarshaledPubKey = try LibP2PCrypto.Keys.unmarshalPublicKey(buf: Array(marshaledPubKey), into: .base16)

        print("Compressed Public Key: \(unmarshaledPubKey)")
        let recoveredPubKey = try Secp256k1PublicKey(hexPublicKey: unmarshaledPubKey)
        #expect(recoveredPubKey.hex() == keyPair.publicKey.asString(base: .base16, withMultibasePrefix: false))

        let pubKey = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: marshaledPubKey).publicKey

        #expect(pubKey.data == keyPair.publicKey.data)
    }

    @Test func testSecp256k1ParseCompressedPublicKey() throws {
        let marshalledCompressedPublicKey = "08021221037777e994e452c21604f91de093ce415f5432f701dd8cd1a7a6fea0e630bfca99"

        let pb = try ProtoPublicKey(serializedBytes: Data(hex: marshalledCompressedPublicKey))

        let pubKey = try Secp256k1PublicKey(publicKey: Array(pb.data))

        let secp256k1PrivateKey = "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"
        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: secp256k1PrivateKey))
        #expect(kp.keyType == .secp256k1)
        let derivedPubKey = kp.publicKey.asString(base: .base16, withMultibasePrefix: false)

        #expect(pubKey.hex() == derivedPubKey)

        let cpk = try pubKey.compressPublicKey()
        #expect(cpk == Array(pb.data))
    }

    /// The public key is embedded in certain PeerID's
    /// Dialed: 12D3KooWAfPDpPRRRBrmqy9is2zjU5srQ4hKuZitiGmh4NTTpS2d
    /// Provided: QmPoHmYtUt8BU9eiwMYdBfT6rooBnna5fdAZHUaZASGQY8
    ///           QmPoHmYtUt8BU9eiwMYdBfT6rooBnna5fdAZHUaZASGQY8
    ///
    /// Dialed: 12D3KooWF5Qbrbvhhha1AcqRULWAfYzFEnKvWVGBUjw489hpo5La
    /// Provided: Qmbp3SxL2SYcH6Ly4r5SGQwfxkDCJPuhJG35GCZimcTiBc
    ///           Qmbp3SxL2SYcH6Ly4r5SGQwfxkDCJPuhJG35GCZimcTiBc
    @Test func testEmbeddedEd25519PublicKey() throws {
        let multi = try Multihash(
            BaseEncoding.decode("12D3KooWF5Qbrbvhhha1AcqRULWAfYzFEnKvWVGBUjw489hpo5La", as: .base58btc)
        )
        print(multi)
        print("\(multi.value) (\(multi.value.count))")
        print("\(multi.digest) (\(multi.digest.count))")

        /// Ensure we can instantiate a ED25519 Public Key from the multihash's digest (identity)
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: multi.digest.dropFirst(4))
        print(key)

        /// Ensure we can instantiate a KeyPair with the public key
        let kp = try LibP2PCrypto.Keys.KeyPair(publicKey: key)
        print(kp)
        #expect(kp.keyType == .ed25519)

        print(try kp.id(withMultibasePrefix: false))

        /// Ensure we can instantiate a key pair directly from the Multihash's Digest (Identity)
        let marshed = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: Data(multi.digest))
        print(marshed)

        print(marshed.keyType)
        print(marshed.publicKey)
        print(try marshed.id(withMultibasePrefix: false))

        #expect(
            try marshed.id(withMultibasePrefix: false) == "12D3KooWF5Qbrbvhhha1AcqRULWAfYzFEnKvWVGBUjw489hpo5La"
        )
    }

    @Test func attributeSizesAreInBits() throws {
        #expect(try LibP2PCrypto.Keys.generateKeyPair(.ed25519).attributes()?.size == 256)
        #expect(try LibP2PCrypto.Keys.generateKeyPair(.secp256k1).attributes()?.size == 256)
        #expect(try LibP2PCrypto.Keys.generateKeyPair(.ecdsa(curve: .p384)).attributes()?.size == 384)
    }

    @Test func secp256k1HexPublicKeyAcceptsPrefix() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)
        let hex = (kp.publicKey as! Secp256k1PublicKey).hex()
        let plain = try Secp256k1PublicKey(hexPublicKey: hex)
        let prefixed = try Secp256k1PublicKey(hexPublicKey: "0x" + hex)
        #expect(plain == prefixed)
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try Secp256k1PublicKey(hexPublicKey: "0x" + String(repeating: "z", count: 128))
        }
    }

    @Test func marshalPrivateKeyStillReportsBadBaseEncoding() {
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try LibP2PCrypto.Keys.marshalPrivateKey(raw: "not a valid base", keyType: .ed25519, fromBase: .base16)
        }
    }

    /// Builds a public-only `KeyPair` by round-tripping the marshaled public key.
    private func publicOnly(_ type: LibP2PCrypto.Keys.KeyPairType = .ed25519) throws -> LibP2PCrypto.Keys.KeyPair {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(type)
        return try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: kp.marshalPublicKey())
    }

    // MARK: - Public-only KeyPair guards

    @Test func publicOnlyKeyPairReportsNoPrivateKey() throws {
        let pub = try publicOnly()
        #expect(pub.hasPrivateKey == false)
        #expect(pub.privateKey == nil)
    }

    /// Regression: `exportEncryptedPrivatePEMString` used to force-unwrap `privateKey!` and crash.
    @Test func exportEncryptedPrivatePEMOnPublicKeyThrowsInsteadOfCrashing() throws {
        let pub = try publicOnly()
        #expect(throws: LibP2PCrypto.Keys.KeyError.noPrivateKey) {
            _ = try pub.exportEncryptedPrivatePEMString(withPassword: "hunter2")
        }
    }

    @Test func privateOnlyOperationsThrowWithoutPrivateKey() throws {
        let pub = try publicOnly()
        let message = Data("libp2p".utf8)
        #expect(throws: LibP2PCrypto.Keys.KeyError.noPrivateKey) { _ = try pub.sign(message: message) }
        #expect(throws: LibP2PCrypto.Keys.KeyError.noPrivateKey) { _ = try pub.marshalPrivateKey() }
        #expect(throws: LibP2PCrypto.Keys.KeyError.noPrivateKey) { _ = try pub.exportPrivatePEM() }
        #expect(throws: LibP2PCrypto.Keys.KeyError.noPrivateKey) { _ = try pub.exportPrivatePEMString() }
    }

    // MARK: - RSA-specific coverage

    /// `attributes()` derives the RSA size from the modulus bit-length rather than a byte-count table.
    @Test func rsaAttributesReportModulusBitLength() throws {
        for (type, expected) in [
            (LibP2PCrypto.Keys.KeyPairType.rsa(bits: .b2048), 2048),
            (LibP2PCrypto.Keys.KeyPairType.rsa(bits: .custom(bits: 2560)), 2560),
        ] {
            let kp = try LibP2PCrypto.Keys.generateKeyPair(type)
            #expect(kp.attributes()?.size == expected)
            #expect(kp.attributes()?.isPrivate == true)
        }
    }

    /// Regression: on Apple platforms `RSAPublicKey.rawRepresentation` returned SPKI while
    /// `init(rawRepresentation:)` only accepted PKCS#1. Both encodings must now be accepted and
    /// `T(rawRepresentation: k.rawRepresentation) == k` must hold for public and private keys.
    @Test func rsaRawRepresentationAcceptsSPKIAndPKCS1() throws {
        let privateKey = try RSAPrivateKey(keySize: .b2048)
        let publicKey = try #require(privateKey.derivePublicKey() as? RSAPublicKey)

        #expect(try RSAPublicKey(rawRepresentation: publicKey.rawRepresentation) == publicKey)
        #expect(try RSAPrivateKey(rawRepresentation: privateKey.rawRepresentation) == privateKey)

        // The BIT STRING contents of the SubjectPublicKeyInfo are the PKCS#1 RSAPublicKey
        let spki = try SubjectPublicKeyInfo(derEncoded: Array(publicKey.rawRepresentation))
        let pkcs1 = Data(spki.key.bytes)
        #expect(try RSAPublicKey(rawRepresentation: pkcs1) == publicKey)

        // The PKCS#8 PrivateKeyInfo wrapping is accepted as well
        let pkcs8 = try Data(privateKey.exportPrivateKeyPEMRaw())
        #expect(try RSAPrivateKey(rawRepresentation: pkcs8) == privateKey)
    }

    /// RSA signature verification returns `false` (rather than throwing) for a signature that doesn't match
    @Test func rsaVerifyReturnsFalseForInvalidSignature() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.rsa(bits: .b2048))
        let message = Data("hello".utf8)
        var signature = try kp.sign(message: message)
        signature[signature.startIndex] ^= 0xFF
        #expect(try kp.verify(signature: signature, for: message) == false)
        #expect(try kp.verify(signature: Data(), for: message) == false)
    }

    // MARK: - Encrypted PEM: raised defaults and the iteration-encoding fix

    /// Regression: `encodePBKDF()` previously encoded the iteration count in a fixed 2 bytes,
    /// silently truncating any value above 65535. This exercises a genuinely large value; it only
    /// encodes/decodes an ASN.1 integer, so it does no key derivation and is cheap in any build.
    @Test func pbkdf2IterationEncodingSurvivesLargeValues() throws {
        let salt = LibP2PCrypto.randomBytes(length: 16)
        let pbkdf = LibP2PCrypto.PEM.PBKDFAlgorithm.pbkdf2(salt: salt, iterations: 310_000)
        let encoded = try pbkdf.encodePBKDF().serializedDERBytes()
        let decoded = try LibP2PCrypto.PEM.decodePBKFD(PBKDF2AlgorithmIdentifier(derEncoded: encoded))
        #expect(decoded.iterations == 310_000)
        #expect(decoded.salt == salt)
    }

    /// The production defaults must stay strong regardless of build configuration. The cheap
    /// constant checks run everywhere; the full-strength derivation (slow in debug) only in release.
    @Test func defaultPBKDF2ParametersAreStrong() throws {
        #expect(LibP2PCrypto.PEM.defaultPBKDF2Iterations >= 310_000)
        #expect(LibP2PCrypto.PEM.defaultPBKDF2SaltLength >= 16)

        #if !DEBUG
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let pemString = try kp.exportEncryptedPrivatePEMString(withPassword: "pw")
        let (type, bytes, _) = try LibP2PCrypto.PEM.pemToData(Array(pemString.utf8))
        #expect(type == .encryptedPrivateKey)
        let decoded = try LibP2PCrypto.PEM.decodeEncryptedPEM(Data(bytes))
        #expect(decoded.pbkdfAlgorithm.iterations == LibP2PCrypto.PEM.defaultPBKDF2Iterations)
        #expect(decoded.pbkdfAlgorithm.salt.count == LibP2PCrypto.PEM.defaultPBKDF2SaltLength)
        #expect(decoded.pbkdfAlgorithm.prf == .hmacWithSHA256)
        #expect(decoded.cipherAlgorithm.desiredKeyLength == 32)
        #endif
    }

    @Test func encryptedPEMWithAES256CBCRoundTrips() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let password = "pw"
        let pemBytes = try kp.exportEncryptedPrivatePEM(
            withPassword: password,
            usingPBKDF: .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 16), iterations: 2048),
            andCipher: .aes256CBC(iv: LibP2PCrypto.randomBytes(length: 16))
        )
        let restored = try LibP2PCrypto.Keys.KeyPair(pem: pemBytes, password: password)
        #expect(restored.publicKey.data == kp.publicKey.data)
    }

    @Test func decryptingEncryptedPEMWithWrongPasswordFails() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let pemBytes = try kp.exportEncryptedPrivatePEM(
            withPassword: "right",
            usingPBKDF: .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 16), iterations: 2048)
        )
        #expect(throws: (any Error).self) {
            _ = try LibP2PCrypto.Keys.KeyPair(pem: pemBytes, password: "wrong")
        }
    }

    // MARK: - Malformed input handling

    @Test func malformedPEMThrows() {
        let junk = "-----BEGIN PUBLIC KEY-----\nnot valid base64 @@@\n-----END PUBLIC KEY-----"
        #expect(throws: (any Error).self) {
            _ = try LibP2PCrypto.Keys.KeyPair(pem: junk)
        }
    }

    @Test func malformedMarshaledKeysThrow() {
        #expect(throws: (any Error).self) {
            _ = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: Data([0x01, 0x02, 0x03]))
        }
        #expect(throws: (any Error).self) {
            _ = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data([0x01, 0x02, 0x03]))
        }
    }

    @Test func truncatedASN1SequenceThrows() {
        // Tag 0x30 (SEQUENCE) declares 5 content bytes but supplies none.
        #expect(throws: (any Error).self) {
            _ = try DER.parse([0x30, 0x05])
        }
    }

    @Test func shortSecp256k1SignatureThrowsInvalidLength() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)
        #expect(throws: (any Error).self) {
            _ = try kp.verify(signature: Data([0x00, 0x01, 0x02]), for: Data("msg".utf8))
        }
    }

    // MARK: - Async key generation

    @Test func asyncKeyGenerationProducesUsableKeyPair() async throws {
        let kp = try await LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let message = Data("async".utf8)
        let signature = try kp.sign(message: message)
        #expect(try kp.verify(signature: signature, for: message))
    }
}

// MARK: - Helpers

extension Data {
    /// Decodes a base16 (hex) encoded string, such as a test fixture
    init(hex: String) throws {
        self.init(try BaseEncoding.decode(hex, as: .base16))
    }
}
