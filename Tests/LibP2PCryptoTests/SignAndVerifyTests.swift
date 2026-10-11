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
import Testing

@testable import LibP2PCrypto

@Suite("Signature & Verification Tests")
struct SignAndVerifyTests {

    @Test func testRSAMessageSignVerify_StaticKey() throws {
        let message = TestFixtures.RSA_2048.rawMessage.data(using: .utf8)!

        let rsa = try LibP2PCrypto.Keys.KeyPair(
            marshaledPrivateKey: TestFixtures.RSA_2048.privateMarshaled,
            base: .base64Pad
        )

        let signedData = try rsa.privateKey!.sign(message: message)

        print(signedData.asString(base: .base64Pad))

        #expect(
            signedData.asString(base: .base64Pad)
                == TestFixtures.RSA_2048.signedMessages["algid:sign:RSA:message-PKCS1v15:SHA256"]
        )
        #expect(message != signedData)

        // This just ensures that a newly instantiated Pub SecKey matches the derived pubkey from the keypair...
        let recoveredPubKey: RSAPublicKey = try RSAPublicKey(rawRepresentation: rsa.publicKey.data)
        #expect(rsa.publicKey.data == recoveredPubKey.rawRepresentation)
        #expect(try rsa.marshalPublicKey().asString(base: .base64Pad) == TestFixtures.RSA_2048.publicMarshaled)

        // Ensure the rsaSignatureMessagePKCS1v15SHA256 algorithm works with our RSA KeyPair
        //#expect(SecKeyIsAlgorithmSupported(recoveredPubKey, .verify, .rsaSignatureMessagePKCS1v15SHA256))

        // Ensure the Signed Data is Valid for the given message
        #expect(try rsa.publicKey.verify(signature: signedData, for: message))

        // Ensure that the signature is no longer valid if it is tweaked in any way
        // (a mismatched signature returns false, a malformed / truncated one may throw instead)
        #expect(try rsa.publicKey.verify(signature: Data(signedData.reversed()), for: message) == false)
        #expect((try? rsa.publicKey.verify(signature: Data(signedData.dropFirst()), for: message)) != true)
        #expect((try? rsa.publicKey.verify(signature: Data(signedData.dropLast()), for: message)) != true)

        // Ensure that the signature is no longer valid if the message is tweaked in any way
        #expect(try rsa.publicKey.verify(signature: signedData, for: Data(message.reversed())) == false)
        #expect(try rsa.publicKey.verify(signature: signedData, for: Data(message.dropFirst())) == false)
        #expect(try rsa.publicKey.verify(signature: signedData, for: Data(message.dropLast())) == false)
    }

    // Secp256k1 Keys

    @Test func secp256k1ErrorsAreKeyErrors() {
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) { try Secp256k1PrivateKey(privateKey: [0x01]) }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) { try Secp256k1PublicKey(publicKey: [0x04, 0x01]) }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            try Secp256k1PrivateKey().publicKey.verify(signature: Data([0x01]), for: Data())
        }
    }

    @Test func testSecp256k1MessageSignVerify() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!

        let secp = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)

        let signedData = try secp.privateKey!.sign(message: message)

        #expect(message != signedData)
        // Signatures are DER encoded (SEQUENCE { INTEGER r, INTEGER s })
        #expect(signedData.first == 0x30)
        #expect(signedData.count <= 72)

        #expect(try secp.publicKey.verify(signature: signedData, for: message))

        var alertedSignedData = signedData
        // Flip the lowest bit of the final byte of `s`
        alertedSignedData[alertedSignedData.count - 1] ^= 0x01
        #expect(try secp.publicKey.verify(signature: alertedSignedData, for: message) == false)
        // Invalid DER will throw error...
        #expect(throws: Error.self) { try secp.publicKey.verify(signature: Data(signedData.dropFirst()), for: message) }
        #expect(throws: Error.self) { try secp.publicKey.verify(signature: Data(signedData.dropLast()), for: message) }

        #expect(try secp.publicKey.verify(signature: signedData, for: Data(message.shuffled())) == false)
        #expect(try secp.publicKey.verify(signature: signedData, for: Data(message.dropFirst())) == false)
        #expect(try secp.publicKey.verify(signature: signedData, for: Data(message.dropLast())) == false)
    }

    /// The libp2p spec test vector private key (marshaled)
    static let secp256k1SpecPrivateKey = "0802122053DADF1D5A164D6B4ACDB15E24AA4C5B1D3461BDBD42ABEDB0A4404D56CED8FB"

    /// Signatures are deterministic (RFC6979), so the spec key always produces the same signature for the same message.
    /// - Note: Verified externally via `openssl dgst -sha256 -verify pub.pem -signature sig.der msg`
    @Test func testSecp256k1DeterministicSignature() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!
        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: Self.secp256k1SpecPrivateKey))

        let signature = try kp.privateKey!.sign(message: message)
        #expect(
            signature.asString(base: .base16)
                == "30440220325b7222967b742414a4a3b51fac64658ba642d2e7cc74b69d5c9555be5d08c6022066526d58da763da195cc25b032a30caed1ac5ce04d418713ec3912b1a5829938"
        )
        #expect(try kp.sign(message: message) == signature)
        #expect(try kp.publicKey.verify(signature: signature, for: message))
    }

    /// Ensures we can verify a SHA-256 / DER signature produced by an external implementation (OpenSSL)
    /// and that non-canonical (high-S) signatures are rejected.
    @Test func testSecp256k1VerifyExternalSignature() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!
        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: Self.secp256k1SpecPrivateKey))

        // Produced by `openssl dgst -sha256 -sign` (OpenSSL doesn't normalize S, this one happens to be high-S)
        let highS = try Data(
            hex:
                "3046022100b1aac74717f91bd5472feba67bbf360deda755da5de620a45223ddc1d040e9f5022100d14180dd96bb0700f3c1cdee04e71b11693701b30ef5d9d0ed24f7647be9200d"
        )
        // The same signature normalized to low-S (s' = n - s)
        let lowS = try Data(
            hex:
                "3045022100b1aac74717f91bd5472feba67bbf360deda755da5de620a45223ddc1d040e9f502202ebe7f226944f8ff0c3e3211fb18e4ed5177db33a052c66ad2ad6728544d2134"
        )

        #expect(try kp.publicKey.verify(signature: lowS, for: message))
        #expect(try kp.publicKey.verify(signature: highS, for: message) == false)
    }

    /// Secp256k1 signatures used to be keccak256 hashed, 65 byte `v || r || s` recoverable signatures.
    /// Per the libp2p spec they are now SHA-256 hashed, DER encoded signatures, ensure the legacy format isn't accepted.
    @Test func testSecp256k1RejectsLegacyRecoverableSignature() throws {
        let message = "Hello, swift-libp2p-crypto!".data(using: .utf8)!
        let kp = try LibP2PCrypto.Keys.KeyPair(marshaledPrivateKey: Data(hex: Self.secp256k1SpecPrivateKey))

        let der = try kp.privateKey!.sign(message: message)
        #expect(der.count != 65)

        // Repackage the DER signature's r and s values as a legacy `v || r || s` signature
        let rLength = Int(der[3])
        let r = der[4..<(4 + rLength)].suffix(32)
        let s = der[(6 + rLength)...].suffix(32)
        let legacy =
            Data([0x00]) + Data(repeating: 0, count: 32 - r.count) + r + Data(repeating: 0, count: 32 - s.count) + s
        #expect(legacy.count == 65)

        #expect(throws: Error.self) { try kp.publicKey.verify(signature: legacy, for: message) }
    }
}
