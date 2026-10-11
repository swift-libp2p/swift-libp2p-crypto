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
import Foundation
import Testing

@testable import LibP2PCrypto

@Suite("ASN1 Tests")
struct ASN1Tests {

    /// The swift-asn1 object identifiers must serialize to the exact bytes our hand-rolled encoder used to emit
    @Test(arguments: [
        (ASN1ObjectIdentifier.LibP2P.rsaEncryption, "06092a864886f70d010101"),
        (ASN1ObjectIdentifier.LibP2P.ed25519, "06032b6570"),
        (ASN1ObjectIdentifier.LibP2P.idEcPublicKey, "06072a8648ce3d0201"),
        (ASN1ObjectIdentifier.LibP2P.secp256k1, "06052b8104000a"),
        (ASN1ObjectIdentifier.LibP2P.pbes2, "06092a864886f70d01050d"),
        (ASN1ObjectIdentifier.LibP2P.pbkdf2, "06092a864886f70d01050c"),
        (ASN1ObjectIdentifier.LibP2P.aes128CBC, "0609608648016503040102"),
        (ASN1ObjectIdentifier.LibP2P.aes256CBC, "060960864801650304012a"),
    ])
    func objectIdentifiersSerializeToLegacyBytes(oid: ASN1ObjectIdentifier, expectedHex: String) throws {
        #expect(try oid.serializedDERBytes() == Array(Data(hex: expectedHex)))
    }

    @Test func keyTypeObjectIdentifiers() {
        #expect(RSAPublicKey.primaryObjectIdentifier == ASN1ObjectIdentifier.LibP2P.rsaEncryption)
        #expect(Curve25519.Signing.PublicKey.primaryObjectIdentifier == "1.3.101.112")
        #expect(Secp256k1PublicKey.primaryObjectIdentifier == "1.2.840.10045.2.1")
        #expect(Secp256k1PublicKey.secondaryObjectIdentifier == "1.3.132.0.10")
        // Private keys use the same id-ecPublicKey + named curve pair as public keys (PKCS #8)
        #expect(Secp256k1PrivateKey.primaryObjectIdentifier == "1.2.840.10045.2.1")
        #expect(Secp256k1PrivateKey.secondaryObjectIdentifier == "1.3.132.0.10")
    }

    @Test func rsaAlgorithmIdentifierIncludesNullParameter() throws {
        #expect(
            try AlgorithmIdentifier.rsaEncryption.serializedDERBytes()
                == Array(Data(hex: "300d06092a864886f70d0101010500"))
        )
    }

    @Test func secp256k1ECPrivateKeyRoundTrips() throws {
        let key = try Secp256k1PrivateKey()
        let der = try key.sec1DER()

        let decoded = try ECPrivateKey(derEncoded: der)
        #expect(Array(decoded.privateKey.bytes) == Array(key.rawRepresentation))
        #expect(decoded.namedCurve == ASN1ObjectIdentifier.LibP2P.secp256k1)
        #expect(try decoded.publicKey.map { Array($0.bytes) } == key.publicKeyDER())
        #expect(try decoded.serializedDERBytes() == der)
    }

    // MARK: Strict DER

    @Test func nonMinimalIntegerIsRejected() {
        // INTEGER 1 encoded with a redundant leading zero byte
        #expect(throws: ASN1Error.self) {
            _ = try Int(derEncoded: [0x02, 0x02, 0x00, 0x01])
        }
    }

    @Test func invalidBitStringPaddingIsRejected() throws {
        var der = try SubjectPublicKeyInfo(
            algorithmIdentifier: AlgorithmIdentifier(algorithm: ASN1ObjectIdentifier.LibP2P.ed25519),
            key: [UInt8](repeating: 0x01, count: 32)
        ).serializedDERBytes()
        // Layout: 30 2a | 30 05 06 03 2b 65 70 | 03 21 <padding> <32 key bytes>
        #expect(der[11] == 0x00)
        der[11] = 0x08
        #expect(throws: ASN1Error.self) {
            _ = try SubjectPublicKeyInfo(derEncoded: der)
        }
    }

    @Test func trailingBytesAreRejected() throws {
        let der = try AlgorithmIdentifier.rsaEncryption.serializedDERBytes()
        #expect(throws: ASN1Error.self) {
            _ = try AlgorithmIdentifier(derEncoded: der + [0x00])
        }
    }

    @Test func zeroPBKDF2IterationCountIsRejected() throws {
        let encoded = try PBKDF2AlgorithmIdentifier(
            algorithm: ASN1ObjectIdentifier.LibP2P.pbkdf2,
            salt: [UInt8](repeating: 0x01, count: 16),
            iterationCount: 0
        ).serializedDERBytes()
        let decoded = try PBKDF2AlgorithmIdentifier(derEncoded: encoded)
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            _ = try LibP2PCrypto.PEM.decodePBKFD(decoded)
        }
    }
}
