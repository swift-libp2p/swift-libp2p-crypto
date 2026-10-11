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

import CryptoExtras
import Foundation
import Testing

@testable import LibP2PCrypto

@Suite("Encrypted PEM PBKDF Tests")
struct EncryptedPEMPBKDFTests {

    let password = "mypassword"
    let salt: [UInt8] = Array(0..<16)
    let iv: [UInt8] = Array(16..<32)
    let iterations = 2048

    /// Minimal DER TLV encoder, kept independent of the library's own ASN.1 serializers
    static func tlv(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        var length: [UInt8]
        if content.count < 0x80 {
            length = [UInt8(content.count)]
        } else {
            var count = content.count
            var bytes: [UInt8] = []
            while count > 0 {
                bytes.insert(UInt8(count & 0xff), at: 0)
                count >>= 8
            }
            length = [0x80 | UInt8(bytes.count)] + bytes
        }
        return [tag] + length + content
    }

    static func sequence(_ children: [UInt8]...) -> [UInt8] { tlv(0x30, children.flatMap { $0 }) }

    static let pbes2OID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D]
    static let pbkdf2OID: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C]
    static let hmacWithSHA256OID: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09]
    static let hmacWithSHA1OID: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07]
    static let aes256CBCOID: [UInt8] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A]
    static let null: [UInt8] = [0x05, 0x00]

    /// Builds an `ENCRYPTED PRIVATE KEY` PEM the way OpenSSL 3's `openssl pkcs8 -topk8` does
    /// (PBES2, PBKDF2 with the specified PRF, AES-256-CBC)
    func encryptedPEM(
        wrapping pkcs8: [UInt8],
        prfOID: [UInt8]?,
        hashFunction: KDF.Insecure.PBKDF2.HashFunction,
        keyLength: Int? = nil
    ) throws -> String {
        let key = try KDF.Insecure.PBKDF2.deriveKey(
            from: Array(password.utf8),
            salt: salt,
            using: hashFunction,
            outputByteCount: 32,
            unsafeUncheckedRounds: iterations
        )
        let ciphertext = try Array(Crypto.AES._CBC.encrypt(pkcs8, using: key, iv: Crypto.AES._CBC.IV(ivBytes: iv)))

        var pbkdf2Params = Self.tlv(0x04, salt) + Self.tlv(0x02, [0x08, 0x00])
        if let keyLength { pbkdf2Params += Self.tlv(0x02, [UInt8(keyLength)]) }
        if let prfOID { pbkdf2Params += Self.sequence(prfOID, Self.null) }

        let der = Self.sequence(
            Self.sequence(
                Self.pbes2OID,
                Self.sequence(
                    Self.sequence(Self.pbkdf2OID, Self.tlv(0x30, pbkdf2Params)),
                    Self.sequence(Self.aes256CBCOID, Self.tlv(0x04, iv))
                )
            ),
            Self.tlv(0x04, ciphertext)
        )

        let body = Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        return "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\(body)\n-----END ENCRYPTED PRIVATE KEY-----"
    }

    /// The optional `prf` (and `keyLength`) PBKDF2 parameters weren't parsed, so PEMs
    /// encrypted by OpenSSL 1.1+ / 3.x (hmacWithSHA256) failed to import
    @Test(arguments: [nil, 32] as [Int?])
    func importsSHA256PRFEncryptedPEM(keyLength: Int?) throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let pem = try encryptedPEM(
            wrapping: kp.privateKey!.exportPrivateKeyPEMRaw(),
            prfOID: Self.hmacWithSHA256OID,
            hashFunction: .sha256,
            keyLength: keyLength
        )

        let restored = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: password)
        #expect(restored.privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation)
    }

    @Test func importsExplicitSHA1PRFEncryptedPEM() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let pem = try encryptedPEM(
            wrapping: kp.privateKey!.exportPrivateKeyPEMRaw(),
            prfOID: Self.hmacWithSHA1OID,
            hashFunction: .insecureSHA1
        )

        let restored = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: password)
        #expect(restored.privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation)
    }

    @Test func rejectsMismatchedKeyLength() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let pem = try encryptedPEM(
            wrapping: kp.privateKey!.exportPrivateKeyPEMRaw(),
            prfOID: Self.hmacWithSHA256OID,
            hashFunction: .sha256,
            keyLength: 16
        )
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            _ = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: password)
        }
    }

    @Test func rejectsUnsupportedPRF() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        // id-hmacWithMD5 isn't an RFC 8018 PBKDF2 PRF
        let unknownOID: [UInt8] = [0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x06]
        let pem = try encryptedPEM(
            wrapping: kp.privateKey!.exportPrivateKeyPEMRaw(),
            prfOID: unknownOID,
            hashFunction: .insecureMD5
        )
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            _ = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: password)
        }
    }

    /// DER requires the DEFAULT (hmacWithSHA1) PRF to be omitted, while any other PRF must be encoded
    @Test func prfEncoding() throws {
        let sha1 = try LibP2PCrypto.PEM.PBKDFAlgorithm.pbkdf2(salt: salt, iterations: iterations).encodePBKDF()
        let sha1Bytes = try sha1.serializedDERBytes()
        #expect(
            sha1Bytes.count
                == Self.sequence(Self.pbkdf2OID, Self.tlv(0x30, Self.tlv(0x04, salt) + Self.tlv(0x02, [0x08, 0x00])))
                .count
        )

        let sha256 = try LibP2PCrypto.PEM.PBKDFAlgorithm.pbkdf2(
            salt: salt,
            iterations: iterations,
            prf: .hmacWithSHA256
        )
        .encodePBKDF()
        let decoded = try LibP2PCrypto.PEM.decodePBKFD(
            PBKDF2AlgorithmIdentifier(derEncoded: sha256.serializedDERBytes())
        )
        #expect(decoded.prf == .hmacWithSHA256)
        #expect(decoded.salt == salt)
        #expect(decoded.iterations == iterations)
    }

    @Test func roundTripsEveryPRF() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        for prf in LibP2PCrypto.PEM.PBKDFAlgorithm.PRF.allCases {
            let pem = try kp.exportEncryptedPrivatePEM(
                withPassword: password,
                usingPBKDF: .pbkdf2(salt: salt, iterations: iterations, prf: prf)
            )
            let restored = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: password)
            #expect(restored.privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation)
        }
    }
}
