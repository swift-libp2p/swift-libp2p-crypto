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
import Multibase
import Testing

@testable import LibP2PCrypto

@Suite("DER and PEM Tests")
struct DERAndPEMTests {

    /// Every key type's `publicKeyDER()` is the SubjectPublicKeyInfo's BIT STRING contents
    @Test(arguments: [
        LibP2PCrypto.Keys.KeyPairType.rsa(), .ed25519, .secp256k1, .ecdsa(curve: .p256),
    ])
    func publicKeyDERIsTheSPKIBitStringContents(type: LibP2PCrypto.Keys.KeyPairType) throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(type)
        let (_, spkiDER, _) = try LibP2PCrypto.PEM.pemToData(keyPair.exportPublicPEM())
        let spki = try SubjectPublicKeyInfo(derEncoded: spkiDER)

        #expect(try Array(spki.key.bytes) == keyPair.publicKey.publicKeyDER())
        #expect(try Array(spki.key.bytes) == keyPair.privateKey?.publicKeyDER())
    }

    @Test func testPemParsing_RSA_2048_Public_Export() throws {
        let pem = TestPEMKeys.RSA_2048_PUBLIC

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 2048)
        #expect(keyPair.privateKey == nil)

        #expect(try keyPair.exportPublicPEMString() == pem)
    }

    @Test func testPemParsing_RSA_2048_Private_Export() throws {
        let pem = TestPEMKeys.RSA_2048_PRIVATE_ENCRYPTED_PAIR.UNENCRYPTED

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 2048)
        #expect(keyPair.privateKey != nil)

        #expect(try keyPair.exportPrivatePEMString() == pem)
    }

    /// PKCS#1 `RSA PUBLIC KEY` PEMs are supported alongside SubjectPublicKeyInfo `PUBLIC KEY` PEMs
    @Test func testPemParsing_RSA_2048_Public_PKCS1() throws {
        // The BIT STRING contents of the SubjectPublicKeyInfo are the PKCS#1 RSAPublicKey
        let (_, spkiDER, _) = try LibP2PCrypto.PEM.pemToData(Array(TestPEMKeys.RSA_2048_PUBLIC.utf8))
        let pkcs1 = try SubjectPublicKeyInfo(derEncoded: spkiDER).key.bytes
        let pem =
            "-----BEGIN RSA PUBLIC KEY-----\n"
            + Data(pkcs1).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            + "\n-----END RSA PUBLIC KEY-----"

        /// Import DER directly
        //let key = try LibP2PCrypto.Keys.importPublicDER(pem)
        let key = try RSAPublicKey(pem: pem)

        /// Let the parsePem method determine that it's a DER file and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(pem)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(key)
        print(keyPair)

        #expect(key.data == keyPair.publicKey.data)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 2048)
        #expect(keyPair.privateKey == nil)
    }

    @Test func testPemParsing_RSA_2048_Public() throws {

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_2048_PUBLIC)
        let key = try RSAPublicKey(pem: TestPEMKeys.RSA_2048_PUBLIC)

        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_2048_PUBLIC)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_2048_PUBLIC)

        print(key)
        print(keyPair)

        #expect(key.rawRepresentation == keyPair.publicKey.data)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 2048)
        #expect(keyPair.privateKey == nil)
    }

    @Test func testPemParsing_RSA_3072_Public() throws {

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_3072_PUBLIC)
        let key = try RSAPublicKey(pem: TestPEMKeys.RSA_3072_PUBLIC)

        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_3072_PUBLIC)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_3072_PUBLIC)

        print(key)
        print(keyPair)

        #expect(key.rawRepresentation == keyPair.publicKey.data)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 3072)
        #expect(keyPair.privateKey == nil)
    }

    @Test func testPemParsing_RSA_4096_Public() throws {

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPublicPem(TestPEMKeys.RSA_4096_PUBLIC)
        let key = try RSAPublicKey(pem: TestPEMKeys.RSA_4096_PUBLIC)

        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_4096_PUBLIC)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_4096_PUBLIC)

        print(key)
        print(keyPair)

        #expect(key.rawRepresentation == keyPair.publicKey.data)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 4096)
        #expect(keyPair.privateKey == nil)
    }

    @Test func testPemParsing_RSA_8192_Public() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.RSA_8192_PUBLIC)

        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.privateKey == nil)

        let attributes = try #require(keyPair.attributes())
        #expect(attributes.size == 8192)
        guard case .rsa(bits: .b8192) = attributes.type else {
            Issue.record("Expected an RSA 8192 attribute type, got \(attributes.type)")
            return
        }

        #expect(try keyPair.exportPublicPEMString() == TestPEMKeys.RSA_8192_PUBLIC)

        // Marshaling round trips and yields the same peer id
        let restored = try LibP2PCrypto.Keys.KeyPair(marshaledPublicKey: keyPair.marshalPublicKey())
        #expect(restored.publicKey.data == keyPair.publicKey.data)
        #expect(try restored.id() == keyPair.id())
    }

    ///[42,134,72,134,247,13,1,1,1]
    @Test func testRSAOpenSSLPemImport() throws {

        /// Generated with
        /// openssl genpkey -algorithm RSA
        ///   -pkeyopt rsa_keygen_bits:3072
        ///   -pkeyopt rsa_keygen_pubexp:65537
        let pem = """
            -----BEGIN PRIVATE KEY-----
            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
            4pMwXeXP+LO8NIfRXV8mgrm86g==
            -----END PRIVATE KEY-----
            """

        /// Import PEM directly
        //let key = try LibP2PCrypto.Keys.importPrivatePem(pem)
        let key = try RSAPrivateKey(pem: pem)

        /// Let the parsePem method determine the format and handle it accordingly
        //let keyPair = try LibP2PCrypto.Keys.parsePem(pem)
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(key)
        print(keyPair)

        #expect(key.rawRepresentation == keyPair.privateKey?.rawRepresentation)
        #expect(try key.derivePublicKey().rawRepresentation == keyPair.publicKey.data)
        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.attributes()?.size == 3072)
        #expect(keyPair.privateKey != nil)
    }

    // Manual PEM import process
    @Test func testED25519PemImport_Public_Manual() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEACM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=
            -----END PUBLIC KEY-----
            """

        let (_, bytes, _) = try LibP2PCrypto.PEM.pemToData(Array(pem.utf8))

        let spki = try SubjectPublicKeyInfo(derEncoded: bytes)

        print(spki)

        #expect(spki.algorithmIdentifier == AlgorithmIdentifier(algorithm: ASN1ObjectIdentifier.LibP2P.ed25519))

        let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: spki.key.bytes)

        print(pubKey)

        print(pubKey.rawRepresentation.asString(base: .base64Pad))

        /// Ensure that we reached the same results using both methods
        #expect(try pubKey.rawRepresentation == LibP2PCrypto.Keys.KeyPair(pem: pem).publicKey.data)
    }

    @Test func testED25519PemImport_Public() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEACM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=
            -----END PUBLIC KEY-----
            """

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        #expect(keyPair.keyType == .ed25519)
        #expect(keyPair.privateKey == nil)

        #expect(try keyPair.exportPublicPEMString() == pem)
    }

    /// This document defines what that is for Ed25519 private keys:
    /// https://tools.ietf.org/html/draft-ietf-curdle-pkix-10
    ///
    /// What it says is that inside the OCTET STRING is another OCTET STRING for the private key data. The ASN.1 tag for OCTET STRING is 0x04, and the length of that string is 32 bytes (0x20 in hex).
    /// So in the above string the leading 0420 is the OCTET STRING tag and length. The remaining 32 bytes are the key itself.
    @Test func testED25519PemImport_Private_Manual() throws {
        let pem = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIOkK9EOHRqD5QueUrMZbia55UWpokoFpWco4r2GnRVZ+
            -----END PRIVATE KEY-----
            """

        let (_, bytes, _) = try LibP2PCrypto.PEM.pemToData(Array(pem.utf8))

        let privateKeyInfo = try PrivateKeyInfo(derEncoded: bytes)

        print(privateKeyInfo)

        //        SEQUENCE {
        //            INTEGER (0)
        //            SEQUENCE {
        //                OBJECT IDENTIFIER (1.3.101.112)
        //            }
        //            OCTET STRING (34 bytes) <- This is actually another octetString
        //        }

        #expect(privateKeyInfo.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.ed25519)

        let privKeyData = try ASN1OctetString(derEncoded: privateKeyInfo.privateKey.bytes).bytes

        #expect(privKeyData.count == 32)

        let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privKeyData)

        print(privKey)

        #expect(
            "CM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA="
                == privKey.publicKey.rawRepresentation.asString(base: .base64Pad)
        )

    }

    @Test func testED25519PemImport_Private() throws {
        let pem = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEIOkK9EOHRqD5QueUrMZbia55UWpokoFpWco4r2GnRVZ+
            -----END PRIVATE KEY-----
            """

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        #expect(keyPair.keyType == .ed25519)
        #expect(keyPair.privateKey != nil)
        #expect(keyPair.publicKey.asString(base: .base64Pad) == "CM3Nzttt7KmXG9qDEYys++oQ9G749jqrbRRs92BUzpA=")

        #expect(try keyPair.exportPrivatePEMString() == pem)
    }

    @Test func testSecp256k1PemImport_Public_Manual() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzw
            xDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
            -----END PUBLIC KEY-----
            """

        let (_, bytes, _) = try LibP2PCrypto.PEM.pemToData(Array(pem.utf8))

        let spki = try SubjectPublicKeyInfo(derEncoded: bytes)

        print(spki)

        //        SEQUENCE {
        //            SEQUENCE {
        //                OBJECT IDENTIFIER   :id-ecPublicKey
        //                OBJECT IDENTIFIER   :secp256k1
        //            }
        //            BIT STRING (65 bytes)
        //        }

        #expect(spki.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.idEcPublicKey)
        #expect(spki.algorithmIdentifier.parameters == .objectIdentifier(ASN1ObjectIdentifier.LibP2P.secp256k1))

        let pubKey = try Secp256k1PublicKey(Array(spki.key.bytes))

        print(pubKey)

        #expect(
            pubKey.rawPublicKey.asString(base: .base64Pad)
                == "IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w=="
        )
        #expect(try pubKey.rawRepresentation == LibP2PCrypto.Keys.KeyPair(pem: pem).publicKey.rawRepresentation)
    }

    @Test func testSecp256k1PemImport_Public() throws {
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzw
            xDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
            -----END PUBLIC KEY-----
            """

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        #expect(keyPair.keyType == .secp256k1)
        #expect(keyPair.privateKey == nil)
        print(keyPair.attributes() ?? "NIL")

        #expect(try keyPair.exportPublicPEMString() == pem)
    }

    @Test func testSecp256k1PemImport_Private_Manual() throws {
        let pem = """
            -----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
            oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
            X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
            -----END EC PRIVATE KEY-----
            """

        let (_, bytes, _) = try LibP2PCrypto.PEM.pemToData(Array(pem.utf8))

        let ecPrivateKey = try ECPrivateKey(derEncoded: bytes)

        print(ecPrivateKey)

        //        SEQUENCE {
        //            INTEGER (1)
        //            OCTET STRING (32 bytes)             // private key data
        //            [0] OBJECT IDENTIFIER   :secp256k1
        //            [1] BIT STRING (65 bytes)           // public key data
        //        }

        #expect(ecPrivateKey.namedCurve == ASN1ObjectIdentifier.LibP2P.secp256k1)
        #expect(ecPrivateKey.publicKey?.bytes.count == 65)

        let privKey = try Secp256k1PrivateKey(Array(ecPrivateKey.privateKey.bytes))

        #expect(
            privKey.rawRepresentation.asString(base: .base64Pad) == "mZunAPeZmGUS2IbOaCuikn+dJ7BzxQ/IET3CJvvjaxo="
        )

        /// Assert that we can derive the public from the private key
        #expect(
            "IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w=="
                == privKey.publicKey.rawPublicKey.asString(base: .base64Pad)
        )
        #expect(try privKey.rawRepresentation == LibP2PCrypto.Keys.KeyPair(pem: pem).privateKey?.rawRepresentation)
        #expect(
            try privKey.publicKey.rawRepresentation == LibP2PCrypto.Keys.KeyPair(pem: pem).publicKey.rawRepresentation
        )
    }

    @Test func testSecp256k1PemImport_Private() throws {
        let pem = """
            -----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
            oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
            X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
            -----END EC PRIVATE KEY-----
            """

        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pem)

        print(keyPair)
        #expect(keyPair.keyType == .secp256k1)
        #expect(keyPair.privateKey != nil)
        #expect(
            keyPair.privateKey?.rawRepresentation.asString(base: .base64Pad)
                == "mZunAPeZmGUS2IbOaCuikn+dJ7BzxQ/IET3CJvvjaxo="
        )
        /// Assert that we can derive the public from the private key
        #expect(
            keyPair.publicKey.asString(base: .base64Pad)
                == "IgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwfX7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w=="
        )

        print(try keyPair.exportPrivatePEM().asString(base: .base16))

        #expect(try keyPair.exportPrivatePEMString() == pem)
    }

    @Test func testTempSecp() throws {
        let pemOG = """
            -----BEGIN EC PRIVATE KEY-----
            MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
            oUQDQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
            X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
            -----END EC PRIVATE KEY-----
            """
        /// Sequence:
        ///     Integer: 01
        ///     OctetString: 999ba700f799986512d886ce682ba2927f9d27b073c50fc8113dc226fbe36b1a
        ///     ObjectID: 06052b8104000a
        ///     BitString: 4200042200beb1c3052d405d7773a5328769e926c46811ab1f2cf0c437af8ec6d4d603a1763bbe15065a00bc1f5fb5e6b0784a145358a554b419784c333cc57f52ddef

        //let pemRECON = """
        //    -----BEGIN EC PRIVATE KEY-----
        //    MHQCAQEEIJmbpwD3mZhlEtiGzmgropJ/nSewc8UPyBE9wib742saoAcGBSuBBAAK
        //    oUQAQgAEIgC+scMFLUBdd3OlModp6SbEaBGrHyzwxDevjsbU1gOhdju+FQZaALwf
        //    X7XmsHhKFFNYpVS0GXhMMzzFf1Ld7w==
        //    -----END EC PRIVATE KEY-----
        //    """
        /// Sequence:
        ///     Integer: 01
        ///     OctetString: 999ba700f799986512d886ce682ba2927f9d27b073c50fc8113dc226fbe36b1a
        ///     ObjectID: 06052b8104000a
        ///     BitString: 4200042200beb1c3052d405d7773a5328769e926c46811ab1f2cf0c437af8ec6d4d603a1763bbe15065a00bc1f5fb5e6b0784a145358a554b419784c333cc57f52ddef

        let chunks = Array(pemOG.utf8).split(separator: 0x0a)
        let base64 = String(data: Data(chunks[1..<chunks.count - 1].joined()), encoding: .utf8)!
        let pemData = Data(base64Encoded: base64)!

        let ecPrivateKey = try ECPrivateKey(derEncoded: Array(pemData))

        print(ecPrivateKey)

        #expect(ecPrivateKey.privateKey.bytes.count == 32)
        #expect(ecPrivateKey.namedCurve == ASN1ObjectIdentifier.LibP2P.secp256k1)
        #expect(ecPrivateKey.publicKey?.bytes.first == 0x04)

        /// Re-encoding the decoded structure reproduces the original DER exactly
        #expect(try ecPrivateKey.serializedDERBytes() == Array(pemData))
    }

    @Test func testRSAEncryptedPrivateKeyPem() throws {
        let pair = TestPEMKeys.RSA_2048_PRIVATE_ENCRYPTED_PAIR.self
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pair.ENCRYPTED, password: pair.PASSWORD)

        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.hasPrivateKey)
    }

    @Test func testImportEncryptedPemKey() throws {
        let pair = TestPEMKeys.RSA_2048_PRIVATE_ENCRYPTED_PAIR.self

        /// We don't support the DES3 Cipher yet
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            try LibP2PCrypto.Keys.KeyPair(pem: pair.ENCRYPTED_DES3, password: pair.PASSWORD)
        }
    }

    /// Decrypts the OpenSSL fixture step by step, then re-encrypts and re-encodes it, ensuring we
    /// reproduce OpenSSL's output byte for byte
    @Test func testRSAEncryptedPrivateKeyPemExportManual() throws {
        let pair = TestPEMKeys.RSA_2048_PRIVATE_ENCRYPTED_PAIR.self
        let (type, der, _) = try LibP2PCrypto.PEM.pemToData(Array(pair.ENCRYPTED.utf8))
        #expect(type == .encryptedPrivateKey)

        let encrypted = try LibP2PCrypto.PEM.decodeEncryptedPEM(Data(der))
        let pbkdf = encrypted.pbkdfAlgorithm
        let cipher = encrypted.cipherAlgorithm
        #expect(pbkdf.iterations == 2048)
        #expect(pbkdf.prf == .hmacWithSHA1)
        #expect(cipher.desiredKeyLength == 16)

        // Derive the encryption key from the password and decrypt the PKCS#8 PrivateKeyInfo
        let key = try pbkdf.deriveKey(password: pair.PASSWORD, ofLength: cipher.desiredKeyLength)
        let plaintext = try cipher.decrypt(bytes: encrypted.ciphertext, withKey: key)

        let (_, unencryptedDER, _) = try LibP2PCrypto.PEM.pemToData(Array(pair.UNENCRYPTED.utf8))
        #expect(plaintext == unencryptedDER)

        // Re-encrypting with the same key and IV reproduces the ciphertext
        let ciphertext = try cipher.encrypt(bytes: plaintext, withKey: key)
        #expect(ciphertext == encrypted.ciphertext)

        // Re-encoding the EncryptedPrivateKeyInfo (including the pbkdf and cipher algos used) reproduces the original DER
        let encoded = try EncryptedPrivateKeyInfo(
            encryptionAlgorithm: ASN1ObjectIdentifier.LibP2P.pbes2,
            keyDerivationFunction: pbkdf.encodePBKDF(),
            encryptionScheme: cipher.encodeCipher(),
            encryptedData: ciphertext
        ).serializedDERBytes()
        #expect(encoded == der)

        let exportedPEM =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
            + Data(encoded).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
            + "\n-----END ENCRYPTED PRIVATE KEY-----"

        #expect(exportedPEM == pair.ENCRYPTED)
    }

    @Test func testRSAEncryptedPrivateKeyPemExport() throws {
        let pair = TestPEMKeys.RSA_2048_PRIVATE_ENCRYPTED_PAIR.self
        let keyPair = try LibP2PCrypto.Keys.KeyPair(pem: pair.ENCRYPTED, password: pair.PASSWORD)

        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.hasPrivateKey)

        #expect(throws: Error.self) { try LibP2PCrypto.Keys.KeyPair(pem: pair.ENCRYPTED, password: "wrongpassword") }

        /// Now lets try and reverse the process and export the encrypted private key using the fixture's salt and IV...
        let (_, der, _) = try LibP2PCrypto.PEM.pemToData(Array(pair.ENCRYPTED.utf8))
        let encrypted = try LibP2PCrypto.PEM.decodeEncryptedPEM(Data(der))

        let exportedPEM = try keyPair.exportEncryptedPrivatePEMString(
            withPassword: pair.PASSWORD,
            usingPBKDF: encrypted.pbkdfAlgorithm,
            andCipher: encrypted.cipherAlgorithm
        )

        #expect(exportedPEM == pair.ENCRYPTED)

        let differentPassword = try keyPair.exportEncryptedPrivatePEMString(
            withPassword: "wrongpassword",
            usingPBKDF: encrypted.pbkdfAlgorithm,
            andCipher: encrypted.cipherAlgorithm
        )

        #expect(differentPassword != pair.ENCRYPTED)
        #expect(differentPassword.count == pair.ENCRYPTED.count)
    }

    @Test func testRSAEncryptedPrivateKeyPemRoundTrip() throws {
        let keyPair = try LibP2PCrypto.Keys.KeyPair(.rsa(bits: .b2048))

        #expect(keyPair.keyType == .rsa)
        #expect(keyPair.hasPrivateKey)

        let exportedPEM = try keyPair.exportEncryptedPrivatePEMString(
            withPassword: "mypassword",
            usingPBKDF: .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 16), iterations: 2048)
        )

        let recoveredKey = try LibP2PCrypto.Keys.KeyPair(pem: exportedPEM, password: "mypassword")

        #expect(recoveredKey.keyType == .rsa)
        #expect(recoveredKey.hasPrivateKey)

        #expect(keyPair.privateKey?.rawRepresentation == recoveredKey.privateKey?.rawRepresentation)
        #expect(keyPair.publicKey.rawRepresentation == recoveredKey.publicKey.rawRepresentation)
        #expect(try keyPair.id() == recoveredKey.id())
    }

    @Test func testRSAEncryptedPrivateKeyPem2() throws {
        let pair = TestPEMKeys.RSA_2048_PRIVATE_ENCRYPTED_PAIR.self

        let fromDecrypted = try LibP2PCrypto.Keys.KeyPair(pem: pair.UNENCRYPTED)
        let fromEncrypted = try LibP2PCrypto.Keys.KeyPair(pem: pair.ENCRYPTED, password: pair.PASSWORD)

        #expect(fromDecrypted.privateKey != nil)
        #expect(fromEncrypted.privateKey != nil)

        #expect(fromDecrypted.keyType == .rsa)
        #expect(fromEncrypted.keyType == .rsa)

        #expect(fromDecrypted.privateKey?.rawRepresentation == fromEncrypted.privateKey?.rawRepresentation)
        #expect(fromDecrypted.publicKey.data == fromEncrypted.publicKey.data)

        let attributes = try #require(fromEncrypted.attributes())
        #expect(attributes.size == 2048)
        #expect(attributes.isPrivate)
    }

    @Test func testRSA_Pem_Parsing_Public() throws {
        let rsaPublic = try RSAPublicKey(pem: TestPEMKeys.RSA_2048_PUBLIC)

        print(rsaPublic)
    }

    @Test func testRSA_Pem_Parsing_Private() throws {
        let rsaPrivate = try RSAPrivateKey(pem: TestPEMKeys.RSA_2048_PRIVATE)

        print(rsaPrivate)
    }

    //    func testEC_Pem_Parsing_Public() throws {
    //        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.EC_256_PUBLIC)
    //
    //        print(parsed)
    //    }
    //
    //    func testEC_Pem_Parsing_Private() throws {
    //        let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.EC_256_PRIVATE)
    //
    //        print(parsed)
    //    }

    @Test func testEd25519_Pem_Parsing_Public() throws {
        //let parsed = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.Ed25519_KeyPair.PUBLIC)

        //print(parsed)

        let ed25519Public = try Curve25519.Signing.PublicKey(
            pem: TestPEMKeys.Ed25519_KeyPair.PUBLIC
        )

        print(ed25519Public)

        let ed25519Private = try Curve25519.Signing.PrivateKey(
            pem: TestPEMKeys.Ed25519_KeyPair.PRIVATE
        )

        print(ed25519Private)

        #expect(ed25519Private.publicKey == ed25519Public)
    }

    @Test func testEd25519_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.Ed25519_KeyPair.PRIVATE)

        print(parsed)
    }

    @Test func testSecp256k1_Pem_Parsing_Private() throws {
        let parsed = try LibP2PCrypto.Keys.KeyPair(pem: TestPEMKeys.SECP256k1_KeyPair.PRIVATE)

        print(parsed)
    }

    @Test func testImportSecp256k1PEM() throws {
        let secp256k1Public = try Secp256k1PublicKey(
            pem: TestPEMKeys.SECP256k1_KeyPair.PUBLIC
        )

        print(secp256k1Public)

        let secp256k1Private = try Secp256k1PrivateKey(
            pem: TestPEMKeys.SECP256k1_KeyPair.PRIVATE
        )

        print(secp256k1Private)

        #expect(secp256k1Private.publicKey == secp256k1Public)
    }

    /// PEMs with CRLF line endings, indentation or surrounding text should still parse
    @Test func importsPEMWithCRLFAndSurroundingText() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ed25519)
        let pem = try kp.exportPrivatePEMString()

        let crlf = pem.replacingOccurrences(of: "\n", with: "\r\n") + "\r\n"
        #expect(
            try LibP2PCrypto.Keys.KeyPair(pem: crlf).privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation
        )

        let decorated = """
            Bag Attributes
                localKeyID: 01 02 03 04
            Key Attributes: <No Attributes>
            \(pem)

            trailing notes
            """
        #expect(
            try LibP2PCrypto.Keys.KeyPair(pem: decorated).privateKey?.rawRepresentation
                == kp.privateKey?.rawRepresentation
        )
    }

    @Test func rejectsPEMWithoutFooterOrBody() {
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            _ = try LibP2PCrypto.PEM.pemToData(Array("-----BEGIN PUBLIC KEY-----\nAAAA\n".utf8))
        }
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            _ = try LibP2PCrypto.PEM.pemToData(Array("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----".utf8))
        }
        #expect(throws: LibP2PCrypto.PEM.Error.self) {
            _ = try LibP2PCrypto.PEM.pemToData(Array("no pem here".utf8))
        }
    }

    /// Encrypted Secp256k1 exports wrapped a SEC1 ECPrivateKey instead of a PKCS #8 PrivateKeyInfo
    @Test func encryptedExportContainsPKCS8() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)
        let password = "pw"
        let pem = try kp.exportEncryptedPrivatePEM(
            withPassword: password,
            usingPBKDF: .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 16), iterations: 2048)
        )

        // Manually decrypt the container
        let (_, bytes, _) = try LibP2PCrypto.PEM.pemToData(pem)
        let encrypted = try LibP2PCrypto.PEM.decodeEncryptedPEM(Data(bytes))
        let key = try encrypted.pbkdfAlgorithm.deriveKey(
            password: password,
            ofLength: encrypted.cipherAlgorithm.desiredKeyLength
        )
        let decrypted = try encrypted.cipherAlgorithm.decrypt(bytes: encrypted.ciphertext, withKey: key)

        let privateKeyInfo = try PrivateKeyInfo(derEncoded: decrypted)
        #expect(privateKeyInfo.algorithmIdentifier.algorithm == ASN1ObjectIdentifier.LibP2P.idEcPublicKey)
        #expect(
            privateKeyInfo.algorithmIdentifier.parameters == .objectIdentifier(ASN1ObjectIdentifier.LibP2P.secp256k1)
        )
        let sec1 = try ECPrivateKey(derEncoded: Array(privateKeyInfo.privateKey.bytes))
        #expect(Data(sec1.privateKey.bytes) == kp.privateKey?.rawRepresentation)

        let restored = try LibP2PCrypto.Keys.KeyPair(pem: pem, password: password)
        #expect(restored.keyType == .secp256k1)
        #expect(restored.privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation)
    }

    @Test func importsUnencryptedPKCS8() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)
        let pkcs8 = try kp.privateKey!.exportPrivateKeyPEMRaw()
        let body = Data(pkcs8).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed])
        let pem = "-----BEGIN PRIVATE KEY-----\n\(body)\n-----END PRIVATE KEY-----"

        let restored = try LibP2PCrypto.Keys.KeyPair(pem: pem)
        #expect(restored.keyType == .secp256k1)
        #expect(restored.privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation)
    }

    @Test func rejectsMismatchedAttachedPublicKey() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)
        let other = try LibP2PCrypto.Keys.generateKeyPair(.secp256k1)
        let sec1 = try ECPrivateKey(
            privateKey: Array(kp.privateKey!.rawRepresentation),
            namedCurve: nil,
            publicKey: other.privateKey!.publicKeyDER()
        ).serializedDERBytes()
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try Secp256k1PrivateKey(privateDER: sec1)
        }
    }

    /// P-256 keys share id-ecPublicKey with Secp256k1 and must still be classified by their named curve
    @Test func p256PKCS8IsNotMistakenForSecp256k1() throws {
        let kp = try LibP2PCrypto.Keys.generateKeyPair(.ecdsa(curve: .p256))
        let restored = try LibP2PCrypto.Keys.KeyPair(pem: kp.exportPrivatePEMString())
        #expect(restored.keyType == .ecdsa)
        #expect(restored.attributes()?.size == 256)
        #expect(restored.privateKey?.rawRepresentation == kp.privateKey?.rawRepresentation)
    }
}
