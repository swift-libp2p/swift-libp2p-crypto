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

@Suite("AES Cipher Tests")
struct AESCipherTests {

    @Test func testAESEncryption128() throws {
        let message = "Hello World!"
        let key128 = "1234567890123456"  // 16 bytes for AES128
        let iv = "abcdefghijklmnop"  // 16 bytes for AES128

        let aes128Key = try LibP2PCrypto.AES.createKey(key: key128, iv: iv)

        let encrypted = try aes128Key.encrypt(message)
        print(encrypted.asString(base: .base16))
        let decrypted: String = try aes128Key.decrypt(encrypted)

        #expect(decrypted == message)
    }

    @Test func testAESEncryption256() throws {
        let message = "Hello World!"
        let key256 = "12345678901234561234567890123456"  // 32 bytes for AES256
        let iv = "abcdefghijklmnop"  // 16 bytes for AES128

        let aes256Key = try LibP2PCrypto.AES.createKey(key: key256, iv: iv)
        let aes256KeyDup = try LibP2PCrypto.AES.createKey(key: key256, iv: iv)

        let encrypted = try aes256Key.encrypt(message)
        let encrypted2 = try aes256KeyDup.encrypt(message)
        print(encrypted.asString(base: .base16))
        print(encrypted2.asString(base: .base16))
        let decrypted: String = try aes256Key.decrypt(encrypted)

        #expect(decrypted == message)
        #expect(encrypted == encrypted2)  //Same Key & IV => Same Encrypted data
    }

    @Test func testAESEncryption256AutoIV() throws {
        let message = "Hello World!"
        let key256 = "12345678901234561234567890123456"  // 32 bytes for AES256

        let aes256Key = try LibP2PCrypto.AES.createKey(key: key256)

        let encrypted = try aes256Key.encrypt(message)
        print(encrypted.asString(base: .base16))
        let decrypted: String = try aes256Key.decrypt(encrypted)

        #expect(decrypted == message)
    }

    @Test func testAESEncryption256AutoIVDifferent() throws {
        let message = "Hello World!"
        let key256 = "12345678901234561234567890123456"  // 32 bytes for AES256

        let aes256Key = try LibP2PCrypto.AES.createKey(key: key256)
        let aes256Key2 = try LibP2PCrypto.AES.createKey(key: key256)

        let encrypted = try aes256Key.encrypt(message)
        let encrypted2 = try aes256Key2.encrypt(message)
        print(encrypted.asString(base: .base16))
        print(encrypted2.asString(base: .base16))
        let decrypted: String = try aes256Key.decrypt(encrypted)
        let decrypted2: String = try aes256Key2.decrypt(encrypted2)

        //Ensure that the encrypted data is different using different keys
        #expect(encrypted != encrypted2)
        //Ensure we can decrypt the data with the proper key
        #expect(decrypted == message)
        //Ensure we can decrypt the data with the proper key
        #expect(decrypted2 == message)

        //The IV is prepended to the ciphertext, so any key instance sharing the same secret can decrypt it
        let decryptedSameSecret: String = try aes256Key.decrypt(encrypted2)
        #expect(decryptedSameSecret == message)

        //Ensure that decryption fails when we use the wrong key
        //Usually results in a padding or String.Encoding Error (cause gibberish)
        let wrongKey = try LibP2PCrypto.AES.createKey(key: "65432109876543216543210987654321")
        let decryptedWrongKey: String? = try? wrongKey.decrypt(encrypted2)
        #expect(decryptedWrongKey != message)
    }

    @Test func testAESGCMEncryptionRoundTrip() throws {

        let message = "Hello World!"

        let encrypted = try message.encryptGCM(password: "mypassword")

        print(encrypted.asString(base: .base32))

        let decrypted = try encrypted.decryptGCM(password: "mypassword")

        let msg = String(data: decrypted, encoding: .utf8)
        print(msg ?? "NIL")

        #expect(msg == message)
    }

    /// Regression: `decryptGCM(password:)` used to crash (`removeFirst(16)`) on payloads shorter than the salt
    @Test(arguments: [0, 1, 15, 16, 27, 43])
    func decryptingTruncatedPayloadThrows(length: Int) throws {
        let payload = [UInt8](repeating: 0x2a, count: length)
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try payload.decryptGCM(password: "mypassword")
        }
    }

    @Test func decryptingTamperedPayloadThrows() throws {
        var encrypted = try Array("Hello World!".utf8).encryptGCM(password: "mypassword")
        encrypted[encrypted.count - 1] ^= 0x01
        #expect(throws: (any Error).self) {
            _ = try encrypted.decryptGCM(password: "mypassword")
        }
    }

    let key256 = "12345678901234561234567890123456"

    /// Regression: keys created with a random IV couldn't be decrypted by any other `AESKey` instance
    @Test func ciphertextDecryptsWithADifferentKeyInstance() throws {
        let encryptor = try LibP2PCrypto.AES.AESKey(key: key256)
        let decryptor = try LibP2PCrypto.AES.AESKey(key: key256)
        #expect(encryptor.iv != decryptor.iv)

        let encrypted = try encryptor.encrypt("Hello World!")
        #expect(encrypted.prefix(16) == encryptor.iv)

        let decrypted: String = try decryptor.decrypt(encrypted)
        #expect(decrypted == "Hello World!")
    }

    @Test func staticPasswordDecryption() throws {
        let encrypted = try LibP2PCrypto.AES.AESKey(key: key256).encrypt("Hello World!")
        let decrypted = try LibP2PCrypto.AES.decrypt(encrypted, withPassword: key256)
        #expect(String(data: decrypted, encoding: .utf8) == "Hello World!")
    }

    /// Regression: the String based initializer skipped key / IV length validation on Apple platforms
    @Test func stringInitializerValidatesLengths() throws {
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try LibP2PCrypto.AES.AESKey(key: "short", iv: "abcdefghijklmnop")
        }
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try LibP2PCrypto.AES.AESKey(key: "1234567890123456", iv: "short")
        }
        // 16 characters but 17 UTF-8 bytes
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try LibP2PCrypto.AES.AESKey(key: "é234567890123456")
        }
    }

    @Test func decryptingTruncatedCiphertextThrows() throws {
        let key = try LibP2PCrypto.AES.AESKey(key: key256)
        #expect(throws: LibP2PCrypto.Keys.KeyError.self) {
            _ = try key.decrypt(Data(repeating: 0, count: 16))
        }
    }

    @Test func emptyMessageRoundTrips() throws {
        let key = try LibP2PCrypto.AES.AESKey(key: key256)
        let encrypted = try key.encrypt(Data())
        #expect(encrypted.count == 32)
        #expect(try key.decrypt(encrypted).isEmpty)
    }
}
