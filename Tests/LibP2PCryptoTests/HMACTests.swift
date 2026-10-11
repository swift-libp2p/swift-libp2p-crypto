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

@Suite("HMAC Tests")
struct HMACTests {

    @Test func testHMAC() throws {
        let message = "Hello World"
        let key = "secret"
        let hmac = LibP2PCrypto.HMAC.authenticationCode(for: message, algorithm: .sha256, secret: key)
        let hmac2 = LibP2PCrypto.HMAC.authenticationCode(for: message, algorithm: .sha256, secret: key)
        let hmac3 = LibP2PCrypto.HMAC.authenticationCode(for: message, algorithm: .sha256, secret: "Secret")

        #expect(hmac == hmac2)  //Same message, same key -> Same hash
        #expect(hmac != hmac3)  //Same message, different key -> Different hash
    }

    @Test func testHMACKey() throws {
        let message = "Hello World"
        let key = "secret"
        let hmacKey = LibP2PCrypto.HMAC.create(algorithm: .sha256, secret: key)

        let encrypted = hmacKey.authenticationCode(for: message)
        let encrypted2 = hmacKey.authenticationCode(for: message)

        #expect(encrypted == encrypted2)
    }

    @Test func testHMACBaseEncoded() throws {
        let message = "Hello World"
        let key = "secret"
        let hmac = LibP2PCrypto.HMAC.authenticationCode(for: message, algorithm: .sha256, secret: key)

        print(hmac.asString(base: .base16))
        print(hmac.asString(base: .base32Hex))
        print(hmac.asString(base: .base64Pad))
    }

    @Test func testHMACVerify() throws {
        let message = "Hello World"
        let key = "secret"
        let hmacKeyLocal = LibP2PCrypto.HMAC.create(algorithm: .sha256, secret: key)
        let hmacKeyRemote = LibP2PCrypto.HMAC.create(algorithm: .sha256, secret: key)

        let encrypted = hmacKeyLocal.authenticationCode(for: message)

        // Correct data, hash matches...
        #expect(hmacKeyRemote.verify(message, hash: encrypted))
        // Corrupted data, hash doesn't match...
        #expect(hmacKeyRemote.verify("HellØ world", hash: encrypted) == false)
    }

    /// Every algorithm, including the deprecated (but still supported) MD5 and SHA1
    @available(*, deprecated, message: "Exercises the deprecated MD5 and SHA1 algorithms")
    static let allAlgorithms: [LibP2PCrypto.HMAC.CryptoAlgorithm] = [.md5, .sha1, .sha256, .sha384, .sha512]

    @available(*, deprecated, message: "Exercises the deprecated MD5 and SHA1 algorithms")
    @Test(arguments: allAlgorithms)
    func verifyAcceptsValidAndRejectsInvalidCodes(algorithm: LibP2PCrypto.HMAC.CryptoAlgorithm) throws {
        let key = LibP2PCrypto.HMAC.HMACKey(algorithm: algorithm, secret: "secret")
        let code = key.authenticationCode(for: "Hello World")

        #expect(key.verify("Hello World", hash: code))
        #expect(key.verify(Data("Hello World".utf8), hash: code))

        var tampered = code
        tampered[tampered.startIndex] ^= 0x01
        #expect(key.verify("Hello World", hash: tampered) == false)
        #expect(key.verify("Hello World", hash: code.dropLast()) == false)
        #expect(key.verify("Hello World", hash: Data()) == false)
        #expect(key.verify("Hello World!", hash: code) == false)
        #expect(
            LibP2PCrypto.HMAC.HMACKey(algorithm: algorithm, secret: "Secret").verify("Hello World", hash: code) == false
        )
    }

    @Test func hmacSecretsAreInterchangeable() {
        let message = "Hello World"
        let fromString = LibP2PCrypto.HMAC.HMACKey(algorithm: .sha256, secret: "secret")
        let fromData = LibP2PCrypto.HMAC.HMACKey(algorithm: .sha256, secret: Data("secret".utf8))
        let fromKey = LibP2PCrypto.HMAC.HMACKey(algorithm: .sha256, key: SymmetricKey(data: Data("secret".utf8)))

        let code = fromString.authenticationCode(for: message)
        #expect(fromData.authenticationCode(for: message) == code)
        #expect(fromKey.authenticationCode(for: message) == code)
        #expect(LibP2PCrypto.HMAC.authenticationCode(for: message, algorithm: .sha256, secret: "secret") == code)
        #expect(
            Data(
                Crypto.HMAC<SHA256>.authenticationCode(
                    for: Data(message.utf8),
                    using: SymmetricKey(data: Data("secret".utf8))
                )
            ) == code
        )
    }
}
