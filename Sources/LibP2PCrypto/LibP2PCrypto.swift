//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-libp2p open source project
//
// Copyright (c) 2022-2025 swift-libp2p project authors
// Licensed under MIT
//
// See LICENSE for license information
// See CONTRIBUTORS for the list of swift-libp2p project authors
//
// SPDX-License-Identifier: MIT
//
//===----------------------------------------------------------------------===//
//
//  - TODO: Support JWK https://tools.ietf.org/html/rfc7517

import Crypto
import CryptoSwift
import Foundation
import Multibase
/// Re-exported so consumers can use `ASN1ObjectIdentifier` (used by `DERDecodable` / `DEREncodable`)
@_exported import SwiftASN1

public enum LibP2PCrypto {

    /// Returns `length` cryptographically secure random bytes (via `SystemRandomNumberGenerator`)
    public static func randomBytes(length: Int) -> [UInt8] {
        var rng = SystemRandomNumberGenerator()
        return (0..<length).map { _ in rng.next() }
    }

}

extension String {

    /// Encrypts a string using a plaintext password with the following AES GCM cipher
    ///
    /// * algorithmTagLength = 16,
    /// * nonceLength = 12,
    /// * keyLength = 16,
    /// * digest = 'sha256',
    /// * saltLength = 16,
    /// * iterations = 32767
    /// * algorithm = 'aes-128-gcm'
    public func encryptGCM(password: String) throws -> Data {
        guard let data = self.data(using: .utf8) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("Failed to encode string into UTF-8 data")
        }
        return try data.encryptGCM(password: password)
    }

    /// Decryptes a BaseEncoded string via AES-GCM password encrypted data and attempts to return the plaintext message...
    public func decryptGCM(password: String, base: BaseEncoding) throws -> String? {
        let decoded = Data(try BaseEncoding.decode(self, as: base))
        return try String(data: decoded.decryptGCM(password: password), encoding: .utf8)
    }

    public func encrypt(withKey key: Encryptable, encodedUsing encoding: String.Encoding = .utf8) throws -> Data {
        try key.encrypt(self, encodedUsing: encoding)
    }

    /// Attempts to decode the string via the specified base encoding then decrypts it
    public func decrypt(withKey key: Decryptable, baseEncoded base: BaseEncoding) throws -> Data {
        try key.decrypt(baseEncoded: self, base: base)
    }

    /// If the string is multibase encoded compliant (includes multibase prefix), we'll automatically decode it and attempt to decrypt the data
    public func decrypt(withKey key: Decryptable) throws -> Data {
        try key.decrypt(multibaseEncoded: self)
    }
}

extension Data {

    /// Returns the encrypted data in the format [ { salt }  { nonce}  { ciphertext }  { GCM algorithm tag } ]
    public func encryptGCM(password: String) throws -> Data {
        try Data(self.byteArray.encryptGCM(password: password))
    }

    /// Returns  decrypted data that was previously encrypted with `encryptGCM(password:)`
    public func decryptGCM(password: String) throws -> Data {
        try Data(self.byteArray.decryptGCM(password: password))
    }

    public func encrypt(withKey key: Encryptable) throws -> Data {
        try key.encrypt(self)
    }

    public func decrypt(withKey key: Decryptable) throws -> Data {
        try key.decrypt(self)
    }
}

extension Array where Element == UInt8 {
    public func encrypt(withKey key: Encryptable) throws -> Data {
        try key.encrypt(self)
    }

    public func decrypt(withKey key: Decryptable) throws -> Data {
        try key.decrypt(self)
    }

    /// Returns the encrypted data in the format [ { salt }  { nonce}  { ciphertext }  { GCM algorithm tag } ]
    public func encryptGCM(password: String) throws -> [UInt8] {
        // Generate a 128-bit salt using a CSPRNG.
        let salt = LibP2PCrypto.randomBytes(length: 16)

        // Attempt to derive the aes encryption key from the password and salt
        // PBKDF2-SHA256
        guard let key = PBKDF2.SHA256(password: password, salt: Data(salt), keyByteCount: 16, rounds: 32767) else {
            throw LibP2PCrypto.Keys.KeyError.encryptionFailed(
                "Failed to derive AES-GCM encryption key from plaintext password"
            )
        }

        // Return the salt prepended to the encrypted data
        return try salt + encryptGCM(data: self, withKey: key)
    }

    /// Returns  decrypted data that was previously encrypted with `encryptGCM(password:)`
    public func decryptGCM(password: String) throws -> [UInt8] {
        // The payload must at least contain a salt, a nonce and an authentication tag
        guard self.count >= 16 + 12 + 16 else {
            throw LibP2PCrypto.Keys.KeyError.decryptionFailed(
                "AES-GCM payload too short (\(self.count) bytes)"
            )
        }

        // Split off the 128-bit salt that was prepended during encryption
        let salt = self.prefix(16)
        let data = Array(self.dropFirst(16))

        // Attempt to derive the aes encryption key from the password and salt
        // PBKDF2-SHA256
        guard let key = PBKDF2.SHA256(password: password, salt: Data(salt), keyByteCount: 16, rounds: 32767) else {
            throw LibP2PCrypto.Keys.KeyError.decryptionFailed(
                "Failed to derive AES-GCM encryption key from plaintext password"
            )
        }

        return try decryptGCM(data: data, withKey: key)
    }

    private func encryptGCM(data: [UInt8], withKey key: Data) throws -> [UInt8] {
        let nonce = LibP2PCrypto.randomBytes(length: 12)

        let aesGCM = try AES.GCM.seal(data, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: nonce))

        // `combined` is only nil for non-standard nonce sizes, which should never happen here
        guard let combined = aesGCM.combined else {
            throw LibP2PCrypto.Keys.KeyError.encryptionFailed("AES-GCM failed to produce a combined sealed box")
        }
        return combined.byteArray  //nonce + ciphertext + tag
    }

    /// Expects `data` in the combined `[ { nonce } { ciphertext } { tag } ]` format
    private func decryptGCM(data: [UInt8], withKey key: Data) throws -> [UInt8] {
        try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: SymmetricKey(data: key)).byteArray
    }
}
