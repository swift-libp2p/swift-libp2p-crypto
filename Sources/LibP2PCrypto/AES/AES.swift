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

import Foundation

#if canImport(CommonCrypto)
import CommonCrypto
#else
import CryptoSwift
#endif

extension LibP2PCrypto {
    public enum AES {
        /// The AES block size, which is also the required IV length for AES-CBC
        static let blockSize = 16

        static func createKey(key: String) throws -> AESKey {
            try AESKey(key: key)
        }

        static func createKey(key: String, iv: String) throws -> AESKey {
            try AESKey(key: key, iv: iv)
        }

        static func createKey(key: Data, iv: Data) throws -> AESKey {
            try AESKey(key: key, iv: iv)
        }

        /// Decrypts data previously encrypted by an `AESKey` created with the same password
        /// - Parameters:
        ///   - data: The IV prefixed ciphertext produced by `AESKey.encrypt(_:)`
        ///   - password: The 16 or 32 byte (UTF-8) password used as the AES key
        public static func decrypt(_ data: Data, withPassword password: String) throws -> Data {
            try LibP2PCrypto.AES.createKey(key: password).decrypt(data)
        }

        /// An AES-CBC (PKCS#7 padded) key
        ///
        /// - Note: `encrypt(_:)` prepends the IV to the returned ciphertext and `decrypt(_:)` expects
        ///   the IV to be prepended, so data can be decrypted by any `AESKey` sharing the same secret key.
        public struct AESKey: Encryptable, Decryptable, Sendable {
            private let key: Data

            /// The initialization vector used when encrypting
            public let iv: Data

            /// Initializes an AES Key with the specified key and Initial Vector
            /// - Parameters:
            ///   - key: Either a 16 or 32 byte secret key
            ///   - iv: A 16 byte initial vector
            /// - Throws: `KeyError.invalidParameters` if the key or iv are the wrong length
            public init(key: Data, iv: Data) throws {
                guard key.count == 16 || key.count == 32 else {
                    throw LibP2PCrypto.Keys.KeyError.invalidParameters("AES: invalid key")
                }

                guard iv.count == AES.blockSize else {
                    throw LibP2PCrypto.Keys.KeyError.invalidParameters("AES: invalid initial vector")
                }
                self.key = key
                self.iv = iv
            }

            /// Initializes an AES Key with the specified key and Initial Vector
            /// - Parameters:
            ///   - key: Either a 16 or 32 byte (UTF-8) secret key
            ///   - iv: A 16 byte (UTF-8) initial vector
            /// - Throws: `KeyError.invalidParameters` if the key or iv are the wrong length
            public init(key: String, iv: String) throws {
                try self.init(key: Data(key.utf8), iv: Data(iv.utf8))
            }

            /// Initializes an AES Key with the specified key and a randomly generated Initial Vector
            /// - Parameter key: Either a 16 or 32 byte (UTF-8) secret key
            /// - Throws: `KeyError.invalidParameters` if the key is the wrong length
            public init(key: String) throws {
                try self.init(key: Data(key.utf8), iv: Data(LibP2PCrypto.randomBytes(length: AES.blockSize)))
            }

            /// Encrypts the data and returns it prefixed with the IV: `[ iv ][ ciphertext ]`
            public func encrypt(_ data: Data) throws -> Data {
                try iv + AES.cbc(data, key: key, iv: iv, encrypt: true)
            }

            /// Decrypts IV prefixed ciphertext (`[ iv ][ ciphertext ]`) produced by `encrypt(_:)`
            public func decrypt(_ data: Data) throws -> Data {
                guard data.count >= AES.blockSize * 2 else {
                    throw LibP2PCrypto.Keys.KeyError.decryptionFailed("AES: ciphertext too short")
                }
                let iv = data.prefix(AES.blockSize)
                let ciphertext = data.dropFirst(AES.blockSize)
                return try AES.cbc(Data(ciphertext), key: key, iv: Data(iv), encrypt: false)
            }
        }

        #if canImport(CommonCrypto)
        /// AES-CBC (PKCS#7 padded) Encrypt / Decrypt data via CommonCrypto
        private static func cbc(_ data: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
            let cryptLength = data.count + kCCBlockSizeAES128
            var cryptData = Data(count: cryptLength)
            var bytesLength = 0

            let status = cryptData.withUnsafeMutableBytes { cryptBytes in
                data.withUnsafeBytes { dataBytes in
                    iv.withUnsafeBytes { ivBytes in
                        key.withUnsafeBytes { keyBytes in
                            CCCrypt(
                                CCOperation(encrypt ? kCCEncrypt : kCCDecrypt),
                                CCAlgorithm(kCCAlgorithmAES),
                                CCOptions(kCCOptionPKCS7Padding),
                                keyBytes.baseAddress,
                                key.count,
                                ivBytes.baseAddress,
                                dataBytes.baseAddress,
                                data.count,
                                cryptBytes.baseAddress,
                                cryptLength,
                                &bytesLength
                            )
                        }
                    }
                }
            }

            guard Int(status) == kCCSuccess else {
                throw LibP2PCrypto.Keys.KeyError.internalError("AES: CCCrypt failed with status \(status)")
            }

            return Data(cryptData.prefix(bytesLength))
        }
        #else
        /// AES-CBC (PKCS#7 padded) Encrypt / Decrypt data via CryptoSwift
        private static func cbc(_ data: Data, key: Data, iv: Data, encrypt: Bool) throws -> Data {
            let aes = try CryptoSwift.AES(key: key.byteArray, blockMode: CBC(iv: iv.byteArray), padding: .pkcs7)
            return try Data(encrypt ? aes.encrypt(data.byteArray) : aes.decrypt(data.byteArray))
        }
        #endif
    }
}
