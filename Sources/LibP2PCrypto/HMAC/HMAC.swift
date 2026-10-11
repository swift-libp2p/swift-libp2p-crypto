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

import Crypto
import Foundation
import Multibase

extension LibP2PCrypto {
    public enum HMAC {
        public enum CryptoAlgorithm: Sendable, Hashable {

            @available(*, deprecated, message: "MD5 is cryptographically broken, use sha256 or stronger")
            case md5

            @available(
                *,
                deprecated,
                message: "SHA1 is considered to be cryptographically insecure, use sha256 or stronger"
            )
            case sha1

            case sha256
            case sha384
            case sha512

            public var description: String {
                switch self {
                case .md5: return "HMAC-MD5"
                case .sha1: return "HMAC-SHA1"
                case .sha256: return "HMAC-SHA256"
                case .sha384: return "HMAC-SHA384"
                case .sha512: return "HMAC-SHA512"
                }
            }

            internal func authenticationCode<D: DataProtocol>(for message: D, using key: SymmetricKey) -> Data {
                switch self {
                case .md5:
                    var hmac = Crypto.HMAC<Insecure.MD5>(key: key)
                    hmac.update(data: message)
                    return Data(hmac.finalize())
                case .sha1:
                    var hmac = Crypto.HMAC<Insecure.SHA1>(key: key)
                    hmac.update(data: message)
                    return Data(hmac.finalize())
                case .sha256:
                    var hmac = Crypto.HMAC<SHA256>(key: key)
                    hmac.update(data: message)
                    return Data(hmac.finalize())
                case .sha384:
                    var hmac = Crypto.HMAC<SHA384>(key: key)
                    hmac.update(data: message)
                    return Data(hmac.finalize())
                case .sha512:
                    var hmac = Crypto.HMAC<SHA512>(key: key)
                    hmac.update(data: message)
                    return Data(hmac.finalize())
                }
            }

            /// Verifies the authentication code
            internal func isValid<C: ContiguousBytes, D: DataProtocol>(
                _ code: C,
                for message: D,
                using key: SymmetricKey
            ) -> Bool {
                switch self {
                case .md5:
                    return Crypto.HMAC<Insecure.MD5>.isValidAuthenticationCode(
                        code,
                        authenticating: message,
                        using: key
                    )
                case .sha1:
                    return Crypto.HMAC<Insecure.SHA1>.isValidAuthenticationCode(
                        code,
                        authenticating: message,
                        using: key
                    )
                case .sha256:
                    return Crypto.HMAC<SHA256>.isValidAuthenticationCode(code, authenticating: message, using: key)
                case .sha384:
                    return Crypto.HMAC<SHA384>.isValidAuthenticationCode(code, authenticating: message, using: key)
                case .sha512:
                    return Crypto.HMAC<SHA512>.isValidAuthenticationCode(code, authenticating: message, using: key)
                }
            }
        }

        public struct HMACKey: Encryptable, Sendable {
            private let algorithm: CryptoAlgorithm
            private let key: SymmetricKey

            /// Initializes a reusable HMAC Key by specifying the Hashing Algorithm and secret key to use
            /// - Parameters:
            ///   - algorithm: The Hashing Algorithm to use
            ///   - key: The shared secret key
            public init(algorithm: CryptoAlgorithm, key: SymmetricKey) {
                self.algorithm = algorithm
                self.key = key
            }

            /// Initializes a reusable HMAC Key by specifying the Hashing Algorithm and secret key to use
            /// - Parameters:
            ///   - algorithm: The Hashing Algorithm to use
            ///   - key: The shared secret key as contiguous bytes
            public init(algorithm: CryptoAlgorithm, secret: ContiguousBytes) {
                self.init(algorithm: algorithm, key: SymmetricKey(data: secret))
            }

            /// Initializes a reusable HMAC Key by specifying the Hashing Algorithm and secret key to use
            /// - Parameters:
            ///   - algorithm: The Hashing Algorithm to use
            ///   - key: The shared secret key as a UTF8 String
            public init(algorithm: CryptoAlgorithm, secret: String) {
                self.init(algorithm: algorithm, secret: Data(secret.utf8))
            }

            /// Computes the authentication code for `message`
            public func authenticationCode<D: DataProtocol>(for message: D) -> Data {
                self.algorithm.authenticationCode(for: message, using: self.key)
            }

            /// Computes the authentication code for the UTF-8 encoded `message`
            public func authenticationCode(for message: String) -> Data {
                self.authenticationCode(for: Data(message.utf8))
            }

            @available(*, deprecated, renamed: "authenticationCode(for:)")
            public func encrypt(_ message: Data) -> Data {
                self.authenticationCode(for: message)
            }

            @available(*, deprecated, renamed: "authenticationCode(for:)")
            public func encrypt(_ message: String) -> Data {
                self.authenticationCode(for: message)
            }

            /// Verifies that `hash` is the authentication code for `data`
            public func verify<C: ContiguousBytes, D: DataProtocol>(_ data: D, hash: C) -> Bool {
                self.algorithm.isValid(hash, for: data, using: self.key)
            }

            /// Verifies that `hash` is the authentication code for `str` (a UTF8 string)
            public func verify(_ str: String, hash: Data) -> Bool {
                self.verify(Data(str.utf8), hash: hash)
            }
        }

        /// Creates an HMACKey that can be used to encrypt / hash multiple data sets...
        /// - Parameters:
        ///   - algorithm: The hashing algorithm to use
        ///   - key: The shared secret key to hash the data against
        /// - Returns: HMACKey
        public static func create(algorithm: CryptoAlgorithm, secret: String) -> LibP2PCrypto.HMAC.HMACKey {
            HMACKey(algorithm: algorithm, secret: secret)
        }

        /// A one off, stateless, HMAC computation
        /// - Parameters:
        ///   - message: The data to authenticate
        ///   - algorithm: The hashing algorithm to use
        ///   - secret: The shared secret key to authenticate the data with
        /// - Returns: The authentication code
        public static func authenticationCode<D: DataProtocol>(
            for message: D,
            algorithm: CryptoAlgorithm,
            secret: String
        ) -> Data {
            HMACKey(algorithm: algorithm, secret: secret).authenticationCode(for: message)
        }

        /// A one off, stateless, HMAC computation
        /// - Parameters:
        ///   - message: The UTF-8 encoded string to authenticate
        ///   - algorithm: The hashing algorithm to use
        ///   - secret: The shared secret key to authenticate the string with
        /// - Returns: The authentication code
        public static func authenticationCode(
            for message: String,
            algorithm: CryptoAlgorithm,
            secret: String
        ) -> Data {
            HMACKey(algorithm: algorithm, secret: secret).authenticationCode(for: message)
        }

        @available(*, deprecated, renamed: "authenticationCode(for:algorithm:secret:)")
        public static func encrypt(message: String, algorithm: CryptoAlgorithm, key: String) -> Data {
            self.authenticationCode(for: message, algorithm: algorithm, secret: key)
        }

        @available(*, deprecated, renamed: "authenticationCode(for:algorithm:secret:)")
        public static func encrypt(_ message: Data, algorithm: CryptoAlgorithm, key: String) -> Data {
            self.authenticationCode(for: message, algorithm: algorithm, secret: key)
        }
    }
}

public protocol Encryptable {
    func encrypt(_ message: Data) throws -> Data
}

// An Encryptable extension that gives us default implementations of Bytes and String Encrypting
extension Encryptable {

    public func encrypt(_ bytes: [UInt8]) throws -> Data {
        try self.encrypt(Data(bytes))
    }

    /// A default string -> data implementation using .utf8 encoding...
    public func encrypt(_ message: String, encodedUsing encoding: String.Encoding = .utf8) throws -> Data {
        guard let d = message.data(using: encoding) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("Failed to encode string using \(encoding)")
        }
        return try self.encrypt(d)
    }

}

public protocol Decryptable {
    func decrypt(_ message: Data) throws -> Data
}

// An Encryptable extension that gives us default implementations of Bytes and String Encrypting
extension Decryptable {

    public func decrypt(_ bytes: [UInt8]) throws -> Data {
        try self.decrypt(Data(bytes))
    }

    /// Attempts to decode a base encoded string into the encrypted data to be decrypted...
    public func decrypt(baseEncoded: String, base: BaseEncoding) throws -> Data {
        let bytes = try Multibase.BaseEncoding.decode(baseEncoded.utf8, as: base)
        return try self.decrypt(bytes)
    }

    /// Attempts to decode a multibase compliant string into the encrypted data to be decrypted...
    public func decrypt(multibaseEncoded: String) throws -> Data {
        let (_, bytes) = try multibaseEncoded.multibase()
        return try self.decrypt(bytes)
    }

    public func decrypt(_ data: Data, intoString encoding: String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(data)
        guard let str = String(data: d, encoding: encoding) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("Failed to decode data using \(encoding)")
        }
        return str
    }

    public func decrypt(_ bytes: [UInt8], intoString encoding: String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(bytes)
        guard let str = String(data: d, encoding: encoding) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("Failed to decode data using \(encoding)")
        }
        return str
    }

    public func decrypt(
        baseEncoded: String,
        base: BaseEncoding,
        intoString encoding: String.Encoding = .utf8
    ) throws -> String {
        let d = try self.decrypt(baseEncoded: baseEncoded, base: base)
        guard let str = String(data: d, encoding: encoding) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("Failed to decode data using \(encoding)")
        }
        return str
    }

    public func decrypt(multibaseEncoded: String, intoString encoding: String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(multibaseEncoded: multibaseEncoded)
        guard let str = String(data: d, encoding: encoding) else {
            throw LibP2PCrypto.Keys.KeyError.invalidParameters("Failed to decode data using \(encoding)")
        }
        return str
    }
}
