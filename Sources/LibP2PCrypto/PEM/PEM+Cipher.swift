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

import CryptoSwift
import Foundation
import SwiftASN1

// MARK: Encrypted PEM Cipher Algorithms

extension LibP2PCrypto.PEM {
    // MARK: Add support for new Cipher Algorithms here...
    public enum CipherAlgorithm {
        case aes_128_cbc(iv: [UInt8])
        case aes_256_cbc(iv: [UInt8])

        init(objID: ASN1ObjectIdentifier, iv: [UInt8]) throws {
            let algorithm: CipherAlgorithm
            switch objID {
            case ASN1ObjectIdentifier.LibP2P.aes128CBC:
                algorithm = .aes_128_cbc(iv: iv)
            case ASN1ObjectIdentifier.LibP2P.aes256CBC:
                algorithm = .aes_256_cbc(iv: iv)
            default:
                throw Error.unsupportedCipherAlgorithm(objID)
            }
            // Validate the IV length up front so a malformed PEM fails here with a clear
            // error rather than deep inside CryptoSwift's CBC block-mode at decrypt time.
            guard iv.count == algorithm.expectedIVLength else {
                throw Error.invalidPEMFormat(
                    "EncryptedPrivateKey::CIPHER::IV length \(iv.count), expected \(algorithm.expectedIVLength)"
                )
            }
            self = algorithm
        }

        func decrypt(bytes: [UInt8], withKey key: [UInt8]) throws -> [UInt8] {
            switch self {
            case .aes_128_cbc(let iv), .aes_256_cbc(let iv):
                return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).decrypt(bytes)
            }
        }

        func encrypt(bytes: [UInt8], withKey key: [UInt8]) throws -> [UInt8] {
            switch self {
            case .aes_128_cbc(let iv), .aes_256_cbc(let iv):
                return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).encrypt(bytes)
            }
        }

        /// The key length used for this Cipher strategy
        /// - Note: we need this information when deriving the key using our PBKDF strategy
        var desiredKeyLength: Int {
            switch self {
            case .aes_128_cbc: return 16
            case .aes_256_cbc: return 32
            }
        }

        /// The initialization-vector length required by this Cipher strategy.
        /// - Note: AES-CBC uses a 16-byte IV (one AES block) for both the 128- and 256-bit key sizes.
        var expectedIVLength: Int {
            switch self {
            case .aes_128_cbc, .aes_256_cbc: return 16
            }
        }

        var objectIdentifier: ASN1ObjectIdentifier {
            switch self {
            case .aes_128_cbc:
                return ASN1ObjectIdentifier.LibP2P.aes128CBC
            case .aes_256_cbc:
                return ASN1ObjectIdentifier.LibP2P.aes256CBC
            }
        }

        var iv: [UInt8] {
            switch self {
            case .aes_128_cbc(let iv), .aes_256_cbc(let iv):
                return iv
            }
        }

        func encodeCipher() throws -> CipherAlgorithmIdentifier {
            CipherAlgorithmIdentifier(algorithm: self.objectIdentifier, iv: self.iv)
        }
    }

    /// Decodes the Cipher ASN1 Block in an Encrypted Private Key PEM file
    /// - Parameter algorithmIdentifier: The decoded cipher AlgorithmIdentifier
    /// - Returns: The CipherAlogrithm if supported
    ///
    /// Expects the following ASN1 structure
    /// ```
    /// SEQUENCE {
    ///     OBJECT IDENTIFIER       // ex: aes-128-cbc
    ///     OCTET STRING            // IV
    /// }
    /// ```
    internal static func decodeCipher(_ algorithmIdentifier: CipherAlgorithmIdentifier) throws -> CipherAlgorithm {
        try CipherAlgorithm(objID: algorithmIdentifier.algorithm, iv: Array(algorithmIdentifier.iv.bytes))
    }
}
