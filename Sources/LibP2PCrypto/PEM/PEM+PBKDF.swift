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

// MARK: Encrypted PEM PBKDF Algorithms

extension LibP2PCrypto {
    public static func random8ByteSalt() throws -> [UInt8] {
        try LibP2PCrypto.randomBytes(length: 8)
    }

    public static func random16ByteSalt() throws -> [UInt8] {
        try LibP2PCrypto.randomBytes(length: 16)
    }
}

extension LibP2PCrypto.PEM {
    // MARK: Add support for new PBKDF Algorithms here...
    public enum PBKDFAlgorithm {
        /// The pseudorandom function used by PBKDF2
        public enum PRF: Sendable, CaseIterable {
            /// HMAC-SHA1, the RFC 8018 default (used when a PEM doesn't specify a PRF)
            case hmacWithSHA1
            case hmacWithSHA224
            case hmacWithSHA256
            case hmacWithSHA384
            case hmacWithSHA512

            var objectIdentifier: ASN1ObjectIdentifier {
                switch self {
                case .hmacWithSHA1: return ASN1ObjectIdentifier.LibP2P.hmacWithSHA1
                case .hmacWithSHA224: return ASN1ObjectIdentifier.LibP2P.hmacWithSHA224
                case .hmacWithSHA256: return ASN1ObjectIdentifier.LibP2P.hmacWithSHA256
                case .hmacWithSHA384: return ASN1ObjectIdentifier.LibP2P.hmacWithSHA384
                case .hmacWithSHA512: return ASN1ObjectIdentifier.LibP2P.hmacWithSHA512
                }
            }

            init(objectIdentifier: ASN1ObjectIdentifier) throws {
                guard let prf = Self.allCases.first(where: { $0.objectIdentifier == objectIdentifier }) else {
                    throw Error.unsupportedPBKDFAlgorithm(objectIdentifier)
                }
                self = prf
            }

            fileprivate var variant: HMAC.Variant {
                switch self {
                case .hmacWithSHA1: return .sha1
                case .hmacWithSHA224: return .sha2(.sha224)
                case .hmacWithSHA256: return .sha2(.sha256)
                case .hmacWithSHA384: return .sha2(.sha384)
                case .hmacWithSHA512: return .sha2(.sha512)
                }
            }
        }

        /// - Note:
        /// Salt is usually 8 or 16 bytes of secure random bytes (consider using `LibP2PCrypto.randomBytes()`)
        /// - Note:
        /// Iterations *should* be in the 100's of thousands (the default is 310_000) lower values are less secure, but faster to compute.
        /// - Note:
        /// The `prf` defaults to HMAC-SHA1 to match RFC 8018, new exports made without an explicit `PBKDFAlgorithm` use HMAC-SHA256.
        case pbkdf2(salt: [UInt8], iterations: Int, prf: PRF = .hmacWithSHA1)

        /// Minimum accepted salt length in bytes (PKCS#5 / RFC 8018 recommend at least 64 bits).
        /// Kept at 8 so previously-encrypted PEMs (whose legacy default salt was 8 bytes) still import.
        static let minimumSaltLength = 8

        init(objID: ASN1ObjectIdentifier, salt: [UInt8], iterations: Int, prf: PRF = .hmacWithSHA1) throws {
            guard iterations > 0 else {
                throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF::iteration count must be positive")
            }
            guard salt.count >= Self.minimumSaltLength else {
                throw Error.invalidPEMFormat(
                    "EncryptedPrivateKey::PBKDF::salt too short (\(salt.count) < \(Self.minimumSaltLength))"
                )
            }
            switch objID {
            case ASN1ObjectIdentifier.LibP2P.pbkdf2:
                self = .pbkdf2(salt: salt, iterations: iterations, prf: prf)
            default:
                throw Error.unsupportedPBKDFAlgorithm(objID)
            }
        }

        func deriveKey(password: String, ofLength keyLength: Int) throws -> [UInt8] {
            switch self {
            case .pbkdf2(let salt, let iterations, let prf):
                return try PKCS5.PBKDF2(
                    password: password.bytes,
                    salt: salt,
                    iterations: iterations,
                    keyLength: keyLength,
                    variant: prf.variant
                ).calculate()
            }
        }

        var objectIdentifier: ASN1ObjectIdentifier {
            switch self {
            case .pbkdf2:
                return ASN1ObjectIdentifier.LibP2P.pbkdf2
            }
        }

        var salt: [UInt8] {
            switch self {
            case .pbkdf2(let salt, _, _):
                return salt
            }
        }

        var iterations: Int {
            switch self {
            case .pbkdf2(_, let iterations, _):
                return iterations
            }
        }

        var prf: PRF {
            switch self {
            case .pbkdf2(_, _, let prf):
                return prf
            }
        }

        func encodePBKDF() throws -> PBKDF2AlgorithmIdentifier {
            PBKDF2AlgorithmIdentifier(
                algorithm: self.objectIdentifier,
                salt: self.salt,
                iterationCount: self.iterations,
                prf: self.prf.objectIdentifier
            )
        }
    }

    /// Decodes the PBKDF ASN1 Block in an Encrypted Private Key PEM file
    /// - Parameter algorithmIdentifier: The decoded pbkdf AlgorithmIdentifier
    /// - Returns: The PBKDFAlogrithm if supported
    ///
    /// Expects the following ASN1 structure
    /// ```
    /// SEQUENCE {
    ///     OBJECT IDENTIFIER       // PBKDF2 (1.2.840.113549.1.5.12)
    ///     SEQUENCE {
    ///         OCTET STRING        // SALT
    ///         INTEGER             // ITERATIONS
    ///         INTEGER             // KEY LENGTH (optional)
    ///         SEQUENCE {          // PRF (optional, defaults to hmacWithSHA1)
    ///             OBJECT IDENTIFIER
    ///             NULL
    ///         }
    ///     }
    /// }
    /// ```
    internal static func decodePBKFD(_ algorithmIdentifier: PBKDF2AlgorithmIdentifier) throws -> PBKDFAlgorithm {
        try PBKDFAlgorithm(
            objID: algorithmIdentifier.algorithm,
            salt: Array(algorithmIdentifier.salt.bytes),
            iterations: algorithmIdentifier.iterationCount,
            prf: PBKDFAlgorithm.PRF(objectIdentifier: algorithmIdentifier.prf)
        )
    }
}
