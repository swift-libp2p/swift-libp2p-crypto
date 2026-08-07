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

extension LibP2PCrypto.Keys {
    /// The errors that can be thrown by the key subsystem.
    ///
    /// This replaces the ad-hoc `NSError(domain:code:)` values that were previously thrown
    /// throughout the library. Prefer matching on a specific case over inspecting the
    /// human-readable `description`.
    public enum KeyError: Swift.Error, CustomStringConvertible, Sendable, Equatable {
        /// An operation that requires a private key was attempted on a public-only `KeyPair`.
        case noPrivateKey
        /// The requested key type isn't supported (by this platform or at all).
        case unsupportedKeyType(String)
        /// The key type doesn't support the requested operation (e.g. Secp256k1 encryption).
        case unsupportedOperation(String)
        /// The provided raw key bytes couldn't be interpreted as a valid key.
        case invalidRawRepresentation(String)
        /// The protobuf-marshaled key data was malformed or of the wrong type.
        case invalidMarshaledData(String)
        /// A private key's on-the-wire encoding failed validation (e.g. mismatched public key).
        case invalidPrivateKeyEncoding(String)
        /// Key generation failed in the underlying crypto provider.
        case keyGenerationFailed(String)
        /// Deriving a public key from a private key failed.
        case publicKeyDerivationFailed(String)
        /// Encryption failed in the underlying crypto provider.
        case encryptionFailed(String)
        /// Decryption failed in the underlying crypto provider.
        case decryptionFailed(String)
        /// Producing a signature failed.
        case signatureFailed(String)
        /// A signature was the wrong length for the key type.
        case invalidSignatureLength(expected: Int, got: Int)
        /// The caller passed invalid or inconsistent parameters.
        case invalidParameters(String)
        /// An unexpected internal failure. The associated value describes the context.
        case internalError(String)

        public var description: String {
            switch self {
            case .noPrivateKey:
                return "No private key available for this operation."
            case .unsupportedKeyType(let detail):
                return "Unsupported key type: \(detail)"
            case .unsupportedOperation(let detail):
                return "Unsupported operation: \(detail)"
            case .invalidRawRepresentation(let detail):
                return "Invalid raw key representation: \(detail)"
            case .invalidMarshaledData(let detail):
                return "Invalid marshaled key data: \(detail)"
            case .invalidPrivateKeyEncoding(let detail):
                return "Invalid private key encoding: \(detail)"
            case .keyGenerationFailed(let detail):
                return "Key generation failed: \(detail)"
            case .publicKeyDerivationFailed(let detail):
                return "Public key derivation failed: \(detail)"
            case .encryptionFailed(let detail):
                return "Encryption failed: \(detail)"
            case .decryptionFailed(let detail):
                return "Decryption failed: \(detail)"
            case .signatureFailed(let detail):
                return "Signature failed: \(detail)"
            case .invalidSignatureLength(let expected, let got):
                return "Invalid signature length, expected at least \(expected) bytes, got \(got)."
            case .invalidParameters(let detail):
                return "Invalid parameters: \(detail)"
            case .internalError(let detail):
                return "Internal error: \(detail)"
            }
        }
    }
}
