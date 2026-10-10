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
import CryptoSwift
import Foundation
import Multibase
import SwiftProtobuf

extension LibP2PCrypto {
    public enum Keys {
        public enum ElipticCurveType: Sendable, Equatable, CaseIterable {
            case P256
            case P384
            case P521

            public var bits: Int {
                switch self {
                case .P256:
                    return 256
                case .P384:
                    return 384
                case .P521:
                    return 521
                }
            }

            var description: String {
                "\(bits) Curve"
            }
        }

        public enum RSABitLength: Sendable {
            /// - Warning: RSA Keys with less than 2048 bits are considered insecure
            case B1024
            case B2048
            case B3072
            case B4096
            /// - Warning: RSA Keys with less than 2048 bits are considered insecure
            case custom(bits: Int)

            var bits: Int {
                switch self {
                case .B1024:
                    return 1024
                case .B2048:
                    return 2048
                case .B3072:
                    return 3072
                case .B4096:
                    return 4096
                case .custom(let bits):
                    return bits
                }
            }

            var description: String {
                "\(self.bits) Bit"
            }
        }

        public enum KeyPairType: Sendable {
            case RSA(bits: RSABitLength = .B2048)
            case Ed25519
            case Secp256k1
            case ECDSA(curve: ElipticCurveType = .P256)

            var toProtoType: KeyType {
                switch self {
                case .RSA:
                    return .rsa
                case .Ed25519:
                    return .ed25519
                case .Secp256k1:
                    return .secp256K1
                case .ECDSA:
                    return .ecdsa
                }
            }

            var description: String {
                switch self {
                case .RSA(let bits):
                    return "\(bits.description) RSA"
                case .Ed25519:
                    return "ED25519 Curve"
                case .Secp256k1:
                    return "Secp256k1"
                case .ECDSA(let curve):
                    return "\(curve.description) ECDSA"
                }
            }
        }

        public static func generateKeyPair(_ type: KeyPairType) throws -> KeyPair {
            try LibP2PCrypto.Keys.KeyPair(type)
        }

        /// Asynchronously generates a new key pair off the calling thread.
        ///
        /// Prefer this over the synchronous initializer for large RSA keys (3072 / 4096 bit),
        /// where generation can take a noticeable amount of time and would otherwise block the
        /// current task/actor.
        public static func generateKeyPair(_ type: KeyPairType) async throws -> KeyPair {
            try await Task.detached(priority: .userInitiated) {
                try LibP2PCrypto.Keys.KeyPair(type)
            }.value
        }

        /// Converts a protobuf serialized public key into its base encoded key data
        /// (for every key type this is the protobuf's `Data` field, ex: the DER encoded SubjectPublicKeyInfo for RSA keys).
        public static func unmarshalPublicKey(buf: [UInt8], into base: BaseEncoding = .base16) throws -> String {
            let pubKeyProto = try PublicKey(serializedBytes: buf)

            guard !pubKeyProto.data.isEmpty else {
                throw KeyError.invalidMarshaledData("Public key payload was empty")
            }

            return pubKeyProto.data.asString(base: base)
        }

        /// Converts a raw private key string into a protobuf serialized private key.
        public static func marshalPrivateKey(
            raw: String,
            asKeyType: KeyPairType,
            fromBase base: BaseEncoding? = nil
        ) throws -> [UInt8] {
            let decoded: [UInt8]
            do {
                if let b = base {
                    decoded = try BaseEncoding.decode(raw, as: b)
                } else {
                    decoded = try BaseEncoding.decode(raw).bytes
                }
            } catch {
                throw KeyError.invalidParameters(
                    "Failed to decode raw private key, unknown base encoding: \(error)"
                )
            }
            return try self.marshalPrivateKey(raw: Data(decoded), keyType: asKeyType)
        }

        public static func marshalPrivateKey(raw: Data, keyType: KeyPairType) throws -> [UInt8] {
            var privKeyProto = PrivateKey()
            privKeyProto.data = raw
            privKeyProto.type = keyType.toProtoType
            return Array(try privKeyProto.serializedData())
        }

        /// Converts a protobuf serialized private key into its representative object.
        public static func unmarshalPrivateKey(buf: [UInt8], into base: BaseEncoding = .base16) throws -> String {
            let privKeyProto = try PrivateKey(serializedBytes: buf)

            let data = privKeyProto.data
            guard !data.isEmpty else { throw KeyError.invalidMarshaledData("Private key payload was empty") }

            return data.asString(base: base)
        }
    }
}
