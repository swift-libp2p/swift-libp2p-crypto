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

// MARK: Encrypted PEM PBKDF Algorithms

extension LibP2PCrypto.PEM {
    // MARK: Add support for new PBKDF Algorithms here...
    internal enum PBKDFAlgorithm {
        case pbkdf2(salt: [UInt8], iterations: Int)

        init(objID: [UInt8], salt: [UInt8], iterations: [UInt8]) throws {
            guard let iterations = Int(iterations.toHexString(), radix: 16) else {
                throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF")
            }
            switch objID {
            case [42, 134, 72, 134, 247, 13, 1, 5, 12]:  // pbkdf2
                self = .pbkdf2(salt: salt, iterations: iterations)
            default:
                throw Error.unsupportedPBKDFAlgorithm(objID)
            }
        }

        func deriveKey(
            password: String,
            ofLength keyLength: Int,
            usingHashVarient variant: HMAC.Variant = .sha1
        ) throws -> [UInt8] {
            switch self {
            case .pbkdf2(let salt, let iterations):
                //print("Salt: \(salt), Iterations: \(iterations)")
                let key = try PKCS5.PBKDF2(
                    password: password.bytes,
                    salt: salt,
                    iterations: iterations,
                    keyLength: keyLength,
                    variant: variant
                ).calculate()
                //print(key)
                return key
            //default:
            //    throw Error.invalidPEMFormat
            }
        }

        var objectIdentifier: [UInt8] {
            switch self {
            case .pbkdf2:
                return [42, 134, 72, 134, 247, 13, 1, 5, 12]
            }
        }

        var salt: [UInt8] {
            switch self {
            case .pbkdf2(let salt, _):
                return salt
            }
        }

        var iterations: Int {
            switch self {
            case .pbkdf2(_, let iterations):
                return iterations
            }
        }

        func encodePBKDF() throws -> ASN1.Node {
            .sequence(nodes: [
                .objectIdentifier(data: Data(self.objectIdentifier)),
                .sequence(nodes: [
                    .octetString(data: Data(self.salt)),
                    .integer(data: Data(Self.encodeIterationCount(self.iterations))),
                ]),
            ])
        }

        /// Encodes the PBKDF2 iteration count as the content octets of a DER `INTEGER`.
        ///
        /// The previous implementation hard-coded a 2-byte width, which silently truncated
        /// iteration counts above 65535. This produces a minimal big-endian encoding and
        /// prepends a `0x00` byte when the most significant bit is set so the value is never
        /// misinterpreted as negative by strict DER parsers (e.g. OpenSSL).
        static func encodeIterationCount(_ value: Int) -> [UInt8] {
            var bytes = withUnsafeBytes(of: value.bigEndian, Array<UInt8>.init)
            while bytes.count > 1, bytes.first == 0 { bytes.removeFirst() }
            if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
            return bytes
        }
    }

    /// Decodes the PBKDF ASN1 Block in an Encrypted Private Key PEM file
    /// - Parameter node: The ASN1 sequence node containing the pbkdf parameters
    /// - Returns: The PBKDFAlogrithm if supported
    ///
    /// Expects an ASN1.Node with the following structure
    /// ```
    /// ASN1.Parser.Node.sequence(nodes: [
    ///     ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
    ///     ASN1.Parser.Node.sequence(nodes: [
    ///         ASN1.Parser.Node.octetString(data: 8 bytes),       //SALT
    ///         ASN1.Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
    ///     ])
    /// ])
    /// ```
    internal static func decodePBKFD(_ node: ASN1.Node) throws -> PBKDFAlgorithm {
        guard case .sequence(let wrapper) = node else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
        guard wrapper.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
        guard case .objectIdentifier(let objID) = wrapper.first else {
            throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF")
        }
        guard case .sequence(let params) = wrapper.last else {
            throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF")
        }
        guard params.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
        guard case .octetString(let salt) = params.first else {
            throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF")
        }
        guard case .integer(let iterations) = params.last else {
            throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF")
        }

        return try PBKDFAlgorithm(objID: objID.byteArray, salt: salt.byteArray, iterations: iterations.byteArray)
    }
}
