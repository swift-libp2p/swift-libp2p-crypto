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

extension LibP2PCrypto {
    public struct PEM {

        public enum Error: Swift.Error {
            /// An error occured while encoding the PEM file
            case encodingError
            /// An error occured while decoding the PEM file
            case decodingError
            /// Encountered an unsupported PEM type
            case unsupportedPEMType
            /// Encountered an invalid/unexpected PEM format
            case invalidPEMFormat(String? = nil)
            /// Encountered an invalid/unexpected PEM header string/delimiter
            case invalidPEMHeader
            /// Encountered an invalid/unexpected PEM footer string/delimiter
            case invalidPEMFooter
            /// Encountered a invalid/unexpected parameters while attempting to decode a PEM file
            case invalidParameters
            /// Encountered an unsupported Cipher algorithm while attempting to decrypt an encrypted PEM file
            case unsupportedCipherAlgorithm(ASN1ObjectIdentifier)
            /// Encountered an unsupported Password Derivation algorithm while attempting to decrypt an encrypted PEM file
            case unsupportedPBKDFAlgorithm(ASN1ObjectIdentifier)
            /// The instiating types objectIdentifier does not match that of the PEM file
            case objectIdentifierMismatch(got: ASN1ObjectIdentifier, expected: ASN1ObjectIdentifier)
        }

        // MARK: Add support for additional PEM types here

        /// General PEM Classification
        internal enum PEMType {
            // Direct DER Exports for RSA Keys (special case)
            case publicRSAKeyDER
            case privateRSAKeyDER

            // Generale PEM Headers
            case publicKey
            case privateKey
            case encryptedPrivateKey
            case ecPrivateKey

            init(headerBytes: ArraySlice<UInt8>) throws {
                guard headerBytes.count > 10 else { throw PEM.Error.unsupportedPEMType }
                let bytes = headerBytes.dropFirst(5).dropLast(5)
                switch bytes {
                //"BEGIN RSA PUBLIC KEY"
                case [
                    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43,
                    0x20,
                    0x4b, 0x45, 0x59,
                ]:
                    self = .publicRSAKeyDER

                //"BEGIN RSA PRIVATE KEY"
                case [
                    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54,
                    0x45,
                    0x20, 0x4b, 0x45, 0x59,
                ]:
                    self = .privateRSAKeyDER

                //"BEGIN PUBLIC KEY"
                case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59]:
                    self = .publicKey

                //"BEGIN PRIVATE KEY"
                case [
                    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45,
                    0x59,
                ]:
                    self = .privateKey

                //"BEGIN ENCRYPTED PRIVATE KEY"
                case [
                    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x20,
                    0x50,
                    0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59,
                ]:
                    self = .encryptedPrivateKey

                //"BEGIN EC PRIVATE KEY"
                case [
                    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
                    0x20,
                    0x4b, 0x45, 0x59,
                ]:
                    self = .ecPrivateKey

                default:
                    throw PEM.Error.unsupportedPEMType
                }
            }

            /// This PEM type's header string (expressed as the utf8 decoded byte representation)
            var headerBytes: [UInt8] {
                switch self {
                case .publicRSAKeyDER:
                    return "-----BEGIN RSA PUBLIC KEY-----".bytes
                case .privateRSAKeyDER:
                    return "-----BEGIN RSA PRIVATE KEY-----".bytes
                case .publicKey:
                    return "-----BEGIN PUBLIC KEY-----".bytes
                case .privateKey:
                    return "-----BEGIN PRIVATE KEY-----".bytes
                case .encryptedPrivateKey:
                    return "-----BEGIN ENCRYPTED PRIVATE KEY-----".bytes
                case .ecPrivateKey:
                    return "-----BEGIN EC PRIVATE KEY-----".bytes
                }
            }

            /// This PEM type's footer string (expressed as the utf8 decoded byte representation)
            var footerBytes: [UInt8] {
                switch self {
                case .publicRSAKeyDER:
                    return "-----END RSA PUBLIC KEY-----".bytes
                case .privateRSAKeyDER:
                    return "-----END RSA PRIVATE KEY-----".bytes
                case .publicKey:
                    return "-----END PUBLIC KEY-----".bytes
                case .privateKey:
                    return "-----END PRIVATE KEY-----".bytes
                case .encryptedPrivateKey:
                    return "-----END ENCRYPTED PRIVATE KEY-----".bytes
                case .ecPrivateKey:
                    return "-----END EC PRIVATE KEY-----".bytes
                }
            }
        }

        /// Wraps DER encoded data with PEM armor, the base64 encoded body wrapped at 64 characters per line,
        /// surrounded by the PEM type's header and footer lines.
        /// - Parameters:
        ///   - der: The DER encoded data
        ///   - type: The PEM type, used for the header and footer
        ///   - withHeaderAndFooter: When false only the wrapped base64 body is returned
        /// - Returns: The UTF8 encoded PEM
        internal static func armor(_ der: [UInt8], as type: PEMType, withHeaderAndFooter: Bool = true) -> [UInt8] {
            let body = Array(
                Data(der).base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]).utf8
            )
            guard withHeaderAndFooter else { return body }
            return type.headerBytes + [0x0a] + body + [0x0a] + type.footerBytes
        }

        /// Converts UTF8 Encoding of PEM file into a PEMType and the base64 decoded key data
        /// - Parameter data: The `UTF8` encoding of the PEM file
        /// - Returns: A tuple containing the PEMType, and the actual base64 decoded PEM data (with the headers and footers removed).
        ///
        /// - Note: Both `\n` and `\r\n` line endings are supported, as is explanatory text before the
        ///   `-----BEGIN` line or after the `-----END` line (ex: OpenSSL's "Bag Attributes"). Only the first PEM block is decoded.
        internal static func pemToData(
            _ data: [UInt8]
        ) throws -> (type: PEMType, bytes: [UInt8], objectIdentifiers: [ASN1ObjectIdentifier]) {
            let fiveDashes = ArraySlice<UInt8>(repeating: 0x2D, count: 5)  // "-----".bytes.toHexString()
            let beginPrefix = ArraySlice("-----BEGIN ".utf8)
            let endPrefix = ArraySlice("-----END ".utf8)

            // Split into lines (0x0a == "\n"), trimming surrounding whitespace and any trailing "\r" (0x0d)
            let isWhitespace: (UInt8) -> Bool = { $0 == 0x20 || $0 == 0x09 || $0 == 0x0d }
            let chunks: [ArraySlice<UInt8>] = data.split(separator: 0x0a).compactMap { line in
                guard let first = line.firstIndex(where: { !isWhitespace($0) }),
                    let last = line.lastIndex(where: { !isWhitespace($0) })
                else { return nil }
                return line[first...last]
            }

            // Enforce a valid PEM header
            guard let headerIndex = chunks.firstIndex(where: { $0.starts(with: beginPrefix) }) else {
                throw PEM.Error.invalidPEMHeader
            }
            let header = chunks[headerIndex]
            guard header.count > 10, header.suffix(5) == fiveDashes else {
                throw PEM.Error.invalidPEMHeader
            }

            // Enforce a valid PEM footer
            guard
                let footerIndex = chunks[(headerIndex + 1)...].firstIndex(where: { $0.starts(with: endPrefix) })
            else {
                throw PEM.Error.invalidPEMFooter
            }
            let footer = chunks[footerIndex]
            guard footer.count > 10, footer.suffix(5) == fiveDashes else {
                throw PEM.Error.invalidPEMFooter
            }

            guard footerIndex - headerIndex > 1 else {
                throw PEM.Error.invalidPEMFormat("expected a header, body and footer, but the body was empty")
            }

            // Attempt to classify the PEMType based on the header
            //
            // - Note: This just gives us a general idea of what direction to head in. Headers that don't match the underlying data will end up throwing an Error later
            let pemType: PEMType = try PEMType(headerBytes: header)

            guard let base64 = String(data: Data(chunks[(headerIndex + 1)..<footerIndex].joined()), encoding: .utf8)
            else {
                throw Error.invalidPEMFormat("Unable to join chunked body data")
            }
            guard let pemData = Data(base64Encoded: base64) else {
                throw Error.invalidPEMFormat("Body of PEM isn't valid base64 encoded")
            }

            let asn1 = try DER.parse(pemData.byteArray)

            // return the PEMType and PEM Data (without header & footer)
            return (
                type: pemType, bytes: pemData.byteArray, objectIdentifiers: asn1.containedObjectIdentifiers
            )
        }

        /// Parses DER encoded data and returns all instances of objectIds contained within it
        internal static func objIdsInSequence(_ der: [UInt8]) throws -> [ASN1ObjectIdentifier] {
            try DER.parse(der).containedObjectIdentifiers
        }

        /// Decodes an ASN1 formatted Public Key into it's raw DER representation
        /// - Parameters:
        ///   - pem: The ASN1 encoded Public Key representation
        ///   - expectedPrimaryObjectIdentifier: The expected objectIdentifier for the particular key type
        ///   - expectedSecondaryObjectIdentifier: The expected secondary objectIdentifier (algorithm parameter) for the particular key type
        /// - Returns: The raw bitString data (Public Key DER)
        ///
        /// ```
        /// 0:d=0  hl=4 l= 546 cons: SEQUENCE
        /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
        /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
        /// 17:d=2  hl=2 l=   0 prim:   NULL
        /// 19:d=1  hl=4 l= 527 prim:  BIT STRING
        /// ```
        internal static func decodePublicKeyPEM(
            _ pem: Data,
            expectedPrimaryObjectIdentifier: ASN1ObjectIdentifier,
            expectedSecondaryObjectIdentifier: ASN1ObjectIdentifier?
        ) throws -> [UInt8] {
            let spki = try SubjectPublicKeyInfo(derEncoded: pem.byteArray)

            try validate(
                spki.algorithmIdentifier,
                expectedPrimaryObjectIdentifier: expectedPrimaryObjectIdentifier,
                expectedSecondaryObjectIdentifier: expectedSecondaryObjectIdentifier
            )

            return Array(spki.key.bytes)
        }

        /// Decodes an ASN1 formatted Private Key into it's raw DER representation
        /// - Parameters:
        ///   - pem: The ASN1 encoded Private Key representation
        ///   - expectedPrimaryObjectIdentifier: The expected objectIdentifier for the particular key type
        ///   - expectedSecondaryObjectIdentifier: The expected secondary objectIdentifier (algorithm parameter) for the particular key type
        /// - Returns: The raw octetString data (Private Key DER)
        ///
        /// Supports both the PKCS#8 `PrivateKeyInfo` structure (version 0)
        /// ```
        /// 0:d=0  hl=4 l= 630 cons: SEQUENCE
        /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
        /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
        /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
        /// 20:d=2  hl=2 l=   0 prim:   NULL
        /// 22:d=1  hl=4 l= 608 prim:  OCTET STRING      [HEX DUMP]:3082...AA50
        /// ```
        /// and the [RFC 5915](https://datatracker.ietf.org/doc/html/rfc5915#section-3) `ECPrivateKey` structure (version 1)
        /// ```
        /// ECPrivateKey ::= SEQUENCE {
        ///     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        ///     privateKey     OCTET STRING,
        ///     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        ///     publicKey  [1] BIT STRING OPTIONAL
        /// }
        /// ```
        internal static func decodePrivateKeyPEM(
            _ pem: Data,
            expectedPrimaryObjectIdentifier: ASN1ObjectIdentifier,
            expectedSecondaryObjectIdentifier: ASN1ObjectIdentifier?
        ) throws -> [UInt8] {
            let node = try DER.parse(pem.byteArray)

            // Peek at the version integer to determine which private key structure we're dealing with
            guard node.identifier == .sequence, case .constructed(let children) = node.content else {
                throw Error.invalidPEMFormat("PrivateKey::Top level node is not a sequence")
            }
            var iterator = children.makeIterator()
            guard let version = try? Int(derEncoded: &iterator) else {
                throw Error.invalidPEMFormat("PrivateKey::First item in top level sequence wasn't an integer")
            }

            switch version {
            case PrivateKeyInfo.version:
                // Proceed with standard pkcs8 private key format
                let privateKeyInfo = try PrivateKeyInfo(derEncoded: node)
                try validate(
                    privateKeyInfo.algorithmIdentifier,
                    expectedPrimaryObjectIdentifier: expectedPrimaryObjectIdentifier,
                    expectedSecondaryObjectIdentifier: expectedSecondaryObjectIdentifier
                )
                return Array(privateKeyInfo.privateKey.bytes)

            case ECPrivateKey.version:
                // Proceed with EC private key format
                let ecPrivateKey = try ECPrivateKey(derEncoded: node)
                // The named curve parameter is optional, but if present, it must match the Key.Type we're attempting to instantiate
                // (the curve is the secondary objectIdentifier for id-ecPublicKey keys, otherwise the primary one, ex: Secp256k1)
                let expectedCurve = expectedSecondaryObjectIdentifier ?? expectedPrimaryObjectIdentifier
                if let namedCurve = ecPrivateKey.namedCurve, namedCurve != expectedCurve {
                    throw Error.objectIdentifierMismatch(got: namedCurve, expected: expectedCurve)
                }
                return Array(ecPrivateKey.privateKey.bytes)

            default:
                throw Error.invalidPEMFormat("Unknown version identifier")
            }
        }

        /// Ensures the AlgorithmIdentifier specified in the PEM matches that of the Key.Type we're attempting to instantiate
        private static func validate(
            _ algorithmIdentifier: AlgorithmIdentifier,
            expectedPrimaryObjectIdentifier: ASN1ObjectIdentifier,
            expectedSecondaryObjectIdentifier: ASN1ObjectIdentifier?
        ) throws {
            guard algorithmIdentifier.algorithm == expectedPrimaryObjectIdentifier else {
                throw Error.objectIdentifierMismatch(
                    got: algorithmIdentifier.algorithm,
                    expected: expectedPrimaryObjectIdentifier
                )
            }

            // If the key supports a secondary objectIdentifier (ensure one is present and that they match)
            if let expectedSecondaryObjectIdentifier = expectedSecondaryObjectIdentifier {
                guard case .objectIdentifier(let secondaryObjectIdentifier) = algorithmIdentifier.parameters else {
                    throw Error.invalidPEMFormat("Missing secondary objectIdentifier")
                }
                guard secondaryObjectIdentifier == expectedSecondaryObjectIdentifier else {
                    throw Error.objectIdentifierMismatch(
                        got: secondaryObjectIdentifier,
                        expected: expectedSecondaryObjectIdentifier
                    )
                }
            }
        }
    }
}
