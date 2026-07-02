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
import Multibase
import P256K

extension P256K.Signing.PublicKey: CommonPublicKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .secp256k1 }

    /// The raw uncompressed public key bytes (without the 0x04 header prefix)
    public var rawPublicKey: [UInt8] {
        // `uncompressedRepresentation` is always the 65 byte `0x04 || X || Y` form
        // regardless of the format this key is stored in. Drop the 0x04 header prefix.
        Array(self.uncompressedRepresentation.byteArray.dropFirst())
    }

    /// Normalizes serialized public key bytes and determines the appropriate P256K format.
    /// - 33 bytes: compressed (`0x02` / `0x03` prefix)
    /// - 65 bytes: uncompressed (`0x04` prefix)
    /// - 64 bytes: uncompressed coordinates without the `0x04` header (prefix is added)
    static func normalizedPublicKey(_ bytes: [UInt8]) -> (bytes: [UInt8], format: P256K.Format) {
        switch bytes.count {
        case 33:
            return (bytes, .compressed)
        case 64:
            return ([0x04] + bytes, .uncompressed)
        default:
            return (bytes, .uncompressed)
        }
    }

    /// Convenient initializer for `init(publicKey:)`
    public init(_ bytes: [UInt8]) throws {
        let (normalized, format) = Self.normalizedPublicKey(bytes)
        try self.init(dataRepresentation: normalized, format: format)
    }

    public init(publicKey bytes: [UInt8]) throws {
        let (normalized, format) = Self.normalizedPublicKey(bytes)
        try self.init(dataRepresentation: normalized, format: format)
    }

    public init(rawRepresentation raw: Data) throws {
        let (normalized, format) = Self.normalizedPublicKey(raw.byteArray)
        try self.init(dataRepresentation: normalized, format: format)
    }

    public init(marshaledData data: Data) throws {
        // The marshaled and RawRespresentation are the same thing for SecP256k1 keys
        try self.init(rawRepresentation: data)
    }

    /// Initializes a new instance of `SecP256k1PublicKey` with the given a hex string.
    /// - Parameter hexPublicKey: The uncompressed (or compressed) hex public key either with the hex prefix `0x` or without.
    /// - throws: SecP256k1PublicKey.Error.keyMalformed if the given `hexPublicKey` does not fulfill the requirements from above. Or a SecP256k1PublicKey.Error.internalError if a secp256k1 library fails to parse / validate the provided key.
    public init(hexPublicKey: String) throws {
        let byteCount = hexPublicKey.count
        guard byteCount == 128 || byteCount == 130 || byteCount == 64 || byteCount == 66 else {
            throw P256K.Signing.Error.keyMalformed
        }

        let decoded = Array(try BaseEncoding.decode(hexPublicKey, as: .base16).data)
        let (normalized, format) = Self.normalizedPublicKey(decoded)
        try self.init(dataRepresentation: normalized, format: format)
    }

    /// The canonical raw representation of a secp256k1 public key: the 64 byte uncompressed
    /// `X || Y` coordinates without the `0x04` header prefix. This is format independent so
    /// two keys representing the same point compare equal regardless of how they were parsed.
    public var rawRepresentation: Data {
        Data(self.rawPublicKey)
    }

    public func encrypt(data: Data) throws -> Data {
        throw P256K.Signing.Error.operationUnsupported("Secp256k1 Keys don't support encryption")
    }

    public func verify(signature: Data, for expectedData: Data) throws -> Bool {
        guard signature.count >= 32 + 32 else {
            throw P256K.Signing.Error.operationUnsupported(
                "Invalid Signature Length, expected at least 64 bytes, got \(signature.count)"
            )
        }
        let sig = try P256K.Signing.ECDSASignature(dataRepresentation: signature)
        return self.isValidSignature(sig, for: expectedData)
    }

    public func marshal() throws -> Data {
        var publicKey = PublicKey()
        publicKey.type = .secp256K1
        // libp2p marshals secp256k1 public keys in their 33 byte compressed form.
        publicKey.data = try Data(self.compressPublicKey())
        return try publicKey.serializedData()
    }

    //    public init(pem: String) throws {
    //        try self.init(pemRepresentation: pem)
    //    }

    /// Returns this public key serialized as a hex string.
    /// - Uncompressed 64 byte public key without the header prefix (0x04)
    public func hex() -> String {
        self.rawPublicKey.asString(base: .base16)
    }

    public func compressPublicKey() throws -> [UInt8] {
        if self.format == .compressed {
            return self.dataRepresentation.byteArray
        }
        // Derive the compressed form (0x02 / 0x03 || X) from the uncompressed `0x04 || X || Y`
        // point by selecting the prefix based on the parity of the Y coordinate.
        let uncompressed = self.uncompressedRepresentation.byteArray
        let x = Array(uncompressed[1..<33])
        let yIsOdd = (uncompressed[64] & 0x01) == 1
        return [yIsOdd ? 0x03 : 0x02] + x
    }
}

extension P256K.Signing.PrivateKey: CommonPrivateKey {
    public static var keyType: LibP2PCrypto.Keys.GenericKeyType { .secp256k1 }

    public init(_ bytes: [UInt8]) throws {
        try self.init(dataRepresentation: bytes)
    }

    public init(privateKey bytes: [UInt8]) throws {
        try self.init(dataRepresentation: bytes)
    }

    public init(rawRepresentation raw: Data) throws {
        try self.init(dataRepresentation: raw)
    }

    public init(marshaledData data: Data) throws {
        // The marshaled and RawRespresentation are the same thing for SecP256k1 keys
        try self.init(rawRepresentation: data)
    }

    /// Initializes a new instance of `EthereumPrivateKey` with the given `hexPrivateKey` hex string.
    ///
    /// - Parameters:
    ///   - hexPrivateKey: must be either 64 characters long or 66 characters (with the hex prefix 0x).
    ///   - ctx: An optional self managed context. If you have specific requirements and
    ///          your app performs not as fast as you want it to, you can manage the
    ///          `secp256k1_context` yourself with the public methods
    ///          `secp256k1_default_ctx_create` and `secp256k1_default_ctx_destroy`.
    ///          If you do this, we will not be able to free memory automatically and you
    ///          __have__ to destroy the context yourself once your app is closed or
    ///          you are sure it will not be used any longer. Only use this optional
    ///          context management if you know exactly what you are doing and you really
    ///          need it.
    /// - throws: EthereumPrivateKey.Error.keyMalformed if the restrictions described above are not met.
    ///           EthereumPrivateKey.Error.internalError if a secp256k1 library call or another internal call fails.
    ///           EthereumPrivateKey.Error.pubKeyGenerationFailed if the public key extraction from the private key fails.
    /// - Note: `privateKey` must be in the secp256k1 range as described in: https://en.bitcoin.it/wiki/Private_key
    /// ```
    /// So any number between
    /// 0x0000000000000000000000000000000000000000000000000000000000000001
    /// and
    /// 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
    /// is considered to be a valid secp256k1 private key.
    ///  ```
    public init(hexPrivateKey: String) throws {
        guard hexPrivateKey.count == 64 || hexPrivateKey.count == 66 else {
            throw P256K.Signing.Error.keyMalformed
        }

        var hexPrivateKey = hexPrivateKey

        if hexPrivateKey.count == 66 {
            let s = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: 0)
            let e = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: 2)
            let prefix = String(hexPrivateKey[s..<e])

            guard prefix == "0x" else {
                throw P256K.Signing.Error.keyMalformed
            }

            // Remove prefix
            hexPrivateKey = String(hexPrivateKey[e...])
        }

        //guard let raw = try? BaseEncoding.decode(hexPrivateKey, as: .base16) else {
        //    throw P256K.Signing.Error.keyMalformed
        //}
        var raw = [UInt8]()
        for i in stride(from: 0, to: hexPrivateKey.count, by: 2) {
            let s = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: i)
            let e = hexPrivateKey.index(hexPrivateKey.startIndex, offsetBy: i + 2)

            guard let b = UInt8(String(hexPrivateKey[s..<e]), radix: 16) else {
                throw P256K.Signing.Error.keyMalformed
            }
            raw.append(b)
        }

        try self.init(privateKey: raw)
    }

    //    public init(pem: String) throws {
    //        try self.init(pemRepresentation: pem)
    //    }

    public var rawRepresentation: Data {
        self.dataRepresentation
    }

    /// Derives a Public Key from the Private Key
    public func derivePublicKey() throws -> CommonPublicKey {
        self.publicKey
    }

    public func decrypt(data: Data) throws -> Data {
        throw P256K.Signing.Error.operationUnsupported("Secp256k1 Keys don't support decryption")
    }

    public func sign(message data: Data) throws -> Data {
        self.signature(for: data).dataRepresentation
    }

    public func marshal() throws -> Data {
        var privateKey = PrivateKey()
        privateKey.type = .secp256K1
        privateKey.data = self.rawRepresentation
        return try privateKey.serializedData()
    }

}

extension P256K.Signing.PublicKey: DERCodable {
    public static var primaryObjectIdentifier: [UInt8] { [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] }
    public static var secondaryObjectIdentifier: [UInt8]? { [0x2B, 0x81, 0x04, 0x00, 0x0A] }

    public init(publicDER: [UInt8]) throws {
        // `publicDER` is the raw EC point bit string (`0x04 || X || Y` uncompressed, or the
        // compressed form) extracted from the SubjectPublicKeyInfo, not a full DER structure.
        try self.init(publicKey: publicDER)
    }

    public init(privateDER: [UInt8]) throws {
        throw P256K.Signing.Error.operationUnsupported("Can't instantiate private key from public DER representation")
    }

    public func publicKeyDER() throws -> [UInt8] {
        // The SubjectPublicKeyInfo bit string carries the full uncompressed point `0x04 || X || Y`.
        self.uncompressedRepresentation.byteArray
    }

    public func privateKeyDER() throws -> [UInt8] {
        throw P256K.Signing.Error.operationUnsupported("Public Key doesn't have private DER representation")
    }

    public func exportPublicKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let publicDER = try self.publicKeyDER()

        let asnNodes: ASN1.Node = .sequence(nodes: [
            .sequence(nodes: [
                .objectIdentifier(data: Data(Self.primaryObjectIdentifier)),
                .objectIdentifier(data: Data(Self.secondaryObjectIdentifier!)),
            ]),
            .bitString(data: Data(publicDER)),
        ])

        let base64String = ASN1.Encoder.encode(asnNodes).toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = Array(bodyString.utf8)

        if withHeaderAndFooter {
            let header = LibP2PCrypto.PEM.PEMType.publicKey.headerBytes + [0x0a]
            let footer = [0x0a] + LibP2PCrypto.PEM.PEMType.publicKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }
}

extension P256K.Signing.PrivateKey: DERCodable {
    public static var primaryObjectIdentifier: [UInt8] { [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A] }
    public static var secondaryObjectIdentifier: [UInt8]? { nil }

    public init(publicDER: [UInt8]) throws {
        throw P256K.Signing.Error.operationUnsupported("Can't instantiate a P256K.Signing.PrivateKey from a public key")
    }

    public init(privateDER: [UInt8]) throws {
        try self.init(rawRepresentation: Data(privateDER))
    }

    public func publicKeyDER() throws -> [UInt8] {
        try self.publicKey.publicKeyDER()
    }

    public func privateKeyDER() throws -> [UInt8] {
        self.rawRepresentation.byteArray
    }

    public func exportPrivateKeyPEMRaw() throws -> [UInt8] {
        let publicDER = try self.publicKeyDER()

        let pubKeyBitString: ASN1.Node = .bitString(data: Data(publicDER))

        let asnNodes: ASN1.Node = .sequence(nodes: [
            .integer(data: Data(hex: "0x01")),
            .octetString(data: self.rawRepresentation),
            .ecObject(data: Data(Self.primaryObjectIdentifier)),
            .ecBits(data: Data(ASN1.Encoder.encode(pubKeyBitString))),
        ])

        return ASN1.Encoder.encode(asnNodes)
    }

    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> [UInt8] {
        let base64String = try self.exportPrivateKeyPEMRaw().toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = Array(bodyString.utf8)

        if withHeaderAndFooter {
            let header = LibP2PCrypto.PEM.PEMType.ecPrivateKey.headerBytes + [0x0a]
            let footer = [0x0a] + LibP2PCrypto.PEM.PEMType.ecPrivateKey.footerBytes

            return header + bodyUTF8Bytes + footer
        } else {
            return bodyUTF8Bytes
        }
    }

}

extension P256K.Signing.PublicKey: @retroactive Equatable {
    public static func == (lhs: P256K.Signing.PublicKey, rhs: P256K.Signing.PublicKey) -> Bool {
        // Compare the underlying curve point, independent of compressed / uncompressed format.
        lhs.uncompressedRepresentation == rhs.uncompressedRepresentation
    }
}

extension P256K.Signing {
    // MARK: - Errors

    public enum Error: Swift.Error {
        case internalError
        case keyMalformed
        case pubKeyGenerationFailed
        case operationUnsupported(String)
    }
}
