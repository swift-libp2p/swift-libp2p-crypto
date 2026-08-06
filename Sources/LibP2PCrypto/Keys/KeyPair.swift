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
import Multihash

extension LibP2PCrypto.Keys {
    public struct KeyPair: Sendable {
        public let keyType: LibP2PCrypto.Keys.GenericKeyType
        public let publicKey: CommonPublicKey
        public let privateKey: CommonPrivateKey?

        public struct Attributes {
            public let type: LibP2PCrypto.Keys.KeyPairType
            public let size: Int
            public let isPrivate: Bool

            internal init(type: LibP2PCrypto.Keys.KeyPairType, size: Int, isPrivate: Bool) {
                self.type = type
                self.size = size
                self.isPrivate = isPrivate
            }
        }

        /// Initialize a new KeyPair (this generates a private & public key of the specified type)
        public init(_ keyType: LibP2PCrypto.Keys.KeyPairType) throws {
            switch keyType {
            case .Ed25519:
                try self.init(privateKey: Curve25519.Signing.PrivateKey())
            case .Secp256k1:
                try self.init(privateKey: Secp256k1PrivateKey())
            case .RSA(let keySize):
                try self.init(privateKey: RSAPrivateKey(keySize: keySize.bits))
            //default:
            //    throw NSError(domain: "Unsupported Key Type", code: 0)
            }
        }

        /// Initialize a KeyPair with a Private Key
        init(privateKey: CommonPrivateKey) throws {
            self.keyType = privateKey.keyType
            self.publicKey = try privateKey.derivePublicKey()
            self.privateKey = privateKey
        }

        /// Initialize a KeyPair with a Public Key
        init(publicKey: CommonPublicKey) throws {
            self.keyType = publicKey.keyType
            self.publicKey = publicKey
            self.privateKey = nil
        }

        /// Whether this `KeyPair` carries a private key (and can therefore sign / decrypt).
        public var hasPrivateKey: Bool {
            privateKey != nil
        }

        /// The public keys multihash value
        ///
        /// - Note: The multihash is the SHA-256 Hash of the DER representation of the PublicKey
        public func multihash() throws -> Multihash {
            try self.publicKey.multihash()
        }

        /// The keys `rawID` is the SHA-256 multihash of its public key
        /// The public key is a protobuf encoding containing a type and the DER encoding
        /// of the PKCS SubjectPublicKeyInfo.
        public func rawID() throws -> [UInt8] {
            try self.multihash().value
        }

        /// The key id is the base58 encoding of the SHA-256 multihash of its public key.
        /// The public key is a protobuf encoding (marshaled) containing a type and the DER encoding
        /// of the PKCS SubjectPublicKeyInfo.
        public func id(withMultibasePrefix: Bool = true) throws -> String {
            //let mh = try Multihash(raw: self.marshal(), hashedWith: .sha2_256)
            let mh = try self.multihash()
            return withMultibasePrefix ? mh.asMultibase(.base58btc) : mh.asString(base: .base58btc)
        }

        /// Misc KeyPair Attributes (type, size, isPrivate)
        ///
        /// For RSA keys the size is derived from the actual modulus bit-length rather than a
        /// table of expected DER byte-counts, so non-standard key sizes are reported correctly.
        public func attributes() -> Attributes? {
            let isPrivate = self.privateKey != nil
            switch self.keyType {
            case .rsa:
                guard let bits = rsaModulusBitCount() else { return nil }
                let type: LibP2PCrypto.Keys.KeyPairType
                switch bits {
                case 1024: type = .RSA(bits: .B1024)
                case 2048: type = .RSA(bits: .B2048)
                case 3072: type = .RSA(bits: .B3072)
                case 4096: type = .RSA(bits: .B4096)
                default: type = .RSA(bits: .custom(bits: bits))
                }
                return Attributes(type: type, size: bits, isPrivate: isPrivate)

            case .ed25519:
                return Attributes(type: .Ed25519, size: 32, isPrivate: isPrivate)

            case .secp256k1:
                return Attributes(type: .Secp256k1, size: 64, isPrivate: isPrivate)
            }
        }

        /// Extracts the RSA modulus bit-length from the public key's SubjectPublicKeyInfo DER.
        ///
        /// Returns `nil` if the key isn't RSA or the DER can't be parsed as expected.
        private func rsaModulusBitCount() -> Int? {
            guard case .rsa = self.keyType else { return nil }
            guard
                case .sequence(let top)? = try? ASN1.Decoder.decode(data: self.publicKey.rawRepresentation),
                top.count >= 2,
                case .bitString(let pkcs1) = top[1],
                case .sequence(let numbers)? = try? ASN1.Decoder.decode(data: pkcs1),
                case .integer(let modulus)? = numbers.first
            else { return nil }
            // Strip DER sign-padding / leading zero bytes, then measure the remaining bits.
            var bytes = modulus.byteArray
            while bytes.first == 0 { bytes.removeFirst() }
            guard let msb = bytes.first else { return nil }
            return bytes.count * 8 - msb.leadingZeroBitCount
        }

        //public func asString(base:BaseEncoding, withMultibasePrefix:Bool = false) -> String {
        //    self.data.asString(base: base, withMultibasePrefix: withMultibasePrefix)
        //}

        // - MARK: Encryption & Decryption

        /// Certain asymmetric keys support encrypting data, use this method to do so.
        public func encrypt(data: Data) throws -> Data {
            try self.publicKey.encrypt(data: data)
        }

        /// Certain asymmetric keys support decrypting data, use this method to decrypt previously encrypted data.
        public func decrypt(data: Data) throws -> Data {
            guard let privateKey = privateKey else {
                throw LibP2PCrypto.Keys.KeyError.noPrivateKey
            }
            return try privateKey.decrypt(data: data)
        }

        // - MARK: Signature & Verifications

        /// Sign a piece of data for verification by another peer.
        ///
        /// - Note: Verify this signature by using the public key and calling
        ///   `verify(signature:for:)`.
        public func sign(message data: Data) throws -> Data {
            guard let privateKey = privateKey else {
                throw LibP2PCrypto.Keys.KeyError.noPrivateKey
            }
            return try privateKey.sign(message: data)
        }

        /// Verify a signature for the expected data.
        public func verify(signature: Data, for data: Data) throws -> Bool {
            try self.publicKey.verify(signature: signature, for: data)
        }

        // - MARK: Imports

        /// Instantiate a KeyPair from a marshaled public key
        public init(marshaledPublicKey str: String, base: BaseEncoding) throws {
            try self.init(marshaledPublicKey: BaseEncoding.decode(str, as: base).data)
        }
        /// Instantiate a KeyPair from a marshaled public key
        public init(marshaledPublicKey data: Data) throws {
            let proto = try PublicKey(serializedBytes: data)
            switch proto.type {
            case .rsa:
                try self.init(publicKey: RSAPublicKey(marshaledData: proto.data))

            case .ed25519:
                try self.init(publicKey: Curve25519.Signing.PublicKey(marshaledData: proto.data))

            case .secp256K1:
                try self.init(publicKey: Secp256k1PublicKey(marshaledData: proto.data))
            }
        }

        /// Instantiate a KeyPair from a marshaled private key
        public init(marshaledPrivateKey str: String, base: BaseEncoding) throws {
            try self.init(marshaledPrivateKey: BaseEncoding.decode(str, as: base).data)
        }

        /// Instantiate a KeyPair from a marshaled private key
        /// https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
        public init(marshaledPrivateKey data: Data) throws {
            let proto = try PrivateKey(serializedBytes: data)
            switch proto.type {
            case .rsa:
                try self.init(privateKey: RSAPrivateKey(marshaledData: proto.data))

            case .ed25519:
                switch proto.data.count {
                case 32:
                    try self.init(privateKey: Curve25519.Signing.PrivateKey(marshaledData: proto.data))
                case 64:
                    // [private key bytes][public key bytes]
                    // Ensure we can derive the attached public key
                    let privkey = try Curve25519.Signing.PrivateKey(marshaledData: proto.data.prefix(32))
                    guard privkey.publicKey.rawRepresentation == proto.data.suffix(32) else {
                        throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                            "Ed25519: unable to validate attached public key"
                        )
                    }
                    try self.init(privateKey: privkey)
                case 96:
                    // [private key][public key][public key]
                    // Ensure the two pubkeys match and we can derive the attached public key
                    let parts = Array(proto.data.chunks(ofCount: 32))
                    guard parts[1] == parts[2] else {
                        throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                            "Ed25519: attached public keys don't match"
                        )
                    }
                    let privkey = try Curve25519.Signing.PrivateKey(marshaledData: parts[0])
                    guard privkey.publicKey.rawRepresentation == parts[1] else {
                        throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                            "Ed25519: unable to validate attached public key"
                        )
                    }
                    try self.init(privateKey: privkey)
                default:
                    throw LibP2PCrypto.Keys.KeyError.invalidPrivateKeyEncoding(
                        "Ed25519: invalid data payload length \(proto.data.count)"
                    )
                }
            case .secp256K1:
                try self.init(privateKey: Secp256k1PrivateKey(marshaledData: proto.data))
            }
        }

        // - MARK: Exports

        /// The protobuf-marshaled representation of the public key
        /// (see the [libp2p peer-id spec](https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md)).
        public func marshalPublicKey() throws -> Data {
            try publicKey.marshal()
        }

        /// The protobuf-marshaled representation of the private key.
        ///
        /// - Throws: ``LibP2PCrypto/Keys/KeyError/noPrivateKey`` if this `KeyPair` only holds a public key.
        public func marshalPrivateKey() throws -> Data {
            guard let privateKey = privateKey else {
                throw LibP2PCrypto.Keys.KeyError.noPrivateKey
            }
            return try privateKey.marshal()
        }

    }
}

extension LibP2PCrypto.Keys {
    public enum GenericKeyType: Sendable, Equatable {
        case rsa
        case ed25519
        case secp256k1

        internal var toProtoType: KeyType {
            switch self {
            case .rsa:
                return .rsa
            case .ed25519:
                return .ed25519
            case .secp256k1:
                return .secp256K1
            }
        }

        internal init(_ t: KeyType) {
            switch t {
            case .rsa:
                self = .rsa
            case .ed25519:
                self = .ed25519
            case .secp256K1:
                self = .secp256k1
            }
        }

        static func == (lhs: GenericKeyType, rhs: KeyType) -> Bool {
            lhs.toProtoType == rhs
        }

        public static func == (lhs: GenericKeyType, rhs: KeyPairType) -> Bool {
            lhs.toProtoType == rhs.toProtoType
        }
    }
}

extension LibP2PCrypto.Keys.KeyPair {
    public init(pem: String, password: String? = nil) throws {
        try self.init(pem: pem.bytes, password: password)
    }

    public init(pem: Data, password: String? = nil) throws {
        try self.init(pem: pem.byteArray, password: password)
    }

    public init(pem pemBytes: [UInt8], password: String? = nil) throws {

        let (type, bytes, ids) = try LibP2PCrypto.PEM.pemToData(pemBytes)

        if password != nil {
            guard type == .encryptedPrivateKey else { throw LibP2PCrypto.PEM.Error.invalidParameters }
        }

        switch type {
        case .publicRSAKeyDER:
            // Ensure the objectIdentifier is rsaEncryption
            try self.init(publicKey: RSAPublicKey(publicDER: bytes))

        case .privateRSAKeyDER:
            // Ensure the objectIdentifier is rsaEncryption
            try self.init(privateKey: RSAPrivateKey(privateDER: bytes))

        case .publicKey:
            // Attempt to further classify the pem into it's exact key type
            if ids.contains(RSAPublicKey.primaryObjectIdentifier) {
                try self.init(publicKey: RSAPublicKey(pem: pemBytes, asType: RSAPublicKey.self))
            } else if ids.contains(Curve25519.Signing.PublicKey.primaryObjectIdentifier) {
                try self.init(
                    publicKey: Curve25519.Signing.PublicKey(pem: pemBytes, asType: Curve25519.Signing.PublicKey.self)
                )
            } else if ids.contains(Secp256k1PublicKey.primaryObjectIdentifier) {
                try self.init(publicKey: Secp256k1PublicKey(pem: pemBytes, asType: Secp256k1PublicKey.self))
            } else {
                throw LibP2PCrypto.PEM.Error.unsupportedPEMType
            }

        case .privateKey, .ecPrivateKey:
            // Attempt to further classify the pem into it's exact key type
            if ids.contains(RSAPrivateKey.primaryObjectIdentifier) {
                try self.init(privateKey: RSAPrivateKey(pem: pemBytes, asType: RSAPrivateKey.self))
            } else if ids.contains(Curve25519.Signing.PrivateKey.primaryObjectIdentifier) {
                try self.init(
                    privateKey: Curve25519.Signing.PrivateKey(pem: pemBytes, asType: Curve25519.Signing.PrivateKey.self)
                )
            } else if ids.contains(Secp256k1PrivateKey.primaryObjectIdentifier) {
                try self.init(privateKey: Secp256k1PrivateKey(pem: pemBytes, asType: Secp256k1PrivateKey.self))
            } else {
                throw LibP2PCrypto.PEM.Error.unsupportedPEMType
            }

        case .encryptedPrivateKey:
            // Decrypt the encrypted PEM and attempt to instantiate it again...

            // Ensure we were provided a password
            guard let password = password else { throw LibP2PCrypto.PEM.Error.invalidParameters }

            // Parse out Encryption Strategy and CipherText
            let decryptionStategy = try LibP2PCrypto.PEM.decodeEncryptedPEM(Data(bytes))

            // Derive Encryption Key from Password
            let key = try decryptionStategy.pbkdfAlgorithm.deriveKey(
                password: password,
                ofLength: decryptionStategy.cipherAlgorithm.desiredKeyLength
            )

            // Decrypt CipherText
            let decryptedPEM = try decryptionStategy.cipherAlgorithm.decrypt(
                bytes: decryptionStategy.ciphertext,
                withKey: key
            )

            // Extract out the objectIdentifiers from the decrypted pem
            let ids: [[UInt8]]
            do {
                ids = try LibP2PCrypto.PEM.objIdsInSequence(ASN1.Decoder.decode(data: Data(decryptedPEM))).map {
                    $0.byteArray
                }
            } catch {
                throw LibP2PCrypto.PEM.Error.decodingError
            }

            // Attempt to classify the Key Type
            if ids.contains(RSAPrivateKey.primaryObjectIdentifier) {
                let der = try LibP2PCrypto.PEM.decodePrivateKeyPEM(
                    Data(decryptedPEM),
                    expectedPrimaryObjectIdentifier: RSAPrivateKey.primaryObjectIdentifier,
                    expectedSecondaryObjectIdentifier: RSAPrivateKey.secondaryObjectIdentifier
                )
                try self.init(privateKey: RSAPrivateKey(privateDER: der))
            } else if ids.contains(Curve25519.Signing.PrivateKey.primaryObjectIdentifier) {
                let der = try LibP2PCrypto.PEM.decodePrivateKeyPEM(
                    Data(decryptedPEM),
                    expectedPrimaryObjectIdentifier: Curve25519.Signing.PrivateKey.primaryObjectIdentifier,
                    expectedSecondaryObjectIdentifier: Curve25519.Signing.PrivateKey.secondaryObjectIdentifier
                )
                try self.init(privateKey: Curve25519.Signing.PrivateKey(privateDER: der))
            } else if ids.contains(Secp256k1PrivateKey.primaryObjectIdentifier) {
                let der = try LibP2PCrypto.PEM.decodePrivateKeyPEM(
                    Data(decryptedPEM),
                    expectedPrimaryObjectIdentifier: Secp256k1PrivateKey.primaryObjectIdentifier,
                    expectedSecondaryObjectIdentifier: Secp256k1PrivateKey.secondaryObjectIdentifier
                )
                try self.init(privateKey: Secp256k1PrivateKey(privateDER: der))
            } else {
                throw LibP2PCrypto.PEM.Error.unsupportedPEMType
            }
        }
    }
}

extension LibP2PCrypto.Keys.KeyPair {

    public func exportPublicPEM(withHeaderAndFooter: Bool = true) throws -> [UInt8] {
        //guard let der = publicKey as? DEREncodable else { throw NSError(domain: "Unknown private key type", code: 0) }
        try publicKey.exportPublicKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
    }

    public func exportPrivatePEM(withHeaderAndFooter: Bool = true) throws -> [UInt8] {
        guard let privKey = self.privateKey else {
            throw LibP2PCrypto.Keys.KeyError.noPrivateKey
        }
        return try privKey.exportPrivateKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
    }

    public func exportPublicPEMString(withHeaderAndFooter: Bool = true) throws -> String {
        //guard let der = publicKey as? DEREncodable else { throw NSError(domain: "Unknown private key type", code: 0) }
        try publicKey.exportPublicKeyPEMString(withHeaderAndFooter: withHeaderAndFooter)
    }

    public func exportPrivatePEMString(withHeaderAndFooter: Bool = true) throws -> String {
        guard let privKey = self.privateKey else {
            throw LibP2PCrypto.Keys.KeyError.noPrivateKey
        }
        return try privKey.exportPrivateKeyPEMString(withHeaderAndFooter: withHeaderAndFooter)
    }

    public func exportEncryptedPrivatePEMString(withPassword password: String) throws -> String {
        try self.exportEncryptedPrivatePEMString(
            withPassword: password,
            usingPBKDF: .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 8), iterations: 2048),
            andCipher: .aes_128_cbc(iv: LibP2PCrypto.randomBytes(length: 16))
        )
    }

    internal func exportEncryptedPrivatePEM(
        withPassword password: String,
        usingPBKDF pbkdf: LibP2PCrypto.PEM.PBKDFAlgorithm? = nil,
        andCipher cipher: LibP2PCrypto.PEM.CipherAlgorithm? = nil
    ) throws -> [UInt8] {
        let cipher = try cipher ?? .aes_128_cbc(iv: LibP2PCrypto.randomBytes(length: 16))
        let pbkdf = try pbkdf ?? .pbkdf2(salt: LibP2PCrypto.randomBytes(length: 8), iterations: 2048)

        return try LibP2PCrypto.PEM.encryptPEM(
            Data(self.privateKey!.exportPrivateKeyPEMRaw()),
            withPassword: password,
            usingPBKDF: pbkdf,
            andCipher: cipher
        ).byteArray
    }

    internal func exportEncryptedPrivatePEMString(
        withPassword password: String,
        usingPBKDF pbkdf: LibP2PCrypto.PEM.PBKDFAlgorithm? = nil,
        andCipher cipher: LibP2PCrypto.PEM.CipherAlgorithm? = nil
    ) throws -> String {
        let data = try self.exportEncryptedPrivatePEM(withPassword: password, usingPBKDF: pbkdf, andCipher: cipher)
        return String(data: Data(data), encoding: .utf8)!
    }

}
