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
import Multihash

public protocol CommonPublicKey: DERCodable, Sendable {
    static var keyType: LibP2PCrypto.Keys.GenericKeyType { get }

    /// Init from raw representation
    init(rawRepresentation: Data) throws

    /// Raw Representation
    var rawRepresentation: Data { get }

    /// Encryption
    func encrypt(data: Data) throws -> Data

    // Signature Verification
    func verify(signature: Data, for: Data) throws -> Bool

    /// Imports
    //init(fromMarshaledData:Data) throws
    //init(pem:String) throws
    //init(der:String) throws

    /// Exports
    //func exportPEM() throws -> Data
    //func exportJWK() throws -> Data
    //func exportCID() throws -> Data
    func marshal() throws -> Data

    ///Misc
    func asString(base: BaseEncoding, withMultibasePrefix: Bool) -> String
    var data: Data { get }
    //func attributes() -> CommonKeyPair.Attributes
    //func id() throws -> String

    //var type:LibP2PCrypto.Keys.KeyPairType
}

extension CommonPublicKey {
    var keyType: LibP2PCrypto.Keys.GenericKeyType { Self.keyType }

    /// The multihash of the marshaled public key, per the libp2p peer-id spec.
    ///
    /// Keys whose marshaled (protobuf) form is 42 bytes or smaller are inlined verbatim using the
    /// `identity` multihash; larger keys are condensed with `sha2-256`. This is a size rule, not a
    /// per-key-type rule, and mirrors go-libp2p's `maxInlineKeyLength` behavior. In practice
    /// Ed25519 (~36 bytes) and Secp256k1 (~37 bytes) keys are inlined while RSA keys are hashed.
    ///
    /// - Reference: https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md
    public func multihash() throws -> Multihash {
        let marshaled = try self.marshal()
        if marshaled.count <= 42 {
            return try Multihash(hashing: marshaled, codec: .identity)
        } else {
            return try Multihash(hashing: marshaled, codec: .sha2_256)
        }
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
        //let mh = try Multihash(hashing: self.marshal(), codec: .sha2_256)
        let mh = try self.multihash()
        return mh.asString(base: .base58btc, withMultibasePrefix: withMultibasePrefix)
    }

    public func asString(base: BaseEncoding, withMultibasePrefix: Bool = false) -> String {
        self.rawRepresentation.asString(base: base, withMultibasePrefix: withMultibasePrefix)
    }

    public var data: Data {
        self.rawRepresentation
    }
}
