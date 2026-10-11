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

public protocol CommonPrivateKey: DERCodable, Sendable {
    static var keyType: LibP2PCrypto.Keys.KeyType { get }

    /// Init from raw representation
    init(rawRepresentation: Data) throws

    /// Raw Representation
    var rawRepresentation: Data { get }

    /// Derivation
    func derivePublicKey() throws -> CommonPublicKey

    /// Decryption
    func decrypt(data: Data) throws -> Data

    /// Signatures
    func sign(message: Data) throws -> Data

    /// The protobuf-marshaled representation of the private key
    func marshal() throws -> Data

    /// Init from the `data` field of a protobuf-marshaled private key
    init(marshaledData: Data) throws
}

extension CommonPrivateKey {
    /// The type of this key
    public var keyType: LibP2PCrypto.Keys.KeyType { Self.keyType }
}

extension CommonPrivateKey {
    /// The keys `rawID` is the multihash (see ``CommonPublicKey/multihash()``) of its marshaled public key
    public func rawID() throws -> [UInt8] {
        try self.derivePublicKey().rawID()
    }

    /// The key id is the base58 encoding of the multihash (see ``CommonPublicKey/multihash()``) of its marshaled public key
    public func id(withMultibasePrefix: Bool = true) throws -> String {
        try self.derivePublicKey().id(withMultibasePrefix: withMultibasePrefix)
    }

    public func asString(base: BaseEncoding, withMultibasePrefix: Bool = false) -> String {
        self.data.asString(base: base, withMultibasePrefix: withMultibasePrefix)
    }

    public var data: Data {
        self.rawRepresentation
    }
}
