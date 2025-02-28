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

extension RSAPublicKey:DERCodable {
    /// RSA Object Identifier Bytes
    public static var primaryObjectIdentifier: Array<UInt8> { [42, 134, 72, 134, 247, 13, 1, 1, 1] }
    
    public static var secondaryObjectIdentifier: Array<UInt8>? { nil }
    
    public func publicKeyDER() throws -> Array<UInt8> {
        return self.rawRepresentation.bytes
    }
    
    public func privateKeyDER() throws -> Array<UInt8> {
        throw NSError(domain: "Public Key doesn't have private DER representation", code: 0)
    }
    
    init(publicDER: Array<UInt8>) throws {
        try self.init(rawRepresentation: Data(publicDER))
    }
    
    init(privateDER: Array<UInt8>) throws {
        throw NSError(domain: "Can't instantiate private key from public DER representation", code: 0)
    }
    
    public func exportPublicKeyPEM(withHeaderAndFooter: Bool) throws -> Array<UInt8> {
        let publicDER = try self.publicKeyDER()

        let base64String = publicDER.toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes
        
        if withHeaderAndFooter {
          let header = PEM.PEMType.publicKey.headerBytes + [0x0a]
          let footer = [0x0a] + PEM.PEMType.publicKey.footerBytes
        
          return header + bodyUTF8Bytes + footer
        } else {
          return bodyUTF8Bytes
        }
    }
}

extension RSAPrivateKey: DERCodable {
    /// RSA Object Identifier Bytes
    public static var primaryObjectIdentifier: Array<UInt8> { [42, 134, 72, 134, 247, 13, 1, 1, 1] }
    
    static var secondaryObjectIdentifier: Array<UInt8>? { nil }
    
    func publicKeyDER() throws -> Array<UInt8> {
        try self.derivePublicKey().rawRepresentation.bytes
    }
    
    func privateKeyDER() throws -> Array<UInt8> {
        self.rawRepresentation.bytes
    }
    
    init(publicDER: Array<UInt8>) throws {
        throw NSError(domain: "Can't instantiate private key from public DER representation", code: 0)
    }
    
    init(privateDER: Array<UInt8>) throws {
        try self.init(rawRepresentation: Data(privateDER))
    }
    
    public func exportPrivateKeyPEMRaw() throws -> Array<UInt8> {
        let privateDER = try self.privateKeyDER()
        let asnNodes:ASN1.Node = .sequence(nodes: [
          .integer(data: Data(hex: "0x00")),
          .sequence(nodes: [
            .objectIdentifier(data: Data(Self.primaryObjectIdentifier)),
            .null
          ]),
          .octetString(data: Data( privateDER ))
        ])
          
        return ASN1.Encoder.encode(asnNodes)
    }
    
    public func exportPrivateKeyPEM(withHeaderAndFooter: Bool) throws -> Array<UInt8> {
        let base64String = try self.exportPrivateKeyPEMRaw().toBase64()
        let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
        let bodyUTF8Bytes = bodyString.bytes
        
        if withHeaderAndFooter {
          let header = PEM.PEMType.privateKey.headerBytes + [0x0a]
          let footer = [0x0a] + PEM.PEMType.privateKey.footerBytes
        
          return header + bodyUTF8Bytes + footer
        } else {
          return bodyUTF8Bytes
        }
    }
}
