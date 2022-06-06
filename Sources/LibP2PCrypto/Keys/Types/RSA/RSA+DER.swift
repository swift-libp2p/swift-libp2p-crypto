//
//  RSA+DER.swift
//  
//
//  Created by Brandon Toms on 6/5/22.
//

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
}
