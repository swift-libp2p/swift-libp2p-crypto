//
//  CommonPublicKey.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation

public protocol CommonPublicKey {
    /// Imports
    //init(byUnmarshalingData:Data) throws
    init(pem:String) throws
    
    /// Encryption
    //func encrypt(data:Data) throws -> Data
    
    /// Exports
    //func exportPEM() throws -> Data
    
    //func exportJWK() throws -> Data
    
    //func exportCID() throws -> Data
    
    //func marshal() throws -> Data
    
    ///Misc
    //func id() throws -> String
    
    //var type:LibP2PCrypto.Keys.KeyPairType
}
