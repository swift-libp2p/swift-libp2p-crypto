//
//  CommonPrivateKey.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation


public protocol CommonPrivateKey {
    /// Imports
    //init(byUnmarshalingData:Data) throws
    init(pemRSA:String) throws
    init(pemEC:String) throws
    
    /// Derivation
    func derivePublicKey() throws -> CommonPublicKey
    
    /// Decryption
    //func decrypt(data:Data) throws -> Data
    
    /// Exports
    //func exportPEM() throws -> Data
    
    //func exportJWK() throws -> Data
    
    //func exportCID() throws -> Data
    
    //func marshal() throws -> Data
    
    /// Misc
    //func stretch() throws -> Data
    //func id() throws -> String
}
