//
//  AES.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import CryptoSwift

extension LibP2PCrypto {
    public enum AES {
        static func createKey(key:String) throws -> AESKey {
            try AESKey(key: key)
        }
        
        static func createKey(key:String, iv:String) throws -> AESKey {
            try AESKey(key: key, iv: iv)
        }
        
        static func createKey(key:Data, iv:Data) throws -> AESKey {
            try AESKey(key: key, iv: iv)
        }
        
        public func decrypt(_ data: Data, withPassword password:String) throws -> Data {
            let key = try LibP2PCrypto.AES.createKey(key: password)
            
            return try key.decrypt(data)
        }
        
        public struct AESKey:Encryptable, Decryptable {
            private let aes:CryptoSwift.AES
            
            public init(key:Data, iv:Data) throws {
                
                guard key.count == 16 || key.count == 32 else {
                    throw NSError(domain: "Error: Failed to set a key.", code: 0, userInfo: nil)
                }
                
                guard iv.count == 16 else {
                    throw NSError(domain: "Error: Failed to set an initial vector.", code: 0, userInfo: nil)
                }
                
                self.aes = try CryptoSwift.AES(key: key.bytes, blockMode: CBC(iv: iv.bytes), padding: .pkcs5)
            }
            
            /// Initializes an AES Key with the specified key and Initial Vector
            /// - Parameters:
            ///   - key: Either a 16 or 32 byte secret key
            ///   - iv: A 16 byte initial vector
            /// - Throws: An error if one is encountered along the way
            public init(key: String, iv: String) throws {
                guard let keyData = key.data(using: .utf8), let ivData = iv.data(using: .utf8) else {
                    throw NSError(domain: "Error: Failed to set a key.", code: 0, userInfo: nil)
                }
                
                try self.init(key: keyData, iv: ivData)
            }
            
            /// Initializes an AES Key with the specified key and a randomly generated Initial Vector
            /// - Parameter key: Either a 16 or 32 byte secret key
            /// - Throws: An error if one is encountered along the way
            public init(key:String) throws {
                guard key.count == 16 || key.count == 32, let keyData = key.data(using: .utf8) else {
                    throw NSError(domain: "Error: Failed to set a key.", code: 0, userInfo: nil)
                }
                
                try self.init(key: keyData, iv: Data(LibP2PCrypto.randomBytes(length: 16)))
            }

            public func encrypt(_ data:Data) throws -> Data {
                return try Data(aes.encrypt(data.bytes))
            }
            
            public func decrypt(_ data: Data) throws -> Data {
                return try Data(aes.decrypt(data.bytes))
            }
        }
    }
}
