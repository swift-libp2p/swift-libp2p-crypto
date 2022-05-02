//
//  HMAC.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import CommonCrypto
import Multibase

extension LibP2PCrypto {
    public enum HMAC {
        public enum CryptoAlgorithm {
            case MD5, SHA1, SHA224, SHA256, SHA384, SHA512

            var HMACAlgorithm: CCHmacAlgorithm {
                var result: Int = 0
                switch self {
                case .MD5:    result = kCCHmacAlgMD5
                case .SHA1:   result = kCCHmacAlgSHA1
                case .SHA224: result = kCCHmacAlgSHA224
                case .SHA256: result = kCCHmacAlgSHA256
                case .SHA384: result = kCCHmacAlgSHA384
                case .SHA512: result = kCCHmacAlgSHA512
                }
                return CCHmacAlgorithm(result)
            }

            var digestLength: Int {
                var result: Int32 = 0
                switch self {
                case .MD5:    result = CC_MD5_DIGEST_LENGTH
                case .SHA1:   result = CC_SHA1_DIGEST_LENGTH
                case .SHA224: result = CC_SHA224_DIGEST_LENGTH
                case .SHA256: result = CC_SHA256_DIGEST_LENGTH
                case .SHA384: result = CC_SHA384_DIGEST_LENGTH
                case .SHA512: result = CC_SHA512_DIGEST_LENGTH
                }
                return Int(result)
            }
        }
        
        public struct HMACKey:Encryptable {
            private let algorithm:CryptoAlgorithm
            private let secret:String
            
            /// Initializes a reusable HMAC Key by specifying the Hashing Algorithm and secret key to use
            /// - Parameters:
            ///   - algorithm: The Hashing Algorithm to use
            ///   - secret: The shared secret key
            public init(algorithm:CryptoAlgorithm, secret:String) {
                self.algorithm = algorithm
                self.secret = secret
            }
            
            public func encrypt(_ message:Data) -> Data {
                LibP2PCrypto.HMAC.encrypt(message, algorithm: self.algorithm, key: self.secret)
            }
            
            public func encrypt(_ message:String) -> Data {
                LibP2PCrypto.HMAC.encrypt(message: message, algorithm: self.algorithm, key: self.secret)
            }
            
            public func verify(_ str:String, hash:Data) -> Bool {
                return self.encrypt(str) == hash
            }
            
            public func verify(_ data:Data, hash:Data) -> Bool {
                return self.encrypt(data) == hash
            }
        }
        
        /// Creates an HMACKey that can be used to encrypt / hash multiple data sets...
        /// - Parameters:
        ///   - algorithm: The hashing algorithm to use
        ///   - secret: The shared secret key to hash the data against
        /// - Returns: HMACKey
        public static func create(algorithm:CryptoAlgorithm, secret:String) -> LibP2PCrypto.HMAC.HMACKey {
            return HMACKey(algorithm: algorithm, secret: secret)
        }
        
        /// A one offf, stateless, HMAC hashing / encryption method
        /// - Parameters:
        ///   - message: The String message to encrypt / hash
        ///   - algorithm: The hashing algorithm to use
        ///   - key: The shared secret key to hash the data against
        /// - Returns: The encrypted / hashed HMAC data
        public static func encrypt(message:String, algorithm: CryptoAlgorithm, key: String) -> Data {
            let data = message.data(using: .utf8)
            return self.encrypt(data!, algorithm: algorithm, key: key)
        }
        
        /// A one offf, stateless, HMAC hashing / encryption method
        /// - Parameters:
        ///   - message: The data to encrypt / hash
        ///   - algorithm: The hashing algorithm to use
        ///   - key: The shared secret key to hash the data against
        /// - Returns: The encrypted / hashed HMAC data
        public static func encrypt(_ message:Data, algorithm: CryptoAlgorithm, key: String) -> Data {
            var data = message
            let dLen = data.count
            let digestLen = algorithm.digestLength
            let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
            let keyStr = key.cString(using: String.Encoding.utf8)
            let keyLen = Int(key.lengthOfBytes(using: String.Encoding.utf8))

            CCHmac(algorithm.HMACAlgorithm, keyStr!, keyLen, &data, dLen, result)

            var d:[UInt8] = []
            for i in 0..<digestLen {
                d.append(result[i])
            }
            
            result.deallocate()
            return Data(d)
        }
    }
}

public protocol Encryptable {
    func encrypt(_ message:Data) throws -> Data
}

// An Encryptable extension that gives us default implementations of Bytes and String Encrypting
public extension Encryptable {
    
    func encrypt(_ bytes:[UInt8]) throws -> Data {
        try self.encrypt(Data(bytes))
    }

    /// A default string -> data implementation using .utf8 encoding...
    func encrypt(_ message:String, encodedUsing encoding:String.Encoding = .utf8) throws -> Data {
        guard let d = message.data(using: encoding) else {
            throw NSError(domain: "Error: Failed to encode string using \(encoding).", code: 0, userInfo: nil)
        }
        return try self.encrypt(d)
    }

}

public protocol Decryptable {
    func decrypt(_ message:Data) throws -> Data
}

// An Encryptable extension that gives us default implementations of Bytes and String Encrypting
public extension Decryptable {
    
    func decrypt(_ bytes:[UInt8]) throws -> Data {
        try self.decrypt(Data(bytes))
    }
    
    /// Attempts to decode a base encoded string into the encrypted data to be decrypted...
    func decrypt(baseEncoded:String, base:BaseEncoding) throws -> Data {
        let d = try Multibase.BaseEncoding.decode(baseEncoded, as: base)
        return try self.decrypt(d.data)
    }
    
    /// Attempts to decode a multibase compliant string into the encrypted data to be decrypted...
    func decrypt(multibaseEncoded:String) throws -> Data {
        let d = try Multibase.BaseEncoding.decode(multibaseEncoded)
        return try self.decrypt(d.data)
    }
    
    func decrypt(_ data:Data, intoString encoding:String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(data)
        guard let str = String(data: d, encoding: encoding) else {
            throw NSError(domain: "Error: Failed to encode data using \(encoding).", code: 0, userInfo: nil)
        }
        return str
    }
    
    func decrypt(_ bytes:[UInt8], intoString encoding:String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(bytes)
        guard let str = String(data: d, encoding: encoding) else {
            throw NSError(domain: "Error: Failed to encode data using \(encoding).", code: 0, userInfo: nil)
        }
        return str
    }
    
    func decrypt(baseEncoded:String, base:BaseEncoding, intoString encoding:String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(baseEncoded: baseEncoded, base: base)
        guard let str = String(data: d, encoding: encoding) else {
            throw NSError(domain: "Error: Failed to encode data using \(encoding).", code: 0, userInfo: nil)
        }
        return str
    }
    
    func decrypt(multibaseEncoded:String, intoString encoding:String.Encoding = .utf8) throws -> String {
        let d = try self.decrypt(multibaseEncoded: multibaseEncoded)
        guard let str = String(data: d, encoding: encoding) else {
            throw NSError(domain: "Error: Failed to encode data using \(encoding).", code: 0, userInfo: nil)
        }
        return str
    }
}


