//
//  PBKDF2.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import CryptoSwift

fileprivate struct PBKDF {
    static let algorithmTagLength = 16
    static let nonceLength = 12
    static let keyLength = 16
    static let digest = "sha256"
    static let saltLength = 16
    static let iterations = 32767
}

struct PBKDF2 {
    static func MD5(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        return try? Data(CryptoSwift.PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes, iterations: rounds, keyLength: keyByteCount, variant: .md5).calculate())
    }
    
    static func SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        return try? Data(CryptoSwift.PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes, iterations: rounds, keyLength: keyByteCount, variant: .sha1).calculate())
    }
    
    static func SHA256(password: String, salt: Data, keyByteCount: Int = PBKDF.keyLength, rounds: Int = PBKDF.iterations) -> Data? {
        return try? Data(CryptoSwift.PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes, iterations: rounds, keyLength: keyByteCount, variant: .sha2(.sha256)).calculate())
    }
    
    static func SHA384(password: String, salt: Data, keyByteCount: Int = PBKDF.keyLength, rounds: Int = PBKDF.iterations) -> Data? {
        return try? Data(CryptoSwift.PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes, iterations: rounds, keyLength: keyByteCount, variant: .sha2(.sha384)).calculate())
    }

    static func SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        return try? Data(CryptoSwift.PKCS5.PBKDF2(password: password.bytes, salt: salt.bytes, iterations: rounds, keyLength: keyByteCount, variant: .sha2(.sha512)).calculate())
    }
}
