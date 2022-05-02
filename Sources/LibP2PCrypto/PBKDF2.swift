//
//  PBKDF2.swift
//  
//
//  Created by Brandon Toms on 5/1/22.
//

import Foundation
import CommonCrypto


fileprivate struct PBKDF {
    static let algorithmTagLength = 16
    static let nonceLength = 12
    static let keyLength = 16
    static let digest = "sha256"
    static let saltLength = 16
    static let iterations = 32767
}

struct PBKDF2 {
    static func SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
    }
    
    static func SHA256(password: String, salt: Data, keyByteCount: Int = 16, rounds: Int = 32767) -> Data? {
        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
    }

    static func SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
    }
    
    private static func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return salt.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    passwordData.count,
                    saltBuffer,
                    salt.count,
                    hash,
                    UInt32(rounds),
                    keyBuffer,
                    derivedCount)
            }
        }
        return derivationStatus == kCCSuccess ? derivedKeyData : nil
    }
}

//extension Data {
//    func pbkdf2SHA1(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
//        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA1), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
//    }
//
//    func pbkdf2SHA256(password: String, salt: Data, keyByteCount: Int = 16, rounds: Int = 32767) -> Data? {
//        //let salt:Data = self.prefix(PBKDF.saltLength)
//        //let ciphertextAndNonce:Data = self.dropFirst(PBKDF.saltLength)
//        
//        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA256), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
//    }
//
//    func pbkdf2SHA512(password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
//        return pbkdf2(hash:CCPBKDFAlgorithm(kCCPRFHmacAlgSHA512), password: password, salt: salt, keyByteCount: keyByteCount, rounds: rounds)
//    }
//
//    private func pbkdf2(hash: CCPBKDFAlgorithm, password: String, salt: Data, keyByteCount: Int, rounds: Int) -> Data? {
//        guard let passwordData = password.data(using: .utf8) else { return nil }
//        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
//        let derivedCount = derivedKeyData.count
//        let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
//            let keyBuffer: UnsafeMutablePointer<UInt8> =
//                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
//            return salt.withUnsafeBytes { saltBytes -> Int32 in
//                let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
//                return CCKeyDerivationPBKDF(
//                    CCPBKDFAlgorithm(kCCPBKDF2),
//                    password,
//                    passwordData.count,
//                    saltBuffer,
//                    salt.count,
//                    hash,
//                    UInt32(rounds),
//                    keyBuffer,
//                    derivedCount)
//            }
//        }
//        return derivationStatus == kCCSuccess ? derivedKeyData : nil
//    }
//}
