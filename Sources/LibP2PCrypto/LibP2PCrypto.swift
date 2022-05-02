//
//  libp2p-crypto.swift
//
//
//  Created by Brandon Toms on 5/1/22.
//
//  - TODO: Support JWK https://tools.ietf.org/html/rfc7517
//  - TODO: Support PEM format 

import Foundation
import Multibase
import CryptoSwift

public enum LibP2PCrypto {
    
    public static func randomBytes(length:Int) throws -> [UInt8] {
        var data = Array<UInt8>(repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, data.count, &data)
        if status == errSecSuccess { return data }
        throw NSError(domain: "Error encountered while generating random bytes: \(status)", code: 0, userInfo: nil)
    }
    
}

public extension String {
    
    /// Encrypts a string using a plaintext password with the following AES GCM cipher
    ///
    /// * algorithmTagLength = 16,
    /// * nonceLength = 12,
    /// * keyLength = 16,
    /// * digest = 'sha256',
    /// * saltLength = 16,
    /// * iterations = 32767
    /// * algorithm = 'aes-128-gcm'
    func encryptGCM(password: String) throws -> Data {
        guard let data = self.data(using: .utf8) else {
            throw NSError(domain: "Failed to decode string into data", code: 0, userInfo: nil)
        }
        return try data.encryptGCM(password: password)
    }
    
    /// Decryptes a BaseEncoded string via AES-GCM password encrypted data and attempts to return the plaintext message...
    func decryptGCM(password: String, base:BaseEncoding) throws -> String? {
        return try String(data: BaseEncoding.decode(self, as: base).data.decryptGCM(password: password), encoding: .utf8)
    }
    
    func encrypt(withKey key:Encryptable, encodedUsing encoding:String.Encoding = .utf8) throws -> Data {
        try key.encrypt(self, encodedUsing: encoding)
    }
    
    /// Attempts to decode the string via the specified base encoding then decrypts it
    func decrypt(withKey key:Decryptable, baseEncoded base:BaseEncoding) throws -> Data {
        try key.decrypt(baseEncoded: self, base: base)
    }
    
    /// If the string is multibase encoded compliant (includes multibase prefix), we'll automatically decode it and attempt to decrypt the data
    func decrypt(withKey key:Decryptable) throws -> Data {
        try key.decrypt(multibaseEncoded: self)
    }
    
    
//    func encrypt(withKeyPair key:LibP2PCrypto.Keys.KeyPair, using encoding:String.Encoding = .utf8) throws -> Data {
//        guard let d = self.data(using: .utf8) else { throw NSError(domain: "Error during string encoding", code: 0, userInfo: nil) }
//        return try LibP2PCrypto.Keys.encrypt(d, publicKey: key.publicKey)
//    }
        
//    func decrypt(withKeyPair key:LibP2PCrypto.Keys.KeyPair, using encoding:String.Encoding = .utf8) throws -> Data {
//        guard let d = self.data(using: .utf8) else { throw NSError(domain: "Error during string encoding", code: 0, userInfo: nil) }
//        return try LibP2PCrypto.Keys.decrypt(d, privateKey: key.privateKey)
//    }
    
//    func encrypt(withAESKey key:LibP2PCrypto.AES.AESKey, using encoding:String.Encoding = .utf8) throws -> Data {
//        try key.encrypt(string: self, using: encoding)
//    }
    
//    func encrypt(withHmacKey key:LibP2PCrypto.HMAC.HMACKey) -> Data {
//        key.encrypt(self)
//    }
}

public extension Data {
    
    /// Returns the encrypted data in the format [ { salt }  { nonce}  { ciphertext }  { GCM algorithm tag } ]
    func encryptGCM(password: String) throws -> Data {
        return try Data(self.bytes.encryptGCM(password: password))
    }
    
    /// Returns  decrypted data that was previously encrypted with `encryptGCM(password:)`
    func decryptGCM(password: String) throws -> Data {
        return try Data(self.bytes.decryptGCM(password: password))
    }
    
    func encrypt(withKey key:Encryptable) throws -> Data  {
        try key.encrypt(self)
    }
    
    func decrypt(withKey key:Decryptable) throws -> Data {
        try key.decrypt(self)
    }
}

public extension Array where Element == UInt8 {
    func encrypt(withKey key:Encryptable) throws -> Data  {
        try key.encrypt(self)
    }
    
    func decrypt(withKey key:Decryptable) throws -> Data {
        try key.decrypt(self)
    }
    
    /// Returns the encrypted data in the format [ { salt }  { nonce}  { ciphertext }  { GCM algorithm tag } ]
    func encryptGCM(password: String) throws -> [UInt8] {
        // Generate a 128-bit salt using a CSPRNG.
        let salt = try LibP2PCrypto.randomBytes(length: 16)
        
        // Attempt to derive the aes encryption key from the password and salt
        // PBKDF2-SHA256
        guard let key = PBKDF2.SHA256(password: password, salt: Data(salt), keyByteCount: 16, rounds: 32767) else {
            throw NSError(domain: "Failed to derive AESGCM encryption key from plaintext password", code: 0, userInfo: nil)
        }
        
        // Return the salt prepended to the encrypted data
        return try salt + encryptGCM(data: self, withKey: key)
    }
    
    /// Returns  decrypted data that was previously encrypted with `encryptGCM(password:)`
    func decryptGCM(password: String) throws -> [UInt8] {
        var data = self
        
        // Generate a 128-bit salt using a CSPRNG.
        let salt = data.prefix(16)
        
        // Strip the salt
        data.removeFirst(16)
        
        // Attempt to derive the aes encryption key from the password and salt
        // PBKDF2-SHA256
        guard let key = PBKDF2.SHA256(password: password, salt: Data(salt), keyByteCount: 16, rounds: 32767) else {
            throw NSError(domain: "Failed to derive AESGCM encryption key from plaintext password", code: 0, userInfo: nil)
        }
        
        return try decryptGCM(data: data, withKey: key)
    }
    
    private func encryptGCM(data:[UInt8], withKey key:Data) throws -> [UInt8] {
        let nonce = try LibP2PCrypto.randomBytes(length: 12)
        
        // AES - GCM
        let aesGCM = try AES(key: key.bytes, blockMode: GCM(iv: nonce, mode: .combined), padding: .noPadding)
    
        // Encrypt and prepend nonce.
        let ciphertext = try aesGCM.encrypt(data)

        return nonce + ciphertext
    }
    
    private func decryptGCM(data:[UInt8], withKey key:Data) throws -> [UInt8] {
        //Strip the nonce off the front of the data
        let nonce = Array(data.prefix(12))
        
        // AES - GCM
        let aesGCM = try AES(key: key.bytes, blockMode: GCM(iv: nonce, mode: .combined), padding: .noPadding)

        // Decrypt the ciphertext
        return try aesGCM.decrypt(data.dropFirst(12))
    }
}


// var pemString = "-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl/zjMK4w1XZAnpIqLeTAMW7cEUNIifP3HjmUavvc2+oPG1QjNCfxQM6LulZSl6qRim2JGxbc3yvnbMRJqch6IhJ/ysbTekVSqOjskIRGxq0pg0J8PqF3ZZQK6D7BYHi6iaJUMVV0ISB5LogJouyOWqsZyiEjgPz3jj0HIrh14Q6wPZVMpVbIwQR9nZp5gU5minseCyZfQs3PArgXgnzRPdw7Hb0/NY5OVE2Rz1SFTnda6w12SEu1IsVhVhJz1QteNrwNwJAT6WgZd+xnOZhU3Ei+EQK2SijfEGqmWNt1utJygK/0APy8w7VTol7ygbqfuHevGcg90QEXjxZKCjkXkQIDAQAB\n-----END RSA PUBLIC KEY-----"


