//
//  File.swift
//  
//
//  Created by Brandon Toms on 5/22/22.
//

import Foundation
import Multibase

extension LibP2PCrypto.Keys {
    /// Expects a PEM Public Key with the x509 header information included (object identifier)
    ///
    /// - Note: Handles RSA and EC Public Keys
    public static func importPublicDER(_ der:String) throws -> KeyPair {
        let chunks = der.split(separator: "\n")
        guard chunks.count > 3,
              let f = chunks.first, f.hasPrefix("-----BEGIN RSA PUBLIC"),
              let l = chunks.last, l.hasSuffix("-----") else {
            throw NSError(domain: "Invalid DER Format", code: 0, userInfo: nil)
        }
        
        let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
        
        print("Trying to Init Public RSA DER Key")
        return try KeyPair(publicKey: RSAPublicKey(rawRepresentation: raw.data))
    }
    
    public static func importPrivateDER(_ der:String) throws -> KeyPair {
        let chunks = der.split(separator: "\n")
        guard chunks.count > 3,
              let f = chunks.first, f.hasPrefix("-----BEGIN RSA PRIVATE"),
              let l = chunks.last, l.hasSuffix("-----") else {
            throw NSError(domain: "Invalid DER Format", code: 0, userInfo: nil)
        }
        
        var raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64).data
        
        while raw.count % 4 != 0 {
            raw.insert(0, at: 0)
        }
        
        print("Trying to Init Private RSA DER Key")
        return try KeyPair(privateKey: RSAPrivateKey(rawRepresentation: raw))
    }
    
    
    
//        /// Expects a DER Public Key without the x509 header information (object identifier)
//        ///
//        /// - Note: Handles nothing at the moment
//        public static func importPrivateDER(_ der:String) throws -> PrivKey {
//
//            let chunks = der.split(separator: "\n")
//            guard chunks.count > 3,
//                  let f = chunks.first, f.hasPrefix("-----BEGIN"),
//                  let l = chunks.last, l.hasSuffix("-----") else {
//                throw NSError(domain: "Invalid PEM Format", code: 0, userInfo: nil)
//            }
//
//            let raw = try BaseEncoding.decode(chunks[1..<chunks.count-1].joined(), as: .base64)
//
//            //let asn1 = try LibP2PCrypto.Keys.parseASN1(pemData: raw.data)
//
//            //print(asn1)
//
//            print("Raw Data Count: \(raw.data.count)")
//            print("Is divisible by 4: \(raw.data.count % 4 == 0)")
//            var d = raw.data
//            d.insert(0, at: 0)
//            print("Data Count: \(d.count)")
//            print("Is divisible by 4: \(d.count % 4 == 0)")
//
//            print("Trying to Init RSA DER Key")
////            let attributes: [String: Any] = [
////                        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
////                        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
////                    ]
//            var error: Unmanaged<CFError>?
//            //let privKey = SecKeyCreateWithData(d as CFData, attributes as CFDictionary, &error)
//            let privKey = SecKeyCreateFromData([:] as CFDictionary, d as CFData, &error)
//
//            guard let key = privKey else {
//
//                throw NSError(domain: "Failed to gen priv key... \(error.debugDescription)", code: 0, userInfo: nil)
//            }
//
//            if let pubkey = try? key.extractPubKey() {
//                print("Got the pub key...")
//                print((try? pubkey.asString(base: .base16)) ?? "nil")
//            }
//
//            print(key.attributes)
//
//            print((try? key.rawRepresentation()) ?? "Failed to get raw rep...")
//
//            return key
//
//            //return try LibP2PCrypto.Keys.secKeyFrom(data: d, isPrivateKey: true, keyType: .EC(curve: .P256))
//        }
    
    /// Appends PEM Header and Footer
    /// Base64 encodes DER PubKey
    /// MacOS -> Use <Security/SecImportExport.h>
    /// iOS roll our own
    /// https://github.com/ibm-cloud-security/Swift-JWK-to-PEM
    /// https://github.com/Kitura/OpenSSL
//        private func toDER(keyPair:LibP2PCrypto.Keys.KeyPair) throws -> String {
//
//            // Line length is typically 64 characters, except the last line.
//            // See https://tools.ietf.org/html/rfc7468#page-6 (64base64char)
//            // See https://tools.ietf.org/html/rfc7468#page-11 (example)
//            let keyData = try keyPair.publicKey.rawRepresentation()
//            let chunks = keyData.base64EncodedString().split(intoChunksOfLength: 64)
//
//            let pem = [
//                "-----BEGIN \(keyPair.keyType.name)-----",
//                chunks.joined(separator: "\n"),
//                "-----END \(keyPair.keyType.name)-----"
//            ]
//
//            return pem.joined(separator: "\n")
//        }
    

}
