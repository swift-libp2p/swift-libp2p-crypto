//
//  signatures.swift
//  
//
//  Created by Brandon Toms on 6/6/22.
//

import Foundation


struct TestFixtures {
    struct Fixture {
        let publicPEM:String
        let privatePEM:String
        let rawMessage:String
        let encryptedMessage:[String:String]
        let signedMessages:[String:String]
        let publicMarshaled:String
        let privateMarshaled:String
    }

    static let RSA_1024 = Fixture(
        publicPEM: """

""",
        privatePEM: """
-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBANSRvSiXv+gtFt9s
upxbjfG0l2HvFD5V/nsNa2QSl5+Vnl9RMg0P6zUCVMC/rc2x9RfcYn+n7mOGeXfP
B5Mqvt7mFoxmo4loBFIqkbE4HDPUrduG8lb6LNfBSvA9tyaSICW+QCyOPWHBGk0P
y382i4X6E7ActAI++RfxgttTOhmvAgMBAAECgYAyjMnf+l5ft0FGNpQWFMunnBuX
5YP54vdWifVs4eL+x1TXM/bkFlIH1BsVjz+kt9oiJ32g/+1364W9URVrEPI8nk5i
Id40q3Qiozvn4ceWtSoCGmuxIbdRqL1JJn5e8Zfzs7E8KZimYu00t2qcidFDUsEC
biCqT14UNcbpwsOpkQJBAPxMogs3OnkgCWlptZckjg+srwxnXIkzDhSO+WaKl2Dm
DvSMnB2Ws64EDu2dP+HLiuoyqG/ZqRabdQqIsIrkLpkCQQDXr+wYGoOiL26PrAew
z49aH/wQZq8fBM2yuwvR+ZDRraQ0otQV1aRwffqlI+IfYowJvyPX+EC/ftcff0qa
6R+HAkAQZlrSJ9DhNrfl5j0rifDCDBOE1uMo9+yeYXzMsY2NeubV9p3fPoCHezQN
Nf+FCdoJxykzvA5Fre05thDjtllhAkEAgdsf2M81y1KlTQi0xKXiV8+D8dfwvUsm
EOJ+Vlfb8fGKOEqER/UNgNDIM96ryFuLll6m1ONZEDHskMERiLysRwJAawkNDlqe
sIjqrfR2luw+TLHkMI0T6pTY9s+79F9VVV/V13v2qtTpXw1eu7Sw+oDBpJoocz/h
+YzU+CyyzO+qUA==
-----END PRIVATE KEY-----
""",
        rawMessage: "Hello RSA Signatures!",
        encryptedMessage: [
            "algid:encrypt:RSA:raw": "N2T56NKkKAFdCytLP9zT0Iu9N0KNKkflB6vsNl6G+nkY/102laZLSbNZbdkzsOYSIml30ZaQSPS76aBuAYttlnCNEckgwmaS2IpHnFcUUFa/MOf+LJRcDXvkp+NoAmF0QFUhQ+VPfdineUrzOkL+xUi4hY614su6VdfPVmtJeog=",
            "algid:encrypt:RSA:PKCS1": "uliKMjgMn54C/WmwagE0dHFrEKw9civz9YYkHS+KKdlqVeCf9qKrFoSHlpA1Mq4JFg0WmpLWaMxgBaD+1CrE4Y+k26+wa4JtffLbyabYrxJkNQ5Am99KnoZO8rLEp2VumxGcsWWseMgSqrlO9KTesD8sJGFCMiz6aSFieedjAu4="
        ],
        signedMessages: [
            "algid:sign:RSA:raw"                    : "zpIDplKEdLvsHopjwoC36mQ3SRg2mZe/0RPP3DaDMnlSDLneoGwzR/L4oR/PTxD34wW7edQV4z5MrFSbmK4a7d+fwvNRQtwYlw/L04GTQyH8G6LhFUKL+++0jdPOMuMXADT8Yfrna6QHti2kqcUE4WSXHe6yY8xZZ6SHEDK71zg=",
            "algid:sign:RSA:digest-PKCS1v15"        : "s64/o2jeSm9OsTwlBuwJXOkJQPLoT300ZnMPDwfAdKsVFq8vR0uUDgkKYGnaogRu66QTWHfjSPcO2RUKV23141GM6Tng3zv3WGQm2Eg663n+9tYpsV5hCussJAcAwuGHoZwFV79alpNZkFyHEjya189zPeT1K3FbZJniL0ykTuk=",
            "algid:sign:RSA:digest-PKCS1v15:SHA1"   : "zIqv0mqhlDl0pf/Z5cRuZSP8oskOJhwluNI9EJRBC8b3RXlPlj2BzZyNbN0Mys3joVlfEiw4YsKYKFWN3SwGSwsYfcfeWpDJ5vJF3s32JkXnfHLdspTeapeVYDSy4MS8mNkVbYB6pQFBNK6scfzUFY7pLPKzUJ1MCnRmwpc0MbU=",
            "algid:sign:RSA:digest-PKCS1v15:SHA224" : "TS9eVlAFagKSmHtSdjunj3hgqQY5Zu7agjeYPvChB+jPgoqw/H3QwdzA4deZgcmsE1BooCgK9/1iekEWU/tjilVVrkhB5Kq5YxAWA7+IBo5pYFbmsAvP4ka+Oq1urfAYQbzTAuFyEXbdfXQATotElZFHwWjlTvZyk/IFfEawqtg=",
            "algid:sign:RSA:digest-PKCS1v15:SHA256" : "bLshLiyA9r2aow0u3+UKTSnyght7+8MuxEFzKsQrKgi9wYNwXsZEToB7jZ6+Y/hbezdIYXHwdtkHmBslAQBEGk+njsggrtWPVSDu/yU6icjEiiEd/35tVzgFejhmhj/5b8odScLrJF+6IeDl4iv9/tQZ7znOGImg5nZSik9c6dI=",
            "algid:sign:RSA:digest-PKCS1v15:SHA384" : "N810I+DcCYE7RROmKCHFl7MZl34dHkIx6Y3TxWv5g/JfvZHGRf+TwaFDjD7cGAdV+jY4wZd6mSNZvrhLgfb8t2X5JOaIiDaXt39etAywgE7OuMMYZsD596UBQFrdEu0bQIsK3+D+GcRCNYFVUUsJmYLvo/cio59IcTSRu1f3/5Y=",
            "algid:sign:RSA:digest-PKCS1v15:SHA512" : "rvrbc/LRhgGbXq1yAybMxfejAf+GHi4bcrhNKMRtg+RT3iw+Z5KLKzcSWinD9yH1j8NrL8u7EPLNDQ6EGt8y0JYSk0KqwseBpC2/zicu2HTypzFLnrNDtAw6E1A+AVOoAPkxkKf8F/ledih4xKn884USD2jO4ncyoXK4sGj0sjA=",
            "algid:sign:RSA:message-PKCS1v15:SHA1"  : "BMmnNyAMr8CMYpiZJAngT1o7wDGB1+hrHBHCs5OLcM/bpzqJ8+L9hHnWBeh4hZGcIkRCnB5KFd42WwcNLUQi1EUQHvDDH9gwpT8oPWn7Y/bkflwtKl9A3R1RiobY2rafe5PlbKW+SlN8ddZ0gevt5w7Ob+vQYRLu+e5dSSxVrtY=",
            "algid:sign:RSA:message-PKCS1v15:SHA224": "Ro+Y9+TavJt18Bin3+WVVg3YOzPsIlky7LiPXkMdsh1Zq5j3CD23EehNIG2HT3QXSG2ySZuaEj0swJvJWEvcmc1lo8f0xONkgCSk8iKtRzoJ6AJe3abqwc2gNHofzUtJq/eh2ZCO/IFvXC0B4sMIf2ztJuSNRW9O8d0m8zCsHZo=",
            "algid:sign:RSA:message-PKCS1v15:SHA256": "kaqP1oUrtRPUTA5uBAcPrIDGQPAqn8uH9pHMFYumS9FwZTYlRAeCFliMuiyW79x+x+BOC6TX+mipXgWJIO1IaucyrLBKlak934SX6q71xWA74SSYlMEzalKPFpi879fvgGyY4fRypJQv5uZ3nvlvxAhyB/pX7jaV07ct9sKIQv4=",
            "algid:sign:RSA:message-PKCS1v15:SHA384": "hxsA7RjGU97s1erJAv1WTkscZk61NHv55s0BWHoJEXgda0WulbcnOQduZJWeSyxJjRh4kGztV42xOvMpo9qcovbYOI3hQJ210gbNTBKmTp9tG79ShV6lx07eceC2XZg9kYxtgkuSpurRjd2PFbkGFGhTZmqRaSQukPjSIhnxoyQ=",
            "algid:sign:RSA:message-PKCS1v15:SHA512": "r31GD74cN5wknycZDyNZdJ4HJBBLv5zMH+dmfYW98i3szDS8txdr0M8ZrmM0jLxcSpwa5461vwMBhyCOYlqY2y3HoKNolIDSANhWPufKFMcv+ob3okNDQGXOAyPKhxn/EW7X2Mz3XQlBnOA6c18KR3UnZvoW5wn9K1tpv4ueEyI="
        ],
        publicMarshaled: "CAASogEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANSRvSiXv+gtFt9supxbjfG0l2HvFD5V/nsNa2QSl5+Vnl9RMg0P6zUCVMC/rc2x9RfcYn+n7mOGeXfPB5Mqvt7mFoxmo4loBFIqkbE4HDPUrduG8lb6LNfBSvA9tyaSICW+QCyOPWHBGk0Py382i4X6E7ActAI++RfxgttTOhmvAgMBAAE=",
        privateMarshaled: "CAAS4AQwggJcAgEAAoGBANSRvSiXv+gtFt9supxbjfG0l2HvFD5V/nsNa2QSl5+Vnl9RMg0P6zUCVMC/rc2x9RfcYn+n7mOGeXfPB5Mqvt7mFoxmo4loBFIqkbE4HDPUrduG8lb6LNfBSvA9tyaSICW+QCyOPWHBGk0Py382i4X6E7ActAI++RfxgttTOhmvAgMBAAECgYAyjMnf+l5ft0FGNpQWFMunnBuX5YP54vdWifVs4eL+x1TXM/bkFlIH1BsVjz+kt9oiJ32g/+1364W9URVrEPI8nk5iId40q3Qiozvn4ceWtSoCGmuxIbdRqL1JJn5e8Zfzs7E8KZimYu00t2qcidFDUsECbiCqT14UNcbpwsOpkQJBAPxMogs3OnkgCWlptZckjg+srwxnXIkzDhSO+WaKl2DmDvSMnB2Ws64EDu2dP+HLiuoyqG/ZqRabdQqIsIrkLpkCQQDXr+wYGoOiL26PrAewz49aH/wQZq8fBM2yuwvR+ZDRraQ0otQV1aRwffqlI+IfYowJvyPX+EC/ftcff0qa6R+HAkAQZlrSJ9DhNrfl5j0rifDCDBOE1uMo9+yeYXzMsY2NeubV9p3fPoCHezQNNf+FCdoJxykzvA5Fre05thDjtllhAkEAgdsf2M81y1KlTQi0xKXiV8+D8dfwvUsmEOJ+Vlfb8fGKOEqER/UNgNDIM96ryFuLll6m1ONZEDHskMERiLysRwJAawkNDlqesIjqrfR2luw+TLHkMI0T6pTY9s+79F9VVV/V13v2qtTpXw1eu7Sw+oDBpJoocz/h+YzU+CyyzO+qUA=="
    )
}


//func testRSAPEMImportSignAndVerify() throws {
//    let expectedSignature: Array<UInt8> = [
//        0x76, 0xEB, 0x7F, 0x10, 0x95, 0x40, 0xC9, 0x19, 0xE6, 0x44, 0x6F, 0xCD, 0x88, 0x83, 0x22, 0x6E,
//        0x5C, 0xE4, 0x1E, 0x87, 0xE3, 0xAF, 0x3B, 0x59, 0xB7, 0xB2, 0x89, 0xFD, 0x88, 0x37, 0xC0, 0xCE,
//        0xEA, 0x0E, 0x87, 0x06, 0x5F, 0x6E, 0xE7, 0x8C, 0xE9, 0x3F, 0xD6, 0xC3, 0xE0, 0x0B, 0x94, 0x19,
//        0xAC, 0x58, 0x2D, 0x73, 0xD3, 0x92, 0x45, 0x2C, 0x66, 0x7F, 0xB5, 0x24, 0xC6, 0xEA, 0xC6, 0xE2,
//        0x0E, 0xBB, 0x12, 0x86, 0x5B, 0xF4, 0x1D, 0x25, 0x2F, 0x68, 0x69, 0x30, 0x80, 0x4D, 0x10, 0xDF,
//        0x25, 0x5E, 0x00, 0x1D, 0x2F, 0x5F, 0x67, 0xE5, 0x4C, 0x7D, 0x1E, 0x64, 0xB2, 0x0B, 0xE8, 0x19,
//        0xE6, 0xB8, 0x62, 0xA6, 0xD1, 0x66, 0x58, 0x47, 0xAC, 0xAB, 0xAB, 0xCD, 0x26, 0x3D, 0x16, 0x52,
//        0xBF, 0x35, 0xB0, 0x21, 0xE2, 0xE3, 0x48, 0x77, 0x1E, 0x81, 0xE8, 0xCF, 0x75, 0x67, 0x64, 0x2A
//    ]
//
//    let message = "Hello RSA Signatures!".data(using: .utf8)!
//
//    let keyPair = try LibP2PCrypto.Keys.parsePem(TestPEMKeys.RSA_1024_PRIVATE)
//
//    let secKey =  try initSecKey(rawRepresentation: keyPair.privateKey!.rawRepresentation)
//
//    let privateMarshaled = try keyPair.privateKey?.marshal()
//    print(privateMarshaled!.asString(base: .base64Pad))
//
//    let publicMarsheled = try keyPair.marshalPublicKey()
//    print(publicMarsheled.asString(base: .base64Pad))
//
//    let pemData = try secKey.extractPubKey().rawRepresentation()
//
//    let pem = "-----BEGIN PUBLIC KEY-----\n" + pemData.asString(base: .base64Pad).split(intoChunksOfLength: 64).joined(separator: "\n") + "\n-----END PUBLIC KEY-----"
//
//    print(pem)
//
//    try sign(message: message, using: secKey)//keyPair.sign(message: message)
//
//    try encrypt(data: message, with: secKey.extractPubKey())
//
////        printHexData16BytesWide(signature.bytes)
////        print(signature.asString(base: .base64Pad))
////
////        XCTAssertEqual(signature.bytes, expectedSignature)
//}

//private func printHexData16BytesWide(_ bytes:[UInt8]) {
//    print(bytes.toHexString().split(intoChunksOfLength: 32).map { $0.split(intoChunksOfLength: 2).map { "0x\($0.uppercased())" }.joined(separator: ", ") }.joined(separator: ",\n"))
//}
//
//private func initSecKey(rawRepresentation raw: Data) throws -> SecKey {
//    let attributes: [String:Any] = [
//        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
//        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
//        kSecAttrKeySizeInBits as String: 1024,
//        kSecAttrIsPermanent as String: false
//    ]
//
//    var error:Unmanaged<CFError>? = nil
//    guard let secKey = SecKeyCreateWithData(raw as CFData, attributes as CFDictionary, &error) else {
//        throw NSError(domain: "Error constructing SecKey from raw key data: \(error.debugDescription)", code: 0, userInfo: nil)
//    }
//
//    return secKey
//}

//private func sign(message: Data, using key: SecKey) throws {
//    let algorithms:[SecKeyAlgorithm] = [
//        .rsaSignatureRaw,
//        //.rsaSignatureDigestPSSSHA1,
//        //.rsaSignatureDigestPSSSHA224,
//        //.rsaSignatureDigestPSSSHA256,
//        //.rsaSignatureDigestPSSSHA384,
//        //.rsaSignatureDigestPSSSHA512,
//        .rsaSignatureDigestPKCS1v15Raw,
//        .rsaSignatureDigestPKCS1v15SHA1,
//        .rsaSignatureDigestPKCS1v15SHA224,
//        .rsaSignatureDigestPKCS1v15SHA256,
//        .rsaSignatureDigestPKCS1v15SHA384,
//        .rsaSignatureDigestPKCS1v15SHA512,
//        //.rsaSignatureMessagePSSSHA1,
//        //.rsaSignatureMessagePSSSHA224,
//        //.rsaSignatureMessagePSSSHA256,
//        //.rsaSignatureMessagePSSSHA384,
//        //.rsaSignatureMessagePSSSHA512,
//        .rsaSignatureMessagePKCS1v15SHA1,
//        .rsaSignatureMessagePKCS1v15SHA224,
//        .rsaSignatureMessagePKCS1v15SHA256,
//        .rsaSignatureMessagePKCS1v15SHA384,
//        .rsaSignatureMessagePKCS1v15SHA512,
//    ]
//
//    for algo in algorithms {
//        var error: Unmanaged<CFError>?
//
//        // Sign the data
//        guard let signature = SecKeyCreateSignature(
//            key,
//            algo,
//            message as CFData,
//            &error) as Data?
//        else { print("\"\(algo.rawValue)\": \"nil\","); continue }
//
//        // Throw the error if we encountered one
//        if let error = error {  print("\"\(algo.rawValue)\": \"\(error.takeRetainedValue())\","); continue }
//
//        // Return the signature
//        print("\"\(algo.rawValue)\": \"\(signature.asString(base: .base64Pad))\",")
//    }
//
//}

//private func encrypt(data: Data, with key:SecKey) throws {
//    let algorithms:[SecKeyAlgorithm] = [
//        .rsaEncryptionRaw,
//        .rsaEncryptionPKCS1
//    ]
//
//    for algo in algorithms {
//        var error:Unmanaged<CFError>?
//        guard let encryptedData = SecKeyCreateEncryptedData(key, .rsaEncryptionPKCS1, data as CFData, &error) else {
//            print("\"\(algo.rawValue)\": \"\(error?.takeRetainedValue().localizedDescription ?? "nil")\","); continue
//        }
//        print("\"\(algo.rawValue)\": \"\((encryptedData as Data).asString(base: .base64Pad))\",")
//    }
//}
