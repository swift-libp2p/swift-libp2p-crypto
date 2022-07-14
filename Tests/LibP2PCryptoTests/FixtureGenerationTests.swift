//
//  FixtureGenerationTests.swift
//  
//
//  Created by Brandon Toms on 7/7/22.
//

import XCTest
@testable import LibP2PCrypto

final class FixtureGenerationTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

  func testCreateRSATestFixture() throws {

    let fixtures = [1024, 2048, 3072, 4096]
    let keyType = "RSA"
    
    for fixture in fixtures {
      let keySize = fixture
      let message = "LibP2P RSA Keys!"

      /// Generate a SecKey RSA Key
      let parameters: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: keySize
      ]

      var error: Unmanaged<CFError>?

      // Generate the RSA SecKey
      guard let rsaSecKey = SecKeyCreateRandomKey(parameters as CFDictionary, &error) else {
        XCTFail("Key Generation Error: \(error.debugDescription)")
        return
      }

      // Extract the public key from the private RSA SecKey
      guard let rsaSecKeyPublic = SecKeyCopyPublicKey(rsaSecKey) else {
        XCTFail("Public Key Extraction Error")
        return
      }

      /// Lets grab the external representation of the public key
      var publicExternalRepError: Unmanaged<CFError>?
      guard let publicRSASecKeyRawRep = SecKeyCopyExternalRepresentation(rsaSecKeyPublic, &publicExternalRepError) as? Data else {
        XCTFail("Failed to copy external representation for RSA SecKey")
        return
      }

      /// Lets grab the external representation of the public key
      var privateExternalRepError: Unmanaged<CFError>?
      guard let privateRSASecKeyRawRep = SecKeyCopyExternalRepresentation(rsaSecKey, &privateExternalRepError) as? Data else {
        XCTFail("Failed to copy external representation for RSA SecKey")
        return
      }
      
      guard let rsaKey = try? RSAPrivateKey(rawRepresentation: privateRSASecKeyRawRep) else {
        XCTFail("Failed to import SecKey as RSAPrivateKey")
        return
      }

      var template = FixtureTemplate
      template = template.replacingOccurrences(of: "{{KEY_TYPE}}", with: keyType)
      template = template.replacingOccurrences(of: "{{KEY_SIZE}}", with: "_\(keySize)")
      
      // DERs
      template = template.replacingOccurrences(of: "{{PUBLIC_DER}}", with: "\(publicRSASecKeyRawRep.base64EncodedString())")
      template = template.replacingOccurrences(of: "{{PRIVATE_DER}}", with: "\(privateRSASecKeyRawRep.base64EncodedString())")
      
      // PEMs
      template = template.replacingOccurrences(of: "{{PUBLIC_PEM}}", with: try rsaKey.exportPublicKeyPEMString(withHeaderAndFooter: true))
      template = template.replacingOccurrences(of: "{{PRIVATE_PEM}}", with: try rsaKey.exportPrivateKeyPEMString(withHeaderAndFooter: true))
      
      // Encrypted PEMs
      template = template.replacingOccurrences(of: "{{ENCRYPTED_PEMS}}", with: "")
      template = template.replacingOccurrences(of: "{{ENCRYPTION_PASSWORD}}", with: "")
      
      // Marshaled
      template = template.replacingOccurrences(of: "{{PUBLIC_MARSHALED}}", with: try rsaKey.derivePublicKey().marshal().base64EncodedString())
      template = template.replacingOccurrences(of: "{{PRIVATE_MARSHALED}}", with: try rsaKey.marshal().base64EncodedString())
      
      // Plaintext Message
      template = template.replacingOccurrences(of: "{{PLAINTEXT_MESSAGE}}", with: message)

      let encryptedMessages = try encrypt(data: message.data(using: .utf8)!, with: rsaSecKeyPublic)
      template = template.replacingOccurrences(of: "{{ENCRYPTED_MESSAGES}}", with: encryptedMessages.joined(separator: ",\n\t  "))

      let signedMessages = try sign(message: message.data(using: .utf8)!, using: rsaSecKey)
      template = template.replacingOccurrences(of: "{{SIGNED_MESSAGES}}", with: signedMessages.joined(separator: ",\n\t  "))

      print(template)
    }
  }
  
  func testCreateED25519TestFixture() throws {

    let message = "LibP2P ED25519 Keys!"
    let keySize:Int? = nil
    let keyType = "ED25519"
    
    // Generate the RSA SecKey
    guard let edKey = try? LibP2PCrypto.Keys.KeyPair(.Ed25519) else {
      XCTFail("Key Generation Error")
      return
    }

    var template = FixtureTemplate
    template = template.replacingOccurrences(of: "{{KEY_TYPE}}", with: keyType)
    template = template.replacingOccurrences(of: "{{KEY_SIZE}}", with: keySize != nil ? "_\(keySize!)" : "")
    
    // DERs
    template = template.replacingOccurrences(of: "{{PUBLIC_DER}}", with: "\(try edKey.publicKey.publicKeyDER().asString(base: .base64Pad))")
    template = template.replacingOccurrences(of: "{{PRIVATE_DER}}", with: "\(try edKey.privateKey!.privateKeyDER().asString(base: .base64Pad))")
    
    // PEMs
    template = template.replacingOccurrences(of: "{{PUBLIC_PEM}}", with: try edKey.exportPublicPEMString(withHeaderAndFooter: true))
    template = template.replacingOccurrences(of: "{{PRIVATE_PEM}}", with: try edKey.exportPrivatePEMString(withHeaderAndFooter: true))
    
    // Encrypted PEMs
    template = template.replacingOccurrences(of: "{{ENCRYPTED_PEMS}}", with: "")
    template = template.replacingOccurrences(of: "{{ENCRYPTION_PASSWORD}}", with: "")
    
    // Marshaled
    template = template.replacingOccurrences(of: "{{PUBLIC_MARSHALED}}", with: try edKey.publicKey.marshal().base64EncodedString())
    template = template.replacingOccurrences(of: "{{PRIVATE_MARSHALED}}", with: try edKey.privateKey!.marshal().base64EncodedString())
    
    // Plaintext Message
    template = template.replacingOccurrences(of: "{{PLAINTEXT_MESSAGE}}", with: message)

    // TODO: Add algorithm prefix
    let encryptedMessages = [try edKey.encrypt(data: message.data(using: .utf8)!).base64EncodedString()]
    template = template.replacingOccurrences(of: "{{ENCRYPTED_MESSAGES}}", with: encryptedMessages.joined(separator: ",\n\t  "))
    
    let signedMessages = [try edKey.sign(message: message.data(using: .utf8)!).base64EncodedString()]
    template = template.replacingOccurrences(of: "{{SIGNED_MESSAGES}}", with: signedMessages.joined(separator: ",\n\t  "))
    
//    let encryptedMessages = try encrypt(data: message.data(using: .utf8)!, with: edKey)
//    template = template.replacingOccurrences(of: "{{ENCRYPTED_MESSAGES}}", with: encryptedMessages.joined(separator: ",\n\t  "))
//
//    let signedMessages = try sign(message: message.data(using: .utf8)!, using: edKey)
//    template = template.replacingOccurrences(of: "{{SIGNED_MESSAGES}}", with: signedMessages.joined(separator: ",\n\t  "))

    print(template)
  }

  private let FixtureTemplate = """
static let {{KEY_TYPE}}{{KEY_SIZE}} = Fixture(
  keySize: {{KEY_SIZE}},
  publicDER: \"\"\"
{{PUBLIC_DER}}
\"\"\",
  privateDER: \"\"\"
{{PRIVATE_DER}}
\"\"\",
  publicPEM: \"\"\"
{{PUBLIC_PEM}}
\"\"\",
  privatePEM: \"\"\"
{{PRIVATE_PEM}}
\"\"\",
  encryptedPEM: [
{{ENCRYPTED_PEMS}}
  ],
  encryptionPassword: \"{{ENCRYPTION_PASSWORD}}\",
  publicMarshaled: \"\"\"
{{PUBLIC_MARSHALED}}
\"\"\",
  privateMarshaled: \"\"\"
{{PRIVATE_MARSHALED}}
\"\"\",
  rawMessage: "{{PLAINTEXT_MESSAGE}}",
  encryptedMessage: [
    {{ENCRYPTED_MESSAGES}}
  ],
  signedMessages: [
    {{SIGNED_MESSAGES}}
  ]
)
"""

  //private func printHexData16BytesWide(_ bytes:[UInt8]) {
//    print(bytes.toHexString().split(intoChunksOfLength: 32).map { $0.split(intoChunksOfLength: 2).map { "0x\($0.uppercased())" }.joined(separator: ", ") }.joined(separator: ",\n"))
  //}

  private func initSecKey(rawRepresentation raw: Data) throws -> SecKey {
    let attributes: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
      kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits as String: 1024,
      kSecAttrIsPermanent as String: false
    ]

    var error: Unmanaged<CFError>?
    guard let secKey = SecKeyCreateWithData(raw as CFData, attributes as CFDictionary, &error) else {
      throw NSError(domain: "Error constructing SecKey from raw key data: \(error.debugDescription)", code: 0, userInfo: nil)
    }

    return secKey
  }

  private func sign(message: Data, using key: SecKey) throws -> [String] {
    let algorithms: [SecKeyAlgorithm] = [
      .rsaSignatureRaw,
      //.rsaSignatureDigestPSSSHA1,
      //.rsaSignatureDigestPSSSHA224,
      //.rsaSignatureDigestPSSSHA256,
      //.rsaSignatureDigestPSSSHA384,
      //.rsaSignatureDigestPSSSHA512,
      .rsaSignatureDigestPKCS1v15Raw,
      .rsaSignatureDigestPKCS1v15SHA1,
      .rsaSignatureDigestPKCS1v15SHA224,
      .rsaSignatureDigestPKCS1v15SHA256,
      .rsaSignatureDigestPKCS1v15SHA384,
      .rsaSignatureDigestPKCS1v15SHA512,
      //.rsaSignatureMessagePSSSHA1,
      //.rsaSignatureMessagePSSSHA224,
      //.rsaSignatureMessagePSSSHA256,
      //.rsaSignatureMessagePSSSHA384,
      //.rsaSignatureMessagePSSSHA512,
      .rsaSignatureMessagePKCS1v15SHA1,
      .rsaSignatureMessagePKCS1v15SHA224,
      .rsaSignatureMessagePKCS1v15SHA256,
      .rsaSignatureMessagePKCS1v15SHA384,
      .rsaSignatureMessagePKCS1v15SHA512,
    ]

    var sigs: [String] = []

    for algo in algorithms {
      var error: Unmanaged<CFError>?

      // Sign the data
      guard let signature = SecKeyCreateSignature(
        key,
        algo,
        message as CFData,
        &error
      ) as Data?
      else { print("\"\(algo.rawValue)\": \"nil\","); continue }

      // Throw the error if we encountered one
      if let error = error { print("\"\(algo.rawValue)\": \"\(error.takeRetainedValue())\","); continue }

      // Append the signature
      sigs.append("\"\(algo.rawValue)\": \"\(signature.base64EncodedString())\"")
    }

    return sigs
  }

  private func encrypt(data: Data, with key: SecKey) throws -> [String] {
    let algorithms: [SecKeyAlgorithm] = [
      .rsaEncryptionRaw,
      .rsaEncryptionPKCS1
    ]

    var encryptions: [String] = []

    for algo in algorithms {
      var error: Unmanaged<CFError>?
      guard let encryptedData = SecKeyCreateEncryptedData(key, algo, data as CFData, &error) as? Data else {
        print("\"\(algo.rawValue)\": \"\(error?.takeRetainedValue().localizedDescription ?? "nil")\","); continue
      }
      encryptions.append("\"\(algo.rawValue)\": \"\(encryptedData.base64EncodedString())\"")
    }

    return encryptions
  }
  
}

struct TestFixtures {
  struct Fixture {
    let keySize: Int
    let publicDER: String
    let privateDER: String
    let publicPEM:String
    let privatePEM:String
    let encryptedPEM:[String:String]
    let encryptionPassword:String
    let publicMarshaled:String
    let privateMarshaled:String
    let rawMessage: String
    let encryptedMessage: [String: String]
    let signedMessages: [String: String]
  }
}
