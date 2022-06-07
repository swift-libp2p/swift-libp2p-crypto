//
//  DER.swift
//  
//
//  Created by Brandon Toms on 5/28/22.
//

import Foundation

/// Conform to this protocol if your type can be instantiated from a ASN1 DER representation
public protocol DERDecodable {
    /// The keys ASN1 object identifier (ex: RSA --> rsaEncryption --> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    static var primaryObjectIdentifier:Array<UInt8> { get }
    /// The keys ASN1 object identifier (ex: RSA --> rsaEncryption --> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
    static var secondaryObjectIdentifier:Array<UInt8>? { get }
    /// Instantiates an instance of your Public Key when given a DER representation of your Public Key
    init(publicDER: Array<UInt8>) throws
    /// Instantiates an instance of your Private Key when given a DER representation of your Private Key
    init(privateDER: Array<UInt8>) throws
    /// Instantiates a DERDecodable Key from a PEM string
    init<Key:DERDecodable>(pem: String, password: String?, asType:Key.Type) throws
    /// Instantiates a DERDecodable Key from ut8 decoded PEM data
    init<Key:DERDecodable>(pem: Data, password: String?, asType:Key.Type) throws
}

public extension DERDecodable {
  /// Instantiates a DERDecodable Key from a PEM string
  /// - Parameters:
  ///   - pem: The PEM file to import
  ///   - password: A password to use to decrypt an encrypted PEM file
  ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
  init<Key:DERDecodable>(pem: String, password: String? = nil, asType:Key.Type = Key.self) throws {
      try self.init(pem: pem.bytes, password: password, asType: Key.self)
  }
    
  /// Instantiates a DERDecodable Key from ut8 decoded PEM data
  /// - Parameters:
  ///   - pem: The PEM file to import
  ///   - password: A password to use to decrypt an encrypted PEM file
  ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
  init<Key:DERDecodable>(pem: Data, password: String? = nil, asType:Key.Type = Key.self) throws {
      try self.init(pem: pem.bytes, password: password, asType: Key.self)
  }
  
  /// Instantiates a DERDecodable Key from ut8 decoded PEM bytes
  /// - Parameters:
  ///   - pem: The PEM file to import
  ///   - password: A password to use to decrypt an encrypted PEM file
  ///   - asType: The underlying DERDecodable Key Type (ex: RSA.self)
  init<Key:DERDecodable>(pem: Array<UInt8>, password: String? = nil, asType:Key.Type = Key.self) throws {
    let (type, bytes, _) = try PEM.pemToData(pem)
          
    if password != nil {
      guard type == .encryptedPrivateKey else { throw PEM.Error.invalidParameters }
    }
    
    switch type {
    case .publicRSAKeyDER:
      // Ensure the objectIdentifier is rsaEncryption
      try self.init(publicDER: bytes)
    case .privateRSAKeyDER:
      // Ensure the objectIdentifier is rsaEncryption
      try self.init(privateDER: bytes)
    case .publicKey:
      let der = try PEM.decodePublicKeyPEM(Data(bytes), expectedPrimaryObjectIdentifier: Key.primaryObjectIdentifier, expectedSecondaryObjectIdentifier: Key.secondaryObjectIdentifier)
      try self.init(publicDER: der)
    case .privateKey, .ecPrivateKey:
      let der = try PEM.decodePrivateKeyPEM(Data(bytes), expectedPrimaryObjectIdentifier: Key.primaryObjectIdentifier, expectedSecondaryObjectIdentifier: Key.secondaryObjectIdentifier)
      try self.init(privateDER: der)
    case .encryptedPrivateKey:
      // Decrypt the encrypted PEM and attempt to instantiate it again...
  
      // Ensure we were provided a password
      guard let password = password else { throw PEM.Error.invalidParameters }
  
      // Parse out Encryption Strategy and CipherText
      let decryptionStategy = try PEM.decodeEncryptedPEM(Data(bytes)) // RSA.decodeEncryptedPEM(Data(bytes))
  
      // Derive Encryption Key from Password
      let key = try decryptionStategy.pbkdfAlgorithm.deriveKey(password: password, ofLength: decryptionStategy.cipherAlgorithm.desiredKeyLength)
  
      // Decrypt CipherText
      let decryptedPEM = try decryptionStategy.cipherAlgorithm.decrypt(bytes: decryptionStategy.ciphertext, withKey: key)
  
      // Proceed with the unencrypted PEM (can public PEM keys be encrypted as well, wouldn't really make sense but idk if we should support it)?
      let der = try PEM.decodePrivateKeyPEM(Data(decryptedPEM), expectedPrimaryObjectIdentifier: Key.primaryObjectIdentifier, expectedSecondaryObjectIdentifier: Key.secondaryObjectIdentifier)
      try self.init(privateDER: der)
    }
  }
}

/// Conform to this protocol if your type can be described in an ASN1 DER representation
public protocol DEREncodable {
  /// The keys ASN1 object identifier (ex: RSA --> rsaEncryption --> [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
  static var primaryObjectIdentifier:Array<UInt8> { get }
  /// The keys ASN1 object identifier (ex: RSA --> null --> nil)
  static var secondaryObjectIdentifier:Array<UInt8>? { get }
    
  func publicKeyDER() throws -> Array<UInt8>
  func privateKeyDER() throws -> Array<UInt8>
  
  /// PublicKey PEM Export Functions
    func exportPublicKeyPEM(withHeaderAndFooter:Bool) throws -> Array<UInt8>
  func exportPublicKeyPEMString(withHeaderAndFooter:Bool) throws -> String
  
  /// PrivateKey PEM Export Functions
  func exportPrivateKeyPEM(withHeaderAndFooter:Bool) throws -> Array<UInt8>
  func exportPrivateKeyPEMString(withHeaderAndFooter:Bool) throws -> String
}

public extension DEREncodable {
  func exportPublicKeyPEM(withHeaderAndFooter:Bool = true) throws -> Array<UInt8> {
    let publicDER = try self.publicKeyDER()
    let asnNodes:ASN1.Node = .sequence(nodes: [
      .sequence(nodes: [
        .objectIdentifier(data: Data(Self.primaryObjectIdentifier)),
        .null
      ]),
      .bitString(data: Data( publicDER ))
    ])
  
    let base64String = ASN1.Encoder.encode(asnNodes).toBase64()
    let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
    let bodyUTF8Bytes = bodyString.bytes
    
    if withHeaderAndFooter {
      let header = PEM.PEMType.publicKey.headerBytes + [0x0a]
      let footer = [0x0a] + PEM.PEMType.publicKey.footerBytes
    
      return header + bodyUTF8Bytes + footer
    } else {
      return bodyUTF8Bytes
    }
  }
  
  func exportPublicKeyPEMString(withHeaderAndFooter:Bool = true) throws -> String {
    let publicPEMData = try exportPublicKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
    guard let pemAsString = String(data: Data(publicPEMData), encoding: .utf8) else {
    throw PEM.Error.encodingError
    }
    return pemAsString
  }
  
  func exportPrivateKeyPEM(withHeaderAndFooter:Bool = true) throws -> Array<UInt8> {
    let privateDER = try self.privateKeyDER()
    let asnNodes:ASN1.Node = .sequence(nodes: [
      .integer(data: Data(hex: "0x00")),
      .sequence(nodes: [
        .objectIdentifier(data: Data(Self.primaryObjectIdentifier)),
        .null
      ]),
      .octetString(data: Data( privateDER ))
    ])
      
    let base64String = ASN1.Encoder.encode(asnNodes).toBase64()
    let bodyString = base64String.chunks(ofCount: 64).joined(separator: "\n")
    let bodyUTF8Bytes = bodyString.bytes
    
    if withHeaderAndFooter {
      let header = PEM.PEMType.privateKey.headerBytes + [0x0a]
      let footer = [0x0a] + PEM.PEMType.privateKey.footerBytes
    
      return header + bodyUTF8Bytes + footer
    } else {
      return bodyUTF8Bytes
    }
  }
  
  func exportPrivateKeyPEMString(withHeaderAndFooter:Bool = true) throws -> String {
    let privatePEMData = try exportPrivateKeyPEM(withHeaderAndFooter: withHeaderAndFooter)
    guard let pemAsString = String(data: Data(privatePEMData), encoding: .utf8) else {
      throw PEM.Error.encodingError
    }
    return pemAsString
  }
}

/// Conform to this protocol if your type can both be instantiated and expressed by an ASN1 DER representation.
public protocol DERCodable: DERDecodable, DEREncodable { }

struct DER {
  /// Integer to Octet String Primitive
  /// - Parameters:
  ///   - x: nonnegative integer to be converted
  ///   - size: intended length of the resulting octet string
  /// - Returns: corresponding octet string of length xLen
  /// - Note: https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
  internal static func i2osp(x:[UInt8], size:Int) -> [UInt8] {
    var modulus = x
    while modulus.count < size {
      modulus.insert(0x00, at: 0)
    }
    if modulus[0] >= 0x80 {
        modulus.insert(0x00, at: 0)
    }
    return modulus
  }
    
  /// Integer to Octet String Primitive
  /// - Parameters:
  ///   - x: nonnegative integer to be converted
  ///   - size: intended length of the resulting octet string
  /// - Returns: corresponding octet string of length xLen
  /// - Note: https://datatracker.ietf.org/doc/html/rfc3447#section-4.1
  internal static func i2ospData(x:[UInt8], size:Int) -> Data {
    return Data(DER.i2osp(x: x, size: size))
  }
}
