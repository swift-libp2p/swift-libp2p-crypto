//
//  PEM.swift
//
//
//  Created by Brandon Toms on 5/28/22.
//

import Foundation
import CryptoSwift

struct PEM {
    
  public enum Error: Swift.Error {
    /// An error occured while encoding the PEM file
    case encodingError
    /// An error occured while decoding the PEM file
    case decodingError
    /// Encountered an unsupported PEM type
    case unsupportedPEMType
    /// Encountered an invalid/unexpected PEM format
    case invalidPEMFormat(String? = nil)
    /// Encountered an invalid/unexpected PEM header string/delimiter
    case invalidPEMHeader
    /// Encountered an invalid/unexpected PEM footer string/delimiter
    case invalidPEMFooter
    /// Encountered a invalid/unexpected parameters while attempting to decode a PEM file
    case invalidParameters
    /// Encountered an unsupported Cipher algorithm while attempting to decrypt an encrypted PEM file
    case unsupportedCipherAlgorithm([UInt8])
    /// Encountered an unsupported Password Derivation algorithm while attempting to decrypt an encrypted PEM file
    case unsupportedPBKDFAlgorithm([UInt8])
    /// The instiating types objectIdentifier does not match that of the PEM file
    case objectIdentifierMismatch(got:[UInt8], expected:[UInt8])
  }
    
  // MARK: Add support for additional PEM types here
    
  /// General PEM Classification
  internal enum PEMType {
    // Direct DER Exports for RSA Keys (special case)
    case publicRSAKeyDER
    case privateRSAKeyDER
  
    // Generale PEM Headers
    case publicKey
    case privateKey
    case encryptedPrivateKey
    case ecPrivateKey
  
    // Others
    //case certificate
  
    init(headerBytes: ArraySlice<UInt8>) throws {
      guard headerBytes.count > 10 else { throw PEM.Error.unsupportedPEMType }
      let bytes = headerBytes.dropFirst(5).dropLast(5)
      switch bytes {
      //"BEGIN RSA PUBLIC KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59]:
        self = .publicRSAKeyDER

      //"BEGIN RSA PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x52, 0x53, 0x41, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .privateRSAKeyDER

      //"BEGIN PUBLIC KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x55, 0x42, 0x4c, 0x49, 0x43, 0x20, 0x4b, 0x45, 0x59]:
        self = .publicKey

      //"BEGIN PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .privateKey

      //"BEGIN ENCRYPTED PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x45, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .encryptedPrivateKey

      //"BEGIN EC PRIVATE KEY"
      case [0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59]:
        self = .ecPrivateKey
      
      default:
        print("Unsupported PEM Type: \(Data(bytes).toHexString())")
        throw PEM.Error.unsupportedPEMType
      }
    }
  
    /// This PEM type's header string (expressed as the utf8 decoded byte representation)
    var headerBytes:Array<UInt8> {
      switch self {
      case .publicRSAKeyDER:
          return "-----BEGIN RSA PUBLIC KEY-----".bytes
      case .privateRSAKeyDER:
          return "-----BEGIN RSA PRIVATE KEY-----".bytes
      case .publicKey:
          return "-----BEGIN PUBLIC KEY-----".bytes
      case .privateKey:
          return "-----BEGIN PRIVATE KEY-----".bytes
      case .encryptedPrivateKey:
          return "-----BEGIN ENCRYPTED PRIVATE KEY-----".bytes
      case .ecPrivateKey:
          return "-----BEGIN EC PRIVATE KEY-----".bytes
      }
    }

    /// This PEM type's footer string (expressed as the utf8 decoded byte representation)
    var footerBytes:Array<UInt8> {
      switch self {
      case .publicRSAKeyDER:
          return "-----END RSA PUBLIC KEY-----".bytes
      case .privateRSAKeyDER:
          return "-----END RSA PRIVATE KEY-----".bytes
      case .publicKey:
          return "-----END PUBLIC KEY-----".bytes
      case .privateKey:
          return "-----END PRIVATE KEY-----".bytes
      case .encryptedPrivateKey:
          return "-----END ENCRYPTED PRIVATE KEY-----".bytes
      case .ecPrivateKey:
          return "-----END EC PRIVATE KEY-----".bytes
      }
    }
  }
    
  /// Converts UTF8 Encoding of PEM file into a PEMType and the base64 decoded key data
  /// - Parameter data: The `UTF8` encoding of the PEM file
  /// - Returns: A tuple containing the PEMType, and the actual base64 decoded PEM data (with the headers and footers removed).
  internal static func pemToData(_ data:Array<UInt8>) throws -> (type: PEMType, bytes: Array<UInt8>, objectIdentifiers:[Array<UInt8>]) {
    let fiveDashes = ArraySlice<UInt8>(repeating: 0x2D, count: 5) // "-----".bytes.toHexString()
    let chunks = data.split(separator: 0x0a) // 0x0a == "\n" `new line` char
    guard chunks.count > 2 else { throw PEM.Error.invalidPEMFormat("expected at least 3 chunks, a header, body and footer, but got \(chunks.count)") }
  
    // Enforce a valid PEM header
    guard let header = chunks.first,
      header.count > 10,
      header.prefix(5) == fiveDashes,
      header.suffix(5) == fiveDashes else {
        throw PEM.Error.invalidPEMHeader
    }
  
    // Enforce a valid PEM footer
    guard let footer = chunks.last,
      footer.count > 10,
      footer.prefix(5) == fiveDashes,
      footer.suffix(5) == fiveDashes else {
        throw PEM.Error.invalidPEMFooter
    }
  
    // Attempt to classify the PEMType based on the header
    //
    // - Note: This just gives us a general idea of what direction to head in. Headers that don't match the underlying data will end up throwing an Error later
    let pemType:PEMType = try PEMType(headerBytes: header)
  
    guard let base64 = String(data: Data(chunks[1..<chunks.count-1].joined()), encoding: .utf8) else { throw Error.invalidPEMFormat("Unable to join chunked body data") }
    guard let pemData = Data(base64Encoded: base64) else { throw Error.invalidPEMFormat("Body of PEM isn't valid base64 encoded") }
  
    let asn1 = try ASN1.Decoder.decode(data: pemData)
      
    // return the PEMType and PEM Data (without header & footer)
      return (type: pemType, bytes: pemData.bytes, objectIdentifiers: objIdsInSequence(asn1).map { $0.bytes })
  }
    
    /// Traverses a Node tree and returns all instances of objectIds
    internal static func objIdsInSequence(_ node:ASN1.Node) -> [Data] {
        if case .objectIdentifier(let id) = node { return [id] }
        else if case .sequence(let nodes) = node {
            return objIdsInSequence(nodes)
        }
        return []
    }
    
    /// Traverses a Node tree and returns all instances of objectIds
    internal static func objIdsInSequence(_ nodes:[ASN1.Node]) -> [Data] {
        var objs:[Data] = []

        nodes.forEach {
            if case .objectIdentifier(let id) = $0 { objs.append(id) }
            else if case .sequence(let nodes) = $0 {
                return objs.append(contentsOf: objIdsInSequence(nodes) )
            }
        }

        return objs
    }

  /// Decodes an ASN1 formatted Public Key into it's raw DER representation
  /// - Parameters:
  ///   - pem: The ASN1 encoded Public Key representation
  ///   - expectedObjectIdentifier: The expected objectIdentifier for the particular key type
  /// - Returns: The raw bitString data (Public Key DER)
  ///
  /// ```
  /// 0:d=0  hl=4 l= 546 cons: SEQUENCE
  /// 4:d=1  hl=2 l=  13 cons:  SEQUENCE
  /// 6:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
  /// 17:d=2  hl=2 l=   0 prim:   NULL
  /// 19:d=1  hl=4 l= 527 prim:  BIT STRING
  /// ```
  internal static func decodePublicKeyPEM(_ pem:Data, expectedPrimaryObjectIdentifier:Array<UInt8>, expectedSecondaryObjectIdentifier:Array<UInt8>?) throws -> Array<UInt8> {
    let asn = try ASN1.Decoder.decode(data: pem)
    
    print("PublicKey")
    print(asn)
      
    // Enforce the above ASN1 Structure
    guard case .sequence(let sequence) = asn else { throw Error.invalidPEMFormat("PublicKey::No top level sequence for PublicKey PEM") }
    guard sequence.count == 2 else { throw Error.invalidPEMFormat("PublicKey::Top level sequnce should contain two nodes but we got \(sequence.count) isntead") }
    guard case .sequence(let params) = sequence.first else { throw Error.invalidPEMFormat("PublicKey::Expected the first node of the top level to be a sequence node, but we got \(sequence.first?.description ?? "NIL") instead") }
    guard params.count >= 1 else { throw Error.invalidPEMFormat("PublicKey::Expected at least one param within the secondary sequence") }
    guard case .objectIdentifier(let objectID) = params.first else { throw Error.invalidPEMFormat("PublicKey::Expected first param of secondary sequence to be an objectIndentifier") }
    
    // Ensure the ObjectID specified in the PEM matches that of the Key.Type we're attempting to instantiate
    guard objectID.bytes == expectedPrimaryObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectID.bytes, expected: expectedPrimaryObjectIdentifier) }
      
    // If the key supports a secondary objectIdentifier (ensure one is present and that they match)
    if let expectedSecondaryObjectIdentifier = expectedSecondaryObjectIdentifier {
      guard params.count >= 2 else { throw Error.invalidPEMFormat("PrivateKey::") }
      guard case .objectIdentifier(let objectIDSecondary) = params[1] else { throw Error.invalidPEMFormat("PrivateKey::") }
      guard objectIDSecondary.bytes == expectedSecondaryObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectIDSecondary.bytes, expected: expectedSecondaryObjectIdentifier) }
    }
      
    guard case .bitString(let bits) = sequence.last else { throw Error.invalidPEMFormat("Expected the last element of the top level sequence to be a bitString") }
    
    return bits.bytes
  }
    
  /// Decodes an ASN1 formatted Private Key into it's raw DER representation
  /// - Parameters:
  ///   - pem: The ASN1 encoded Private Key representation
  ///   - expectedObjectIdentifier: The expected objectIdentifier for the particular key type
  /// - Returns: The raw octetString data (Private Key DER)
  internal static func decodePrivateKeyPEM(_ pem:Data, expectedPrimaryObjectIdentifier:Array<UInt8>, expectedSecondaryObjectIdentifier:Array<UInt8>?) throws -> Array<UInt8> {
    let asn = try ASN1.Decoder.decode(data: pem)
  
    print("PrivateKey")
    print(asn)
  
    // Enforce the above ASN1 Structure
    guard case .sequence(let sequence) = asn else { throw Error.invalidPEMFormat("PrivateKey::Top level node is not a sequence") }
    // Enforce the integer/version param as the first param in our top level sequence
    guard case .integer(let integer) = sequence.first else { throw Error.invalidPEMFormat("PrivateKey::First item in top level sequence wasn't an integer") }
      print("PEM Version: \(integer.bytes)")
      switch integer {
      case Data(hex: "0x00"):
        //Proceed with standard pkcs1 private key format
        return try decodePrivateKey(sequence, expectedPrimaryObjectIdentifier: expectedPrimaryObjectIdentifier, expectedSecondaryObjectIdentifier: expectedSecondaryObjectIdentifier)
      case Data(hex: "0x01"):
        //Proceed with EC private key format
        return try decodePrivateECKey(sequence, expectedPrimaryObjectIdentifier: expectedPrimaryObjectIdentifier)
      default:
        throw Error.invalidPEMFormat("Unknown version identifier")
      }
  }
    
  /// Decodes a standard (RSA) Private Key PEM file
  /// - Parameters:
  ///   - sequence: The contents of the top level ASN1 Sequence node
  ///   - expectedPrimaryObjectIdentifier: The expected primary object identifier key to compare the PEM contents against
  ///   - expectedSecondaryObjectIdentifier: The expected secondary object identifier key to compare the PEM contents against
  /// - Returns: The private key bytes
  ///
  /// [Private key format]()
  /// ```
  /// 0:d=0  hl=4 l= 630 cons: SEQUENCE
  /// 4:d=1  hl=2 l=   1 prim:  INTEGER           :00
  /// 7:d=1  hl=2 l=  13 cons:  SEQUENCE
  /// 9:d=2  hl=2 l=   9 prim:   OBJECT            :rsaEncryption
  /// 20:d=2  hl=2 l=   0 prim:   NULL
  /// 22:d=1  hl=4 l= 608 prim:  OCTET STRING      [HEX DUMP]:3082...AA50
  /// ```
  private static func decodePrivateKey(_ sequence:[ASN1.Node], expectedPrimaryObjectIdentifier:Array<UInt8>, expectedSecondaryObjectIdentifier:Array<UInt8>?) throws -> Array<UInt8> {
    guard sequence.count == 3 else { throw Error.invalidPEMFormat("PrivateKey::Top level sequence doesn't contain 3 items") }
    guard case .sequence(let params) = sequence[1] else { throw Error.invalidPEMFormat("PrivateKey::Second item wasn't a sequence") }
    guard params.count >= 1 else { throw Error.invalidPEMFormat("PrivateKey::Second sequence contained fewer than expected parameters") }
    guard case .objectIdentifier(let objectID) = params.first else { throw Error.invalidPEMFormat("PrivateKey::") }
  
    // Ensure the ObjectID specified in the PEM matches that of the Key.Type we're attempting to instantiate
    guard objectID.bytes == expectedPrimaryObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectID.bytes, expected: expectedPrimaryObjectIdentifier) }
  
    // If the key supports a secondary objectIdentifier (ensure one is present and that they match)
    if let expectedSecondaryObjectIdentifier = expectedSecondaryObjectIdentifier {
    guard params.count >= 2 else { throw Error.invalidPEMFormat("PrivateKey::") }
    guard case .objectIdentifier(let objectIDSecondary) = params[1] else { throw Error.invalidPEMFormat("PrivateKey::") }
      guard objectIDSecondary.bytes == expectedSecondaryObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectIDSecondary.bytes, expected: expectedSecondaryObjectIdentifier) }
    }
  
    guard case .octetString(let octet) = sequence[2] else { throw Error.invalidPEMFormat("PrivateKey::") }
  
    return octet.bytes
  }
    
  /// Decodes an Eliptic Curve Private Key PEM that conforms to the IETF RFC5915 structure
  /// - Parameters:
  ///   - node: The contents of the top level ASN1 Sequence node
  ///   - expectedPrimaryObjectIdentifier: The expected primary object identifier key to compare the PEM contents against
  /// - Returns: The EC private key bytes
  ///
  /// [EC private key format](https://datatracker.ietf.org/doc/html/rfc5915#section-3)
  /// ```
  /// ECPrivateKey ::= SEQUENCE {
  ///     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
  ///     privateKey     OCTET STRING,
  ///     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
  ///     publicKey  [1] BIT STRING OPTIONAL
  /// }
  /// ```
  private static func decodePrivateECKey(_ sequence:[ASN1.Node], expectedPrimaryObjectIdentifier:Array<UInt8>) throws -> Array<UInt8> {
    guard sequence.count >= 2 else { throw Error.invalidPEMFormat("PrivateKey::EC::Top level sequence doesn't contain at least 2 items") }
    guard case .octetString(let octet) = sequence[1] else { throw Error.invalidPEMFormat("PrivateKey::EC::Second item wasn't an octetString") }
  
    // Remaining parameters are optional...
    if sequence.count > 2 {
      guard case .objectIdentifier(let objectID) = sequence[2] else { throw Error.invalidPEMFormat("PrivateKey::EC::Missing objectIdentifier in top level sequence") }
      // Ensure the ObjectID specified in the PEM matches that of the Key.Type we're attempting to instantiate
      guard objectID.bytes == expectedPrimaryObjectIdentifier else { throw Error.objectIdentifierMismatch(got: objectID.bytes, expected: expectedPrimaryObjectIdentifier) }
    }
  
    //if sequence.count > 3 {
    //    // Optional Public Key
    //    guard case .bitString(let _) = sequence[3] else { throw Error.invalidPEMFormat("PrivateKey::EC::") }
    //}
  
    return octet.bytes
  }
}


// MARK: Encrypted PEM

extension PEM {
    
  internal struct EncryptedPEM {
    let objectIdentifer:[UInt8]
    let ciphertext:[UInt8]
    let pbkdfAlgorithm:PBKDFAlgorithm
    let cipherAlgorithm:CipherAlgorithm
  }

  /// Attempts to decode an encrypted Private Key PEM, returning all of the information necessary to decrypt the encrypted PEM
  /// - Parameter encryptedPEM: The raw base64 decoded PEM data
  /// - Returns: An `EncryptedPEM` Struct containing the ciphertext, the pbkdf alogrithm for key derivation, the cipher algorithm for decrypting and the objectIdentifier describing the contents of this PEM data
  ///
  /// To decrypt an encrypted PEM Private Key...
  /// 1) Strip the headers of the PEM and base64 decode the data
  /// 2) Parse the data via ASN1 looking for both the pbkdf and cipher algorithms, their respective parameters (salt, iv and itterations) and the ciphertext (aka octet string))
  /// 3) Derive the encryption key using the appropriate pbkdf alogorithm, found in step 2
  /// 4) Use the encryption key to instantiate the appropriate cipher algorithm, also found in step 2
  /// 5) Decrypt the encrypted ciphertext (the contents of the octetString node)
  /// 6) The decrypted octet string can now be handled like any other Private Key PEM
  ///
  /// ```
  /// sequence(nodes: [
  ///   ASN1.Parser.Node.sequence(nodes: [
  ///       ASN1.Parser.Node.objectIdentifier(data: 9 bytes),              // PEM's ObjectIdentifier
  ///       ASN1.Parser.Node.sequence(nodes: [
  ///           ASN1.Parser.Node.sequence(nodes: [
  ///               ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      // PBKDF Algorithm
  ///               ASN1.Parser.Node.sequence(nodes: [
  ///                   ASN1.Parser.Node.octetString(data: 8 bytes),       // SALT
  ///                   ASN1.Parser.Node.integer(data: 2 bytes)            // ITERATIONS
  ///               ])
  ///           ]),
  ///           ASN1.Parser.Node.sequence(nodes: [
  ///               ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      // Cipher Algorithm (ex: des-ede3-cbc)
  ///               ASN1.Parser.Node.octetString(data: 16 bytes)           // Initial Vector (IV)
  ///           ])
  ///       ])
  ///   ]),
  ///   ASN1.Parser.Node.octetString(data: 640 bytes)
  /// ])
  /// ```
  internal static func decodeEncryptedPEM(_ encryptedPEM:Data) throws -> EncryptedPEM {
    let asn = try ASN1.Decoder.decode(data: encryptedPEM)
    
    guard case .sequence(let encryptedPEMWrapper) = asn else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    guard encryptedPEMWrapper.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    guard case .sequence(let encryptionInfoWrapper) = encryptedPEMWrapper.first else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    guard encryptionInfoWrapper.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    guard case .objectIdentifier(let objID) = encryptionInfoWrapper.first else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    guard case .sequence(let encryptionAlgorithmsWrapper) = encryptionInfoWrapper.last else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    guard encryptionAlgorithmsWrapper.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
    let pbkdf = try decodePBKFD(encryptionAlgorithmsWrapper.first!)
    let cipher = try decodeCipher(encryptionAlgorithmsWrapper.last!)
    guard case .octetString(let octets) = encryptedPEMWrapper.last else { throw Error.invalidPEMFormat("EncryptedPrivateKey::") }
  
    return EncryptedPEM(objectIdentifer: objID.bytes, ciphertext: octets.bytes, pbkdfAlgorithm: pbkdf, cipherAlgorithm: cipher)
  }
    
  internal static func encryptPEM(_ pem:Data, withPassword password:String, usingPBKDF pbkdf:PBKDFAlgorithm = .pbkdf2(salt: try! LibP2PCrypto.randomBytes(length: 8), iterations: 2048), andCipher cipher:CipherAlgorithm = .aes_128_cbc(iv: try! LibP2PCrypto.randomBytes(length: 16))) throws -> Data {

    // Generate Encryption Key from Password
    let key = try pbkdf.deriveKey(password: password, ofLength: cipher.desiredKeyLength)

    // Encrypt Plaintext
    let ciphertext = try cipher.encrypt(bytes: pem.bytes, withKey: key)

    // Encode Encrypted PEM (including pbkdf and cipher algos used)
    let nodes:ASN1.Node = .sequence(nodes: [
      .sequence(nodes: [
        .objectIdentifier(data: Data(hex: "2a864886f70d01050d")),
        .sequence(nodes: [
          try pbkdf.encodePBKDF(),
          try cipher.encodeCipher()
        ])
      ]),
      .octetString(data: Data(ciphertext))
    ])

    let encoded = ASN1.Encoder.encode(nodes)

    let base64 = "\n" + encoded.toBase64().split(intoChunksOfLength: 64).joined(separator: "\n") + "\n"
      
      return Data(PEM.PEMType.encryptedPrivateKey.headerBytes + base64.bytes +  PEM.PEMType.encryptedPrivateKey.footerBytes)
  }
    
  internal static func encryptPEMString(_ pem:Data, withPassword password:String, usingPBKDF pbkdf:PBKDFAlgorithm = .pbkdf2(salt: try! LibP2PCrypto.randomBytes(length: 8), iterations: 2048), andCipher cipher:CipherAlgorithm = .aes_128_cbc(iv: try! LibP2PCrypto.randomBytes(length: 16))) throws -> String {
      let data = try PEM.encryptPEM(pem, withPassword: password, usingPBKDF: pbkdf, andCipher: cipher)
      return String(data: data, encoding: .utf8)!
  }
}


// MARK: Encrypted PEM PBKDF Algorithms

extension PEM {
  // MARK: Add support for new PBKDF Algorithms here...
  internal enum PBKDFAlgorithm {
    case pbkdf2(salt: [UInt8], iterations: Int)
  
    init(objID:[UInt8], salt:[UInt8], iterations:[UInt8]) throws {
      guard let iterations = Int(iterations.toHexString(), radix: 16) else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
      switch objID {
      case [42, 134, 72, 134, 247, 13, 1, 5, 12]: // pbkdf2
        self = .pbkdf2(salt: salt, iterations: iterations)
      default:
        throw Error.unsupportedPBKDFAlgorithm(objID)
      }
    }
  
    func deriveKey(password:String, ofLength keyLength:Int, usingHashVarient variant:HMAC.Variant = .sha1) throws -> [UInt8] {
      switch self {
      case .pbkdf2(let salt, let iterations):
        //print("Salt: \(salt), Iterations: \(iterations)")
        let key = try PKCS5.PBKDF2(password: password.bytes, salt: salt, iterations: iterations, keyLength: keyLength, variant: variant).calculate()
        //print(key)
        return key
      //default:
      //    throw Error.invalidPEMFormat
      }
    }
      
    var objectIdentifier:[UInt8] {
      switch self {
      case .pbkdf2:
        return [42, 134, 72, 134, 247, 13, 1, 5, 12]
      }
    }
      
    var salt:[UInt8] {
      switch self {
      case .pbkdf2(let salt, _):
        return salt
      }
    }
    
    var iterations:Int {
      switch self {
      case .pbkdf2(_, let iterations):
        return iterations
      }
    }
    
    func encodePBKDF() throws -> ASN1.Node {
      return .sequence(nodes: [
        .objectIdentifier(data: Data(self.objectIdentifier)),
        .sequence(nodes: [
            .octetString(data: Data(self.salt)),
            .integer(data: Data(self.iterations.bytes(totalBytes: 2)))
        ])
      ])
    }
  }
  
  /// Decodes the PBKDF ASN1 Block in an Encrypted Private Key PEM file
  /// - Parameter node: The ASN1 sequence node containing the pbkdf parameters
  /// - Returns: The PBKDFAlogrithm if supported
  ///
  /// Expects an ASN1.Node with the following structure
  /// ```
  /// ASN1.Parser.Node.sequence(nodes: [
  ///     ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //PBKDF2 //[42,134,72,134,247,13,1,5,12]
  ///     ASN1.Parser.Node.sequence(nodes: [
  ///         ASN1.Parser.Node.octetString(data: 8 bytes),       //SALT
  ///         ASN1.Parser.Node.integer(data: 2 bytes)            //ITTERATIONS
  ///     ])
  /// ])
  /// ```
  fileprivate static func decodePBKFD(_ node:ASN1.Node) throws -> PBKDFAlgorithm {
    guard case .sequence(let wrapper) = node else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
    guard wrapper.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
    guard case .objectIdentifier(let objID) = wrapper.first else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
    guard case .sequence(let params) = wrapper.last else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
    guard params.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
    guard case .octetString(let salt) = params.first else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
    guard case .integer(let iterations) = params.last else { throw Error.invalidPEMFormat("EncryptedPrivateKey::PBKDF") }
  
    return try PBKDFAlgorithm(objID: objID.bytes, salt: salt.bytes, iterations: iterations.bytes)
  }
}


// MARK: Encrypted PEM Cipher Algorithms

extension PEM {
  // MARK: Add support for new Cipher Algorithms here...
  internal enum CipherAlgorithm {
    case aes_128_cbc(iv:[UInt8])
    case aes_256_cbc(iv:[UInt8])
    //case des3(iv: [UInt8])
  
    init(objID:[UInt8], iv:[UInt8]) throws {
      switch objID {
      case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]: // aes-128-cbc
        self = .aes_128_cbc(iv: iv)
      case [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]: // aes-256-cbc
        self = .aes_256_cbc(iv: iv)
      //case [42, 134, 72, 134, 247, 13, 3, 7]:
      //  self = .des3(iv: iv)
      default:
        throw Error.unsupportedCipherAlgorithm(objID)
      }
    }
  
    func decrypt(bytes: [UInt8], withKey key:[UInt8]) throws -> [UInt8] {
      switch self {
      case .aes_128_cbc(let iv):
        //print("128 IV: \(iv)")
        return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).decrypt(bytes)
      case .aes_256_cbc(let iv):
        //print("256 IV: \(iv)")
        return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).decrypt(bytes)
      //default:
        //throw Error.invalidPEMFormat
      }
    }
    
    func encrypt(bytes: [UInt8], withKey key:[UInt8]) throws -> [UInt8] {
      switch self {
      case .aes_128_cbc(let iv):
        return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).encrypt(bytes)
      case .aes_256_cbc(let iv):
        return try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7).encrypt(bytes)
      }
    }
  
    /// The key length used for this Cipher strategy
    /// - Note: we need this information when deriving the key using our PBKDF strategy
    var desiredKeyLength:Int {
      switch self {
      case .aes_128_cbc: return 16
      case .aes_256_cbc: return 32
      }
    }
      
    var objectIdentifier:[UInt8] {
      switch self {
      case .aes_128_cbc:
        return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02]
      case .aes_256_cbc:
        return [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a]
      }
    }
    
    var iv:[UInt8] {
      switch self {
      case .aes_128_cbc(let iv):
        return iv
      case .aes_256_cbc(let iv):
        return iv
      }
    }
      
    func encodeCipher() throws -> ASN1.Node {
      return .sequence(nodes: [
        .objectIdentifier(data: Data(self.objectIdentifier)),
        .octetString(data: Data(self.iv))
      ])
    }
  }
  
  /// Decodes the Cipher ASN1 Block in an Encrypted Private Key PEM file
  /// - Parameter node: The ASN1 sequence node containing the cipher parameters
  /// - Returns: The CipherAlogrithm if supported
  ///
  /// Expects an ASN1.Node with the following structure
  /// ```
  /// ASN1.Parser.Node.sequence(nodes: [
  ///     ASN1.Parser.Node.objectIdentifier(data: 9 bytes),      //des-ede3-cbc
  ///     ASN1.Parser.Node.octetString(data: 16 bytes)           //IV
  /// ])
  /// ```
  fileprivate static func decodeCipher(_ node:ASN1.Node) throws -> CipherAlgorithm {
    guard case .sequence(let params) = node else { throw Error.invalidPEMFormat("EncryptedPrivateKey::CIPHER") }
    guard params.count == 2 else { throw Error.invalidPEMFormat("EncryptedPrivateKey::CIPHER") }
    guard case .objectIdentifier(let objID) = params.first else { throw Error.invalidPEMFormat("EncryptedPrivateKey::CIPHER") }
    guard case .octetString(let initialVector) = params.last else { throw Error.invalidPEMFormat("EncryptedPrivateKey::CIPHER") }
  
    return try CipherAlgorithm(objID: objID.bytes, iv: initialVector.bytes)
  }
}
