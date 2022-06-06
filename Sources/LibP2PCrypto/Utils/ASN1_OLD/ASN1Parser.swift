////
////  Asn1Parser.swift
////  SwiftyRSA
////
////  Created by Lois Di Qual on 5/9/17.
////  Copyright © 2017 Scoop. All rights reserved.
////  Modified by Brandon Toms on 5/1/22
////
//
//import Foundation
//import Multibase
//
///// Object Identifiers
///// [6,8,42,134,72,206,61,3,1,7]  -> EC Curve 256   ':prime256v1'
///// [6,5,43,129,4,0,34]           -> EC Curve 384   'secp384r1'
///// [6,5,43,129,4,0,35]           -> EC Curve 521   ':secp521r1'
///// [42,134,72,206,61,2,1]        -> EC Pub         ':id-ecPublicKey'
///// [42,134,72,206,61,3,1,7]      -> EC Pub 256     ':prime256v1'
///// [43,129,4,0,34]               -> EC Pub 384     ':secp384r1'
///// [43,129,4,0,35]               -> EC Pub 521     ':secp521r1'
///// [6,5,43,129,4,0,10]           -> EC Secp256k1 Private
//
///// Simple data scanner that consumes bytes from a raw data and keeps an updated position.
//private class Scanner {
//    
//    enum ScannerError: Error {
//        case outOfBounds
//    }
//    
//    let data: Data
//    var index: Int = 0
//    
//    /// Returns whether there is no more data to consume
//    var isComplete: Bool {
//        return index >= data.count
//    }
//    
//    /// Creates a scanner with provided data
//    ///
//    /// - Parameter data: Data to consume
//    init(data: Data) {
//        self.data = data
//    }
//    
//    /// Consumes data of provided length and returns it
//    ///
//    /// - Parameter length: length of the data to consume
//    /// - Returns: data consumed
//    /// - Throws: ScannerError.outOfBounds error if asked to consume too many bytes
//    func consume(length: Int) throws -> Data {
//        
//        guard length > 0 else {
//            return Data()
//        }
//        
//        guard index + length <= data.count else {
//            throw ScannerError.outOfBounds
//        }
//        
//        let subdata = data.subdata(in: index..<index + length)
//        index += length
//        return subdata
//    }
//    
//    /// Consumes a primitive, definite ASN1 length and returns its value.
//    ///
//    /// See http://luca.ntop.org/Teaching/Appunti/asn1.html,
//    ///
//    /// - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
//    /// - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and
//    ///   bits 7-1 give the number of additional length octets.
//    ///   Second and following octets give the length, base 256, most significant digit first.
//    ///
//    /// - Returns: Length that was consumed
//    /// - Throws: ScannerError.outOfBounds error if asked to consume too many bytes
//    func consumeLength() throws -> Int {
//        
//        let lengthByte = try consume(length: 1).firstByte
//        
//        // If the first byte's value is less than 0x80, it directly contains the length
//        // so we can return it
//        guard lengthByte >= 0x80 else {
//            return Int(lengthByte)
//        }
//        
//        // If the first byte's value is more than 0x80, it indicates how many following bytes
//        // will describe the length. For instance, 0x85 indicates that 0x85 - 0x80 = 0x05 = 5
//        // bytes will describe the length, so we need to read the 5 next bytes and get their integer
//        // value to determine the length.
//        let nextByteCount = lengthByte - 0x80
//        let length = try consume(length: Int(nextByteCount))
//        
//        return length.integer
//    }
//}
//
//private extension Data {
//    
//    /// Returns the first byte of the current data
//    var firstByte: UInt8 {
//        var byte: UInt8 = 0
//        copyBytes(to: &byte, count: MemoryLayout<UInt8>.size)
//        return byte
//    }
//    
//    /// Returns the integer value of the current data.
//    /// @warning: this only supports data up to 4 bytes, as we can only extract 32-bit integers.
//    var integer: Int {
//        
//        guard count > 0 else {
//            return 0
//        }
//        
//        var int: UInt32 = 0
//        var offset: Int32 = Int32(count - 1)
//        forEach { byte in
//            let byte32 = UInt32(byte)
//            let shifted = byte32 << (UInt32(offset) * 8)
//            int = int | shifted
//            offset -= 1
//        }
//        
//        return Int(int)
//    }
//}
//
///// A simple ASN1 parser that will recursively iterate over a root node and return a Node tree.
///// The root node can be any of the supported nodes described in `Node`. If the parser encounters a sequence
///// it will recursively parse its children.
//enum Asn1Parser {
//    
//    /// An ASN1 node
//    enum Node:CustomStringConvertible {
//        case sequence(nodes: [Node])
//        case integer(data: Data)
//        case objectIdentifier(data: Data)
//        case null
//        case bitString(data: Data)
//        case octetString(data: Data)
//        
//        var description: String {
//            printNode(self, level: 0)
//        }
//    }
//    
//    enum ParserError: Error {
//        case noType
//        case invalidType(value: UInt8)
//    }
//    
//    /// Parses ASN1 data and returns its root node.
//    ///
//    /// - Parameter data: ASN1 data to parse
//    /// - Returns: Root ASN1 Node
//    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
//    static func parse(data: Data) throws -> Node {
//        let scanner = Scanner(data: data)
//        let node = try parseNode(scanner: scanner)
//        return node
//    }
//    
//    /// Parses an ASN1 given an existing scanne.
//    /// @warning: this will modify the state (ie: position) of the provided scanner.
//    ///
//    /// - Parameter scanner: Scanner to use to consume the data
//    /// - Returns: Parsed node
//    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
//    private static func parseNode(scanner: Scanner) throws -> Node {
//        
//        let firstByte = try scanner.consume(length: 1).firstByte
//        
////        print([firstByte].asString(base: .base16))
//        
//        // Sequence
//        if firstByte == 0x30 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            let nodes = try parseSequence(data: data)
//            return .sequence(nodes: nodes)
//        }
//        
//        // Integer
//        if firstByte == 0x02 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            //print(Int(data.asString(base: .base16), radix: 16) ?? -1)
//            return .integer(data: data)
//        }
//        
//        // Object identifier
//        if firstByte == 0x06 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            //print(String(data: data, encoding: .ascii))
//            //print("Object ID: [\(data.map { "\($0)" }.joined(separator: ","))]")
//            return .objectIdentifier(data: data)
//        }
//        
//        // Null
//        if firstByte == 0x05 {
//            _ = try scanner.consume(length: 1)
//            return .null
//        }
//        
//        // Bit String
//        if firstByte == 0x03 {
//            let length = try scanner.consumeLength()
//            
//            // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
//            // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
//            _ = try scanner.consume(length: 1)
//            
//            let data = try scanner.consume(length: length - 1)
//            return .bitString(data: data)
//        }
//        
//        // Octet String
//        if firstByte == 0x04 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
////            print(data.asString(base: .base64))
////            print()
////            print(data.bytes)
////            print()
//            return .octetString(data: data)
//        }
//        
//        throw ParserError.invalidType(value: firstByte)
//    }
//    
//    /// Parses an ASN1 sequence and returns its child nodes
//    ///
//    /// - Parameter data: ASN1 data
//    /// - Returns: A list of ASN1 nodes
//    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
//    private static func parseSequence(data: Data) throws -> [Node] {
//        let scanner = Scanner(data: data)
//        var nodes: [Node] = []
//        while !scanner.isComplete {
//            let node = try parseNode(scanner: scanner)
//            nodes.append(node)
//        }
//        return nodes
//    }
//}
//
//
//private let Mappings:[Array<UInt8>:String] = [
//    [6,8,42,134,72,206,61,3,1,7]: "prime256v1",
//    [6,5,43,129,4,0,34]:          "secp384r1",
//    [6,5,43,129,4,0,35]:          "secp521r1",
//    [42,134,72,206,61,2,1]:       "id-ecPublicKey",
//    [42,134,72,206,61,3,1,7]:     "prime256v1",
//    [43,129,4,0,34]:              "secp384r1",
//    [43,129,4,0,35]:              "secp521r1",
//    [6,5,43,129,4,0,10]:          "secp256k1",
//    [43,101,112]:                 "Ed25519",
//    [42,134,72,134,247,13,1,1,1]: "rsaEncryption"
//]
//
///// A simple ASN1 parser that will recursively iterate over a root node and return a Node tree.
///// The root node can be any of the supported nodes described in `Node`. If the parser encounters a sequence
///// it will recursively parse its children.
//enum Asn1ParserECPrivate {
//    
//    enum ObjectIdentifier:CustomStringConvertible {
//        case prime256v1
//        case secp384r1
//        case secp521r1
//        case id_ecPublicKey
//        case secp256k1
//        case Ed25519
//        case rsaEncryption
//        /// Encryption Tags and Ciphers
//        case aes_128_cbc // The cipher used to encrypt an encrypted key // des_ede3_cbc
//        case PBKDF2 //An Encrypted PEM Key that uses PBKDF2 to derive a the AES key
//        case PBES2 //An Encrypted PEM Key
//        case unknown(Data)
//        
//        init(data:Data) {
//            /// Often times Object Identifiers in private keys begin with an additional 6,5 or 6,8.
//            /// If the objID has this prefix, we drop the first two bytes before attempting to classify...
//            let d = data.first == 6 ? data.dropFirst(2) : data
//            switch d.bytes {
//            case [42,134,72,206,61,2,1]:
//                self = .id_ecPublicKey
//                
//            case [42,134,72,206,61,3,1,7]:
//                self = .prime256v1
//                
//            case [43,129,4,0,34]:
//                self = .secp384r1
//                
//            case [43,129,4,0,35]:
//                self = .secp521r1
//                
//            case [43,129,4,0,10]:
//                self = .secp256k1
//                
//            case [43,101,112]:
//                self = .Ed25519
//                
//            case [42,134,72,134,247,13,1,1,1]:
//                self = .rsaEncryption
//        
//            case [96,134,72,1,101,3,4,1,2]:
//                self = .aes_128_cbc
//                
//            case [42,134,72,134,247,13,1,5,12]:
//                self = .PBKDF2
//                
//            case [42,134,72,134,247,13,1,5,13]:
//                self = .PBES2
//                
//            default:
//                print("Found an unknown Obj ID: [\(data.map { "\($0)" }.joined(separator: ","))]")
//                self = .unknown(data)
//            }
//        }
//        
//        var keyType:KeyType? {
//            switch self {
//            case .secp256k1:
//                return .secp256K1
//            case .Ed25519:
//                return .ed25519
//            case .rsaEncryption:
//                return .rsa
//            default: //Generic EC Curves aren't supported yet...
//                return nil
//            }
//        }
//        
//        var description:String {
//            switch self {
//            case .prime256v1:     return "prime256v1"
//            case .secp384r1:      return "secp384r1"
//            case .secp521r1:      return "secp521r1"
//            case .id_ecPublicKey: return "id_ecPublicKey"
//            case .secp256k1:      return "secp256k1"
//            case .Ed25519:        return "Ed25519"
//            case .rsaEncryption:  return "rsaEncryption"
//            /// Encryption Tags and Ciphers....
//            case .PBES2:          return "PBES2"
//            case .PBKDF2:         return "PBKDF2"
//            case .aes_128_cbc:    return "aes_128_cbc"
//            case .unknown(let data):
//                return "Unknown Obj ID: [\(data.map { "\($0)" }.joined(separator: ","))]"
//            }
//        }
//    }
//    
//    /// An ASN1 node
//    enum Node {
//        case sequence(nodes: [Node])
//        case integer(data: Data)
//        case objectIdentifier(data: ObjectIdentifier)
//        case null
//        case bitString(data: Data)
//        case octetString(data: Data)
//    }
//    
//    enum ParserError: Error {
//        case noType
//        case invalidType(value: UInt8)
//    }
//    
//    /// Parses ASN1 data and returns its root node.
//    ///
//    /// - Parameter data: ASN1 data to parse
//    /// - Returns: Root ASN1 Node
//    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
//    static func parse(data: Data) throws -> Node {
//        let scanner = Scanner(data: data)
//        let node = try parseNode(scanner: scanner)
//        return node
//    }
//    
//    /// Parses an ASN1 given an existing scanne.
//    /// @warning: this will modify the state (ie: position) of the provided scanner.
//    ///
//    /// - Parameter scanner: Scanner to use to consume the data
//    /// - Returns: Parsed node
//    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
//    private static func parseNode(scanner: Scanner) throws -> Node {
//        
//        let firstByte = try scanner.consume(length: 1).firstByte
//                
//        // Sequence
//        if firstByte == 0x30 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            let nodes = try parseSequence(data: data)
//            return .sequence(nodes: nodes)
//        }
//        
//        // Integer
//        if firstByte == 0x02 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            return .integer(data: data)
//        }
//        
//        // Object identifier
//        if firstByte == 0x06 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            return .objectIdentifier(data: ObjectIdentifier(data: data))
//        }
//        
//        // Null
//        if firstByte == 0x05 {
//            _ = try scanner.consume(length: 1)
//            return .null
//        }
//        
//        // Bit String
//        if firstByte == 0x03 {
//            let length = try scanner.consumeLength()
//            
//            // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
//            // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
//            _ = try scanner.consume(length: 1)
//            
//            let data = try scanner.consume(length: length - 1)
//            return .bitString(data: data)
//        }
//        
//        // Octet String
//        if firstByte == 0x04 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            return .octetString(data: data)
//        }
//        
//        // EC Curves Cont 0 identifier (obj id)
//        if firstByte == 0xa0 {
//            let length = try scanner.consumeLength()
//            let data = try scanner.consume(length: length)
//            //print("Found an EC Curve Obj ID: [\(data.map { "\($0)" }.joined(separator: ","))]")
//            return .objectIdentifier(data: ObjectIdentifier(data: data))
//        }
//        
//        // EC Curves Cont 1 identifier (bit string)
//        if firstByte == 0xa1 {
//            let length = try scanner.consumeLength()
//            
//            // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
//            // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
//            _ = try scanner.consume(length: 1)
//            
//            let data = try scanner.consume(length: length - 1)
//            //print("Found an EC Curve Bit String: [\(data.map { "\($0)" }.joined(separator: ","))]")
//            return .bitString(data: data)
//        }
//        
//        print("Unknown byte: \([firstByte].asString(base: .base16))")
//        
//        throw ParserError.invalidType(value: firstByte)
//    }
//    
//    /// Parses an ASN1 sequence and returns its child nodes
//    ///
//    /// - Parameter data: ASN1 data
//    /// - Returns: A list of ASN1 nodes
//    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
//    private static func parseSequence(data: Data) throws -> [Node] {
//        let scanner = Scanner(data: data)
//        var nodes: [Node] = []
//        do {
//            while !scanner.isComplete {
//                let node = try parseNode(scanner: scanner)
//                nodes.append(node)
//            }
//        } catch {
//            return nodes
//        }
//        return nodes
//    }
//}
//
//extension LibP2PCrypto.Keys {
//    
//    // 256 objId -> 2a8648ce3d0301
//    // 384 objId -> 2a8648ce3d0201
//    // 521 objId -> 2a8648ce3d0201
//    public struct ASN1Parts {
//        let isPrivateKey:Bool
//        let keyBits:Data
//        let objectIdentifier:Data
//    }
//    
//    public static func parseASN1(pemData:Data) throws -> ASN1Parts {
//        let asn = try Asn1Parser.parse(data: pemData)
//        
//        var bitString:Data? = nil
//        var objId:Data? = nil
//        var isPrivate:Bool = false
//        if case .sequence(let nodes) = asn {
//            nodes.forEach {
//                switch $0 {
//                case .objectIdentifier(let data):
//                    if data.first == 0x2a {
//                        //print("Got our obj id: \(data.asString(base: .base64))")
//                        objId = data
//                    }
//                case .bitString(let data):
//                    //print("Got our bit string: \(data.asString(base: .base64))")
//                    bitString = data
//                case .sequence(let nodes):
//                    nodes.forEach { n in
//                        switch n {
//                        case .objectIdentifier(let data):
//                            if data.first == 0x2a {
//                                //print("Got our obj id: \(data.asString(base: .base64))")
//                                objId = data
//                            }
//                        case .bitString(let data):
//                            //print("Got our bit string: \(data.asString(base: .base64))")
//                            bitString = data
//                        case .octetString(let data):
//                            //Private Keys trigger
//                            bitString = data
//                            isPrivate = true
//                        default:
//                            return
//                        }
//                    }
//                case .octetString(let data):
//                    //Private Keys trigger
//                    bitString = data
//                    isPrivate = true
//                default:
//                    return
//                }
//            }
//        }
//        
//        guard let id = objId, let bits = bitString else {
//            throw NSError(domain: "Unsupported asn1 format", code: 0, userInfo: nil)
//        }
//        
//        return ASN1Parts(isPrivateKey: isPrivate, keyBits: bits, objectIdentifier: id)
//           
//    }
//    
//    public static func parseASN1ECPrivate(pemData:Data) throws -> Data {
//        let asn = try Asn1ParserECPrivate.parse(data: pemData)
//        
//        var octetString:Data? = nil
//        if case .sequence(let nodes) = asn {
//            nodes.forEach {
//                switch $0 {
//                case .sequence(let nodes):
//                    nodes.forEach { n in
//                        switch n {
//                        case .octetString(let data):
//                            octetString = data
//                        default:
//                            return
//                        }
//                    }
//                case .octetString(let data):
//                    octetString = data
//                default:
//                    return
//                }
//            }
//        } else if case .octetString(let data) = asn {
//            octetString = data
//        }
//        
//        guard let bits = octetString else {
//            throw NSError(domain: "Unsupported asn1 format", code: 0, userInfo: nil)
//        }
//        
//        return bits
//    }
//    
//    /// This method strips the x509 header from a provided ASN.1 DER key.
//    /// If the key doesn't contain a header, the DER data is returned as is.
//    ///
//    /// Supported formats are:
//    ///
//    /// Headerless:
//    /// SEQUENCE
//    ///    INTEGER (1024 or 2048 bit) -- modulo
//    ///    INTEGER -- public exponent
//    ///
//    /// With x509 header:
//    /// SEQUENCE
//    ///    SEQUENCE
//    ///    OBJECT IDENTIFIER 1.2.840.113549.1.1.1
//    ///    NULL
//    ///    BIT STRING
//    ///    SEQUENCE
//    ///    INTEGER (1024 or 2048 bit) -- modulo
//    ///    INTEGER -- public exponent
//    ///
//    /// Example of headerless key:
//    ///https://lapo.it/asn1js/#3082010A0282010100C1A0DFA367FBC2A5FD6ED5A071E02A4B0617E19C6B5AD11BB61192E78D212F10A7620084A3CED660894134D4E475BAD7786FA1D40878683FD1B7A1AD9C0542B7A666457A270159DAC40CE25B2EAE7CCD807D31AE725CA394F90FBB5C5BA500545B99C545A9FE08EFF00A5F23457633E1DB84ED5E908EF748A90F8DFCCAFF319CB0334705EA012AF15AA090D17A9330159C9AFC9275C610BB9B7C61317876DC7386C723885C100F774C19830F475AD1E9A9925F9CA9A69CE0181A214DF2EB75FD13E6A546B8C8ED699E33A8521242B7E42711066AEC22D25DD45D56F94D3170D6F2C25164D2DACED31C73963BA885ADCB706F40866B8266433ED5161DC50E4B3B0203010001
//    ///
//    /// Example of key with X509 header (notice the additional ASN.1 sequence):
//    ///https://lapo.it/asn1js/#30819F300D06092A864886F70D010101050003818D0030818902818100D0674615A252ED3D75D2A3073A0A8A445F3188FD3BEB8BA8584F7299E391BDEC3427F287327414174997D147DD8CA62647427D73C9DA5504E0A3EED5274A1D50A1237D688486FADB8B82061675ABFA5E55B624095DB8790C6DBCAE83D6A8588C9A6635D7CF257ED1EDE18F04217D37908FD0CBB86B2C58D5F762E6207FF7B92D0203010001
//   public static func stripX509HeaderFromDER(keyData: Data) throws -> Data {
//       
//       let node: Asn1Parser.Node
//       do {
//           node = try Asn1Parser.parse(data: keyData)
//       } catch {
//           throw NSError(domain: "asn1ParsingFailed", code: 0, userInfo: nil)
//       }
//       
//       // Ensure the raw data is an ASN1 sequence
//       guard case .sequence(let nodes) = node else {
//           throw NSError(domain: "invalidAsn1RootNode", code: 0, userInfo: nil)
//       }
//       
//       // Detect whether the sequence only has integers, in which case it's a headerless key
//       let onlyHasIntegers = nodes.filter { node -> Bool in
//           if case .integer = node {
//               return false
//           }
//           return true
//       }.isEmpty
//       
//       // Headerless key
//       if onlyHasIntegers {
//           return keyData
//       }
//       
//       // If last element of the sequence is a bit string, return its data
//       if let last = nodes.last, case .bitString(let data) = last {
//           return data
//       }
//       
//       // If last element of the sequence is an octet string, return its data
//       if let last = nodes.last, case .octetString(let data) = last {
//           return data
//       }
//       
//       // Unable to extract bit/octet string or raw integer sequence
//       throw NSError(domain: "invalidAsn1Structure", code: 0, userInfo: nil)
//   }
//}
//
//enum ASN1Encoder {
//    private static func asn1LengthPrefix(_ bytes:[UInt8]) -> [UInt8] {
//        if bytes.count >= 0x80 {
//            var lengthAsBytes = withUnsafeBytes(of: bytes.count.bigEndian, Array<UInt8>.init)
//            while lengthAsBytes.first == 0 { lengthAsBytes.removeFirst() }
//            return [(0x80 + UInt8(lengthAsBytes.count))] + lengthAsBytes
//        } else {
//            return [UInt8(bytes.count)]
//        }
//    }
//    
//    private static func asn1LengthPrefixed(_ bytes:[UInt8]) -> [UInt8] {
//        asn1LengthPrefix(bytes) + bytes
//    }
//    
//    public static func encode(_ node:Asn1Parser.Node) -> [UInt8] {
//        switch node {
//        case .integer(let integer):
//            return [0x02] + asn1LengthPrefixed(integer.bytes)
//        case .bitString(let bits):
//            return [0x03] + asn1LengthPrefixed([0x00] + bits.bytes)
//        case .octetString(let octet):
//            return [0x04] + asn1LengthPrefixed(octet.bytes)
//        case .null:
//            return [0x05, 0x00]
//        case .objectIdentifier(let oid):
//            return [0x06] + asn1LengthPrefixed(oid.bytes)
//        case .sequence(let nodes):
//            return [0x30] + asn1LengthPrefixed( nodes.reduce(into: Array<UInt8>(), { partialResult, node in
//                partialResult += encode(node)
//            }) )
//        }
//    }
//}
//
//fileprivate func printNode(_ node:Asn1Parser.Node, level:Int) -> String {
//    var str:[String] = []
//    let prefix = String(repeating: "\t", count: level)
//    switch node {
//    case .integer(let int):
//        str.append("\(prefix)Integer: \(int.asString(base: .base16))")
//    case .bitString(let bs):
//        str.append("\(prefix)BitString: \(bs.asString(base: .base16))")
//    case .null:
//        str.append("\(prefix)NULL")
//    case .objectIdentifier(let oid):
//        str.append("\(prefix)ObjectID: \(oid.asString(base: .base16))")
//    case .octetString(let os):
//        str.append("\(prefix)OctetString: \(os.asString(base: .base16))")
//    case .sequence(let nodes):
//        nodes.forEach { str.append(printNode($0, level: level + 1)) }
//    }
//    return str.joined(separator: "\n")
//}
