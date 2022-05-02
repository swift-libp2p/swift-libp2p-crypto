//
//  Asn1Parser.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/9/17.
//  Copyright © 2017 Scoop. All rights reserved.
//  Modified by Brandon Toms on 5/1/22
//

import Foundation
import Multibase

/// Object Identifiers
/// [6,8,42,134,72,206,61,3,1,7]  -> EC Curve 256   ':prime256v1'
/// [6,5,43,129,4,0,34]           -> EC Curve 384   'secp384r1'
/// [6,5,43,129,4,0,35]           -> EC Curve 521   ':secp521r1'
/// [42,134,72,206,61,2,1]        -> EC Pub         ':id-ecPublicKey'
/// [42,134,72,206,61,3,1,7]      -> EC Pub 256     ':prime256v1'
/// [43,129,4,0,34]               -> EC Pub 384     ':secp384r1'
/// [43,129,4,0,35]               -> EC Pub 521     ':secp521r1'
/// [6,5,43,129,4,0,10]           -> EC Secp256k1 Private

/// Simple data scanner that consumes bytes from a raw data and keeps an updated position.
private class Scanner {
    
    enum ScannerError: Error {
        case outOfBounds
    }
    
    let data: Data
    var index: Int = 0
    
    /// Returns whether there is no more data to consume
    var isComplete: Bool {
        return index >= data.count
    }
    
    /// Creates a scanner with provided data
    ///
    /// - Parameter data: Data to consume
    init(data: Data) {
        self.data = data
    }
    
    /// Consumes data of provided length and returns it
    ///
    /// - Parameter length: length of the data to consume
    /// - Returns: data consumed
    /// - Throws: ScannerError.outOfBounds error if asked to consume too many bytes
    func consume(length: Int) throws -> Data {
        
        guard length > 0 else {
            return Data()
        }
        
        guard index + length <= data.count else {
            throw ScannerError.outOfBounds
        }
        
        let subdata = data.subdata(in: index..<index + length)
        index += length
        return subdata
    }
    
    /// Consumes a primitive, definite ASN1 length and returns its value.
    ///
    /// See http://luca.ntop.org/Teaching/Appunti/asn1.html,
    ///
    /// - Short form. One octet. Bit 8 has value "0" and bits 7-1 give the length.
    /// - Long form. Two to 127 octets. Bit 8 of first octet has value "1" and
    ///   bits 7-1 give the number of additional length octets.
    ///   Second and following octets give the length, base 256, most significant digit first.
    ///
    /// - Returns: Length that was consumed
    /// - Throws: ScannerError.outOfBounds error if asked to consume too many bytes
    func consumeLength() throws -> Int {
        
        let lengthByte = try consume(length: 1).firstByte
        
        // If the first byte's value is less than 0x80, it directly contains the length
        // so we can return it
        guard lengthByte >= 0x80 else {
            return Int(lengthByte)
        }
        
        // If the first byte's value is more than 0x80, it indicates how many following bytes
        // will describe the length. For instance, 0x85 indicates that 0x85 - 0x80 = 0x05 = 5
        // bytes will describe the length, so we need to read the 5 next bytes and get their integer
        // value to determine the length.
        let nextByteCount = lengthByte - 0x80
        let length = try consume(length: Int(nextByteCount))
        
        return length.integer
    }
}

private extension Data {
    
    /// Returns the first byte of the current data
    var firstByte: UInt8 {
        var byte: UInt8 = 0
        copyBytes(to: &byte, count: MemoryLayout<UInt8>.size)
        return byte
    }
    
    /// Returns the integer value of the current data.
    /// @warning: this only supports data up to 4 bytes, as we can only extract 32-bit integers.
    var integer: Int {
        
        guard count > 0 else {
            return 0
        }
        
        var int: UInt32 = 0
        var offset: Int32 = Int32(count - 1)
        forEach { byte in
            let byte32 = UInt32(byte)
            let shifted = byte32 << (UInt32(offset) * 8)
            int = int | shifted
            offset -= 1
        }
        
        return Int(int)
    }
}

/// A simple ASN1 parser that will recursively iterate over a root node and return a Node tree.
/// The root node can be any of the supported nodes described in `Node`. If the parser encounters a sequence
/// it will recursively parse its children.
enum Asn1Parser {
    
    /// An ASN1 node
    enum Node {
        case sequence(nodes: [Node])
        case integer(data: Data)
        case objectIdentifier(data: Data)
        case null
        case bitString(data: Data)
        case octetString(data: Data)
    }
    
    enum ParserError: Error {
        case noType
        case invalidType(value: UInt8)
    }
    
    /// Parses ASN1 data and returns its root node.
    ///
    /// - Parameter data: ASN1 data to parse
    /// - Returns: Root ASN1 Node
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    static func parse(data: Data) throws -> Node {
        let scanner = Scanner(data: data)
        let node = try parseNode(scanner: scanner)
        return node
    }
    
    /// Parses an ASN1 given an existing scanne.
    /// @warning: this will modify the state (ie: position) of the provided scanner.
    ///
    /// - Parameter scanner: Scanner to use to consume the data
    /// - Returns: Parsed node
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    private static func parseNode(scanner: Scanner) throws -> Node {
        
        let firstByte = try scanner.consume(length: 1).firstByte
        
//        print([firstByte].asString(base: .base16))
        
        // Sequence
        if firstByte == 0x30 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            let nodes = try parseSequence(data: data)
            return .sequence(nodes: nodes)
        }
        
        // Integer
        if firstByte == 0x02 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            print(Int(data.asString(base: .base16), radix: 16) ?? -1)
            return .integer(data: data)
        }
        
        // Object identifier
        if firstByte == 0x06 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            //print(String(data: data, encoding: .ascii))
            print("Object ID: [\(data.map { "\($0)" }.joined(separator: ","))]")
            return .objectIdentifier(data: data)
        }
        
        // Null
        if firstByte == 0x05 {
            _ = try scanner.consume(length: 1)
            return .null
        }
        
        // Bit String
        if firstByte == 0x03 {
            let length = try scanner.consumeLength()
            
            // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
            // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
            _ = try scanner.consume(length: 1)
            
            let data = try scanner.consume(length: length - 1)
            return .bitString(data: data)
        }
        
        // Octet String
        if firstByte == 0x04 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
//            print(data.asString(base: .base64))
//            print()
//            print(data.bytes)
//            print()
            return .octetString(data: data)
        }
        
        throw ParserError.invalidType(value: firstByte)
    }
    
    /// Parses an ASN1 sequence and returns its child nodes
    ///
    /// - Parameter data: ASN1 data
    /// - Returns: A list of ASN1 nodes
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    private static func parseSequence(data: Data) throws -> [Node] {
        let scanner = Scanner(data: data)
        var nodes: [Node] = []
        while !scanner.isComplete {
            let node = try parseNode(scanner: scanner)
            nodes.append(node)
        }
        return nodes
    }
}


private let Mappings:[Array<UInt8>:String] = [
    [6,8,42,134,72,206,61,3,1,7]: "prime256v1",
    [6,5,43,129,4,0,34]:          "secp384r1",
    [6,5,43,129,4,0,35]:          "secp521r1",
    [42,134,72,206,61,2,1]:       "id-ecPublicKey",
    [42,134,72,206,61,3,1,7]:     "prime256v1",
    [43,129,4,0,34]:              "secp384r1",
    [43,129,4,0,35]:              "secp521r1",
    [6,5,43,129,4,0,10]:          "secp256k1",
    [43,101,112]:                 "Ed25519",
    [42,134,72,134,247,13,1,1,1]: "rsaEncryption"
]

/// A simple ASN1 parser that will recursively iterate over a root node and return a Node tree.
/// The root node can be any of the supported nodes described in `Node`. If the parser encounters a sequence
/// it will recursively parse its children.
enum Asn1ParserECPrivate {
    
    enum ObjectIdentifier:CustomStringConvertible {
        case prime256v1
        case secp384r1
        case secp521r1
        case id_ecPublicKey
        case secp256k1
        case Ed25519
        case rsaEncryption
        /// Encryption Tags and Ciphers
        case aes_128_cbc // The cipher used to encrypt an encrypted key // des_ede3_cbc
        case PBKDF2 //An Encrypted PEM Key that uses PBKDF2 to derive a the AES key
        case PBES2 //An Encrypted PEM Key
        case unknown(Data)
        
        init(data:Data) {
            /// Often times Object Identifiers in private keys begin with an additional 6,5 or 6,8.
            /// If the objID has this prefix, we drop the first two bytes before attempting to classify...
            let d = data.first == 6 ? data.dropFirst(2) : data
            switch d.bytes {
            case [42,134,72,206,61,2,1]:
                self = .id_ecPublicKey
                
            case [42,134,72,206,61,3,1,7]:
                self = .prime256v1
                
            case [43,129,4,0,34]:
                self = .secp384r1
                
            case [43,129,4,0,35]:
                self = .secp521r1
                
            case [43,129,4,0,10]:
                self = .secp256k1
                
            case [43,101,112]:
                self = .Ed25519
                
            case [42,134,72,134,247,13,1,1,1]:
                self = .rsaEncryption
        
            case [96,134,72,1,101,3,4,1,2]:
                self = .aes_128_cbc
                
            case [42,134,72,134,247,13,1,5,12]:
                self = .PBKDF2
                
            case [42,134,72,134,247,13,1,5,13]:
                self = .PBES2
                
            default:
                print("Found an unknown Obj ID: [\(data.map { "\($0)" }.joined(separator: ","))]")
                self = .unknown(data)
            }
        }
        
        var keyType:KeyType? {
            switch self {
            case .secp256k1:
                return .secp256K1
            case .Ed25519:
                return .ed25519
            case .rsaEncryption:
                return .rsa
            default: //Generic EC Curves aren't supported yet...
                return nil
            }
        }
        
        var description:String {
            switch self {
            case .prime256v1:     return "prime256v1"
            case .secp384r1:      return "secp384r1"
            case .secp521r1:      return "secp521r1"
            case .id_ecPublicKey: return "id_ecPublicKey"
            case .secp256k1:      return "secp256k1"
            case .Ed25519:        return "Ed25519"
            case .rsaEncryption:  return "rsaEncryption"
            /// Encryption Tags and Ciphers....
            case .PBES2:          return "PBES2"
            case .PBKDF2:         return "PBKDF2"
            case .aes_128_cbc:    return "aes_128_cbc"
            case .unknown(let data):
                return "Unknown Obj ID: [\(data.map { "\($0)" }.joined(separator: ","))]"
            }
        }
    }
    
    /// An ASN1 node
    enum Node {
        case sequence(nodes: [Node])
        case integer(data: Data)
        case objectIdentifier(data: ObjectIdentifier)
        case null
        case bitString(data: Data)
        case octetString(data: Data)
    }
    
    enum ParserError: Error {
        case noType
        case invalidType(value: UInt8)
    }
    
    /// Parses ASN1 data and returns its root node.
    ///
    /// - Parameter data: ASN1 data to parse
    /// - Returns: Root ASN1 Node
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    static func parse(data: Data) throws -> Node {
        let scanner = Scanner(data: data)
        let node = try parseNode(scanner: scanner)
        return node
    }
    
    /// Parses an ASN1 given an existing scanne.
    /// @warning: this will modify the state (ie: position) of the provided scanner.
    ///
    /// - Parameter scanner: Scanner to use to consume the data
    /// - Returns: Parsed node
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    private static func parseNode(scanner: Scanner) throws -> Node {
        
        let firstByte = try scanner.consume(length: 1).firstByte
                
        // Sequence
        if firstByte == 0x30 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            let nodes = try parseSequence(data: data)
            return .sequence(nodes: nodes)
        }
        
        // Integer
        if firstByte == 0x02 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            return .integer(data: data)
        }
        
        // Object identifier
        if firstByte == 0x06 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            return .objectIdentifier(data: ObjectIdentifier(data: data))
        }
        
        // Null
        if firstByte == 0x05 {
            _ = try scanner.consume(length: 1)
            return .null
        }
        
        // Bit String
        if firstByte == 0x03 {
            let length = try scanner.consumeLength()
            
            // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
            // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
            _ = try scanner.consume(length: 1)
            
            let data = try scanner.consume(length: length - 1)
            return .bitString(data: data)
        }
        
        // Octet String
        if firstByte == 0x04 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            return .octetString(data: data)
        }
        
        // EC Curves Cont 0 identifier (obj id)
        if firstByte == 0xa0 {
            let length = try scanner.consumeLength()
            let data = try scanner.consume(length: length)
            //print("Found an EC Curve Obj ID: [\(data.map { "\($0)" }.joined(separator: ","))]")
            return .objectIdentifier(data: ObjectIdentifier(data: data))
        }
        
        // EC Curves Cont 1 identifier (bit string)
        if firstByte == 0xa1 {
            let length = try scanner.consumeLength()
            
            // There's an extra byte (0x00) after the bit string length in all the keys I've encountered.
            // I couldn't find a specification that referenced this extra byte, but let's consume it and discard it.
            _ = try scanner.consume(length: 1)
            
            let data = try scanner.consume(length: length - 1)
            print("Found an EC Curve Bit String: [\(data.map { "\($0)" }.joined(separator: ","))]")
            return .bitString(data: data)
        }
        
        print("Unknown byte: \([firstByte].asString(base: .base16))")
        
        throw ParserError.invalidType(value: firstByte)
    }
    
    /// Parses an ASN1 sequence and returns its child nodes
    ///
    /// - Parameter data: ASN1 data
    /// - Returns: A list of ASN1 nodes
    /// - Throws: A ParserError if anything goes wrong, or if an unknown node was encountered
    private static func parseSequence(data: Data) throws -> [Node] {
        let scanner = Scanner(data: data)
        var nodes: [Node] = []
        do {
            while !scanner.isComplete {
                let node = try parseNode(scanner: scanner)
                nodes.append(node)
            }
        } catch {
            return nodes
        }
        return nodes
    }
}
