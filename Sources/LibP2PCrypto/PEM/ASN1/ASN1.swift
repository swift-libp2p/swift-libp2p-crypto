//
//  Original Asn1Parser.swift from SwiftyRSA
//
//  Created by Lois Di Qual on 5/9/17.
//  Copyright © 2017 Scoop. All rights reserved.
//
//  Modified by Brandon Toms on 5/1/22
//

import Foundation

enum ASN1 {
  internal enum IDENTIFIERS:UInt8, Equatable {
    case SEQUENCE    = 0x30
    case INTERGER    = 0x02
    case OBJECTID    = 0x06
    case NULL        = 0x05
    case BITSTRING   = 0x03
    case OCTETSTRING = 0x04
    case EC_OBJECT   = 0xA0
    case EC_BITS     = 0xA1
      
    static func == (lhs:UInt8, rhs:IDENTIFIERS) -> Bool {
      lhs == rhs.rawValue
    }
    
    var bytes:[UInt8] {
      switch self {
      case .NULL:
        return [self.rawValue, 0x00]
      default:
        return [self.rawValue]
      }
    }
  }
  
  /// An ASN1 node
  enum Node:CustomStringConvertible {
    case sequence(nodes: [Node])
    case integer(data: Data)
    case objectIdentifier(data: Data)
    case null
    case bitString(data: Data)
    case octetString(data: Data)
    case ecObject(data: Data)
    case ecBits(data: Data)
      
    var description: String {
      ASN1.printNode(self, level: 0)
    }
    
  }
    
  internal static func printNode(_ node:ASN1.Node, level:Int) -> String {
    var str:[String] = []
    let prefix = String(repeating: "\t", count: level)
    switch node {
    case .integer(let int):
      str.append("\(prefix)Integer: \(int.toHexString())")
    case .bitString(let bs):
      str.append("\(prefix)BitString: \(bs.toHexString())")
    case .null:
      str.append("\(prefix)NULL")
    case .objectIdentifier(let oid):
      str.append("\(prefix)ObjectID: \(oid.toHexString())")
    case .octetString(let os):
      str.append("\(prefix)OctetString: \(os.toHexString())")
    case .ecObject(let ecObj):
      str.append("\(prefix)EC Object: \(ecObj.toHexString())")
    case .ecBits(let ecBits):
      str.append("\(prefix)EC Bits: \(ecBits.toHexString())")
    case .sequence(let nodes):
      str.append("\(prefix)Sequence:")
      nodes.forEach { str.append(printNode($0, level: level + 1)) }
    }
    return str.joined(separator: "\n")
  }
}



