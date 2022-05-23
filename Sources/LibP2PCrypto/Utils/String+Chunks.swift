//
//  File.swift
//  
//
//  Created by Brandon Toms on 5/23/22.
//

import Foundation

public extension String {
    func split(intoChunksOfLength length: Int) -> [String] {
        return stride(from: 0, to: self.count, by: length).map { index -> String in
            let startIndex = self.index(self.startIndex, offsetBy: index)
            let endIndex = self.index(startIndex, offsetBy: length, limitedBy: self.endIndex) ?? self.endIndex
            return String(self[startIndex..<endIndex])
        }
    }
}
