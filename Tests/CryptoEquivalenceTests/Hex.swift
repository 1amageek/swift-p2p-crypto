// Hex.swift
// Test-only hex helpers.
import Foundation

enum Hex {
    static func decode(_ string: String) -> [UInt8] {
        let chars = Array(string.filter { !$0.isWhitespace })
        precondition(chars.count % 2 == 0, "hex string must have even length")
        var out = [UInt8]()
        out.reserveCapacity(chars.count / 2)
        var index = 0
        while index < chars.count {
            out.append(UInt8(nibble(chars[index]) << 4 | nibble(chars[index + 1])))
            index += 2
        }
        return out
    }

    private static func nibble(_ c: Character) -> Int {
        switch c {
        case "0"..."9": return Int(c.asciiValue! - Character("0").asciiValue!)
        case "a"..."f": return Int(c.asciiValue! - Character("a").asciiValue! + 10)
        case "A"..."F": return Int(c.asciiValue! - Character("A").asciiValue! + 10)
        default: preconditionFailure("invalid hex char \(c)")
        }
    }
}
