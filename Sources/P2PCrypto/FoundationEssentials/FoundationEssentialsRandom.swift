// FoundationEssentialsRandom.swift
// CSPRNG over SystemRandomNumberGenerator (the current stack idiom). crypto-impl.md §4.
import P2PCoreCrypto

/// CSPRNG. Conforms `P2PCoreCrypto.RandomSource`.
public struct FoundationEssentialsRandom: RandomSource {
    public init() {}

    public func randomBytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        var out = [UInt8]()
        out.reserveCapacity(count)
        for _ in 0..<count {
            out.append(generator.next())
        }
        return out
    }

    public func fill(_ buffer: inout [UInt8]) {
        var generator = SystemRandomNumberGenerator()
        for index in 0..<buffer.count {
            buffer[index] = generator.next()
        }
    }
}
