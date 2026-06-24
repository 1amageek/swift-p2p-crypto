// BoringRandom.swift
// CSPRNG over BoringSSL RAND_bytes (crypto-impl.md §2.9). Replaces Foundation's
// SystemRandomNumberGenerator / SymmetricKey(size:) idiom.
import P2PCoreCrypto
import CP2PBoringSSL

/// CSPRNG. Conforms `P2PCoreCrypto.RandomSource`.
public struct BoringRandom: RandomSource {
    public init() {}

    public func randomBytes(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        if count > 0 {
            out.withUnsafeMutableBufferPointer { op in
                _ = CP2PBoringSSL_RAND_bytes(op.baseAddress, op.count)
            }
        }
        return out
    }

    public func fill(_ buffer: inout [UInt8]) {
        if buffer.isEmpty { return }
        buffer.withUnsafeMutableBufferPointer { bp in
            _ = CP2PBoringSSL_RAND_bytes(bp.baseAddress, bp.count)
        }
    }
}
