// BoringRandom.swift
// CSPRNG over BoringSSL RAND_bytes (crypto-impl.md §2.9). Replaces the host
// provider's SystemRandomNumberGenerator / SymmetricKey(size:) idiom.
import P2PCoreCrypto
import CP2PBoringSSL

/// CSPRNG. Conforms `P2PCoreCrypto.RandomSource`.
public struct BoringRandom: RandomSource {
    public init() {}

    public func randomBytes(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        if count > 0 {
            out.withUnsafeMutableBufferPointer { op in
                // RAND_bytes returns 1 on success, 0 on failure. A CSPRNG failure is
                // unrecoverable — returning the zero-initialized buffer would hand out
                // predictable bytes for keys / serials (a silent fallback). Fail closed.
                let rc = CP2PBoringSSL_RAND_bytes(op.baseAddress, op.count)
                precondition(rc == 1, "BoringSSL RAND_bytes failed; refusing to return non-random bytes")
            }
        }
        return out
    }

    public func fill(_ buffer: inout [UInt8]) {
        if buffer.isEmpty { return }
        buffer.withUnsafeMutableBufferPointer { bp in
            let rc = CP2PBoringSSL_RAND_bytes(bp.baseAddress, bp.count)
            precondition(rc == 1, "BoringSSL RAND_bytes failed; refusing to return non-random bytes")
        }
    }
}
