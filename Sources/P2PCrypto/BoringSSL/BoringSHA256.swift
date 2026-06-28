// BoringSHA256.swift
// SHA-256 over BoringSSL SHA256_Init/Update/Final (crypto-impl.md §2.2).
// Value type holding the C context; `finalize()` is consuming (single-use state).
import P2PCoreCrypto
import CP2PBoringSSL

/// SHA-256. Conforms `P2PCoreCrypto.HashFunction`.
public struct BoringSHA256: HashFunction {
    public static let digestLength = 32
    public static let blockLength  = 64

    private var ctx = SHA256_CTX()

    public init() {
        _ = CP2PBoringSSL_SHA256_Init(&ctx)
    }

    public mutating func update(_ data: Span<UInt8>) {
        let bytes = data.toArray()
        bytes.withUnsafeBufferPointer { bp in
            _ = CP2PBoringSSL_SHA256_Update(&ctx, bp.baseAddress, bp.count)
        }
    }

    public consuming func finalize() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: Self.digestLength)
        out.withUnsafeMutableBufferPointer { op in
            _ = CP2PBoringSSL_SHA256_Final(op.baseAddress, &ctx)
        }
        return out
    }
}
