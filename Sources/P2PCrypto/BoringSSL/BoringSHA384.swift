// BoringSHA384.swift
// SHA-384 over BoringSSL SHA384_Init/Update/Final (uses SHA512_CTX).
// crypto-impl.md §2.2.
import P2PCoreCrypto
import CP2PBoringSSL

/// SHA-384. Conforms `P2PCoreCrypto.HashFunction`.
public struct BoringSHA384: HashFunction {
    public static let digestLength = 48
    public static let blockLength  = 128

    private var ctx = SHA512_CTX()

    public init() {
        _ = CP2PBoringSSL_SHA384_Init(&ctx)
    }

    public mutating func update(_ data: Span<UInt8>) {
        let bytes = data.toArray()
        bytes.withUnsafeBufferPointer { bp in
            _ = CP2PBoringSSL_SHA384_Update(&ctx, bp.baseAddress, bp.count)
        }
    }

    public consuming func finalize() -> [UInt8] {
        var out = [UInt8](repeating: 0, count: Self.digestLength)
        out.withUnsafeMutableBufferPointer { op in
            _ = CP2PBoringSSL_SHA384_Final(op.baseAddress, &ctx)
        }
        return out
    }
}
