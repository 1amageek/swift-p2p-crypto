// FoundationEssentialsSHA256.swift
// SHA-256 over swift-crypto. crypto-impl.md §4.
import P2PCoreCrypto
import Crypto

/// SHA-256. Conforms `P2PCoreCrypto.HashFunction`.
public struct FoundationEssentialsSHA256: P2PCoreCrypto.HashFunction {
    public static let digestLength = 32
    public static let blockLength  = 64

    private var hasher = Crypto.SHA256()

    public init() {}

    public mutating func update(_ data: Span<UInt8>) {
        hasher.update(data: data.toArray())
    }

    public consuming func finalize() -> [UInt8] {
        [UInt8](hasher.finalize())
    }
}
