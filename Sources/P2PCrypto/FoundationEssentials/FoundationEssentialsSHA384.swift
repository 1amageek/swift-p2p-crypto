// FoundationEssentialsSHA384.swift
// SHA-384 over swift-crypto. crypto-impl.md §4.
import P2PCoreCrypto
import Crypto

/// SHA-384. Conforms `P2PCoreCrypto.HashFunction`.
public struct FoundationEssentialsSHA384: P2PCoreCrypto.HashFunction {
    public static let digestLength = 48
    public static let blockLength  = 128

    private var hasher = Crypto.SHA384()

    public init() {}

    public mutating func update(_ data: Span<UInt8>) {
        hasher.update(data: data.toArray())
    }

    public consuming func finalize() -> [UInt8] {
        [UInt8](hasher.finalize())
    }
}
