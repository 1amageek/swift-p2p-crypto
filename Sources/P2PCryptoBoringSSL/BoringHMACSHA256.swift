// BoringHMACSHA256.swift
// HMAC-SHA256 (QUIC/TLS/Noise). crypto-impl.md §2.4.
import P2PCoreCrypto

/// HMAC-SHA256. Conforms `P2PCoreCrypto.MessageAuthenticationCode`.
public struct BoringHMACSHA256: MessageAuthenticationCode {
    public static let macLength = 32

    private let key: [UInt8]
    private var buffer: [UInt8]

    public init(key: Span<UInt8>) {
        self.key = key.toArray()
        self.buffer = []
    }

    public mutating func update(_ data: Span<UInt8>) {
        buffer.append(contentsOf: data.toArray())
    }

    public consuming func finalize() -> [UInt8] {
        BoringHMACCore.authenticate(.sha256, key: key, message: buffer)
    }

    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        BoringHMACCore.authenticate(.sha256, key: key.toArray(), message: message.toArray())
    }

    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        let expected = authenticationCode(for: message, key: key)
        return ConstantTime.equal(mac.toArray(), expected)
    }
}
