// FoundationHMACSHA256.swift
// HMAC-SHA256 over swift-crypto. crypto-impl.md §4.
import P2PCoreCrypto
import Foundation
import Crypto

/// HMAC-SHA256. Conforms `P2PCoreCrypto.MessageAuthenticationCode`.
public struct FoundationHMACSHA256: P2PCoreCrypto.MessageAuthenticationCode {
    public static let macLength = 32

    private var hasher: HMAC<Crypto.SHA256>

    public init(key: Span<UInt8>) {
        self.hasher = HMAC<Crypto.SHA256>(key: SymmetricKey(data: key.toData()))
    }

    public mutating func update(_ data: Span<UInt8>) {
        hasher.update(data: data.toArray())
    }

    public consuming func finalize() -> [UInt8] {
        let code = hasher.finalize()
        return code.withUnsafeBytes { Array($0) }
    }

    public static func authenticationCode(for message: Span<UInt8>, key: Span<UInt8>) -> [UInt8] {
        let code = HMAC<Crypto.SHA256>.authenticationCode(
            for: message.toArray(), using: SymmetricKey(data: key.toData()))
        return code.withUnsafeBytes { Array($0) }
    }

    public static func isValid(_ mac: Span<UInt8>, for message: Span<UInt8>, key: Span<UInt8>) -> Bool {
        HMAC<Crypto.SHA256>.isValidAuthenticationCode(
            mac.toData(), authenticating: message.toArray(), using: SymmetricKey(data: key.toData()))
    }
}
