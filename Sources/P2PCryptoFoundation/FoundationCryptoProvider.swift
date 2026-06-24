// FoundationCryptoProvider.swift
// The host (non-Embedded) CryptoProvider conformance over swift-crypto /
// CryptoKit (+ CommonCrypto for AES header protection). crypto-impl.md §4.
// Byte-identical to the current swift-quic/swift-tls/swift-libp2p crypto
// behavior; the reference for CryptoEquivalenceTests.
import P2PCoreCrypto

/// Aggregates the swift-crypto–backed primitives behind
/// `P2PCoreCrypto.CryptoProvider` for the host build.
public enum FoundationCryptoProvider: CryptoProvider {
    // AEAD
    public typealias AESGCM128  = FoundationAEAD
    public typealias AESGCM256  = FoundationAEAD
    public typealias ChaChaPoly = FoundationAEAD

    // Hashes
    public typealias SHA256 = FoundationSHA256
    public typealias SHA384 = FoundationSHA384

    // Key derivation
    public typealias HKDFSHA256 = FoundationHKDFSHA256
    public typealias HKDFSHA384 = FoundationHKDFSHA384

    // Message authentication
    public typealias HMACSHA1   = FoundationHMACSHA1
    public typealias HMACSHA256 = FoundationHMACSHA256
    public typealias HMACSHA384 = FoundationHMACSHA384

    // Key agreement
    public typealias X25519        = FoundationX25519
    public typealias P256Agreement = FoundationP256Agreement
    public typealias P384Agreement = FoundationP384Agreement

    // Signatures
    public typealias Ed25519       = FoundationEd25519
    public typealias P256Signature = FoundationP256Signature
    public typealias P384Signature = FoundationP384Signature

    // Ambient capabilities
    public typealias Random          = FoundationRandom
    public typealias Clock           = FoundationMonotonicClock
    public typealias HeaderProtection = FoundationHeaderProtection

    // AEAD factories
    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> FoundationAEAD {
        try FoundationAEAD(algorithm: .aes128gcm, key: key)
    }

    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> FoundationAEAD {
        try FoundationAEAD(algorithm: .aes256gcm, key: key)
    }

    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> FoundationAEAD {
        try FoundationAEAD(algorithm: .chacha20poly1305, key: key)
    }

    // Ambient singletons
    public static let random = FoundationRandom()
    public static let clock  = FoundationMonotonicClock()
}
