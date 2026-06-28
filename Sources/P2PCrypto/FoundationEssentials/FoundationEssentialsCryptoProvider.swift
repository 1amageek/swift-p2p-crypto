// FoundationEssentialsCryptoProvider.swift
// The host (non-Embedded) CryptoProvider conformance over swift-crypto /
// CryptoKit (+ CommonCrypto for AES header protection). crypto-impl.md §4.
// Byte-identical to the current swift-quic/swift-tls/swift-libp2p crypto
// behavior; the reference for CryptoEquivalenceTests.
import P2PCoreCrypto

/// Aggregates the swift-crypto–backed primitives behind
/// `P2PCoreCrypto.CryptoProvider` for the host build.
public enum FoundationEssentialsCryptoProvider: CryptoProvider {
    // AEAD
    public typealias AESGCM128  = FoundationEssentialsAEAD
    public typealias AESGCM256  = FoundationEssentialsAEAD
    public typealias ChaChaPoly = FoundationEssentialsAEAD

    // Hashes
    public typealias SHA256 = FoundationEssentialsSHA256
    public typealias SHA384 = FoundationEssentialsSHA384

    // Key derivation
    public typealias HKDFSHA256 = FoundationEssentialsHKDFSHA256
    public typealias HKDFSHA384 = FoundationEssentialsHKDFSHA384

    // Message authentication
    public typealias HMACSHA1   = FoundationEssentialsHMACSHA1
    public typealias HMACSHA256 = FoundationEssentialsHMACSHA256
    public typealias HMACSHA384 = FoundationEssentialsHMACSHA384

    // Key agreement
    public typealias X25519        = FoundationEssentialsX25519
    public typealias P256Agreement = FoundationEssentialsP256Agreement
    public typealias P384Agreement = FoundationEssentialsP384Agreement

    // Signatures
    public typealias Ed25519       = FoundationEssentialsEd25519
    public typealias P256Signature = FoundationEssentialsP256Signature
    public typealias P384Signature = FoundationEssentialsP384Signature

    // Ambient capabilities
    public typealias Random          = FoundationEssentialsRandom
    public typealias Clock           = FoundationEssentialsMonotonicClock
    public typealias HeaderProtection = FoundationEssentialsHeaderProtection

    // AEAD factories
    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> FoundationEssentialsAEAD {
        try FoundationEssentialsAEAD(algorithm: .aes128gcm, key: key)
    }

    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> FoundationEssentialsAEAD {
        try FoundationEssentialsAEAD(algorithm: .aes256gcm, key: key)
    }

    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> FoundationEssentialsAEAD {
        try FoundationEssentialsAEAD(algorithm: .chacha20poly1305, key: key)
    }

    // Ambient singletons
    public static let random = FoundationEssentialsRandom()
    public static let clock  = FoundationEssentialsMonotonicClock()
}
