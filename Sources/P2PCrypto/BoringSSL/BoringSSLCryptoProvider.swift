// BoringSSLCryptoProvider.swift
// The Embedded-clean CryptoProvider conformance: binds every associatedtype to a
// BoringSSL-backed primitive (crypto-impl.md §1, §2, §3). No `any`, typed throws,
// [UInt8] buffers, final-class/value wrappers, key-material zeroization.
// Named for the backend (BoringSSL), not the deployment mode (Embedded).
import P2PCoreCrypto

/// Aggregates the BoringSSL-backed primitives behind `P2PCoreCrypto.CryptoProvider`.
///
/// All three AEAD associatedtypes resolve to `BoringAEAD` (one class keyed per
/// construction); the factory selects the algorithm. The two HKDF types are
/// hash-bound to the matching SHA primitive by the protocol's same-type
/// constraint (`HKDFSHA256.Hash == SHA256`).
public enum BoringSSLCryptoProvider: CryptoProvider {
    // AEAD
    public typealias AESGCM128  = BoringAEAD
    public typealias AESGCM256  = BoringAEAD
    public typealias ChaChaPoly = BoringAEAD

    // Hashes
    public typealias SHA256 = BoringSHA256
    public typealias SHA384 = BoringSHA384

    // Key derivation
    public typealias HKDFSHA256 = BoringHKDFSHA256
    public typealias HKDFSHA384 = BoringHKDFSHA384

    // Message authentication
    public typealias HMACSHA1   = BoringHMACSHA1
    public typealias HMACSHA256 = BoringHMACSHA256
    public typealias HMACSHA384 = BoringHMACSHA384

    // Key agreement
    public typealias X25519        = BoringX25519
    public typealias P256Agreement = BoringP256Agreement
    public typealias P384Agreement = BoringP384Agreement

    // Signatures
    public typealias Ed25519       = BoringEd25519
    public typealias P256Signature = BoringP256Signature
    public typealias P384Signature = BoringP384Signature

    // Ambient capabilities
    public typealias Random          = BoringRandom
    public typealias Clock           = SystemMonotonicClock
    public typealias HeaderProtection = BoringHeaderProtection

    // AEAD factories
    public static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> BoringAEAD {
        try BoringAEAD(algorithm: .aes128gcm, key: key)
    }

    public static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> BoringAEAD {
        try BoringAEAD(algorithm: .aes256gcm, key: key)
    }

    public static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> BoringAEAD {
        try BoringAEAD(algorithm: .chacha20poly1305, key: key)
    }

    // Ambient singletons
    public static let random = BoringRandom()
    public static let clock  = SystemMonotonicClock()
}
