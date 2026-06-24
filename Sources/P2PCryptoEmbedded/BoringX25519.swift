// BoringX25519.swift
// X25519 ECDH over BoringSSL X25519 shims (crypto-impl.md §2.5). Raw 32-byte
// little-endian key encodings map directly to the seam's rawRepresentation.
import P2PCoreCrypto
import CCryptoBoringSSL
import CCryptoBoringSSLShims

/// X25519 key agreement. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum BoringX25519: KeyAgreement {
    private static let keyLength = 32

    /// A 32-byte X25519 private scalar, zeroized on drop (§5.2).
    public struct PrivateKey: Sendable {
        let secret: SecretBytes
        init(_ bytes: [UInt8]) { self.secret = SecretBytes(bytes) }
    }

    /// A 32-byte X25519 public value.
    public struct PublicKey: Sendable {
        let bytes: [UInt8]
    }

    public static func generatePrivateKey() throws(CryptoError) -> PrivateKey {
        var priv = [UInt8](repeating: 0, count: keyLength)
        var pub = [UInt8](repeating: 0, count: keyLength)
        pub.withUnsafeMutableBufferPointer { pubp in
            priv.withUnsafeMutableBufferPointer { privp in
                CCryptoBoringSSLShims_X25519_keypair(pubp.baseAddress!, privp.baseAddress!)
            }
        }
        return PrivateKey(priv)
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey {
        guard rawRepresentation.count == keyLength else {
            throw .invalidLength(expected: keyLength, actual: rawRepresentation.count)
        }
        return PrivateKey(rawRepresentation.toArray())
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey {
        guard rawRepresentation.count == keyLength else {
            throw .invalidLength(expected: keyLength, actual: rawRepresentation.count)
        }
        return PublicKey(bytes: rawRepresentation.toArray())
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        var pub = [UInt8](repeating: 0, count: keyLength)
        pub.withUnsafeMutableBufferPointer { pubp in
            privateKey.secret.bytes.withUnsafeBufferPointer { privp in
                CCryptoBoringSSLShims_X25519_public_from_private(pubp.baseAddress!, privp.baseAddress!)
            }
        }
        return PublicKey(bytes: pub)
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        privateKey.secret.bytes
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        publicKey.bytes
    }

    public static func sharedSecret(
        privateKey: PrivateKey,
        peerPublicKey: PublicKey
    ) throws(CryptoError) -> [UInt8] {
        var shared = [UInt8](repeating: 0, count: keyLength)
        let ok = shared.withUnsafeMutableBufferPointer { sp in
            privateKey.secret.bytes.withUnsafeBufferPointer { dp in
                peerPublicKey.bytes.withUnsafeBufferPointer { pp in
                    CCryptoBoringSSLShims_X25519(sp.baseAddress!, dp.baseAddress!, pp.baseAddress!)
                }
            }
        }
        // X25519 returns 0 for a degenerate/low-order peer point (RFC 7748 §6.1):
        // never silently accept the all-zero shared secret.
        guard ok == 1 else { throw .keyAgreementFailure }
        return shared
    }
}
