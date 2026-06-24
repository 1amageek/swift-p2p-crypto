// BoringEd25519.swift
// Ed25519 sign/verify over BoringSSL ED25519 shims (crypto-impl.md §2.7).
// The BoringSSL "private key" is seed(32) || public(32). libp2p identity keys
// store a 32-byte seed, so signingKey(rawRepresentation:) expands it and
// rawRepresentation(of:) returns the seed back.
import P2PCoreCrypto
import CCryptoBoringSSL
import CCryptoBoringSSLShims

/// Ed25519 signatures. Conforms `P2PCoreCrypto.SignatureScheme`.
public enum BoringEd25519: SignatureScheme {
    private static let seedLength = 32
    private static let expandedLength = 64
    private static let publicLength = 32
    private static let signatureLength = 64

    /// An Ed25519 signing key (expanded seed||public form), zeroized on drop (§5.2).
    public struct SigningKey: Sendable {
        let expanded: SecretBytes   // 64 bytes: seed(32) || public(32)
        init(_ bytes: [UInt8]) { self.expanded = SecretBytes(bytes) }
    }

    /// An Ed25519 verifying key (32-byte public value).
    public struct VerifyingKey: Sendable {
        let publicKey: [UInt8]
    }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        var pub = [UInt8](repeating: 0, count: publicLength)
        var priv = [UInt8](repeating: 0, count: expandedLength)
        pub.withUnsafeMutableBufferPointer { pp in
            priv.withUnsafeMutableBufferPointer { sp in
                CCryptoBoringSSLShims_ED25519_keypair(pp.baseAddress!, sp.baseAddress!)
            }
        }
        return SigningKey(priv)
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        guard rawRepresentation.count == seedLength else {
            throw .invalidLength(expected: seedLength, actual: rawRepresentation.count)
        }
        let seed = rawRepresentation.toArray()
        var pub = [UInt8](repeating: 0, count: publicLength)
        var priv = [UInt8](repeating: 0, count: expandedLength)
        pub.withUnsafeMutableBufferPointer { pp in
            priv.withUnsafeMutableBufferPointer { sp in
                seed.withUnsafeBufferPointer { dp in
                    CCryptoBoringSSLShims_ED25519_keypair_from_seed(pp.baseAddress!, sp.baseAddress!, dp.baseAddress!)
                }
            }
        }
        return SigningKey(priv)
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        guard rawRepresentation.count == publicLength else {
            throw .invalidLength(expected: publicLength, actual: rawRepresentation.count)
        }
        return VerifyingKey(publicKey: rawRepresentation.toArray())
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        // The public half is the trailing 32 bytes of the expanded key.
        let bytes = signingKey.expanded.bytes
        return VerifyingKey(publicKey: Array(bytes[seedLength..<expandedLength]))
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        // libp2p stores the 32-byte seed.
        Array(signingKey.expanded.bytes[0..<seedLength])
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        verifyingKey.publicKey
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] {
        let messageBytes = message.toArray()
        var sig = [UInt8](repeating: 0, count: signatureLength)
        let ok = sig.withUnsafeMutableBufferPointer { sp in
            messageBytes.withUnsafeBufferPointer { mp in
                signingKey.expanded.bytes.withUnsafeBufferPointer { kp in
                    CCryptoBoringSSLShims_ED25519_sign(sp.baseAddress!, mp.baseAddress, mp.count, kp.baseAddress!)
                }
            }
        }
        guard ok == 1 else { throw .providerFailure }
        return sig
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard signature.count == signatureLength else { return false }
        let messageBytes = message.toArray()
        let signatureBytes = signature.toArray()
        let ok = messageBytes.withUnsafeBufferPointer { mp in
            signatureBytes.withUnsafeBufferPointer { sp in
                verifyingKey.publicKey.withUnsafeBufferPointer { kp in
                    CCryptoBoringSSLShims_ED25519_verify(mp.baseAddress, mp.count, sp.baseAddress!, kp.baseAddress!)
                }
            }
        }
        return ok == 1
    }
}
