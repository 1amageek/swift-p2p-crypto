// BoringAEAD.swift
// AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 over a single EVP_AEAD_CTX
// (crypto-impl.md §2.1). The cipher is selected by the EVP_AEAD* the selector
// returns. seal returns `ciphertext || tag`; open throws `.authenticationFailure`
// on a bad tag (no silent fallback). Verified to seal/open/auth-fail under
// Embedded (crypto-impl.md §9).
import P2PCoreCrypto
import CP2PBoringSSL

/// One keyed AEAD over `EVP_AEAD_CTX`. Conforms `P2PCoreCrypto.AEAD`.
///
/// `EVP_AEAD_CTX_seal`/`open` are re-entrant on a const ctx, so concurrent
/// seal/open with distinct nonces is safe; there is no shared mutable Swift
/// state, hence `@unchecked Sendable` with no lock (crypto-impl.md §2.1).
public final class BoringAEAD: AEAD, @unchecked Sendable {
    public static let nonceLength = 12
    public static let tagLength   = 16

    /// The three constructions this class can be keyed for.
    public enum Algorithm: Sendable {
        case aes128gcm
        case aes256gcm
        case chacha20poly1305

        var keyLength: Int {
            switch self {
            case .aes128gcm:        return 16
            case .aes256gcm:        return 32
            case .chacha20poly1305: return 32
            }
        }
    }

    // Typed, NOT OpaquePointer — the C struct evp_aead_ctx_st is visible and the
    // `_new` selector returns the typed pointer (crypto-impl.md §1.4.2).
    private let ctx: UnsafeMutablePointer<EVP_AEAD_CTX>

    /// Keys an AEAD for `algorithm`. The input key buffer is cleansed after
    /// `EVP_AEAD_CTX_new` consumes it (BoringSSL holds the expanded schedule).
    public init(algorithm: Algorithm, key: Span<UInt8>) throws(CryptoError) {
        guard key.count == algorithm.keyLength else {
            throw .invalidLength(expected: algorithm.keyLength, actual: key.count)
        }
        // Inferred type — EVP_AEAD is not nameable as a bare typedef (§1.4.3).
        let aead = switch algorithm {
        case .aes128gcm:        CP2PBoringSSL_EVP_aead_aes_128_gcm()
        case .aes256gcm:        CP2PBoringSSL_EVP_aead_aes_256_gcm()
        case .chacha20poly1305: CP2PBoringSSL_EVP_aead_chacha20_poly1305()
        }
        let keyBytes = SecretBytes(key.toArray())
        let created: UnsafeMutablePointer<EVP_AEAD_CTX>? = keyBytes.bytes.withUnsafeBufferPointer { kp in
            CP2PBoringSSL_EVP_AEAD_CTX_new(aead, kp.baseAddress, kp.count, Self.tagLength)
        }
        guard let created else { throw .providerFailure }
        ctx = created
        // keyBytes is cleansed on drop here.
    }

    deinit {
        CP2PBoringSSL_EVP_AEAD_CTX_free(ctx)
    }

    public func seal(
        _ plaintext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(CryptoError) -> [UInt8] {
        guard nonce.count == Self.nonceLength else {
            throw .invalidLength(expected: Self.nonceLength, actual: nonce.count)
        }
        let plaintextBytes = plaintext.toArray()
        let nonceBytes = nonce.toArray()
        let aadBytes = aad.toArray()
        let maxOut = plaintextBytes.count + Self.tagLength
        var out = [UInt8](repeating: 0, count: maxOut)
        var outLen = 0
        let ok = out.withUnsafeMutableBufferPointer { op in
            nonceBytes.withUnsafeBufferPointer { np in
                plaintextBytes.withUnsafeBufferPointer { pp in
                    aadBytes.withUnsafeBufferPointer { ap in
                        CP2PBoringSSL_EVP_AEAD_CTX_seal(
                            ctx, op.baseAddress, &outLen, maxOut,
                            np.baseAddress, np.count,
                            pp.baseAddress, pp.count,
                            ap.baseAddress, ap.count)
                    }
                }
            }
        }
        guard ok == 1 else { throw .providerFailure }
        out.removeLast(maxOut - outLen)
        return out                                  // ciphertext || tag
    }

    public func open(
        _ ciphertext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(CryptoError) -> [UInt8] {
        guard nonce.count == Self.nonceLength else {
            throw .invalidLength(expected: Self.nonceLength, actual: nonce.count)
        }
        guard ciphertext.count >= Self.tagLength else {
            throw .invalidLength(expected: Self.tagLength, actual: ciphertext.count)
        }
        let ciphertextBytes = ciphertext.toArray()
        let nonceBytes = nonce.toArray()
        let aadBytes = aad.toArray()
        let maxOut = ciphertextBytes.count
        var out = [UInt8](repeating: 0, count: maxOut)
        var outLen = 0
        let ok = out.withUnsafeMutableBufferPointer { op in
            nonceBytes.withUnsafeBufferPointer { np in
                ciphertextBytes.withUnsafeBufferPointer { cp in
                    aadBytes.withUnsafeBufferPointer { ap in
                        CP2PBoringSSL_EVP_AEAD_CTX_open(
                            ctx, op.baseAddress, &outLen, maxOut,
                            np.baseAddress, np.count,
                            cp.baseAddress, cp.count,
                            ap.baseAddress, ap.count)
                    }
                }
            }
        }
        // open returns 0 on a bad tag — NEVER return garbage (crypto-impl.md §2.1).
        guard ok == 1 else { throw .authenticationFailure }
        out.removeLast(maxOut - outLen)
        return out
    }
}
