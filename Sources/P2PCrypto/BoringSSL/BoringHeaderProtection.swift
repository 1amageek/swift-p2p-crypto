// BoringHeaderProtection.swift
// QUIC header protection (RFC 9001 §5.4) over BoringSSL single-block primitives
// (crypto-impl.md §3). AES path = one AES-ECB block on the 16-byte sample;
// ChaCha path = RFC-8439 block via CRYPTO_chacha_20. Both return the first 5
// keystream/cipher bytes as the mask. No _CryptoExtras, no CBC-IV-0 hack.
import P2PCoreCrypto
import CP2PBoringSSL

/// QUIC header protection. Conforms `P2PCoreCrypto.HeaderProtectionProvider`.
public enum BoringHeaderProtection: HeaderProtectionProvider {
    public static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        guard key.count == 16 || key.count == 32 else {
            throw .invalidLength(expected: 16, actual: key.count)
        }
        guard sample.count >= 16 else {
            throw .invalidLength(expected: 16, actual: sample.count)
        }
        let keyBytes = key.toArray()
        let sampleBytes = Array(sample.toArray()[0..<16])
        var aeskey = AES_KEY()
        let bits = UInt32(keyBytes.count * 8)
        let rc = keyBytes.withUnsafeBufferPointer { kp in
            CP2PBoringSSL_AES_set_encrypt_key(kp.baseAddress, bits, &aeskey)
        }
        guard rc == 0 else { throw .providerFailure }
        var out = [UInt8](repeating: 0, count: 16)
        sampleBytes.withUnsafeBufferPointer { sp in
            out.withUnsafeMutableBufferPointer { op in
                CP2PBoringSSL_AES_encrypt(sp.baseAddress, op.baseAddress, &aeskey)
            }
        }
        return Array(out[0..<5])
    }

    public static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(CryptoError) -> [UInt8] {
        guard key.count == 32 else {
            throw .invalidLength(expected: 32, actual: key.count)
        }
        guard sample.count >= 16 else {
            throw .invalidLength(expected: 16, actual: sample.count)
        }
        let sampleBytes = sample.toArray()
        // RFC 9001 §5.4.4: counter = sample[0..<4] LE, nonce = sample[4..<16].
        let counter = UInt32(sampleBytes[0])
            | (UInt32(sampleBytes[1]) << 8)
            | (UInt32(sampleBytes[2]) << 16)
            | (UInt32(sampleBytes[3]) << 24)
        let nonce = Array(sampleBytes[4..<16])
        let keyBytes = key.toArray()
        let zeros = [UInt8](repeating: 0, count: 5)
        var out = [UInt8](repeating: 0, count: 5)
        out.withUnsafeMutableBufferPointer { op in
            zeros.withUnsafeBufferPointer { zp in
                keyBytes.withUnsafeBufferPointer { kp in
                    nonce.withUnsafeBufferPointer { np in
                        CP2PBoringSSL_CRYPTO_chacha_20(
                            op.baseAddress, zp.baseAddress, 5,
                            kp.baseAddress, np.baseAddress, counter)
                    }
                }
            }
        }
        return out
    }
}
