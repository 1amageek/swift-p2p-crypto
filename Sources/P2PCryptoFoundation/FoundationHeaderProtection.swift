// FoundationHeaderProtection.swift
// QUIC header protection (RFC 9001 §5.4) on the host. AES path = single-block
// AES-ECB via CommonCrypto on Apple (current AEAD.swift behavior); ChaCha path =
// the RFC-8439 block. crypto-impl.md §4. The single divergence between providers
// is the AES backend (CommonCrypto here, BoringSSL AES_encrypt in the Embedded
// provider) — both compute identical ECB output, pinned by CryptoEquivalenceTests.
import P2PCoreCrypto
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// QUIC header protection. Conforms `P2PCoreCrypto.HeaderProtectionProvider`.
public enum FoundationHeaderProtection: HeaderProtectionProvider {
    public static func aesECBBlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard key.count == 16 || key.count == 32 else {
            throw .invalidLength(expected: 16, actual: key.count)
        }
        guard sample.count >= 16 else {
            throw .invalidLength(expected: 16, actual: sample.count)
        }
        let keyBytes = key.toArray()
        let sampleBytes = Array(sample.toArray()[0..<16])
        #if canImport(CommonCrypto)
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let status = keyBytes.withUnsafeBytes { kp in
            sampleBytes.withUnsafeBytes { ip in
                out.withUnsafeMutableBytes { op in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode),
                        kp.baseAddress, keyBytes.count,
                        nil,
                        ip.baseAddress, 16,
                        op.baseAddress, 16,
                        &moved)
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else { throw .providerFailure }
        return Array(out[0..<5])
        #else
        // Off-Apple AES header protection would use _CryptoExtras AES._CBC with a
        // zero IV; not available in this checkout. Surface explicitly rather than
        // silently returning a wrong mask.
        throw .unsupportedParameter
        #endif
    }

    public static func chaCha20BlockMask(key: Span<UInt8>, sample: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard key.count == 32 else {
            throw .invalidLength(expected: 32, actual: key.count)
        }
        guard sample.count >= 16 else {
            throw .invalidLength(expected: 16, actual: sample.count)
        }
        let sampleBytes = sample.toArray()
        let counter = UInt32(sampleBytes[0])
            | (UInt32(sampleBytes[1]) << 8)
            | (UInt32(sampleBytes[2]) << 16)
            | (UInt32(sampleBytes[3]) << 24)
        let nonce = Array(sampleBytes[4..<16])
        let keystream = ChaCha20Block.keystream(
            key: key.toArray(), nonce: nonce, counter: counter, outputCount: 5)
        return keystream
    }
}
