// ChaCha20Block.swift
// Pure-Swift RFC 8439 ChaCha20 block function, used for QUIC ChaCha20 header
// protection (RFC 9001 §5.4.4) on the host provider. Deterministic and
// algorithm-identical to BoringSSL's CRYPTO_chacha_20, so the two providers
// produce byte-identical header masks.
enum ChaCha20Block {
    /// Returns the first `outputCount` keystream bytes for one ChaCha20 block
    /// under `key` (32 B), `nonce` (12 B), and the 32-bit block `counter`.
    static func keystream(key: [UInt8], nonce: [UInt8], counter: UInt32, outputCount: Int) -> [UInt8] {
        precondition(key.count == 32)
        precondition(nonce.count == 12)
        precondition(outputCount <= 64)

        var state = [UInt32](repeating: 0, count: 16)
        // Constants "expand 32-byte k".
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574
        for i in 0..<8 {
            state[4 + i] = loadLE32(key, i * 4)
        }
        state[12] = counter
        for i in 0..<3 {
            state[13 + i] = loadLE32(nonce, i * 4)
        }

        var working = state
        for _ in 0..<10 {
            quarterRound(&working, 0, 4, 8, 12)
            quarterRound(&working, 1, 5, 9, 13)
            quarterRound(&working, 2, 6, 10, 14)
            quarterRound(&working, 3, 7, 11, 15)
            quarterRound(&working, 0, 5, 10, 15)
            quarterRound(&working, 1, 6, 11, 12)
            quarterRound(&working, 2, 7, 8, 13)
            quarterRound(&working, 3, 4, 9, 14)
        }
        for i in 0..<16 {
            working[i] = working[i] &+ state[i]
        }

        var out = [UInt8]()
        out.reserveCapacity(outputCount)
        for i in 0..<outputCount {
            let word = working[i / 4]
            let shift = UInt32((i % 4) * 8)
            out.append(UInt8((word >> shift) & 0xff))
        }
        return out
    }

    private static func loadLE32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24)
    }

    private static func quarterRound(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        s[a] = s[a] &+ s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
        s[c] = s[c] &+ s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
        s[a] = s[a] &+ s[b]; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
        s[c] = s[c] &+ s[d]; s[b] ^= s[c]; s[b] = rotl(s[b], 7)
    }

    private static func rotl(_ value: UInt32, _ count: UInt32) -> UInt32 {
        (value << count) | (value >> (32 - count))
    }
}
