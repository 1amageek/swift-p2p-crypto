// ConstantTime.swift
// Constant-time equality over BoringSSL's CRYPTO_memcmp (crypto-impl.md §2.10).
// Length is public, so the length check is allowed to short-circuit; the byte
// comparison itself is constant-time.
import CCryptoBoringSSL

enum ConstantTime {
    /// Returns `true` iff `a` and `b` are byte-equal, comparing in constant time.
    ///
    /// The length comparison is not secret and may short-circuit. The content
    /// comparison uses `CRYPTO_memcmp`, never `==` on `[UInt8]`.
    static func equal(_ a: borrowing [UInt8], _ b: borrowing [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        if a.isEmpty { return true }
        let result = a.withUnsafeBufferPointer { ap in
            b.withUnsafeBufferPointer { bp in
                CCryptoBoringSSL_CRYPTO_memcmp(ap.baseAddress, bp.baseAddress, a.count)
            }
        }
        return result == 0
    }
}
