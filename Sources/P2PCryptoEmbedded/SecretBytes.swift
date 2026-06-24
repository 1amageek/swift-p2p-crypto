// SecretBytes.swift
// Key-material container that cleanses its storage on drop using BoringSSL's
// OPENSSL_cleanse (a compiler-barrier memset that is guaranteed not to be
// optimized away). Embedded allows `final class` + `deinit`; a value `struct`
// cannot run cleanup on drop under Embedded.
import CCryptoBoringSSL

/// Owns secret key bytes and zeroizes them on deinit (crypto-impl.md §5.2).
///
/// Use this for any value-type secret (private scalars, expanded signing keys,
/// AEAD key buffers held before they are consumed by BoringSSL). A plain
/// `for i { b[i] = 0 }` is dead-store-eliminable; `OPENSSL_cleanse` is not.
public final class SecretBytes: @unchecked Sendable {
    public private(set) var bytes: [UInt8]

    public init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    public init(repeating value: UInt8, count: Int) {
        self.bytes = [UInt8](repeating: value, count: count)
    }

    /// The number of secret bytes held.
    public var count: Int { bytes.count }

    deinit {
        bytes.withUnsafeMutableBufferPointer { buffer in
            if let base = buffer.baseAddress, buffer.count > 0 {
                CCryptoBoringSSL_OPENSSL_cleanse(base, buffer.count)
            }
        }
    }
}
