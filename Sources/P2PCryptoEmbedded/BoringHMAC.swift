// BoringHMAC.swift
// One-shot HMAC core over BoringSSL HMAC() (crypto-impl.md §2.4). The incremental
// interface buffers input and computes the one-shot HMAC at finalize: every call
// site in the stack is one-shot, and buffering keeps the value-type (no C-context
// lifecycle that would force a `final class`).
//
// The EVP_MD selector (EVP_sha1/256/384) return type is not nameable as a bare
// typedef (crypto-impl.md §1.4.3); each MAC type passes the live selector result
// in via the `md` closure so its type is inferred, never annotated.
import CP2PBoringSSL

/// Identifies which BoringSSL digest backs an HMAC.
enum HMACDigest {
    case sha1
    case sha256
    case sha384

    var digestLength: Int {
        switch self {
        case .sha1:   return 20
        case .sha256: return 32
        case .sha384: return 48
        }
    }
}

enum BoringHMACCore {
    /// Computes `HMAC_md(key, message)` into a fresh `[UInt8]` of the digest length.
    static func authenticate(
        _ digest: HMACDigest,
        key: borrowing [UInt8],
        message: borrowing [UInt8]
    ) -> [UInt8] {
        // Selector result type inferred (§1.4.3).
        let md = switch digest {
        case .sha1:   CP2PBoringSSL_EVP_sha1()
        case .sha256: CP2PBoringSSL_EVP_sha256()
        case .sha384: CP2PBoringSSL_EVP_sha384()
        }
        var out = [UInt8](repeating: 0, count: digest.digestLength)
        var outLen: UInt32 = 0
        _ = key.withUnsafeBufferPointer { kp in
            message.withUnsafeBufferPointer { mp in
                out.withUnsafeMutableBufferPointer { op in
                    CP2PBoringSSL_HMAC(
                        md, kp.baseAddress, kp.count,
                        mp.baseAddress, mp.count,
                        op.baseAddress, &outLen)
                }
            }
        }
        return out
    }
}
