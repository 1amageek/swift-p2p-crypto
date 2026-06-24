// BoringHKDFSHA256.swift
// HKDF-SHA256 (RFC 5869) over BoringSSL HKDF_extract/HKDF_expand
// (crypto-impl.md §2.3). Hash-bound to BoringSHA256 via the Hash associatedtype.
import P2PCoreCrypto
import CCryptoBoringSSL

/// HKDF with SHA-256. Conforms `P2PCoreCrypto.KeyDerivation`.
public struct BoringHKDFSHA256: KeyDerivation {
    public typealias Hash = BoringSHA256

    private static let digestLength = 32

    public init() {}

    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        // BoringSSL's extract takes (secret, salt) = (ikm, salt).
        let md = CCryptoBoringSSL_EVP_sha256()
        let ikmBytes = ikm.toArray()
        let saltBytes = salt.toArray()
        var out = [UInt8](repeating: 0, count: Self.digestLength)
        var outLen = 0
        _ = out.withUnsafeMutableBufferPointer { op in
            ikmBytes.withUnsafeBufferPointer { ip in
                saltBytes.withUnsafeBufferPointer { sp in
                    CCryptoBoringSSL_HKDF_extract(
                        op.baseAddress, &outLen, md,
                        ip.baseAddress, ip.count,
                        sp.baseAddress, sp.count)
                }
            }
        }
        return out
    }

    public func expand(
        prk: Span<UInt8>,
        info: Span<UInt8>,
        length: Int
    ) throws(CryptoError) -> [UInt8] {
        let maxLength = 255 * Self.digestLength
        guard length >= 0, length <= maxLength else {
            throw .invalidLength(expected: maxLength, actual: length)
        }
        let md = CCryptoBoringSSL_EVP_sha256()
        let prkBytes = prk.toArray()
        let infoBytes = info.toArray()
        var out = [UInt8](repeating: 0, count: length)
        let ok = out.withUnsafeMutableBufferPointer { op in
            prkBytes.withUnsafeBufferPointer { pp in
                infoBytes.withUnsafeBufferPointer { fp in
                    CCryptoBoringSSL_HKDF_expand(
                        op.baseAddress, length, md,
                        pp.baseAddress, pp.count,
                        fp.baseAddress, fp.count)
                }
            }
        }
        guard ok == 1 else { throw .providerFailure }
        return out
    }
}
