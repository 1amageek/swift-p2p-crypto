// ECDSACore.swift
// ECDSA sign/verify over BoringSSL ECDSA_sign_p1363 / ECDSA_verify_p1363
// (crypto-impl.md §2.8). Signatures are raw r||s (64 B P-256 / 96 B P-384),
// matching TLS 1.3 / QUIC CertificateVerify and CryptoKit's rawRepresentation.
// ECDSA signs a DIGEST: the caller hashes the message first (SHA-256 for P-256,
// SHA-384 for P-384).
import P2PCoreCrypto
import CCryptoBoringSSL
import CCryptoBoringSSLShims

enum ECDSACore {
    /// Signs a pre-computed `digest` with the raw private `scalar`. Returns r||s.
    static func sign(
        _ curve: ECCurve,
        digest: borrowing [UInt8],
        scalar: borrowing [UInt8],
        signatureLength: Int
    ) throws(CryptoError) -> [UInt8] {
        guard let key = CCryptoBoringSSL_EC_KEY_new_by_curve_name(curve.nid) else {
            throw .providerFailure
        }
        let managed = ManagedECKey(key: key)
        guard let bn = scalar.withUnsafeBufferPointer({ bp in
            CCryptoBoringSSLShims_BN_bin2bn(bp.baseAddress, bp.count, nil)
        }) else { throw .providerFailure }
        defer { CCryptoBoringSSL_BN_free(bn) }
        guard CCryptoBoringSSL_EC_KEY_set_private_key(managed.key, bn) == 1 else {
            throw .providerFailure
        }

        var sig = [UInt8](repeating: 0, count: signatureLength)
        var sigLen = 0
        let ok = sig.withUnsafeMutableBufferPointer { sp in
            digest.withUnsafeBufferPointer { dp in
                CCryptoBoringSSL_ECDSA_sign_p1363(
                    dp.baseAddress, dp.count, sp.baseAddress, &sigLen, signatureLength, managed.key)
            }
        }
        guard ok == 1, sigLen == signatureLength else { throw .providerFailure }
        return sig
    }

    /// Verifies a raw r||s `signature` over `digest` against an uncompressed point.
    static func verify(
        _ curve: ECCurve,
        digest: borrowing [UInt8],
        signature: borrowing [UInt8],
        publicUncompressed: borrowing [UInt8]
    ) -> Bool {
        guard let group = CCryptoBoringSSL_EC_GROUP_new_by_curve_name(curve.nid) else { return false }
        defer { CCryptoBoringSSL_EC_GROUP_free(group) }
        guard let key = CCryptoBoringSSL_EC_KEY_new_by_curve_name(curve.nid) else { return false }
        let managed = ManagedECKey(key: key)
        guard let point = CCryptoBoringSSL_EC_POINT_new(group) else { return false }
        defer { CCryptoBoringSSL_EC_POINT_free(point) }
        let parsed = publicUncompressed.withUnsafeBufferPointer { pp in
            CCryptoBoringSSL_EC_POINT_oct2point(group, point, pp.baseAddress, pp.count, nil)
        }
        guard parsed == 1 else { return false }
        guard CCryptoBoringSSL_EC_KEY_set_public_key(managed.key, point) == 1 else { return false }

        let ok = digest.withUnsafeBufferPointer { dp in
            signature.withUnsafeBufferPointer { sp in
                CCryptoBoringSSL_ECDSA_verify_p1363(
                    dp.baseAddress, dp.count, sp.baseAddress, sp.count, managed.key)
            }
        }
        return ok == 1
    }
}
