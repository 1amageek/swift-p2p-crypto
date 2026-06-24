// ECCore.swift
// Shared NIST-curve (P-256 / P-384) plumbing over BoringSSL EC_KEY / EC_POINT /
// ECDH (crypto-impl.md §2.6, §2.8). Private keys are stored as the raw scalar
// (zeroized via SecretBytes); an EC_KEY is reconstructed per operation. Public
// keys are X9.62 uncompressed points (65 B P-256 / 97 B P-384), matching
// CryptoKit's x963Representation for cross-provider equivalence.
import P2PCoreCrypto
import CCryptoBoringSSL
import CCryptoBoringSSLShims

/// Parameters identifying a NIST prime curve.
struct ECCurve: Sendable {
    let nid: Int32
    let scalarLength: Int        // 32 (P-256) / 48 (P-384)
    let uncompressedLength: Int  // 65 (P-256) / 97 (P-384)

    static let p256 = ECCurve(nid: NID_X9_62_prime256v1, scalarLength: 32, uncompressedLength: 65)
    static let p384 = ECCurve(nid: NID_secp384r1, scalarLength: 48, uncompressedLength: 97)
}

/// Owns an `EC_KEY*`, freeing (and cleansing the private scalar) on deinit.
/// A value `struct` cannot own a C resource with cleanup under Embedded.
final class ManagedECKey {
    let key: OpaquePointer

    init(key: OpaquePointer) { self.key = key }

    deinit { CCryptoBoringSSL_EC_KEY_free(key) }
}

enum ECCore {
    /// Generates a fresh key pair and returns the raw private scalar
    /// (big-endian, fixed `scalarLength`).
    static func generateScalar(_ curve: ECCurve) throws(CryptoError) -> [UInt8] {
        guard let key = CCryptoBoringSSL_EC_KEY_new_by_curve_name(curve.nid) else {
            throw .providerFailure
        }
        let managed = ManagedECKey(key: key)
        guard CCryptoBoringSSL_EC_KEY_generate_key(managed.key) == 1 else {
            throw .providerFailure
        }
        guard let bn = CCryptoBoringSSL_EC_KEY_get0_private_key(managed.key) else {
            throw .providerFailure
        }
        return try scalarToBytes(bn, length: curve.scalarLength)
    }

    /// Derives the X9.62 uncompressed public point for a raw private scalar.
    static func publicPoint(_ curve: ECCurve, scalar: borrowing [UInt8]) throws(CryptoError) -> [UInt8] {
        guard let group = CCryptoBoringSSL_EC_GROUP_new_by_curve_name(curve.nid) else {
            throw .providerFailure
        }
        defer { CCryptoBoringSSL_EC_GROUP_free(group) }
        guard let bn = scalar.withUnsafeBufferPointer({ bp in
            CCryptoBoringSSLShims_BN_bin2bn(bp.baseAddress, bp.count, nil)
        }) else { throw .providerFailure }
        defer { CCryptoBoringSSL_BN_free(bn) }
        guard let point = CCryptoBoringSSL_EC_POINT_new(group) else { throw .providerFailure }
        defer { CCryptoBoringSSL_EC_POINT_free(point) }
        // point = generator * scalar
        guard CCryptoBoringSSL_EC_POINT_mul(group, point, bn, nil, nil, nil) == 1 else {
            throw .providerFailure
        }
        return try encodePoint(group: group, point: point, length: curve.uncompressedLength)
    }

    /// Validates and re-encodes an uncompressed public point (rejects off-curve).
    static func importPoint(_ curve: ECCurve, uncompressed: [UInt8]) throws(CryptoError) -> [UInt8] {
        guard uncompressed.count == curve.uncompressedLength else {
            throw .invalidLength(expected: curve.uncompressedLength, actual: uncompressed.count)
        }
        guard let group = CCryptoBoringSSL_EC_GROUP_new_by_curve_name(curve.nid) else {
            throw .providerFailure
        }
        defer { CCryptoBoringSSL_EC_GROUP_free(group) }
        guard let point = CCryptoBoringSSL_EC_POINT_new(group) else { throw .providerFailure }
        defer { CCryptoBoringSSL_EC_POINT_free(point) }
        let parsed = uncompressed.withUnsafeBufferPointer { pp in
            CCryptoBoringSSL_EC_POINT_oct2point(group, point, pp.baseAddress, pp.count, nil)
        }
        // oct2point rejects off-curve points.
        guard parsed == 1 else { throw .keyAgreementFailure }
        return Array(uncompressed)
    }

    /// Raw ECDH: returns the X-coordinate shared secret (scalarLength bytes).
    static func ecdh(
        _ curve: ECCurve,
        scalar: borrowing [UInt8],
        peerUncompressed: borrowing [UInt8]
    ) throws(CryptoError) -> [UInt8] {
        guard let group = CCryptoBoringSSL_EC_GROUP_new_by_curve_name(curve.nid) else {
            throw .providerFailure
        }
        defer { CCryptoBoringSSL_EC_GROUP_free(group) }

        guard let key = CCryptoBoringSSL_EC_KEY_new_by_curve_name(curve.nid) else {
            throw .providerFailure
        }
        let managed = ManagedECKey(key: key)
        guard let bn = scalar.withUnsafeBufferPointer({ bp in
            CCryptoBoringSSLShims_BN_bin2bn(bp.baseAddress, bp.count, nil)
        }) else { throw .keyAgreementFailure }
        defer { CCryptoBoringSSL_BN_free(bn) }
        guard CCryptoBoringSSL_EC_KEY_set_private_key(managed.key, bn) == 1 else {
            throw .keyAgreementFailure
        }

        guard let peer = CCryptoBoringSSL_EC_POINT_new(group) else { throw .providerFailure }
        defer { CCryptoBoringSSL_EC_POINT_free(peer) }
        let parsed = peerUncompressed.withUnsafeBufferPointer { pp in
            CCryptoBoringSSL_EC_POINT_oct2point(group, peer, pp.baseAddress, pp.count, nil)
        }
        guard parsed == 1 else { throw .keyAgreementFailure }

        var shared = [UInt8](repeating: 0, count: curve.scalarLength)
        let written = shared.withUnsafeMutableBufferPointer { sp in
            CCryptoBoringSSL_ECDH_compute_key(sp.baseAddress, curve.scalarLength, peer, managed.key, nil)
        }
        guard written == curve.scalarLength else { throw .keyAgreementFailure }
        return shared
    }

    // MARK: - Helpers

    /// Serializes a BIGNUM to a fixed-length big-endian buffer (left zero-padded).
    /// `BIGNUM` is a visible C struct, so the main-module functions surface it as
    /// `UnsafePointer<BIGNUM>` (the shims surface it as `OpaquePointer`).
    static func scalarToBytes(_ bn: UnsafePointer<BIGNUM>, length: Int) throws(CryptoError) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        let ok = out.withUnsafeMutableBufferPointer { op in
            CCryptoBoringSSL_BN_bn2bin_padded(op.baseAddress, length, bn)
        }
        guard ok == 1 else { throw .providerFailure }
        return out
    }

    static func encodePoint(group: OpaquePointer, point: OpaquePointer, length: Int) throws(CryptoError) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        let written = out.withUnsafeMutableBufferPointer { op in
            CCryptoBoringSSL_EC_POINT_point2oct(
                group, point, POINT_CONVERSION_UNCOMPRESSED, op.baseAddress, length, nil)
        }
        guard written == length else { throw .providerFailure }
        return out
    }
}
