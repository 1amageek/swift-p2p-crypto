// FoundationEssentialsHKDFSHA256.swift
// HKDF-SHA256 over swift-crypto. crypto-impl.md §4.
import P2PCoreCrypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#endif
import Crypto

/// HKDF with SHA-256. Conforms `P2PCoreCrypto.KeyDerivation`.
public struct FoundationEssentialsHKDFSHA256: KeyDerivation {
    public typealias Hash = FoundationEssentialsSHA256

    private static let digestLength = 32

    public init() {}

    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = HKDF<Crypto.SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.toArray()),
            salt: salt.toArray())
        return prk.withUnsafeBytes { Array($0) }
    }

    public func expand(
        prk: Span<UInt8>,
        info: Span<UInt8>,
        length: Int
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        let maxLength = 255 * Self.digestLength
        guard length >= 0, length <= maxLength else {
            throw .invalidLength(expected: maxLength, actual: length)
        }
        let key = HKDF<Crypto.SHA256>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.toArray()),
            info: info.toArray(),
            outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }
}
