// FoundationEssentialsHKDFSHA384.swift
// HKDF-SHA384 over swift-crypto. crypto-impl.md §4.
import P2PCoreCrypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#else
#error("FoundationEssentials or Foundation is required for the host provider")
#endif
import Crypto

/// HKDF with SHA-384. Conforms `P2PCoreCrypto.KeyDerivation`.
public struct FoundationEssentialsHKDFSHA384: KeyDerivation {
    public typealias Hash = FoundationEssentialsSHA384

    private static let digestLength = 48

    public init() {}

    public func extract(salt: Span<UInt8>, ikm: Span<UInt8>) -> [UInt8] {
        let prk = HKDF<Crypto.SHA384>.extract(
            inputKeyMaterial: SymmetricKey(data: ikm.toData()),
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
        let key = HKDF<Crypto.SHA384>.expand(
            pseudoRandomKey: SymmetricKey(data: prk.toData()),
            info: info.toArray(),
            outputByteCount: length)
        return key.withUnsafeBytes { Array($0) }
    }
}
