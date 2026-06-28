// FoundationEssentialsAEAD.swift
// AES-128/256-GCM and ChaCha20-Poly1305 over swift-crypto (CryptoKit on Apple,
// BoringSSL on Linux). crypto-impl.md §4. seal returns ciphertext || tag; open
// rethrows CryptoKitError.authenticationFailure as .authenticationFailure
// (no silent fallback).
import P2PCoreCrypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#endif
import Crypto

/// One keyed AEAD over swift-crypto. Conforms `P2PCoreCrypto.AEAD`.
public struct FoundationEssentialsAEAD: AEAD {
    public static let nonceLength = 12
    public static let tagLength   = 16

    /// The three constructions this adapter can be keyed for.
    public enum Algorithm: Sendable {
        case aes128gcm
        case aes256gcm
        case chacha20poly1305

        var keyLength: Int {
            switch self {
            case .aes128gcm:        return 16
            case .aes256gcm:        return 32
            case .chacha20poly1305: return 32
            }
        }
    }

    private let algorithm: Algorithm
    private let key: SymmetricKey

    public init(algorithm: Algorithm, key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) {
        guard key.count == algorithm.keyLength else {
            throw .invalidLength(expected: algorithm.keyLength, actual: key.count)
        }
        self.algorithm = algorithm
        self.key = SymmetricKey(data: key.toArray())
    }

    public func seal(
        _ plaintext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard nonce.count == Self.nonceLength else {
            throw .invalidLength(expected: Self.nonceLength, actual: nonce.count)
        }
        let pt = plaintext.toArray()
        let nonceData = nonce.toArray()
        let aadData = aad.toArray()
        switch algorithm {
        case .aes128gcm, .aes256gcm:
            do {
                let aesNonce = try AES.GCM.Nonce(data: nonceData)
                let box = try AES.GCM.seal(pt, using: key, nonce: aesNonce, authenticating: aadData)
                return Self.combine(ciphertext: box.ciphertext, tag: box.tag)
            } catch {
                throw .providerFailure
            }
        case .chacha20poly1305:
            do {
                let ccNonce = try ChaChaPoly.Nonce(data: nonceData)
                let box = try ChaChaPoly.seal(pt, using: key, nonce: ccNonce, authenticating: aadData)
                return Self.combine(ciphertext: box.ciphertext, tag: box.tag)
            } catch {
                throw .providerFailure
            }
        }
    }

    public func open(
        _ ciphertext: Span<UInt8>,
        nonce: Span<UInt8>,
        aad: Span<UInt8>
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        guard nonce.count == Self.nonceLength else {
            throw .invalidLength(expected: Self.nonceLength, actual: nonce.count)
        }
        guard ciphertext.count >= Self.tagLength else {
            throw .invalidLength(expected: Self.tagLength, actual: ciphertext.count)
        }
        let combined = ciphertext.toArray()
        let splitIndex = combined.count - Self.tagLength
        let ctData = combined[..<splitIndex]
        let tagData = combined[splitIndex..<combined.count]
        let nonceData = nonce.toArray()
        let aadData = aad.toArray()
        switch algorithm {
        case .aes128gcm, .aes256gcm:
            do {
                let aesNonce = try AES.GCM.Nonce(data: nonceData)
                let box = try AES.GCM.SealedBox(nonce: aesNonce, ciphertext: ctData, tag: tagData)
                let plaintext = try AES.GCM.open(box, using: key, authenticating: aadData)
                return [UInt8](plaintext)
            } catch let error as CryptoKitError {
                throw mapOpenError(error)
            } catch {
                throw .providerFailure
            }
        case .chacha20poly1305:
            do {
                let ccNonce = try ChaChaPoly.Nonce(data: nonceData)
                let box = try ChaChaPoly.SealedBox(nonce: ccNonce, ciphertext: ctData, tag: tagData)
                let plaintext = try ChaChaPoly.open(box, using: key, authenticating: aadData)
                return [UInt8](plaintext)
            } catch let error as CryptoKitError {
                throw mapOpenError(error)
            } catch {
                throw .providerFailure
            }
        }
    }

    /// Concatenates `ciphertext || tag` into one owned buffer.
    private static func combine<Ciphertext: Collection, Tag: Collection>(
        ciphertext: Ciphertext,
        tag: Tag
    ) -> [UInt8] where Ciphertext.Element == UInt8, Tag.Element == UInt8 {
        var result: [UInt8] = []
        result.reserveCapacity(ciphertext.count + tag.count)
        result.append(contentsOf: ciphertext)
        result.append(contentsOf: tag)
        return result
    }

    private func mapOpenError(_ error: CryptoKitError) -> P2PCoreCrypto.CryptoError {
        switch error {
        case .authenticationFailure:
            return .authenticationFailure
        default:
            return .providerFailure
        }
    }
}
