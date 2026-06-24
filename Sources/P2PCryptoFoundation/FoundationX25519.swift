// FoundationX25519.swift
// X25519 ECDH over swift-crypto. crypto-impl.md §4. Raw 32-byte encodings.
import P2PCoreCrypto
import Foundation
import Crypto

/// X25519 key agreement. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum FoundationX25519: KeyAgreement {
    public struct PrivateKey: Sendable {
        let key: Curve25519.KeyAgreement.PrivateKey
    }

    public struct PublicKey: Sendable {
        let key: Curve25519.KeyAgreement.PublicKey
    }

    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        PrivateKey(key: Curve25519.KeyAgreement.PrivateKey())
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        do {
            return PrivateKey(key: try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey {
        do {
            return PublicKey(key: try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        PublicKey(key: privateKey.key.publicKey)
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        [UInt8](privateKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        [UInt8](publicKey.key.rawRepresentation)
    }

    public static func sharedSecret(
        privateKey: PrivateKey,
        peerPublicKey: PublicKey
    ) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            let secret = try privateKey.key.sharedSecretFromKeyAgreement(with: peerPublicKey.key)
            return secret.withUnsafeBytes { Array($0) }
        } catch {
            throw .keyAgreementFailure
        }
    }
}
