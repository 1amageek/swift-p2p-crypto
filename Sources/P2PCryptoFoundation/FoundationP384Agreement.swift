// FoundationP384Agreement.swift
// P-384 ECDH over swift-crypto. crypto-impl.md §4. Private = raw scalar (48 B);
// public = X9.62 uncompressed point (97 B, CryptoKit x963Representation).
import P2PCoreCrypto
import Foundation
import Crypto

/// P-384 ECDH key agreement. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum FoundationP384Agreement: KeyAgreement {
    public struct PrivateKey: Sendable {
        let key: P384.KeyAgreement.PrivateKey
    }

    public struct PublicKey: Sendable {
        let key: P384.KeyAgreement.PublicKey
    }

    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        PrivateKey(key: P384.KeyAgreement.PrivateKey())
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        do {
            return PrivateKey(key: try P384.KeyAgreement.PrivateKey(
                rawRepresentation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 48, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey {
        do {
            return PublicKey(key: try P384.KeyAgreement.PublicKey(
                x963Representation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 97, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        PublicKey(key: privateKey.key.publicKey)
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        [UInt8](privateKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        [UInt8](publicKey.key.x963Representation)
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
