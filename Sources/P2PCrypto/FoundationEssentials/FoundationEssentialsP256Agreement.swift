// FoundationEssentialsP256Agreement.swift
// P-256 ECDH over swift-crypto. crypto-impl.md §4. Private = raw scalar (32 B);
// public = X9.62 uncompressed point (65 B, CryptoKit x963Representation).
import P2PCoreCrypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#endif
import Crypto

/// P-256 ECDH key agreement. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum FoundationEssentialsP256Agreement: KeyAgreement {
    public struct PrivateKey: Sendable {
        let key: P256.KeyAgreement.PrivateKey
    }

    public struct PublicKey: Sendable {
        let key: P256.KeyAgreement.PublicKey
    }

    public static func generatePrivateKey() throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        PrivateKey(key: P256.KeyAgreement.PrivateKey())
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PrivateKey {
        do {
            return PrivateKey(key: try P256.KeyAgreement.PrivateKey(
                rawRepresentation: rawRepresentation.toArray()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> PublicKey {
        do {
            return PublicKey(key: try P256.KeyAgreement.PublicKey(
                x963Representation: rawRepresentation.toArray()))
        } catch {
            throw .invalidLength(expected: 65, actual: rawRepresentation.count)
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
