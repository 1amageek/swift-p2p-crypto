// FoundationP384Signature.swift
// ECDSA P-384 sign/verify over swift-crypto. crypto-impl.md §4. CryptoKit hashes
// the message with SHA-384 internally; signatures are raw r||s (96 B,
// rawRepresentation). Verifying key = X9.62 uncompressed point (97 B).
import P2PCoreCrypto
import Foundation
import Crypto

/// ECDSA over P-384. Conforms `P2PCoreCrypto.SignatureScheme`.
public enum FoundationP384Signature: SignatureScheme {
    public struct SigningKey: Sendable {
        let key: P384.Signing.PrivateKey
    }

    public struct VerifyingKey: Sendable {
        let key: P384.Signing.PublicKey
    }

    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        SigningKey(key: P384.Signing.PrivateKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        do {
            return SigningKey(key: try P384.Signing.PrivateKey(
                rawRepresentation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 48, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try P384.Signing.PublicKey(
                x963Representation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 97, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(key: signingKey.key.publicKey)
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        [UInt8](signingKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        [UInt8](verifyingKey.key.x963Representation)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            let signature = try signingKey.key.signature(for: message.toArray())
            return [UInt8](signature.rawRepresentation)
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        do {
            let sig = try P384.Signing.ECDSASignature(rawRepresentation: signature.toData())
            return verifyingKey.key.isValidSignature(sig, for: message.toArray())
        } catch {
            return false
        }
    }
}
