// FoundationEssentialsEd25519.swift
// Ed25519 sign/verify over swift-crypto. crypto-impl.md §4. Signing key raw rep
// is the 32-byte seed (libp2p convention, matches CryptoKit rawRepresentation).
import P2PCoreCrypto
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#else
#error("FoundationEssentials or Foundation is required for the host provider")
#endif
import Crypto

/// Ed25519 signatures. Conforms `P2PCoreCrypto.SignatureScheme`.
public enum FoundationEssentialsEd25519: SignatureScheme {
    public struct SigningKey: Sendable {
        let key: Curve25519.Signing.PrivateKey
    }

    public struct VerifyingKey: Sendable {
        let key: Curve25519.Signing.PublicKey
    }

    public static func generateSigningKey() throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        SigningKey(key: Curve25519.Signing.PrivateKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> SigningKey {
        do {
            return SigningKey(key: try Curve25519.Signing.PrivateKey(
                rawRepresentation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> VerifyingKey {
        do {
            return VerifyingKey(key: try Curve25519.Signing.PublicKey(
                rawRepresentation: rawRepresentation.toData()))
        } catch {
            throw .invalidLength(expected: 32, actual: rawRepresentation.count)
        }
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(key: signingKey.key.publicKey)
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        [UInt8](signingKey.key.rawRepresentation)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        [UInt8](verifyingKey.key.rawRepresentation)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(P2PCoreCrypto.CryptoError) -> [UInt8] {
        do {
            return [UInt8](try signingKey.key.signature(for: message.toArray()))
        } catch {
            throw .providerFailure
        }
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        verifyingKey.key.isValidSignature(signature.toData(), for: message.toArray())
    }
}
