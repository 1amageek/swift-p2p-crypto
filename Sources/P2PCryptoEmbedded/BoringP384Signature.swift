// BoringP384Signature.swift
// ECDSA P-384 sign/verify (crypto-impl.md §2.8). Signs SHA-384(message); raw
// r||s signatures (96 B). Signing key = raw scalar (48 B, zeroized); verifying
// key = X9.62 uncompressed point (97 B).
import P2PCoreCrypto

/// ECDSA over P-384. Conforms `P2PCoreCrypto.SignatureScheme`.
public enum BoringP384Signature: SignatureScheme {
    static let curve = ECCurve.p384
    static let signatureLength = 96

    /// A P-384 signing scalar, zeroized on drop (§5.2).
    public struct SigningKey: Sendable {
        let secret: SecretBytes
        init(_ bytes: [UInt8]) { self.secret = SecretBytes(bytes) }
    }

    /// A P-384 verifying key as an X9.62 uncompressed point (97 B).
    public struct VerifyingKey: Sendable {
        let uncompressed: [UInt8]
    }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        SigningKey(try ECCore.generateScalar(curve))
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        guard rawRepresentation.count == curve.scalarLength else {
            throw .invalidLength(expected: curve.scalarLength, actual: rawRepresentation.count)
        }
        return SigningKey(rawRepresentation.toArray())
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        let validated = try ECCore.importPoint(curve, uncompressed: rawRepresentation.toArray())
        return VerifyingKey(uncompressed: validated)
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        do {
            let point = try ECCore.publicPoint(curve, scalar: signingKey.secret.bytes)
            return VerifyingKey(uncompressed: point)
        } catch {
            fatalError("BoringP384Signature: public-key derivation failed for a validated scalar")
        }
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        signingKey.secret.bytes
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        verifyingKey.uncompressed
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] {
        let digest = BoringSHA384.hash(message)
        return try ECDSACore.sign(
            curve, digest: digest, scalar: signingKey.secret.bytes, signatureLength: signatureLength)
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard signature.count == signatureLength else { return false }
        let digest = BoringSHA384.hash(message)
        return ECDSACore.verify(
            curve, digest: digest, signature: signature.toArray(),
            publicUncompressed: verifyingKey.uncompressed)
    }
}
