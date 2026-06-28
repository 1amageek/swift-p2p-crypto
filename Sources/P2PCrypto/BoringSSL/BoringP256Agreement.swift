// BoringP256Agreement.swift
// P-256 ECDH (crypto-impl.md §2.6). Private key = raw scalar (zeroized);
// public key = X9.62 uncompressed point (65 B).
import P2PCoreCrypto

/// P-256 ECDH key agreement. Conforms `P2PCoreCrypto.KeyAgreement`.
public enum BoringP256Agreement: KeyAgreement {
    static let curve = ECCurve.p256

    /// A P-256 private scalar, zeroized on drop (§5.2).
    public struct PrivateKey: Sendable {
        let secret: SecretBytes
        init(_ bytes: [UInt8]) { self.secret = SecretBytes(bytes) }
    }

    /// A P-256 public key as an X9.62 uncompressed point (65 B).
    public struct PublicKey: Sendable {
        let uncompressed: [UInt8]
    }

    public static func generatePrivateKey() throws(CryptoError) -> PrivateKey {
        PrivateKey(try ECCore.generateScalar(curve))
    }

    public static func privateKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PrivateKey {
        guard rawRepresentation.count == curve.scalarLength else {
            throw .invalidLength(expected: curve.scalarLength, actual: rawRepresentation.count)
        }
        return PrivateKey(rawRepresentation.toArray())
    }

    public static func publicKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> PublicKey {
        let validated = try ECCore.importPoint(curve, uncompressed: rawRepresentation.toArray())
        return PublicKey(uncompressed: validated)
    }

    public static func publicKey(for privateKey: PrivateKey) -> PublicKey {
        // The protocol signature is non-throwing. A derivation failure for an
        // already-validated scalar is an unrecoverable provider fault, not a
        // recoverable input error — trap rather than silently return garbage.
        do {
            let point = try ECCore.publicPoint(curve, scalar: privateKey.secret.bytes)
            return PublicKey(uncompressed: point)
        } catch {
            fatalError("BoringP256Agreement: public-key derivation failed for a validated scalar")
        }
    }

    public static func rawRepresentation(of privateKey: PrivateKey) -> [UInt8] {
        privateKey.secret.bytes
    }

    public static func rawRepresentation(of publicKey: PublicKey) -> [UInt8] {
        publicKey.uncompressed
    }

    public static func sharedSecret(
        privateKey: PrivateKey,
        peerPublicKey: PublicKey
    ) throws(CryptoError) -> [UInt8] {
        try ECCore.ecdh(curve, scalar: privateKey.secret.bytes, peerUncompressed: peerPublicKey.uncompressed)
    }
}
