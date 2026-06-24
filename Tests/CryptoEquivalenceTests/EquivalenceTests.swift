// EquivalenceTests.swift
// Cross-provider byte-equivalence: BoringSSLCryptoProvider (BoringSSL) vs
// FoundationCryptoProvider (swift-crypto/CryptoKit) MUST produce byte-identical
// outputs for every deterministic operation, and interoperate (each opens the
// other's ciphertext, each verifies the other's signature). This is the test
// that pins the hand-written EVP plumbing to the trusted reference.
//
// Note: CryptoKit's Ed25519 signing is randomized (RFC-8032-compatible but not
// byte-deterministic), so signatures are cross-VERIFIED rather than byte-compared.
// ECDSA is likewise randomized in both backends → cross-verify only. ECDH and
// X25519 shared secrets, hashes, HKDF, HMAC, and AEAD seal are deterministic and
// are byte-compared.
import Testing
import P2PCoreCrypto
@testable import P2PCryptoEmbedded
@testable import P2PCryptoFoundation

@Suite("Cross-provider equivalence")
struct CryptoEquivalenceTests {

    private func randomBytes(_ n: Int, seed: UInt8) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: n)
        var x: UInt8 = seed &+ 1
        for i in 0..<n { x = x &* 31 &+ 7; out[i] = x }
        return out
    }

    // MARK: AEAD seal byte-identical + cross-open interop.

    @Test func aesGCM128SealIdentical() throws {
        let key = randomBytes(16, seed: 1)
        let nonce = randomBytes(12, seed: 2)
        let aad = randomBytes(20, seed: 3)
        let pt = randomBytes(64, seed: 4)
        let e = try BoringAEAD(algorithm: .aes128gcm, key: key.span)
        let f = try FoundationAEAD(algorithm: .aes128gcm, key: key.span)
        let eSealed = try e.seal(pt.span, nonce: nonce.span, aad: aad.span)
        let fSealed = try f.seal(pt.span, nonce: nonce.span, aad: aad.span)
        #expect(eSealed == fSealed)
        // Cross-open both ways.
        let fOpenedE = try f.open(eSealed.span, nonce: nonce.span, aad: aad.span)
        let eOpenedF = try e.open(fSealed.span, nonce: nonce.span, aad: aad.span)
        #expect(fOpenedE == pt)
        #expect(eOpenedF == pt)
    }

    @Test func aesGCM256SealIdentical() throws {
        let key = randomBytes(32, seed: 5)
        let nonce = randomBytes(12, seed: 6)
        let aad = randomBytes(7, seed: 7)
        let pt = randomBytes(33, seed: 8)
        let e = try BoringAEAD(algorithm: .aes256gcm, key: key.span)
        let f = try FoundationAEAD(algorithm: .aes256gcm, key: key.span)
        let eSealed = try e.seal(pt.span, nonce: nonce.span, aad: aad.span)
        let fSealed = try f.seal(pt.span, nonce: nonce.span, aad: aad.span)
        #expect(eSealed == fSealed)
    }

    @Test func chaChaPolySealIdentical() throws {
        let key = randomBytes(32, seed: 9)
        let nonce = randomBytes(12, seed: 10)
        let aad = randomBytes(13, seed: 11)
        let pt = randomBytes(100, seed: 12)
        let e = try BoringAEAD(algorithm: .chacha20poly1305, key: key.span)
        let f = try FoundationAEAD(algorithm: .chacha20poly1305, key: key.span)
        let eSealed = try e.seal(pt.span, nonce: nonce.span, aad: aad.span)
        let fSealed = try f.seal(pt.span, nonce: nonce.span, aad: aad.span)
        #expect(eSealed == fSealed)
        let fOpenedE = try f.open(eSealed.span, nonce: nonce.span, aad: aad.span)
        #expect(fOpenedE == pt)
    }

    // MARK: Hash identical.

    @Test func sha256Identical() {
        for seed: UInt8 in 0..<8 {
            let data = randomBytes(Int(seed) * 17, seed: seed)
            #expect(BoringSHA256.hash(data.span) == FoundationSHA256.hash(data.span))
        }
    }

    @Test func sha384Identical() {
        for seed: UInt8 in 0..<8 {
            let data = randomBytes(Int(seed) * 23 + 1, seed: seed)
            #expect(BoringSHA384.hash(data.span) == FoundationSHA384.hash(data.span))
        }
    }

    // MARK: HKDF identical.

    @Test func hkdfSHA256Identical() throws {
        let salt = randomBytes(13, seed: 20)
        let ikm = randomBytes(22, seed: 21)
        let info = randomBytes(10, seed: 22)
        let eKdf = BoringHKDFSHA256()
        let fKdf = FoundationHKDFSHA256()
        let ePrk = eKdf.extract(salt: salt.span, ikm: ikm.span)
        let fPrk = fKdf.extract(salt: salt.span, ikm: ikm.span)
        #expect(ePrk == fPrk)
        let eOkm = try eKdf.expand(prk: ePrk.span, info: info.span, length: 80)
        let fOkm = try fKdf.expand(prk: fPrk.span, info: info.span, length: 80)
        #expect(eOkm == fOkm)
    }

    @Test func hkdfSHA384Identical() throws {
        let salt = randomBytes(16, seed: 30)
        let ikm = randomBytes(48, seed: 31)
        let info = randomBytes(12, seed: 32)
        let eKdf = BoringHKDFSHA384()
        let fKdf = FoundationHKDFSHA384()
        let ePrk = eKdf.extract(salt: salt.span, ikm: ikm.span)
        #expect(ePrk == fKdf.extract(salt: salt.span, ikm: ikm.span))
        let eOkm = try eKdf.expand(prk: ePrk.span, info: info.span, length: 96)
        let fOkm = try fKdf.expand(prk: ePrk.span, info: info.span, length: 96)
        #expect(eOkm == fOkm)
    }

    // MARK: HMAC identical.

    @Test func hmacIdentical() {
        let key = randomBytes(24, seed: 40)
        let msg = randomBytes(55, seed: 41)
        #expect(BoringHMACSHA1.authenticationCode(for: msg.span, key: key.span)
                == FoundationHMACSHA1.authenticationCode(for: msg.span, key: key.span))
        #expect(BoringHMACSHA256.authenticationCode(for: msg.span, key: key.span)
                == FoundationHMACSHA256.authenticationCode(for: msg.span, key: key.span))
        #expect(BoringHMACSHA384.authenticationCode(for: msg.span, key: key.span)
                == FoundationHMACSHA384.authenticationCode(for: msg.span, key: key.span))
    }

    // MARK: Header protection identical (pins Embedded HP to CommonCrypto/RFC block).

    @Test func aesHeaderProtectionIdentical() throws {
        let key = randomBytes(16, seed: 50)
        let sample = randomBytes(16, seed: 51)
        let eMask = try BoringHeaderProtection.aesECBBlockMask(key: key.span, sample: sample.span)
        let fMask = try FoundationHeaderProtection.aesECBBlockMask(key: key.span, sample: sample.span)
        #expect(eMask == fMask)
    }

    @Test func chaCha20HeaderProtectionIdentical() throws {
        let key = randomBytes(32, seed: 52)
        let sample = randomBytes(16, seed: 53)
        let eMask = try BoringHeaderProtection.chaCha20BlockMask(key: key.span, sample: sample.span)
        let fMask = try FoundationHeaderProtection.chaCha20BlockMask(key: key.span, sample: sample.span)
        #expect(eMask == fMask)
    }

    // MARK: X25519 shared secret identical (import one provider's keys into the other).

    @Test func x25519SharedSecretIdentical() throws {
        let aRaw = randomBytes(32, seed: 60)
        let bRaw = randomBytes(32, seed: 61)
        // Embedded.
        let eA = try BoringX25519.privateKey(rawRepresentation: aRaw.span)
        let eB = try BoringX25519.privateKey(rawRepresentation: bRaw.span)
        let eBPub = BoringX25519.publicKey(for: eB)
        let eShared = try BoringX25519.sharedSecret(privateKey: eA, peerPublicKey: eBPub)
        // Foundation (same raw keys).
        let fA = try FoundationX25519.privateKey(rawRepresentation: aRaw.span)
        let fB = try FoundationX25519.privateKey(rawRepresentation: bRaw.span)
        let fBPub = FoundationX25519.publicKey(for: fB)
        let fShared = try FoundationX25519.sharedSecret(privateKey: fA, peerPublicKey: fBPub)
        #expect(eShared == fShared)
        // Public keys must match too.
        #expect(BoringX25519.rawRepresentation(of: eBPub)
                == FoundationX25519.rawRepresentation(of: fBPub))
        // Cross-provider agreement: Embedded private with Foundation-derived peer.
        let crossPeer = try BoringX25519.publicKey(
            rawRepresentation: FoundationX25519.rawRepresentation(of: fBPub).span)
        let crossShared = try BoringX25519.sharedSecret(privateKey: eA, peerPublicKey: crossPeer)
        #expect(crossShared == fShared)
    }

    // MARK: P-256 / P-384 shared secret identical for the same key pair.

    @Test func p256SharedSecretIdentical() throws {
        // Generate via Embedded, import raw into Foundation.
        let a = try BoringP256Agreement.generatePrivateKey()
        let b = try BoringP256Agreement.generatePrivateKey()
        let aRaw = BoringP256Agreement.rawRepresentation(of: a)
        let bPubRaw = BoringP256Agreement.rawRepresentation(of: BoringP256Agreement.publicKey(for: b))
        let eShared = try BoringP256Agreement.sharedSecret(
            privateKey: a, peerPublicKey: BoringP256Agreement.publicKey(for: b))
        let fA = try FoundationP256Agreement.privateKey(rawRepresentation: aRaw.span)
        let fBPub = try FoundationP256Agreement.publicKey(rawRepresentation: bPubRaw.span)
        let fShared = try FoundationP256Agreement.sharedSecret(privateKey: fA, peerPublicKey: fBPub)
        #expect(eShared == fShared)
    }

    @Test func p384SharedSecretIdentical() throws {
        let a = try BoringP384Agreement.generatePrivateKey()
        let b = try BoringP384Agreement.generatePrivateKey()
        let aRaw = BoringP384Agreement.rawRepresentation(of: a)
        let bPubRaw = BoringP384Agreement.rawRepresentation(of: BoringP384Agreement.publicKey(for: b))
        let eShared = try BoringP384Agreement.sharedSecret(
            privateKey: a, peerPublicKey: BoringP384Agreement.publicKey(for: b))
        let fA = try FoundationP384Agreement.privateKey(rawRepresentation: aRaw.span)
        let fBPub = try FoundationP384Agreement.publicKey(rawRepresentation: bPubRaw.span)
        let fShared = try FoundationP384Agreement.sharedSecret(privateKey: fA, peerPublicKey: fBPub)
        #expect(eShared == fShared)
    }

    // MARK: Ed25519 deterministic key derivation identical + cross-verify.

    @Test func ed25519PublicKeyIdenticalAndCrossVerify() throws {
        let seed = randomBytes(32, seed: 70)
        let eKey = try BoringEd25519.signingKey(rawRepresentation: seed.span)
        let fKey = try FoundationEd25519.signingKey(rawRepresentation: seed.span)
        // Public keys derived from the same seed must be byte-identical.
        let ePub = BoringEd25519.rawRepresentation(of: BoringEd25519.verifyingKey(for: eKey))
        let fPub = FoundationEd25519.rawRepresentation(of: FoundationEd25519.verifyingKey(for: fKey))
        #expect(ePub == fPub)

        // Cross-verify: each provider verifies the other's signature.
        let message = randomBytes(48, seed: 71)
        let eSig = try BoringEd25519.sign(message.span, with: eKey)
        let fSig = try FoundationEd25519.sign(message.span, with: fKey)
        let fVerifiesE = FoundationEd25519.isValid(
            signature: eSig.span, for: message.span,
            with: try FoundationEd25519.verifyingKey(rawRepresentation: ePub.span))
        let eVerifiesF = BoringEd25519.isValid(
            signature: fSig.span, for: message.span,
            with: try BoringEd25519.verifyingKey(rawRepresentation: fPub.span))
        #expect(fVerifiesE)
        #expect(eVerifiesF)
    }

    // MARK: ECDSA cross-verify (randomized signatures → verify, not byte-compare).

    @Test func ecdsaP256CrossVerify() throws {
        let eKey = try BoringP256Signature.generateSigningKey()
        let eRaw = BoringP256Signature.rawRepresentation(of: eKey)
        let ePubRaw = BoringP256Signature.rawRepresentation(of: BoringP256Signature.verifyingKey(for: eKey))
        let message = randomBytes(40, seed: 80)
        let eSig = try BoringP256Signature.sign(message.span, with: eKey)
        // Foundation verifies the Embedded signature.
        let fPub = try FoundationP256Signature.verifyingKey(rawRepresentation: ePubRaw.span)
        let fVerifies = FoundationP256Signature.isValid(signature: eSig.span, for: message.span, with: fPub)
        #expect(fVerifies)
        // Embedded verifies a Foundation signature with the same key.
        let fKey = try FoundationP256Signature.signingKey(rawRepresentation: eRaw.span)
        let fSig = try FoundationP256Signature.sign(message.span, with: fKey)
        let ePub = try BoringP256Signature.verifyingKey(rawRepresentation: ePubRaw.span)
        let eVerifies = BoringP256Signature.isValid(signature: fSig.span, for: message.span, with: ePub)
        #expect(eVerifies)
    }
}
