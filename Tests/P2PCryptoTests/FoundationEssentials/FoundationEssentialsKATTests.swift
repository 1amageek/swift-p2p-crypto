// FoundationEssentialsKATTests.swift
// KAT/RFC vectors for the FoundationEssentialsCryptoProvider (the cross-provider reference).
// These confirm the swift-crypto/CryptoKit adapter produces the same standard
// outputs the BoringSSL provider is pinned against.
import Testing
import P2PCoreCrypto
@testable import P2PCrypto

@Suite("FoundationEssentials AEAD KAT")
struct FoundationEssentialsAEADTests {
    @Test func chaCha20Poly1305RFC8439() throws {
        let key = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = Hex.decode("070000004041424344454647")
        let aad = Hex.decode("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let expectedCT = Hex.decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        let expectedTag = Hex.decode("1ae10b594f09e26a7e902ecbd0600691")
        let aead = try FoundationEssentialsAEAD(algorithm: .chacha20poly1305, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: nonce.span, aad: aad.span)
        #expect(sealed == expectedCT + expectedTag)
        let opened = try aead.open(sealed.span, nonce: nonce.span, aad: aad.span)
        #expect(opened == plaintext)
    }

    @Test func aes128GCMNIST() throws {
        let key = Hex.decode("feffe9928665731c6d6a8f9467308308")
        let iv = Hex.decode("cafebabefacedbaddecaf888")
        let plaintext = Hex.decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        let aad = Hex.decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let expectedCT = Hex.decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
        let expectedTag = Hex.decode("5bc94fbc3221a5db94fae95ae7121a47")
        let aead = try FoundationEssentialsAEAD(algorithm: .aes128gcm, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: iv.span, aad: aad.span)
        #expect(sealed == expectedCT + expectedTag)
    }

    @Test func tamperedAADThrows() throws {
        let key = Hex.decode("feffe9928665731c6d6a8f9467308308")
        let iv = Hex.decode("cafebabefacedbaddecaf888")
        let plaintext = Hex.decode("00112233445566778899aabbccddeeff")
        let aad = Hex.decode("aabbccdd")
        let aead = try FoundationEssentialsAEAD(algorithm: .aes128gcm, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: iv.span, aad: aad.span)
        let badAAD = Hex.decode("99999999")
        #expect(throws: CryptoError.authenticationFailure) {
            _ = try aead.open(sealed.span, nonce: iv.span, aad: badAAD.span)
        }
    }
}

@Suite("FoundationEssentials Hash/HKDF/HMAC KAT")
struct FoundationEssentialsDigestTests {
    @Test func sha256ABC() {
        let input = Array("abc".utf8)
        #expect(FoundationEssentialsSHA256.hash(input.span) == Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
    }

    @Test func sha384ABC() {
        let input = Array("abc".utf8)
        #expect(FoundationEssentialsSHA384.hash(input.span) == Hex.decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"))
    }

    @Test func hkdfSHA256RFC5869TC1() throws {
        let ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = Hex.decode("000102030405060708090a0b0c")
        let info = Hex.decode("f0f1f2f3f4f5f6f7f8f9")
        let kdf = FoundationEssentialsHKDFSHA256()
        let prk = kdf.extract(salt: salt.span, ikm: ikm.span)
        #expect(prk == Hex.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
        let okm = try kdf.expand(prk: prk.span, info: info.span, length: 42)
        #expect(okm == Hex.decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    }

    @Test func hmacSHA256RFC4231TC2() {
        let key = Array("Jefe".utf8)
        let data = Array("what do ya want for nothing?".utf8)
        #expect(FoundationEssentialsHMACSHA256.authenticationCode(for: data.span, key: key.span)
                == Hex.decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
    }

    @Test func hmacSHA1RFC2202TC2() {
        let key = Array("Jefe".utf8)
        let data = Array("what do ya want for nothing?".utf8)
        #expect(FoundationEssentialsHMACSHA1.authenticationCode(for: data.span, key: key.span)
                == Hex.decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"))
    }
}

@Suite("FoundationEssentials Curve/Signature KAT")
struct FoundationEssentialsCurveTests {
    @Test func x25519RFC7748() throws {
        let scalar = Hex.decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        let uCoordinate = Hex.decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        let priv = try FoundationEssentialsX25519.privateKey(rawRepresentation: scalar.span)
        let peer = try FoundationEssentialsX25519.publicKey(rawRepresentation: uCoordinate.span)
        let shared = try FoundationEssentialsX25519.sharedSecret(privateKey: priv, peerPublicKey: peer)
        #expect(shared == Hex.decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"))
    }

    @Test func p256ECDHRoundtrip() throws {
        let a = try FoundationEssentialsP256Agreement.generatePrivateKey()
        let b = try FoundationEssentialsP256Agreement.generatePrivateKey()
        let aPub = FoundationEssentialsP256Agreement.publicKey(for: a)
        let bPub = FoundationEssentialsP256Agreement.publicKey(for: b)
        let ab = try FoundationEssentialsP256Agreement.sharedSecret(privateKey: a, peerPublicKey: bPub)
        let ba = try FoundationEssentialsP256Agreement.sharedSecret(privateKey: b, peerPublicKey: aPub)
        #expect(ab == ba)
    }

    @Test func ed25519SignVerify() throws {
        let signingKey = try FoundationEssentialsEd25519.generateSigningKey()
        let verifyingKey = FoundationEssentialsEd25519.verifyingKey(for: signingKey)
        let message = Array("hello".utf8)
        let sig = try FoundationEssentialsEd25519.sign(message.span, with: signingKey)
        let valid = FoundationEssentialsEd25519.isValid(signature: sig.span, for: message.span, with: verifyingKey)
        #expect(valid)
    }

    @Test func p256ECDSASignVerify() throws {
        let signingKey = try FoundationEssentialsP256Signature.generateSigningKey()
        let verifyingKey = FoundationEssentialsP256Signature.verifyingKey(for: signingKey)
        let message = Array("the message to sign".utf8)
        let sig = try FoundationEssentialsP256Signature.sign(message.span, with: signingKey)
        let valid = FoundationEssentialsP256Signature.isValid(signature: sig.span, for: message.span, with: verifyingKey)
        #expect(valid)
    }
}

@Suite("FoundationEssentials HeaderProtection KAT")
struct FoundationEssentialsHeaderProtectionTests {
    @Test func aesHeaderProtectionRFC9001() throws {
        let hpKey = Hex.decode("9f50449e04a0e810283a1e9933adedd2")
        let sample = Hex.decode("d1b1c98dd7689fb8ec11d242b123dc9b")
        let mask = try FoundationEssentialsHeaderProtection.aesECBBlockMask(key: hpKey.span, sample: sample.span)
        #expect(mask == Hex.decode("437b9aec36"))
    }

    @Test func chaCha20HeaderProtectionRFC9001() throws {
        let hpKey = Hex.decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        let sample = Hex.decode("5e5cd55c41f69080575d7999c25a5bfb")
        let mask = try FoundationEssentialsHeaderProtection.chaCha20BlockMask(key: hpKey.span, sample: sample.span)
        #expect(mask == Hex.decode("aefefe7d03"))
    }
}
