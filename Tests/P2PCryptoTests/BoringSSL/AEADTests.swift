// AEADTests.swift
// AEAD KATs for the BoringSSLCryptoProvider: RFC 8439 ChaCha20-Poly1305, NIST
// AES-GCM, and the mandatory auth-failure-throws negative test.
import Testing
import P2PCoreCrypto
@testable import P2PCrypto

@Suite("BoringSSL AEAD KAT")
struct BoringSSLAEADTests {

    // RFC 8439 §2.8.2 worked example.
    @Test func chaCha20Poly1305RFC8439() throws {
        let key = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        let nonce = Hex.decode("070000004041424344454647")
        let aad = Hex.decode("50515253c0c1c2c3c4c5c6c7")
        let plaintext = Array("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let expectedCT = Hex.decode("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        let expectedTag = Hex.decode("1ae10b594f09e26a7e902ecbd0600691")

        let aead = try BoringAEAD(algorithm: .chacha20poly1305, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: nonce.span, aad: aad.span)
        #expect(sealed == expectedCT + expectedTag)

        let opened = try aead.open(sealed.span, nonce: nonce.span, aad: aad.span)
        #expect(opened == plaintext)
    }

    // NIST CAVP AES-128-GCM (gcmEncryptExtIV128, a known case with AAD).
    @Test func aes128GCMNIST() throws {
        let key = Hex.decode("feffe9928665731c6d6a8f9467308308")
        let iv = Hex.decode("cafebabefacedbaddecaf888")
        let plaintext = Hex.decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        let aad = Hex.decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let expectedCT = Hex.decode("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091")
        let expectedTag = Hex.decode("5bc94fbc3221a5db94fae95ae7121a47")

        let aead = try BoringAEAD(algorithm: .aes128gcm, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: iv.span, aad: aad.span)
        #expect(sealed == expectedCT + expectedTag)
        let opened = try aead.open(sealed.span, nonce: iv.span, aad: aad.span)
        #expect(opened == plaintext)
    }

    // NIST CAVP AES-256-GCM (gcmEncryptExtIV256).
    @Test func aes256GCMNIST() throws {
        let key = Hex.decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
        let iv = Hex.decode("cafebabefacedbaddecaf888")
        let plaintext = Hex.decode("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
        let aad = Hex.decode("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        let expectedCT = Hex.decode("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662")
        let expectedTag = Hex.decode("76fc6ece0f4e1768cddf8853bb2d551b")

        let aead = try BoringAEAD(algorithm: .aes256gcm, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: iv.span, aad: aad.span)
        #expect(sealed == expectedCT + expectedTag)
        let opened = try aead.open(sealed.span, nonce: iv.span, aad: aad.span)
        #expect(opened == plaintext)
    }

    // No silent fallback: tampered AAD MUST throw .authenticationFailure.
    @Test func tamperedAADThrows() throws {
        let key = Hex.decode("feffe9928665731c6d6a8f9467308308")
        let iv = Hex.decode("cafebabefacedbaddecaf888")
        let plaintext = Hex.decode("00112233445566778899aabbccddeeff")
        let aad = Hex.decode("aabbccdd")
        let aead = try BoringAEAD(algorithm: .aes128gcm, key: key.span)
        let sealed = try aead.seal(plaintext.span, nonce: iv.span, aad: aad.span)
        let badAAD = Hex.decode("99999999")
        #expect(throws: CryptoError.authenticationFailure) {
            _ = try aead.open(sealed.span, nonce: iv.span, aad: badAAD.span)
        }
    }

    // Tampered ciphertext MUST throw .authenticationFailure.
    @Test func tamperedCiphertextThrows() throws {
        let key = Hex.decode("00000000000000000000000000000000000000000000000000000000000000ff")
        let iv = Hex.decode("000000000000000000000000")
        let plaintext = Hex.decode("0011223344556677")
        let aad = [UInt8]()
        let aead = try BoringAEAD(algorithm: .aes256gcm, key: key.span)
        var sealed = try aead.seal(plaintext.span, nonce: iv.span, aad: aad.span)
        sealed[0] ^= 0x01
        #expect(throws: CryptoError.authenticationFailure) {
            _ = try aead.open(sealed.span, nonce: iv.span, aad: aad.span)
        }
    }
}
