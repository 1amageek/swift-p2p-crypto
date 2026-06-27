// QUICVectorTests.swift
// RFC 9001 Appendix A end-to-end vectors: client Initial AEAD protection and the
// Retry integrity tag, plus a CSPRNG non-repetition smoke test.
import Testing
import P2PCoreCrypto
@testable import P2PCryptoBoringSSL

@Suite("BoringSSL QUIC RFC 9001 vectors")
struct BoringSSLQUICVectorTests {
    // RFC 9001 Appendix A.2: protect the first byte of the client Initial packet
    // payload. The client Initial AEAD is AES-128-GCM with:
    //   key   = 1f369613dd76d5467730efcbe3b1a22d
    //   iv    = fa044b2f42a3fd3b46fb255c
    //   nonce = iv XOR packet number (pn=2 here, so last byte ^= 2 -> ...5e)
    // The header (AAD) and 1162-byte plaintext appear in the RFC; we test the
    // first ciphertext bytes against the published protected payload.
    @Test func clientInitialAEAD() throws {
        let key = Hex.decode("1f369613dd76d5467730efcbe3b1a22d")
        let iv = Hex.decode("fa044b2f42a3fd3b46fb255c")
        // RFC 9001 A.2 unprotected header (packet number 2, pn length 4).
        let header = Hex.decode("c300000001088394c8f03e5157080000449e00000002")
        // First 16 bytes of the RFC's CRYPTO-frame payload (the full 1162-byte
        // frame is in the RFC; the first block is sufficient to pin the binding).
        let plaintextHead = Hex.decode("060040f1010000ed0303ebf8fa56f129")
        // Nonce = iv XOR pn (pn=2). iv last byte 5c ^ 02 = 5e.
        var nonce = iv
        nonce[nonce.count - 1] ^= 0x02
        let aead = try BoringAEAD(algorithm: .aes128gcm, key: key.span)
        let sealed = try aead.seal(plaintextHead.span, nonce: nonce.span, aad: header.span)
        // RFC 9001 A.2 protected payload begins with these bytes.
        #expect(Array(sealed[0..<16]) == Hex.decode("d1b1c98dd7689fb8ec11d242b123dc9b"))
        // Roundtrip back.
        let opened = try aead.open(sealed.span, nonce: nonce.span, aad: header.span)
        #expect(opened == plaintextHead)
    }

    // RFC 9001 Appendix A.4: Retry integrity tag (AES-128-GCM over the Retry
    // pseudo-packet with the fixed Retry key/nonce).
    @Test func retryIntegrityTag() throws {
        let key = Hex.decode("be0c690b9f66575a1d766b54e368c84e")
        let nonce = Hex.decode("461599d35d632bf2239825bb")
        // Retry pseudo-packet from RFC 9001 A.4:
        //   ODCID length (1) = 0x08 || ODCID (8) = 8394c8f03e515708
        //   || Retry packet without the 16-byte integrity tag.
        let pseudoPacket = Hex.decode("088394c8f03e515708ff000000010008f067a5502a4262b5746f6b656e")
        let empty = [UInt8]()
        let aead = try BoringAEAD(algorithm: .aes128gcm, key: key.span)
        let sealed = try aead.seal(empty.span, nonce: nonce.span, aad: pseudoPacket.span)
        // The tag is the 16-byte ciphertext (empty plaintext -> tag only).
        #expect(sealed == Hex.decode("04a265ba2eff4d829058fb3f0f2496ba"))
    }

    @Test func randomNonRepetition() {
        let random = BoringRandom()
        let a = random.randomBytes(32)
        let b = random.randomBytes(32)
        #expect(a.count == 32)
        #expect(b.count == 32)
        #expect(a != b)   // overwhelmingly likely; smoke test, not a KAT
    }
}
