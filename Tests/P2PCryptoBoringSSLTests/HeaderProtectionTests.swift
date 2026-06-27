// HeaderProtectionTests.swift
// QUIC header-protection KATs (RFC 9001 Appendix A) for the BoringSSL provider.
import Testing
import P2PCoreCrypto
@testable import P2PCryptoBoringSSL

@Suite("BoringSSL HeaderProtection KAT")
struct BoringSSLHeaderProtectionTests {
    // RFC 9001 Appendix A.2: AES-128 header protection.
    // hp key, 16-byte sample -> first 5 bytes of AES-ECB(sample) = the mask.
    @Test func aesHeaderProtectionRFC9001() throws {
        let hpKey = Hex.decode("9f50449e04a0e810283a1e9933adedd2")
        let sample = Hex.decode("d1b1c98dd7689fb8ec11d242b123dc9b")
        let mask = try BoringHeaderProtection.aesECBBlockMask(key: hpKey.span, sample: sample.span)
        #expect(mask == Hex.decode("437b9aec36"))
    }

    // RFC 9001 Appendix A.5: ChaCha20 header protection.
    // counter = sample[0..<4] LE, nonce = sample[4..<16], 5 keystream bytes = mask.
    @Test func chaCha20HeaderProtectionRFC9001() throws {
        let hpKey = Hex.decode("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        let sample = Hex.decode("5e5cd55c41f69080575d7999c25a5bfb")
        let mask = try BoringHeaderProtection.chaCha20BlockMask(key: hpKey.span, sample: sample.span)
        #expect(mask == Hex.decode("aefefe7d03"))
    }

    @Test func aesHeaderProtectionRejectsShortSample() {
        let hpKey = Hex.decode("9f50449e04a0e810283a1e9933adedd2")
        let shortSample = Hex.decode("d1b1c98d")
        #expect(throws: CryptoError.self) {
            _ = try BoringHeaderProtection.aesECBBlockMask(key: hpKey.span, sample: shortSample.span)
        }
    }
}
