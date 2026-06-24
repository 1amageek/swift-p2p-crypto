// HashHKDFHMACTests.swift
// SHA-256/384, HKDF (RFC 5869), and HMAC (RFC 4231/2202) KATs for the Embedded
// provider.
import Testing
import P2PCoreCrypto
@testable import P2PCryptoEmbedded

@Suite("Embedded Hash KAT")
struct EmbeddedHashTests {
    // FIPS 180-4: SHA-256("abc").
    @Test func sha256ABC() {
        let input = Array("abc".utf8)
        let digest = BoringSHA256.hash(input.span)
        #expect(digest == Hex.decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))
    }

    // FIPS 180-4: SHA-384("abc").
    @Test func sha384ABC() {
        let input = Array("abc".utf8)
        let digest = BoringSHA384.hash(input.span)
        #expect(digest == Hex.decode("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"))
    }

    // SHA-256 empty.
    @Test func sha256Empty() {
        let input = [UInt8]()
        let digest = BoringSHA256.hash(input.span)
        #expect(digest == Hex.decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    }

    // Incremental update equals one-shot.
    @Test func sha256Incremental() {
        let part1 = Array("Hello, ".utf8)
        let part2 = Array("world!".utf8)
        var hasher = BoringSHA256()
        hasher.update(part1.span)
        hasher.update(part2.span)
        let incremental = hasher.finalize()
        let whole = Array("Hello, world!".utf8)
        #expect(incremental == BoringSHA256.hash(whole.span))
    }
}

@Suite("Embedded HKDF KAT")
struct EmbeddedHKDFTests {
    // RFC 5869 Appendix A.1 (SHA-256, Test Case 1).
    @Test func hkdfSHA256TC1() throws {
        let ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = Hex.decode("000102030405060708090a0b0c")
        let info = Hex.decode("f0f1f2f3f4f5f6f7f8f9")
        let kdf = BoringHKDFSHA256()
        let prk = kdf.extract(salt: salt.span, ikm: ikm.span)
        #expect(prk == Hex.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"))
        let okm = try kdf.expand(prk: prk.span, info: info.span, length: 42)
        #expect(okm == Hex.decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))
    }

    // RFC 5869 Appendix A.2 (SHA-256, Test Case 2, longer inputs).
    @Test func hkdfSHA256TC2() throws {
        let ikm = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
        let salt = Hex.decode("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
        let info = Hex.decode("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        let kdf = BoringHKDFSHA256()
        let prk = kdf.extract(salt: salt.span, ikm: ikm.span)
        let okm = try kdf.expand(prk: prk.span, info: info.span, length: 82)
        #expect(okm == Hex.decode("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"))
    }

    // RFC 5869 Appendix A.3 (SHA-256, Test Case 3, zero-length salt+info).
    @Test func hkdfSHA256TC3() throws {
        let ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        let salt = [UInt8]()
        let info = [UInt8]()
        let kdf = BoringHKDFSHA256()
        let prk = kdf.extract(salt: salt.span, ikm: ikm.span)
        #expect(prk == Hex.decode("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"))
        let okm = try kdf.expand(prk: prk.span, info: info.span, length: 42)
        #expect(okm == Hex.decode("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))
    }

    @Test func hkdfExpandTooLongThrows() {
        let kdf = BoringHKDFSHA256()
        let prk = Hex.decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        let info = [UInt8]()
        #expect(throws: CryptoError.self) {
            _ = try kdf.expand(prk: prk.span, info: info.span, length: 255 * 32 + 1)
        }
    }
}

@Suite("Embedded HMAC KAT")
struct EmbeddedHMACTests {
    // RFC 4231 Test Case 2 (HMAC-SHA-256/384).
    @Test func hmacSHA256TC2() {
        let key = Array("Jefe".utf8)
        let data = Array("what do ya want for nothing?".utf8)
        let mac = BoringHMACSHA256.authenticationCode(for: data.span, key: key.span)
        #expect(mac == Hex.decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"))
    }

    @Test func hmacSHA384TC2() {
        let key = Array("Jefe".utf8)
        let data = Array("what do ya want for nothing?".utf8)
        let mac = BoringHMACSHA384.authenticationCode(for: data.span, key: key.span)
        #expect(mac == Hex.decode("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"))
    }

    // RFC 2202 Test Case 2 (HMAC-SHA-1).
    @Test func hmacSHA1TC2() {
        let key = Array("Jefe".utf8)
        let data = Array("what do ya want for nothing?".utf8)
        let mac = BoringHMACSHA1.authenticationCode(for: data.span, key: key.span)
        #expect(mac == Hex.decode("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"))
    }

    @Test func hmacIncrementalEqualsOneShot() {
        let key = Array("the-key".utf8)
        let part1 = Array("abc".utf8)
        let part2 = Array("def".utf8)
        var mac = BoringHMACSHA256(key: key.span)
        mac.update(part1.span)
        mac.update(part2.span)
        let incremental = mac.finalize()
        let whole = Array("abcdef".utf8)
        #expect(incremental == BoringHMACSHA256.authenticationCode(for: whole.span, key: key.span))
    }

    @Test func hmacIsValidConstantTime() {
        let key = Array("the-key".utf8)
        let data = Array("message".utf8)
        let mac = BoringHMACSHA256.authenticationCode(for: data.span, key: key.span)
        let valid = BoringHMACSHA256.isValid(mac.span, for: data.span, key: key.span)
        #expect(valid)
        var wrong = mac
        wrong[0] ^= 0x01
        let invalid = BoringHMACSHA256.isValid(wrong.span, for: data.span, key: key.span)
        #expect(!invalid)
    }
}
