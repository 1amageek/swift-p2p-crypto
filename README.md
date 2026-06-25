# swift-p2p-crypto

Concrete crypto providers for the `CryptoProvider` capability protocols
defined in [`swift-p2p-core`](../swift-p2p-core). Ships two interchangeable
backends — vendored BoringSSL for Embedded Swift, and Apple's swift-crypto /
CryptoKit on the host — behind one umbrella that auto-selects per build.

## Status

This package has no git remote and no released tag yet (first release is
gated behind milestone M8). Until then, depend on it via a local path:

```swift
.package(path: "../swift-p2p-crypto")
```

No version or URL is published; do not pin a tag that does not exist.

## Products

| Product | Provider | Backend |
|---|---|---|
| `P2PCrypto` | `DefaultCryptoProvider` (typealias) | BoringSSL under Embedded, Foundation on host |
| `P2PCryptoEmbedded` | `BoringSSLCryptoProvider` | Vendored BoringSSL (C/C++) |
| `P2PCryptoFoundation` | `FoundationCryptoProvider` | swift-crypto / CryptoKit |

`BoringSSLCryptoProvider` and `FoundationCryptoProvider` are public `enum`s
that conform to `CryptoProvider`, wiring each capability associated type
(AEAD, hash, HKDF, HMAC, ECDH, signatures, random, clock, header protection)
to a backend-specific implementation.

## Backend selection

`P2PCrypto` exposes `DefaultCryptoProvider`, a typealias chosen at compile
time:

```swift
#if hasFeature(Embedded)
public typealias DefaultCryptoProvider = BoringSSLCryptoProvider
#else
public typealias DefaultCryptoProvider = FoundationCryptoProvider
#endif
```

The umbrella target's dependency is matched to the same condition (Embedded
builds link only `P2PCryptoEmbedded`; host builds link only
`P2PCryptoFoundation`), so the import always resolves. Depend on `P2PCrypto`
and use `DefaultCryptoProvider` to get the right backend automatically, or
depend on a specific backend product directly.

## Vendored BoringSSL

The Embedded backend uses a vendored BoringSSL under `vendor/p2p-boringssl`
(do not edit — it is upstream). It is a distinct SwiftPM package identity,
`p2p-boringssl`, with C targets `CP2PBoringSSL` and `CP2PBoringSSLShims`
aggregated by the `CBoringSSLForProbe` product. Symbols carry a
`CP2PBoringSSL_*` prefix so the library can coexist in the same binary with
the BoringSSL embedded inside Apple's swift-crypto without duplicate-symbol
collisions. Because BoringSSL is C++, `P2PCryptoEmbedded` links `libc++`.

## Dependencies

| Dependency | Reference | Used by |
|---|---|---|
| `swift-p2p-core` | local path `../swift-p2p-core` | both backends (`P2PCoreCrypto`, `P2PCoreBytes`) |
| `p2p-boringssl` | local path `vendor/p2p-boringssl` | `P2PCryptoEmbedded` |
| `swift-crypto` | `"3.12.3"..<"5.0.0"` | `P2PCryptoFoundation` |

The swift-crypto range deliberately spans into the 4.x line: in the wider
swift-libp2p graph this package is resolved transitively alongside
`swift-tls` and `swift-webrtc`, which require swift-crypto `>= 4.2.0`.

## Correctness

Both backends are exercised against known-answer tests (KATs), and the two
are checked for cross-provider byte-equivalence:

- `P2PCryptoEmbeddedTests` — AEAD (RFC 8439 ChaCha20-Poly1305, NIST
  AES-GCM), hash/HKDF/HMAC, key agreement, signatures, header protection,
  QUIC vectors.
- `P2PCryptoFoundationTests` — KAT / RFC vectors for the Foundation backend.
- `CryptoEquivalenceTests` — AEAD seal output, hashes, and HKDF MUST be
  byte-identical across BoringSSL and swift-crypto, with cross-open interop.
  Signatures and ECDH are cross-*verified* rather than byte-compared, since
  both backends sign non-deterministically.

## Embedded build

Gated on the `P2P_CRYPTO_EMBEDDED` environment variable; the `Lifetimes`
feature is always on (the core's Span surface requires it):

```bash
# Host build (default): swift-crypto backend
swift build

# Embedded build: BoringSSL backend + Embedded feature + WMO
P2P_CRYPTO_EMBEDDED=1 swift build
```

## Requirements

- Swift 6.2+ (tools version `6.2`)
- macOS 26+ / iOS 26+
