# swift-p2p-crypto

Concrete crypto providers for the `CryptoProvider` capability protocols
defined in [`swift-p2p-core`](../swift-p2p-core). Ships two interchangeable
backends — vendored BoringSSL for Embedded Swift, and Apple's swift-crypto /
CryptoKit on the host — behind one umbrella that auto-selects per build,
operating over the stack's `[UInt8]` / `Span<UInt8>` byte currency.

> **Release status.** Current release: `0.1.1`.

## Requirements

- Swift 6.2+ (tools version `6.2`)
- macOS 26+ / iOS 26+

## Installation

Add swift-p2p-crypto to your `Package.swift`:

```swift
.package(url: "https://github.com/1amageek/swift-p2p-crypto.git", from: "0.1.1")
```

## Products

| Product | Provider | Backend |
|---|---|---|
| `P2PCrypto` | `DefaultCryptoProvider` (typealias) | BoringSSL under Embedded, Foundation on host |

`BoringSSLCryptoProvider` and `FoundationEssentialsCryptoProvider` are public `enum`s
that conform to `CryptoProvider`, wiring each capability associated type
(AEAD, hash, HKDF, HMAC, ECDH, signatures, random, clock, header protection)
to a backend-specific implementation.

## Architecture

### Backend selection

`P2PCrypto` exposes `DefaultCryptoProvider`, a typealias chosen at compile
time:

```swift
#if P2P_CRYPTO_DEFAULT_BORINGSSL
public typealias DefaultCryptoProvider = BoringSSLCryptoProvider
#else
public typealias DefaultCryptoProvider = FoundationEssentialsCryptoProvider
#endif
```

The `P2PCrypto` target's source set and dependencies are selected by build
settings. Depend on `P2PCrypto` and use `DefaultCryptoProvider` to get the
right backend automatically.

### Vendored BoringSSL

The Embedded backend uses a vendored BoringSSL under `vendor/p2p-boringssl`
(do not edit; it is upstream-derived). It is wired as local C targets
`CP2PBoringSSL` and `CP2PBoringSSLShims`. Symbols carry a
`CP2PBoringSSL_*` prefix so the library can coexist in the same binary with
the BoringSSL embedded inside Apple's swift-crypto without duplicate-symbol
collisions. Because BoringSSL is C++, BoringSSL builds link `libc++`.

### Dependencies

| Dependency | Reference | Used by |
|---|---|---|
| `swift-p2p-core` | `from: "0.2.1"` | both backends (`P2PCoreCrypto`, `P2PCoreBytes`) |
| vendored BoringSSL | local C targets under `vendor/p2p-boringssl` | BoringSSL backend |
| `swift-crypto` | `"3.12.3"..<"5.0.0"` | FoundationEssentials backend |

The swift-crypto range deliberately spans into the 4.x line: in the wider
swift-libp2p graph this package is resolved transitively alongside
`swift-tls` and `swift-webrtc`, which require swift-crypto `>= 4.2.0`.

## Security

Both backends are exercised against known-answer tests (KATs), and the two
are checked for cross-provider byte-equivalence so a build can swap backends
without changing wire output:

- BoringSSL tests — AEAD (RFC 8439 ChaCha20-Poly1305, NIST
  AES-GCM), hash/HKDF/HMAC, key agreement, signatures, header protection,
  QUIC vectors.
- FoundationEssentials tests — KAT / RFC vectors for the host backend.
- Equivalence tests — AEAD seal output, hashes, and HKDF MUST be
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

# Host BoringSSL backend build
P2P_CRYPTO_BACKEND=boringssl swift build

# Host equivalence test build with both backends present
P2P_CRYPTO_BACKEND=all swift test
```

## Testing

The KAT, RFC-vector, and cross-provider equivalence suites listed under
[Security](#security) run on the host with the default toolchain:

```bash
swift test
```
