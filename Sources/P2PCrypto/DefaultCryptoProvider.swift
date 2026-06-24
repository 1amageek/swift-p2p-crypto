// DefaultCryptoProvider.swift
// The single resolution point for the whole stack: `DefaultCryptoProvider`
// selects the right `CryptoProvider` backend for the current build.
//
// Host builds resolve to `FoundationCryptoProvider` (swift-crypto / CryptoKit);
// Embedded builds resolve to `BoringSSLCryptoProvider` (vendored BoringSSL).
//
// The `#if hasFeature(Embedded)` branch is matched by the package manifest: under
// `P2P_CRYPTO_EMBEDDED=1` this target depends ONLY on `P2PCryptoEmbedded`, so the
// Embedded build never links the Foundation provider (no Foundation leak); on the
// host it depends ONLY on `P2PCryptoFoundation`. Each branch therefore names a
// type that is actually present in that build.
#if hasFeature(Embedded)
import P2PCryptoEmbedded

/// The crypto backend selected for this build (Embedded → BoringSSL).
public typealias DefaultCryptoProvider = BoringSSLCryptoProvider
#else
import P2PCryptoFoundation

/// The crypto backend selected for this build (host → swift-crypto / CryptoKit).
public typealias DefaultCryptoProvider = FoundationCryptoProvider
#endif
