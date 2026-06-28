// DefaultCryptoProvider.swift
// The single resolution point for the whole stack: `DefaultCryptoProvider`
// selects the right `CryptoProvider` backend for the current build.
//
// Host builds resolve to `FoundationEssentialsCryptoProvider` (swift-crypto / CryptoKit);
// Embedded builds resolve to `BoringSSLCryptoProvider` (vendored BoringSSL).
//
// The manifest includes exactly the backend source set selected by build settings.
#if P2P_CRYPTO_DEFAULT_BORINGSSL
/// The crypto backend selected for this build (Embedded -> BoringSSL).
public typealias DefaultCryptoProvider = BoringSSLCryptoProvider
#else
/// The crypto backend selected for this build (host -> swift-crypto / CryptoKit).
public typealias DefaultCryptoProvider = FoundationEssentialsCryptoProvider
#endif
