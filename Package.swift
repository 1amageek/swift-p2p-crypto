// swift-tools-version: 6.2
// REQUIRED: platforms .v26 needs PackageDescription 6.2 (Span availability on host).
import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO for the
// P2PCryptoEmbedded provider (BoringSSLCryptoProvider) and the P2PCrypto
// umbrella. The Foundation provider and all test targets are NEVER built
// Embedded.
let embeddedEnabled = Context.environment["P2P_CRYPTO_EMBEDDED"] == "1"

// Lifetimes is enabled in BOTH modes because the protocol surface passes
// Span<UInt8> in/out (P2PCoreCrypto enables it; matched here).
let embeddedSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    return s
}()

let package = Package(
    name: "swift-p2p-crypto",
    platforms: [
        .macOS(.v26),   // Span/RawSpan are @available(macOS 26+) for the host build.
        .iOS(.v26),
    ],
    products: [
        // The Tier-2 umbrella: surfaces `DefaultCryptoProvider` (the single
        // backend-resolution point) for the whole stack. Resolves to the
        // Foundation provider on host, the BoringSSL provider under Embedded.
        .library(name: "P2PCrypto",           targets: ["P2PCrypto"]),
        .library(name: "P2PCryptoEmbedded",   targets: ["P2PCryptoEmbedded"]),
        .library(name: "P2PCryptoFoundation", targets: ["P2PCryptoFoundation"]),
    ],
    dependencies: [
        .package(path: "../swift-p2p-core"),
        // A single vendored swift-crypto checkout (BoringSSL commit
        // 0226f30467f540a3f62ef48d453f93927da199b6) serves BOTH providers:
        //   - the C BoringSSL targets (CBoringSSLForProbe) for the Embedded provider,
        //   - the high-level Crypto / _CryptoExtras for the host provider.
        // Using one checkout avoids the cross-package C-target name collision that
        // two separate swift-crypto packages would cause. Only the manifest differs
        // from the spike; no BoringSSL/Swift source is modified.
        .package(path: "vendor/swift-crypto"),
    ],
    targets: [
        // ---- Umbrella: the single `DefaultCryptoProvider` resolution point ----
        // Conditional dependency keeps the Embedded build free of the Foundation
        // provider: under P2P_CRYPTO_EMBEDDED=1 it depends ONLY on the BoringSSL
        // provider; on host ONLY on the Foundation provider. The source matches
        // this with `#if hasFeature(Embedded)`.
        .target(
            name: "P2PCrypto",
            dependencies: embeddedEnabled
                ? ["P2PCryptoEmbedded"]
                : ["P2PCryptoFoundation"],
            swiftSettings: embeddedSettings
        ),
        // ---- Embedded-clean provider: thin Swift shim over vendored C BoringSSL ----
        .target(
            name: "P2PCryptoEmbedded",
            dependencies: [
                .product(name: "P2PCoreCrypto",       package: "swift-p2p-core"),
                .product(name: "P2PCoreBytes",        package: "swift-p2p-core"),
                .product(name: "CBoringSSLForProbe",  package: "swift-crypto"),
            ],
            swiftSettings: embeddedSettings,
            // BoringSSL is C++ (.cc): the final embedder/host link pulls in the C++
            // runtime. For the host test build this is `-lc++` (probe confirmed).
            linkerSettings: [.linkedLibrary("c++", .when(platforms: [.macOS, .iOS, .linux]))]
        ),
        // ---- Host-only Foundation provider: swift-crypto / CryptoKit (+ _CryptoExtras) ----
        .target(
            name: "P2PCryptoFoundation",
            dependencies: [
                .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
                .product(name: "P2PCoreBytes",  package: "swift-p2p-core"),
                .product(name: "Crypto",        package: "swift-crypto"),
                // _CryptoExtras (AES._CBC) is only the off-Apple AES header-protection
                // fallback (crypto-impl.md §4). On Apple the host provider uses
                // CommonCrypto AES-ECB, so _CryptoExtras is intentionally not a
                // dependency here. It would be added with a `.when(platforms:)`
                // guard for a Linux host build.
            ]
        ),
        // ---- Tests (host-only) ----
        .testTarget(
            name: "P2PCryptoEmbeddedTests",
            dependencies: ["P2PCryptoEmbedded"]
        ),
        .testTarget(
            name: "P2PCryptoFoundationTests",
            dependencies: ["P2PCryptoFoundation"]
        ),
        .testTarget(
            name: "CryptoEquivalenceTests",
            dependencies: ["P2PCryptoEmbedded", "P2PCryptoFoundation"]
        ),
    ]
)
