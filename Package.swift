// swift-tools-version: 6.2
// REQUIRED: platforms .v26 needs PackageDescription 6.2 (Span availability on host).
import PackageDescription

// Embedded toggle controls the experimental Embedded feature + WMO for the
// P2PCrypto umbrella. Embedded builds use the BoringSSL backend.
let embeddedEnabled = Context.environment["P2P_CRYPTO_EMBEDDED"] == "1"
let requestedBackend = Context.environment["P2P_CRYPTO_BACKEND"]
let cryptoBackend = embeddedEnabled ? "boringssl" : (requestedBackend ?? "foundation")
let includeBoringSSL = cryptoBackend == "boringssl" || cryptoBackend == "all"
let includeFoundationEssentials = cryptoBackend == "foundation" || cryptoBackend == "all"
let defaultUsesBoringSSL = cryptoBackend == "boringssl"

// Lifetimes is enabled in BOTH modes because the protocol surface passes
// Span<UInt8> in/out (P2PCoreCrypto enables it; matched here).
let embeddedSettings: [SwiftSetting] = {
    var s: [SwiftSetting] = [.enableExperimentalFeature("Lifetimes")]
    if embeddedEnabled {
        s += [.enableExperimentalFeature("Embedded"), .unsafeFlags(["-wmo"])]
    }
    if defaultUsesBoringSSL {
        s += [.define("P2P_CRYPTO_DEFAULT_BORINGSSL")]
    }
    return s
}()

let cryptoDependencies: [Target.Dependency] = {
    var dependencies: [Target.Dependency] = [
        .product(name: "P2PCoreCrypto", package: "swift-p2p-core"),
        .product(name: "P2PCoreBytes", package: "swift-p2p-core"),
    ]
    if includeBoringSSL {
        dependencies += ["CP2PBoringSSL", "CP2PBoringSSLShims"]
    }
    if includeFoundationEssentials {
        dependencies += [.product(name: "Crypto", package: "swift-crypto")]
    }
    return dependencies
}()

let cryptoSourceExcludes: [String] = {
    switch (includeBoringSSL, includeFoundationEssentials) {
    case (true, true):
        return []
    case (true, false):
        return ["FoundationEssentials"]
    case (false, true):
        return ["BoringSSL"]
    case (false, false):
        return ["BoringSSL", "FoundationEssentials"]
    }
}()

let cryptoTestExcludes: [String] = {
    switch (includeBoringSSL, includeFoundationEssentials) {
    case (true, true):
        return []
    case (true, false):
        return ["FoundationEssentials", "Equivalence"]
    case (false, true):
        return ["BoringSSL", "Equivalence"]
    case (false, false):
        return ["BoringSSL", "FoundationEssentials", "Equivalence"]
    }
}()

let cryptoLinkerSettings: [LinkerSetting] = includeBoringSSL
    ? [.linkedLibrary("c++", .when(platforms: [.macOS, .iOS, .linux]))]
    : []

let packageDependencies: [Package.Dependency] = {
    var dependencies: [Package.Dependency] = [
        .package(url: "https://github.com/1amageek/swift-p2p-core.git", from: "0.2.1"),
    ]
    if includeFoundationEssentials {
        dependencies += [
            .package(url: "https://github.com/apple/swift-crypto.git", "3.12.3"..<"5.0.0"),
        ]
    }
    return dependencies
}()

// The vendored BoringSSL C targets are part of this package's release artifact.
// Keeping them as local targets avoids a separate package identity while retaining
// the CP2PBoringSSL module names and symbol prefix that prevent collisions with
// apple/swift-crypto's BoringSSL.
let boringSSLTargetExclude: [String] = [
    "PrivacyInfo.xcprivacy",
    "hash.txt",
    "CMakeLists.txt",
    "crypto/bio/connect.cc",
    "crypto/bio/socket_helper.cc",
    "crypto/bio/socket.cc",
]

let boringSSLShimsTargetExclude: [String] = [
    "PrivacyInfo.xcprivacy",
    "CMakeLists.txt",
]

let package = Package(
    name: "swift-p2p-crypto",
    platforms: [
        .macOS(.v26),   // Span/RawSpan are @available(macOS 26+) for the host build.
        .iOS(.v26),
    ],
    products: [
        // The Tier-2 umbrella: surfaces `DefaultCryptoProvider` (the single
        // backend-resolution point) for the whole stack. Resolves to the
        // FoundationEssentials host provider on host, the BoringSSL provider
        // under Embedded.
        .library(name: "P2PCrypto",           targets: ["P2PCrypto"]),
    ],
    dependencies: packageDependencies,
    targets: [
        // ---- Umbrella: the single `DefaultCryptoProvider` resolution point ----
        // Build settings select which backend source set and dependencies are
        // present. The public module name stays `P2PCrypto` in every mode.
        .target(
            name: "P2PCrypto",
            dependencies: cryptoDependencies,
            exclude: cryptoSourceExcludes,
            swiftSettings: embeddedSettings,
            // BoringSSL is C++ (.cc): the final embedder/host link pulls in the C++
            // runtime. For the host test build this is `-lc++` (probe confirmed).
            linkerSettings: cryptoLinkerSettings
        ),
        // Vendored BoringSSL is wired as local C targets below. Its C modules are
        // renamed to `CP2PBoringSSL` / `CP2PBoringSSLShims` and its link symbols
        // are prefixed `CP2PBoringSSL_*`, so it coexists with apple/swift-crypto
        // without adding another release repository.
        // The host FoundationEssentials provider sources its high-level `Crypto`
        // from the canonical `apple/swift-crypto` (CryptoKit on Apple). This is
        // the SAME `swift-crypto` identity that swift-p2p-core /
        // swift-certificates use, so a consumer pulling both swift-p2p-crypto and
        // swift-certificates sees one coherent `swift-crypto` and the platform
        // floor is whatever the consumer graph resolves (no forced
        // `.macOS(.v26)`).
        //
        // The range MUST overlap the 4.x line: in the swift-libp2p graph this
        // package is pulled transitively (via quic) alongside swift-tls and
        // swift-webrtc, which both require `swift-crypto >= 4.2.0`. A `from: "3.0.0"`
        // SemVer cap (`3.0.0 ..< 4.0.0`) is DISJOINT from `>= 4.2.0`, so the
        // resolver fails. This range mirrors swift-quic's exact range so the whole
        // graph agrees on one `swift-crypto`. The CryptoKit-style high-level APIs
        // used by FoundationEssentialsCryptoProvider are stable across 3.x -> 4.x.
        .target(
            name: "CP2PBoringSSL",
            path: "vendor/p2p-boringssl/Sources/CP2PBoringSSL",
            exclude: boringSSLTargetExclude,
            cSettings: [
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [Platform.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [Platform.windows])),
                .define("NOMINMAX", .when(platforms: [Platform.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [Platform.windows])),
                .define(
                    "OPENSSL_NO_THREADS_CORRUPT_MEMORY_AND_LEAK_SECRETS_IF_THREADED",
                    .when(platforms: [Platform.wasi])
                ),
                .define("OPENSSL_NO_ASM", .when(platforms: [Platform.wasi])),
            ]
        ),
        .target(
            name: "CP2PBoringSSLShims",
            dependencies: ["CP2PBoringSSL"],
            path: "vendor/p2p-boringssl/Sources/CP2PBoringSSLShims",
            exclude: boringSSLShimsTargetExclude
        ),
        // ---- Tests (host-only) ----
        .testTarget(
            name: "P2PCryptoTests",
            dependencies: ["P2PCrypto"],
            exclude: cryptoTestExcludes
        ),
    ],
    cxxLanguageStandard: .cxx17
)
