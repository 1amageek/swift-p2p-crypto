// swift-tools-version:6.2
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2023 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// This package contains a vendored copy of BoringSSL. For ease of tracking
// down problems with the copy of BoringSSL in use, we include a copy of the
// commit hash of the revision of BoringSSL included in the given release.
// This is also reproduced in a file called hash.txt in the
// Sources/CP2PBoringSSL directory. The source repository is at
// https://boringssl.googlesource.com/boringssl.
//
// BoringSSL Commit: 0226f30467f540a3f62ef48d453f93927da199b6

import PackageDescription

// MINIMAL VENDORED BoringSSL for swift-p2p-crypto's Embedded provider.
//
// This package has a DISTINCT identity (`p2p-boringssl`, derived from the
// directory name) so it never collides with `apple/swift-crypto` when both are
// present in a consumer's package graph. The host Foundation provider sources
// its high-level `Crypto` from `apple/swift-crypto`; this package only exposes
// the C BoringSSL targets the Embedded provider links.
//
// The C BoringSSL targets are renamed to `CP2PBoringSSL` / `CP2PBoringSSLShims`
// (module + SwiftPM target names) AND the `BORINGSSL_PREFIX` symbol-mangling
// value is changed to `CP2PBoringSSL`, so the exported link symbols are
// `CP2PBoringSSL_*` rather than `CCryptoBoringSSL_*`. This lets the vendored
// BoringSSL coexist in the same binary as `apple/swift-crypto`'s BoringSSL
// (e.g. the cross-provider equivalence tests) without duplicate-symbol errors.
//
// C compilation is clang-driven and unaffected by the Embedded Swift flag,
// which is applied by the *consuming* target. No BoringSSL source is modified
// beyond the prefix/target renames described above.

// In Darwin builds the privacy manifest resource pulls in Foundation via the
// SPM-generated `Bundle.module` accessor, which cannot compile under Embedded.
// Drop the resource entirely on all platforms; exclude it from the sources.
let privacyManifestExclude: [String] = ["PrivacyInfo.xcprivacy"]
let privacyManifestResource: [PackageDescription.Resource] = []

let package = Package(
    name: "p2p-boringssl",
    platforms: [.macOS("26.0"), .iOS("26.0")],
    products: [
        // Expose the C BoringSSL targets for the Embedded BoringSSLCryptoProvider.
        .library(name: "CBoringSSLForProbe", targets: ["CP2PBoringSSL", "CP2PBoringSSLShims"]),
    ],
    targets: [
        .target(
            name: "CP2PBoringSSL",
            exclude: privacyManifestExclude + [
                "hash.txt",
                "CMakeLists.txt",
                /*
                 * These files are excluded to support WASI libc which doesn't provide <netdb.h>.
                 * This is safe for all platforms as we do not rely on networking features.
                 */
                "crypto/bio/connect.cc",
                "crypto/bio/socket_helper.cc",
                "crypto/bio/socket.cc",
            ],
            resources: privacyManifestResource,
            cSettings: [
                // These defines come from BoringSSL's build system
                .define("_HAS_EXCEPTIONS", to: "0", .when(platforms: [Platform.windows])),
                .define("WIN32_LEAN_AND_MEAN", .when(platforms: [Platform.windows])),
                .define("NOMINMAX", .when(platforms: [Platform.windows])),
                .define("_CRT_SECURE_NO_WARNINGS", .when(platforms: [Platform.windows])),
                /*
                 * These defines are required on Wasm/WASI, to disable use of pthread.
                 */
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
            exclude: privacyManifestExclude + [
                "CMakeLists.txt"
            ],
            resources: privacyManifestResource
        ),
    ],
    cxxLanguageStandard: .cxx17
)
