//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// EMBEDDED SPIKE: Foundation-free replacement. Original extended `Data` with
// init(copying: RawSpan) and append(contentsOf: RawSpan). Embedded cannot import
// Foundation, so we provide [UInt8] equivalents. The C BoringSSL layer takes raw
// pointers regardless of the Swift container type.

extension [UInt8] {
    /// Copy the raw bytes from the given span into a new byte array.
    init(copying bytes: RawSpan) {
        if bytes.byteCount == 0 {
            self = []
        } else {
            self = bytes.withUnsafeBytes { buffer in
                [UInt8](
                    UnsafeBufferPointer<UInt8>(
                        start: buffer.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        count: buffer.count
                    )
                )
            }
        }
    }

    /// Append the contents of the given span to this byte array.
    mutating func append(contentsOf bytes: RawSpan) {
        bytes.withUnsafeBytes { buffer in
            self.append(contentsOf: buffer)
        }
    }
}
