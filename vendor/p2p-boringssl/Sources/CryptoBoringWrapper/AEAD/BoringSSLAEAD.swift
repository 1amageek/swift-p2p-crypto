//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2022 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CCryptoBoringSSL
import CCryptoBoringSSLShims

// EMBEDDED SPIKE: no Foundation import. All `Data` returns/uses replaced by [UInt8].

/// An abstraction over a BoringSSL AEAD
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum BoringSSLAEAD {
    /// The supported AEAD ciphers for BoringSSL.
    case aes128gcm
    case aes192gcm
    case aes256gcm
    case aes128gcmsiv
    case aes256gcmsiv
    case chacha20
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    // Arguably this class is excessive, but it's probably better for this API to be as safe as possible
    // rather than rely on defer statements for our cleanup.
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public final class AEADContext {
        private var context: EVP_AEAD_CTX

        public init(cipher: BoringSSLAEAD, key: [UInt8]) throws(CryptoBoringWrapperError) {
            self.context = EVP_AEAD_CTX()

            let rc: CInt = key.withUnsafeBytes { keyPointer in
                withUnsafeMutablePointer(to: &self.context) { contextPointer in
                    // Create the AEAD context with a default tag length using the given key.
                    CCryptoBoringSSLShims_EVP_AEAD_CTX_init(
                        contextPointer,
                        cipher.boringSSLCipher,
                        keyPointer.baseAddress,
                        keyPointer.count,
                        0,
                        nil
                    )
                }
            }

            guard rc == 1 else {
                throw CryptoBoringWrapperError.internalBoringSSLError()
            }
        }

        deinit {
            withUnsafeMutablePointer(to: &self.context) { contextPointer in
                CCryptoBoringSSL_EVP_AEAD_CTX_cleanup(contextPointer)
            }
        }
    }
}

// MARK: - Sealing

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD.AEADContext {
    /// The main entry point for sealing data.
    /// EMBEDDED SPIKE: was generic over DataProtocol/ContiguousBytes (Foundation protocols).
    /// Replaced with concrete [UInt8] to keep the wrapper Foundation-free. The real M4
    /// patch would instead make these generic over a stdlib `Sequence<UInt8>`/`Span` so
    /// the higher-level Crypto module can still pass its byte containers.
    public func seal(
        message: [UInt8],
        nonce: [UInt8],
        authenticatedData: [UInt8]
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        try self._sealContiguous(
            message: message,
            nonce: nonce,
            authenticatedData: authenticatedData
        )
    }

    /// A fast-path for sealing contiguous data.
    @inlinable
    func _sealContiguous(
        message: [UInt8],
        nonce: [UInt8],
        authenticatedData: [UInt8]
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        try message.withUnsafeBytes { messagePointer in
            try nonce.withUnsafeBytes { noncePointer in
                try authenticatedData.withUnsafeBytes { authenticatedDataPointer in
                    try self._sealContiguous(
                        plaintext: messagePointer.bytes,
                        nonce: noncePointer.bytes,
                        authenticatedData: authenticatedDataPointer.bytes
                    )
                }
            }
        }
    }

    /// Lowest level seal operation that calls into BoringSSL directly and
    /// operates on already-allocated memory.
    #if swift(<6.3)
    @_lifetime(tag: copy tag)
    #endif
    public func seal(
        message: inout MutableRawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan,
        tag: inout OutputRawSpan
    ) throws(CryptoBoringWrapperError) {
        let tagByteCount = CCryptoBoringSSL_EVP_AEAD_max_overhead(self.context.aead)
        precondition(tag.freeCapacity >= tagByteCount)
        var actualTagSize = tagByteCount

        let rc = withUnsafeMutablePointer(to: &self.context) { contextPointer in
            message.withUnsafeMutableBytes { messageBuffer in
                tag.withUnsafeMutableBytes { tagBuffer, tagInitializedCount in
                    defer {
                        tagInitializedCount += actualTagSize
                    }

                    return authenticatedData.withUnsafeBytes { authenticatedDataBuffer in
                        nonce.withUnsafeBytes { nonceBuffer in
                            CCryptoBoringSSLShims_EVP_AEAD_CTX_seal_scatter(
                                contextPointer,
                                messageBuffer.baseAddress,
                                tagBuffer.baseAddress! + tagInitializedCount,
                                &actualTagSize,
                                tagBuffer.count - tagInitializedCount,
                                nonceBuffer.baseAddress,
                                nonceBuffer.count,
                                messageBuffer.baseAddress,
                                messageBuffer.count,
                                nil,
                                0,
                                authenticatedDataBuffer.baseAddress,
                                authenticatedDataBuffer.count
                            )
                        }

                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
    }

    /// The unsafe base call: not inlinable so that it can touch private variables.
    @usableFromInline
    func _sealContiguous(
        plaintext: RawSpan,
        nonce: RawSpan,
        authenticatedData: RawSpan
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        let tagByteCount = CCryptoBoringSSL_EVP_AEAD_max_overhead(self.context.aead)

        // Form the combined represention of a sealed box with nonce + plaintext + tag.
        var combined = [UInt8]()
        combined.reserveCapacity(nonce.byteCount + plaintext.byteCount + tagByteCount)
        combined.append(contentsOf: nonce)
        combined.append(contentsOf: plaintext)
        combined.append(contentsOf: [UInt8](repeating: 0, count: tagByteCount))

        try combined.withUnsafeMutableBytes { (combinedBuffer: UnsafeMutableRawBufferPointer) in
            let messageRange = nonce.byteCount..<(nonce.byteCount + plaintext.byteCount)
            let messageBuffer = UnsafeMutableRawBufferPointer(rebasing: combinedBuffer[messageRange])
            var messageSpan = messageBuffer.mutableBytes

            let tagBuffer = UnsafeMutableRawBufferPointer(
                rebasing: combinedBuffer[(nonce.byteCount + plaintext.byteCount)...]
            )
            var tagSpan = OutputRawSpan(buffer: tagBuffer, initializedCount: 0)
            try seal(
                message: &messageSpan,
                nonce: nonce,
                authenticatedData: authenticatedData,
                tag: &tagSpan
            )
            let tagBytesWritten = tagSpan.finalize(for: tagBuffer)
            assert(tagBytesWritten == tagByteCount)
        }

        return combined
    }
}

// MARK: - Opening

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD.AEADContext {
    /// The main entry point for opening data.
    /// EMBEDDED SPIKE: concrete [UInt8] instead of DataProtocol/ContiguousBytes generics.
    @inlinable
    public func open(
        ciphertext: [UInt8],
        nonce: [UInt8],
        tag: [UInt8],
        authenticatedData: [UInt8]
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        try self._openContiguous(
            ciphertext: ciphertext,
            nonce: nonce,
            tag: tag,
            authenticatedData: authenticatedData
        )
    }

    /// A fast-path for opening contiguous data.
    @inlinable
    func _openContiguous(
        ciphertext: [UInt8],
        nonce: [UInt8],
        tag: [UInt8],
        authenticatedData: [UInt8]
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        try ciphertext.withUnsafeBytes { ciphertextPointer in
            try nonce.withUnsafeBytes { nonceBytes in
                try tag.withUnsafeBytes { tagBytes in
                    try authenticatedData.withUnsafeBytes { authenticatedDataBytes in
                        try self._openContiguous(
                            ciphertext: ciphertextPointer.bytes,
                            nonceBytes: nonceBytes.bytes,
                            tagBytes: tagBytes.bytes,
                            authenticatedData: authenticatedDataBytes.bytes
                        )
                    }
                }
            }
        }
    }

    /// Lowest level call into BoringSSL that decrypts in place.
    #if swift(<6.3)
    @_lifetime(message: copy message)
    #endif
    public func open(
        message: inout MutableRawSpan,
        nonce: RawSpan,
        tag: RawSpan,
        authenticatedData: RawSpan
    ) throws(CryptoBoringWrapperError) {
        let rc = withUnsafePointer(to: &self.context) { contextPointer in
            message.withUnsafeMutableBytes { messageBuffer in
                nonce.withUnsafeBytes { nonceBuffer in
                    tag.withUnsafeBytes { tagBuffer in
                        authenticatedData.withUnsafeBytes { adBuffer in
                            CCryptoBoringSSLShims_EVP_AEAD_CTX_open_gather(
                                contextPointer,
                                messageBuffer.baseAddress,
                                nonceBuffer.baseAddress,
                                nonceBuffer.count,
                                messageBuffer.baseAddress,
                                messageBuffer.count,
                                tagBuffer.baseAddress,
                                tagBuffer.count,
                                adBuffer.baseAddress,
                                adBuffer.count
                            )
                        }
                    }
                }
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }
    }

    /// The unsafe base call: not inlinable so that it can touch private variables.
    @usableFromInline
    func _openContiguous(
        ciphertext: RawSpan,
        nonceBytes: RawSpan,
        tagBytes: RawSpan,
        authenticatedData: RawSpan
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        var output = [UInt8](copying: ciphertext)
        try output.withUnsafeMutableBytes { bytes in
            var outputSpan = bytes.mutableBytes
            try open(message: &outputSpan, nonce: nonceBytes, tag: tagBytes, authenticatedData: authenticatedData)
        }
        return output
    }

    /// An additional entry point for opening combined ciphertext+tag.
    /// EMBEDDED SPIKE: concrete [UInt8] instead of DataProtocol/ContiguousBytes generics.
    @inlinable
    public func open(
        combinedCiphertextAndTag: [UInt8],
        nonce: [UInt8],
        authenticatedData: [UInt8]
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        try combinedCiphertextAndTag.withUnsafeBytes { combinedCiphertextAndTagPointer in
            try nonce.withUnsafeBytes { nonceBytes in
                try authenticatedData.withUnsafeBytes { authenticatedDataBytes in
                    try self._openContiguous(
                        combinedCiphertextAndTag: combinedCiphertextAndTagPointer,
                        nonceBytes: nonceBytes,
                        authenticatedData: authenticatedDataBytes
                    )
                }
            }
        }
    }

    /// The unsafe base call: not inlinable so that it can touch private variables.
    @usableFromInline
    func _openContiguous(
        combinedCiphertextAndTag: UnsafeRawBufferPointer,
        nonceBytes: UnsafeRawBufferPointer,
        authenticatedData: UnsafeRawBufferPointer
    ) throws(CryptoBoringWrapperError) -> [UInt8] {
        // EMBEDDED SPIKE: allocate a [UInt8] output buffer instead of malloc + Data(bytesNoCopy:).
        var output = [UInt8](repeating: 0, count: combinedCiphertextAndTag.count)

        var writtenBytes = 0
        let rc = output.withUnsafeMutableBytes { outputBuffer in
            withUnsafePointer(to: &self.context) { contextPointer in
                CCryptoBoringSSLShims_EVP_AEAD_CTX_open(
                    contextPointer,
                    outputBuffer.baseAddress,
                    &writtenBytes,
                    outputBuffer.count,
                    nonceBytes.baseAddress,
                    nonceBytes.count,
                    combinedCiphertextAndTag.baseAddress,
                    combinedCiphertextAndTag.count,
                    authenticatedData.baseAddress,
                    authenticatedData.count
                )
            }
        }

        guard rc == 1 else {
            throw CryptoBoringWrapperError.internalBoringSSLError()
        }

        output.removeLast(output.count - writtenBytes)
        return output
    }

}

// MARK: - Supported ciphers

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BoringSSLAEAD {
    var boringSSLCipher: OpaquePointer {
        switch self {
        case .aes128gcm:
            return CCryptoBoringSSL_EVP_aead_aes_128_gcm()
        case .aes192gcm:
            return CCryptoBoringSSL_EVP_aead_aes_192_gcm()
        case .aes256gcm:
            return CCryptoBoringSSL_EVP_aead_aes_256_gcm()
        case .aes128gcmsiv:
            return CCryptoBoringSSL_EVP_aead_aes_128_gcm_siv()
        case .aes256gcmsiv:
            return CCryptoBoringSSL_EVP_aead_aes_256_gcm_siv()
        case .chacha20:
            return CCryptoBoringSSL_EVP_aead_chacha20_poly1305()
        }
    }
}
