// SpanData.swift
// Bridges the protocol's borrowed `Span<UInt8>` surface to swift-crypto's
// `Data`/`[UInt8]` APIs. Host-only; this target is never built Embedded.
//
// Both conversions are single bulk copies (one `memcpy`-class operation), never
// the element-wise `for`-append loop that regressed AEAD throughput: that loop
// re-checks Array growth and bounds per byte, while `withUnsafeBufferPointer`
// hands the contiguous storage to a single `update(from:)` / `Data(buffer:)`.
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#else
#error("FoundationEssentials or Foundation is required for the host provider")
#endif

extension Span where Element == UInt8 {
    /// Copies the borrowed span into an owned array in one bulk copy.
    func toArray() -> [UInt8] {
        let n = count
        guard n > 0 else { return [] }
        return [UInt8](unsafeUninitializedCapacity: n) { destination, initializedCount in
            withUnsafeBufferPointer { source in
                destination.baseAddress!.update(from: source.baseAddress!, count: n)
            }
            initializedCount = n
        }
    }

    /// Copies the borrowed span into `Data` in one bulk copy.
    func toData() -> Data {
        let n = count
        guard n > 0 else { return Data() }
        return withUnsafeBufferPointer { source in
            Data(buffer: source)
        }
    }
}
