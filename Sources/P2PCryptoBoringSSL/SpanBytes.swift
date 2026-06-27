// SpanBytes.swift
// Local helpers to move between the protocol's borrowed `Span<UInt8>` surface
// and the owned `[UInt8]` buffers BoringSSL consumes. The C calls run inside
// `withUnsafeBufferPointer`; we never throw from inside that closure (the typed
// error is raised outside, sidestepping the rethrows/`any Error` erosion noted
// in crypto-impl.md §5.1).
extension Span where Element == UInt8 {
    /// Copies the borrowed span into an owned array in one bulk copy (the only
    /// safe way to hand a span's bytes to a C call that may outlive the borrow
    /// scope's closure nesting). A single `update(from:)` `memcpy` replaces the
    /// element-wise `for`-append loop that re-checks Array growth per byte.
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
}
