//===----------------------------------------------------------------------===//
//
// EMBEDDED SPIKE shim.
//
//===----------------------------------------------------------------------===//

// `ContiguousBytes` is a Foundation protocol. Under Embedded (no Foundation), we provide
// a minimal local definition so the BoringSSL wrapper's generic byte-input APIs keep working.
// The real M4 patch would either vendor this protocol in P2PCoreBytes or replace the generic
// parameters with concrete [UInt8]/Span.

public protocol ContiguousBytes {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R
}

extension [UInt8]: ContiguousBytes {}
extension ArraySlice<UInt8>: ContiguousBytes {}
extension UnsafeRawBufferPointer: ContiguousBytes {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try body(self)
    }
}
