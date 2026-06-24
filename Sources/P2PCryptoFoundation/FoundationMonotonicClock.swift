// FoundationMonotonicClock.swift
// Monotonic time for the host provider. Uses Swift's ContinuousClock, which is
// monotonic and Foundation-free on the host. crypto-impl.md §4.
import P2PCoreCrypto

/// A monotonic clock for the host build. Conforms `P2PCoreCrypto.MonotonicClock`.
public struct FoundationMonotonicClock: MonotonicClock {
    private let origin = ContinuousClock.now

    public init() {}

    public func monotonicMillis() -> UInt64 {
        monotonicNanos() / 1_000_000
    }

    public func monotonicNanos() -> UInt64 {
        let elapsed = ContinuousClock.now - origin
        let (seconds, attoseconds) = elapsed.components
        let nanos = UInt64(max(0, seconds)) &* 1_000_000_000
            &+ UInt64(max(0, attoseconds) / 1_000_000_000)
        return nanos
    }
}
