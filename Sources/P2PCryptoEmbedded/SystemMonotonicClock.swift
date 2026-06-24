// SystemMonotonicClock.swift
// Monotonic time over POSIX clock_gettime(CLOCK_MONOTONIC). Foundation-free and
// Embedded-clean (the Darwin/Glibc C shims compile + link under Embedded Swift).
import P2PCoreCrypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// A monotonic clock backed by `CLOCK_MONOTONIC`. Conforms
/// `P2PCoreCrypto.MonotonicClock`.
public struct SystemMonotonicClock: MonotonicClock {
    public init() {}

    public func monotonicMillis() -> UInt64 {
        monotonicNanos() / 1_000_000
    }

    public func monotonicNanos() -> UInt64 {
        var ts = timespec()
        _ = clock_gettime(CLOCK_MONOTONIC, &ts)
        return UInt64(ts.tv_sec) &* 1_000_000_000 &+ UInt64(ts.tv_nsec)
    }
}
