// SystemMonotonicClock.swift
// Monotonic time over the platform C clock. Foundation-free and Embedded-clean.
import P2PCoreCrypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WASILibc)
import WASILibc
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
        #if canImport(WASILibc)
        var timestamp: __wasi_timestamp_t = 0
        let errno = __wasi_clock_time_get(__wasi_clockid_t(1), 1, &timestamp)
        guard errno == 0 else {
            preconditionFailure("WASI monotonic clock unavailable")
        }
        return UInt64(timestamp)
        #else
        _ = clock_gettime(CLOCK_MONOTONIC, &ts)
        return UInt64(ts.tv_sec) &* 1_000_000_000 &+ UInt64(ts.tv_nsec)
        #endif
    }
}
