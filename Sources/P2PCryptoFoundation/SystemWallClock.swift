// SystemWallClock.swift
// The host wall-clock: real Unix-epoch seconds from the system calendar clock.
// Conforms `P2PCoreCrypto.WallClock`. The Embedded build supplies its own
// device-RTC-backed `WallClock` (there is NO Foundation `Date` under Embedded);
// this host default is the one used on macOS/iOS.
import Foundation
import P2PCoreCrypto

/// A host ``WallClock`` backed by the system calendar clock (Foundation `Date`).
public struct SystemWallClock: WallClock {
    public init() {}

    public func nowUnixSeconds() -> Int64 {
        Int64(Date().timeIntervalSince1970)
    }
}
