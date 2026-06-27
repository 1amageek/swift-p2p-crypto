// FoundationEssentialsWallClock.swift
// The host wall-clock: real Unix-epoch seconds from the system calendar clock.
// Conforms `P2PCoreCrypto.WallClock`. The Embedded build supplies its own
// device-RTC-backed `WallClock`; this host default is the one used on macOS/iOS.
#if canImport(FoundationEssentials)
import FoundationEssentials
#elseif canImport(Foundation)
import Foundation
#else
#error("FoundationEssentials or Foundation is required for the host provider")
#endif
import P2PCoreCrypto

/// A host ``WallClock`` backed by the system calendar clock.
public struct FoundationEssentialsWallClock: WallClock {
    public init() {}

    public func nowUnixSeconds() -> Int64 {
        Int64(Date().timeIntervalSince1970)
    }
}
