import Foundation
import Darwin
import XCTest
@testable import GuardCore

final class RouteChangeTrackerTests: XCTestCase {
    func testCountsDistinctObservedChangesWithinWindow() async {
        let tracker = RouteChangeTracker()
        await tracker.observe(Data([1]), at: 10)
        await tracker.observe(Data([1]), at: 11)
        await tracker.observe(Data([2]), at: 12)
        await tracker.observe(nil, at: 13)
        // A missing sample breaks continuity; it is not a measured change.
        await tracker.observe(Data([3]), at: 14)
        await tracker.observe(Data([4]), at: 15)
        await tracker.observe(Data([5]), at: 16)
        let current = await tracker.count(at: 16)
        XCTAssertEqual(current, 3)
        let later = await tracker.count(at: 613)
        XCTAssertEqual(later, 2)
        let expired = await tracker.count(at: 617)
        XCTAssertEqual(expired, 0)
    }

    func testStableRouteOnlyPassesAfterAContinuouslyObservedWindow() async {
        let tracker = RouteChangeTracker()
        for step in 0...300 {
            await tracker.observe(Data([1]), at: 100 + Double(step) * 2)
        }
        let count = await tracker.count(at: 700)
        let covered = await tracker.windowCovered(at: 700)
        XCTAssertEqual(count, 0)
        XCTAssertTrue(covered)
    }

    func testObservationGapAndWakeResetTheStableWindow() async {
        let tracker = RouteChangeTracker()
        for step in 0...20 {
            await tracker.observe(Data([1]), at: 100 + Double(step) * 2)
        }
        let beforeGap = await tracker.windowCovered(at: 141)
        XCTAssertFalse(beforeGap)
        await tracker.observe(Data([1]), at: 200)
        let afterGap = await tracker.windowCovered(at: 200)
        XCTAssertFalse(afterGap)
        await tracker.resetContinuity()
        let afterWake = await tracker.windowCovered()
        XCTAssertFalse(afterWake)
    }

    func testPersistentTrackerRetainsOnlyBoundedRouteTransitions() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("route-changes.json").path
        let key = Data(repeating: 0xA7, count: 32)
        let fingerprint = try SystemFingerprint(keyData: key)
        func route(_ proxy: String) throws -> Data {
            try XCTUnwrap(fingerprint.routeConfigurationDigest(
                proxies: ["HTTPEnable": 1, "HTTPProxy": proxy],
                dns: ["State:/Network/Global/DNS": ["ServerAddresses": ["192.0.2.53"]]]
            ))
        }
        let first = try RouteChangeTracker(persistentPath: path, keyData: key)
        await first.observe(try route("proxy-one.example"))
        await first.observe(try route("proxy-two.example"))
        await first.observe(try route("proxy-three.example"))

        let reloaded = try RouteChangeTracker(persistentPath: path, keyData: key)
        let count = await reloaded.count(at: ProcessInfo.processInfo.systemUptime)
        XCTAssertEqual(count, 2)
        let file = try Data(contentsOf: URL(fileURLWithPath: path))
        let serialized = String(decoding: file, as: UTF8.self)
        XCTAssertFalse(serialized.contains("proxy-one.example"))
        XCTAssertFalse(serialized.contains("192.0.2.53"))
        var info = stat()
        XCTAssertEqual(lstat(path, &info), 0)
        XCTAssertEqual(info.st_mode & 0o777, 0o600)
    }

    func testPersistentFingerprintIsStableOnlyWithTheSameLocalKey() throws {
        let key = Data(repeating: 0x51, count: 32)
        let first = try SystemFingerprint(keyData: key)
        let second = try SystemFingerprint(keyData: key)
        let unrelated = SystemFingerprint()
        let proxies: [String: Any] = ["HTTPEnable": 1, "HTTPProxy": "proxy.example"]
        let dns: [String: Any] = [
            "State:/Network/Global/DNS": ["ServerAddresses": ["192.0.2.53"]]
        ]
        XCTAssertEqual(first.routeConfigurationDigest(proxies: proxies, dns: dns),
                       second.routeConfigurationDigest(proxies: proxies, dns: dns))
        XCTAssertNotEqual(first.routeConfigurationDigest(proxies: proxies, dns: dns),
                          unrelated.routeConfigurationDigest(proxies: proxies, dns: dns))
    }

    func testPersistentFingerprintRejectsWeakKeyMaterial() {
        XCTAssertThrowsError(try SystemFingerprint(keyData: Data(repeating: 1, count: 31)))
    }

    func testKeyRotationDiscardsIncomparablePersistentRouteHistory() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("route-changes.json").path
        let first = try RouteChangeTracker(persistentPath: path,
                                           keyData: Data(repeating: 0x11, count: 32))
        await first.observe(Data(repeating: 0xA1, count: 32))
        await first.observe(Data(repeating: 0xA2, count: 32))

        let rotated = try RouteChangeTracker(persistentPath: path,
                                             keyData: Data(repeating: 0x22, count: 32))
        let count = await rotated.count()
        let covered = await rotated.windowCovered()
        XCTAssertEqual(count, 0)
        XCTAssertFalse(covered)
        await rotated.observe(Data(repeating: 0xA2, count: 32))
        let freshCount = await rotated.count()
        XCTAssertEqual(freshCount, 0)
    }
}
