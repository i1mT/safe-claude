import Foundation
import XCTest
@testable import GuardCore

final class LaunchRateTrackerTests: XCTestCase {
    func testAuthorizedLaunchRateSurvivesTrackerRestart() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("launch-rate.json").path

        let first = try LaunchRateTracker(path: path)
        let firstCount = try await first.recordStart()
        let secondCount = try await first.recordStart()
        XCTAssertEqual(firstCount, 1)
        XCTAssertEqual(secondCount, 2)

        let relaunched = try LaunchRateTracker(path: path)
        let relaunchedCount = await relaunched.count()
        XCTAssertEqual(relaunchedCount, 2)
        let stored = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: path))) as? [String: Any])
        XCTAssertEqual(Set(stored.keys), Set(["version", "starts"]))
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testExpiredLaunchesDoNotSurviveTheRollingWindow() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: directory.path)
        let path = directory.appendingPathComponent("launch-rate.json").path
        let old = Date(timeIntervalSinceNow: -120)
        let data = try JSONSerialization.data(withJSONObject: [
            "version": 1,
            "starts": [old.timeIntervalSinceReferenceDate],
        ])
        try data.write(to: URL(fileURLWithPath: path))
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: path)

        let tracker = try LaunchRateTracker(path: path)
        let count = await tracker.count()
        XCTAssertEqual(count, 0)
    }

    func testRejectsCorruptAndSymlinkedStores() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: directory.path)
        let target = directory.appendingPathComponent("target.json")
        let path = directory.appendingPathComponent("launch-rate.json")
        try Data("{}".utf8).write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: target.path)
        try FileManager.default.createSymbolicLink(at: path, withDestinationURL: target)
        XCTAssertThrowsError(try LaunchRateTracker(path: path.path))

        try FileManager.default.removeItem(at: path)
        try Data("invalid".utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600],
                                              ofItemAtPath: path.path)
        XCTAssertThrowsError(try LaunchRateTracker(path: path.path))
    }

    func testFailedPersistenceRollsBackTheInMemoryCounter() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let path = directory.appendingPathComponent("launch-rate.json").path
        let tracker = try LaunchRateTracker(path: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o500],
                                              ofItemAtPath: directory.path)
        do {
            _ = try await tracker.recordStart()
            XCTFail("a read-only data directory must reject persistence")
        } catch {
            let countAfterFailure = await tracker.count()
            XCTAssertEqual(countAfterFailure, 0)
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o700],
                                              ofItemAtPath: directory.path)
        let recoveredCount = try await tracker.recordStart()
        XCTAssertEqual(recoveredCount, 1)
    }
}
