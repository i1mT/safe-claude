import Darwin
import Foundation
import XCTest
@testable import GuardCore

final class NetworkTimeStatusTests: XCTestCase {
    func testParserAcceptsOnlyExactSuccessfulSystemSetupOutput() {
        XCTAssertEqual(NetworkTimeStatus.parseSystemSetup(output: "Network Time: On\n", exitCode: 0), .enabled)
        XCTAssertEqual(NetworkTimeStatus.parseSystemSetup(output: "Network Time: Off\n", exitCode: 0), .disabled)
        XCTAssertNil(NetworkTimeStatus.parseSystemSetup(output: "Network Time: On\n", exitCode: 1))
        XCTAssertNil(NetworkTimeStatus.parseSystemSetup(output: "Network Time: Maybe\n", exitCode: 0))
        XCTAssertNil(NetworkTimeStatus.parseSystemSetup(
            output: "Network Time: On\nunexpected\n", exitCode: 0))
        XCTAssertNil(NetworkTimeStatus.parseSystemSetup(output: String(repeating: "x", count: 4097), exitCode: 0))
    }

    func testSnapshotValidationRejectsStaleFutureMalformedAndOversizedEvidence() throws {
        let now = Date(timeIntervalSince1970: 1_000)
        func encoded(_ value: NetworkTimeStatusValue, at time: TimeInterval) throws -> Data {
            try JSONEncoder().encode(NetworkTimeStatusSnapshot(
                value: value, observedAt: Date(timeIntervalSince1970: time)))
        }

        XCTAssertEqual(NetworkTimeStatus.validatedSnapshot(
            from: try encoded(.enabled, at: 820), now: now)?.value, .enabled)
        XCTAssertEqual(NetworkTimeStatus.validatedSnapshot(
            from: try encoded(.enabled, at: 1_005), now: now)?.value, .enabled)
        XCTAssertNil(NetworkTimeStatus.validatedSnapshot(
            from: try encoded(.enabled, at: 819.999), now: now))
        XCTAssertNil(NetworkTimeStatus.validatedSnapshot(
            from: try encoded(.enabled, at: 1_005.001), now: now))
        XCTAssertNil(NetworkTimeStatus.validatedSnapshot(
            from: Data("{".utf8), now: now))
        XCTAssertNil(NetworkTimeStatus.validatedSnapshot(
            from: Data(repeating: 0x20, count: 4097), now: now))

        let unavailable = try encoded(.unavailable, at: 1_000)
        XCTAssertEqual(NetworkTimeStatus.validatedSnapshot(from: unavailable, now: now)?.value,
                       .unavailable)
    }

    func testStatusFileAndDirectoryMetadataMustBeRootOwnedAndNonWritable() {
        XCTAssertTrue(NetworkTimeStatus.isTrustedStatusFile(
            owner: 0, mode: mode_t(S_IFREG | 0o644), size: 128))
        XCTAssertFalse(NetworkTimeStatus.isTrustedStatusFile(
            owner: 501, mode: mode_t(S_IFREG | 0o644), size: 128))
        XCTAssertFalse(NetworkTimeStatus.isTrustedStatusFile(
            owner: 0, mode: mode_t(S_IFREG | 0o666), size: 128))
        XCTAssertFalse(NetworkTimeStatus.isTrustedStatusFile(
            owner: 0, mode: mode_t(S_IFLNK | 0o777), size: 128))
        XCTAssertFalse(NetworkTimeStatus.isTrustedStatusFile(
            owner: 0, mode: mode_t(S_IFREG | 0o644), size: 0))
        XCTAssertFalse(NetworkTimeStatus.isTrustedStatusFile(
            owner: 0, mode: mode_t(S_IFREG | 0o644), size: 4097))

        XCTAssertTrue(NetworkTimeStatus.isTrustedRootDirectory(
            owner: 0, mode: mode_t(S_IFDIR | 0o755)))
        XCTAssertFalse(NetworkTimeStatus.isTrustedRootDirectory(
            owner: 0, mode: mode_t(S_IFDIR | 0o777)))
        XCTAssertFalse(NetworkTimeStatus.isTrustedRootDirectory(
            owner: 501, mode: mode_t(S_IFDIR | 0o755)))
        XCTAssertFalse(NetworkTimeStatus.isTrustedRootDirectory(
            owner: 0, mode: mode_t(S_IFLNK | 0o777)))
        XCTAssertTrue(NetworkTimeStatus.isSafeToRemoveStatusFile(
            owner: 501, expectedOwner: 501, mode: mode_t(S_IFREG | 0o644),
            size: 0, linkCount: 1))
        XCTAssertFalse(NetworkTimeStatus.isSafeToRemoveStatusFile(
            owner: 501, expectedOwner: 0, mode: mode_t(S_IFREG | 0o644),
            size: 0, linkCount: 1))
        XCTAssertFalse(NetworkTimeStatus.isSafeToRemoveStatusFile(
            owner: 501, expectedOwner: 501, mode: mode_t(S_IFLNK | 0o777),
            size: 10, linkCount: 1))
        XCTAssertFalse(NetworkTimeStatus.isSafeToRemoveStatusFile(
            owner: 501, expectedOwner: 501, mode: mode_t(S_IFREG | 0o644),
            size: 4097, linkCount: 1))
        XCTAssertFalse(NetworkTimeStatus.isSafeToRemoveStatusFile(
            owner: 501, expectedOwner: 501, mode: mode_t(S_IFREG | 0o644),
            size: 10, linkCount: 2))
        XCTAssertFalse(NetworkTimeStatus.isSafeToRemoveStatusFile(
            owner: 501, expectedOwner: 501, mode: mode_t(S_IFREG | 0o4644),
            size: 10, linkCount: 1))
    }

    func testSnapshotRemovalUsesNoFollowAndRejectsHardLinks() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("safeclaude-status-removal-\(UUID().uuidString)",
                                   isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let owner = geteuid()
        let snapshot = directory.appendingPathComponent("network-time-status.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: snapshot.path, contents: Data("{}".utf8),
                                                     attributes: [.posixPermissions: 0o644]))
        XCTAssertTrue(try NetworkTimeStatus.removeSnapshotFile(at: snapshot.path,
                                                                expectedOwner: owner))
        XCTAssertFalse(FileManager.default.fileExists(atPath: snapshot.path))

        let target = directory.appendingPathComponent("outside.json")
        let link = directory.appendingPathComponent("network-time-status.json")
        XCTAssertTrue(FileManager.default.createFile(atPath: target.path, contents: Data("keep".utf8),
                                                     attributes: [.posixPermissions: 0o644]))
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        XCTAssertThrowsError(try NetworkTimeStatus.removeSnapshotFile(
            at: link.path, expectedOwner: owner))
        XCTAssertEqual(try Data(contentsOf: target), Data("keep".utf8))

        try FileManager.default.removeItem(at: link)
        let secondLink = directory.appendingPathComponent("second-link.json")
        try FileManager.default.linkItem(at: target, to: secondLink)
        XCTAssertThrowsError(try NetworkTimeStatus.removeSnapshotFile(
            at: target.path, expectedOwner: owner))
        XCTAssertTrue(FileManager.default.fileExists(atPath: target.path))
    }

    func testE08UsesFreshPrivilegedEvidenceAndScoresExplicitDisablement() {
        let snapshot = LocalEnvironmentSnapshot.collect(environment: [:],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en-US"], collectedAt: Date())
        func status(_ value: NetworkTimeStatusValue?) -> ObservationStatus? {
            EnvironmentAssessment.observations(snapshot: snapshot, apiTrace: nil,
                reputation: nil, countryLanguages: nil, firstRun: false,
                networkTimeStatus: value.map { NetworkTimeStatusSnapshot(value: $0) })
                .first(where: { $0.id == "E08" })?.status
        }
        XCTAssertEqual(status(.enabled), .passed)
        XCTAssertEqual(status(.disabled), .triggered(.standard, deduplicationKey: nil))
        XCTAssertEqual(status(.unavailable),
            .unknown(source: "network-time-status-privileged", critical: true))
        XCTAssertEqual(status(nil), .unknown(source: "network-time-status-privileged", critical: true))
    }
}
