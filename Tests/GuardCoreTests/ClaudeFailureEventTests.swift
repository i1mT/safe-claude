import Foundation
import XCTest
@testable import GuardCore

final class ClaudeFailureEventTests: XCTestCase {
    func testRuntimeDispositionUsesConfiguredThresholdAndFailsClosedWithoutEvidence() {
        XCTAssertFalse(ClaudeFailureDisposition.shouldTerminate(safetyScore: 81, minimumScore: 80))
        XCTAssertFalse(ClaudeFailureDisposition.shouldTerminate(safetyScore: 80, minimumScore: 80))
        XCTAssertTrue(ClaudeFailureDisposition.shouldTerminate(safetyScore: 79, minimumScore: 80))
        XCTAssertTrue(ClaudeFailureDisposition.shouldTerminate(safetyScore: nil, minimumScore: 80))
        XCTAssertTrue(ClaudeFailureDisposition.shouldTerminate(safetyScore: 90, minimumScore: nil))
        XCTAssertTrue(ClaudeFailureDisposition.shouldTerminate(safetyScore: 101, minimumScore: 80))
    }

    private func event(_ kind: String, session: String = "session-123") throws -> ClaudeFailureEvent {
        let data = try JSONSerialization.data(withJSONObject: [
            "hook_event_name": "StopFailure", "session_id": session, "error": kind,
        ])
        return try XCTUnwrap(ClaudeFailureEvent.parse(data))
    }

    func testParsesOnlyAllowlistedStopFailureMetadata() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "hook_event_name": "StopFailure",
            "session_id": "session-123",
            "error": "authentication_failed",
            "error_details": "secret detail",
            "last_assistant_message": "sensitive API error text",
        ])
        let event = try XCTUnwrap(ClaudeFailureEvent.parse(data))
        XCTAssertEqual(event.kind, .authenticationFailure)
        XCTAssertEqual(event.sessionDigest.count, 64)
        XCTAssertFalse(event.sessionDigest.contains("session"))
    }

    func testClassifiesNonAuthenticationStopFailureAsAPIFailure() throws {
        let data = try JSONSerialization.data(withJSONObject: [
            "hook_event_name": "StopFailure",
            "session_id": "session-123",
            "error": "rate_limit",
        ])
        XCTAssertEqual(ClaudeFailureEvent.parse(data)?.kind, .apiFailure)
    }

    func testAmbiguousCredentialFailureCategoriesAreConservative() throws {
        for error in ["server_error", "unknown"] {
            let data = try JSONSerialization.data(withJSONObject: [
                "hook_event_name": "StopFailure", "session_id": "session-123", "error": error,
            ])
            XCTAssertEqual(ClaudeFailureEvent.parse(data)?.kind, .authenticationFailure, error)
        }
    }

    func testRejectsOtherEventsUnknownErrorTypesAndMalformedPayloads() throws {
        for object: [String: Any] in [
            ["hook_event_name": "Stop", "session_id": "s", "error": "rate_limit"],
            ["hook_event_name": "StopFailure", "session_id": "s", "error": "arbitrary text"],
            ["hook_event_name": "StopFailure", "session_id": "s"],
        ] {
            XCTAssertNil(ClaudeFailureEvent.parse(try JSONSerialization.data(withJSONObject: object)))
        }
        XCTAssertNil(ClaudeFailureEvent.parse(Data(repeating: 0x20, count: 65_537)))
        XCTAssertNil(ClaudeFailureEvent.parse(Data("not-json".utf8)))
    }

    func testTrackerUsesSeparateRollingWindowsAndDoesNotMixSessions() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let tracker = ClaudeFailureTracker(path: root.appendingPathComponent("failures.json").path)
        let start = Date()
        for offset in 0..<11 {
            let counts = try await tracker.record(event("rate_limit"), at: start.addingTimeInterval(Double(offset)))
            XCTAssertEqual(counts.apiFailuresInMinute, offset + 1)
        }
        let sessionDigest = try event("rate_limit").sessionDigest
        let priorCounts = try await tracker.counts(for: sessionDigest, at: start.addingTimeInterval(11))
        XCTAssertEqual(priorCounts.apiFailuresInMinute, 11)
        for offset in 0..<3 {
            let counts = try await tracker.record(event("authentication_failed"),
                at: start.addingTimeInterval(Double(11 + offset)))
            XCTAssertEqual(counts.authenticationFailuresInTenMinutes, offset + 1)
            XCTAssertEqual(counts.apiFailuresInMinute, 12 + offset)
        }
        let otherSession = try event("rate_limit", session: "different-session")
        let isolated = try await tracker.record(otherSession, at: start.addingTimeInterval(12))
        XCTAssertEqual(isolated.apiFailuresInMinute, 1)
        XCTAssertEqual(isolated.authenticationFailuresInTenMinutes, 0)
        let expired = try await tracker.counts(for: otherSession.sessionDigest,
            at: start.addingTimeInterval(73))
        XCTAssertEqual(expired.apiFailuresInMinute, 0)
    }

    func testTrackerPersistsOnlyHashedSessionMetadataWithPrivatePermissions() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("failures.json").path
        let event = try event("authentication_failed")
        let at = Date()
        _ = try await ClaudeFailureTracker(path: path).record(event, at: at)
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        XCTAssertFalse(String(decoding: data, as: UTF8.self).contains("session-123"))
        XCTAssertEqual(try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber,
                       NSNumber(value: 0o600))
        let counts = try await ClaudeFailureTracker(path: path).counts(for: event.sessionDigest,
            at: at.addingTimeInterval(1))
        XCTAssertEqual(counts.authenticationFailuresInTenMinutes, 1)
    }
}
