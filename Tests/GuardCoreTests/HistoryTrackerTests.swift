import Foundation
import XCTest
@testable import GuardCore

final class HistoryTrackerTests: XCTestCase {
    func testFailedHistoryWriteRemainsFailureUntilStorageRecovers() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let storage = root.appendingPathComponent("storage")
        let tracker = try HistoryTracker(persistentPath: storage.appendingPathComponent("history.json").path,
                                         keyData: Data(repeating: 1, count: 32))
        try FileManager.default.removeItem(at: storage)
        let trace = TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US")
        let now = Date()
        let first = await tracker.observe(environment: [:], trace: trace, reputation: nil, at: now)
        let second = await tracker.observe(environment: [:], trace: trace, reputation: nil, at: now)
        XCTAssertNil(first)
        XCTAssertNil(second)
        try FileManager.default.createDirectory(at: storage, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let recovered = await tracker.observe(environment: [:], trace: trace, reputation: nil, at: now)
        XCTAssertNotNil(recovered)
        XCTAssertTrue(FileManager.default.fileExists(atPath: storage.appendingPathComponent("history.json").path))
    }
    func testChangesAreScopedAndOverlappingEventIsDeduplicated() async throws {
        let tracker = HistoryTracker()
        let start = Date()
        var last: HistoryTracker.Summary?
        for i in 0...6 {
            let ip = "192.0.2.\(i + 1)"
            let country = i % 2 == 0 ? "US" : "JP"
            let trace = TraceObservation(targetHost: "api.anthropic.com", ip: ip, countryCode: country)
            let rep = IPReputation(ip: ip, countryCode: country, timeZone: nil, autonomousSystem: 64000 + i,
                                   isDatacenter: nil, isVPN: nil, isProxy: nil, isTor: nil, isAbuser: nil)
            last = await tracker.observe(environment: ["HTTPS_PROXY": "http://user:password@127.0.0.1:8000"],
                                         trace: trace, reputation: rep, at: start.addingTimeInterval(Double(i) * 10))
        }
        let summary = try XCTUnwrap(last)
        XCTAssertTrue(summary.firstRun)
        XCTAssertEqual(Set(summary.triggered.map(\.id)), Set(["C02", "C03", "C04"]))
        let keys = summary.triggered.compactMap { observation -> String? in
            if case .triggered(_, let key) = observation.status { return key }; return nil
        }
        XCTAssertEqual(Set(keys).count, 1)
        let isolated = await tracker.observe(environment: [:],
            trace: TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.7", countryCode: "US"),
            reputation: nil, at: start.addingTimeInterval(70))
        XCTAssertTrue(try XCTUnwrap(isolated).triggered.isEmpty)
    }
    func testIPv6PrivacyChangesInSamePrefixDoNotCountAsNewExit() async throws {
        let tracker = HistoryTracker()
        let start = Date()
        var summary: HistoryTracker.Summary?
        for i in 1...8 {
            summary = await tracker.observe(environment: [:],
                trace: TraceObservation(targetHost: "api.anthropic.com", ip: "2001:db8:1:2::\(i)", countryCode: "US"),
                reputation: nil, at: start.addingTimeInterval(Double(i)))
        }
        XCTAssertFalse(try XCTUnwrap(summary).triggered.contains { $0.id == "C04" })
    }
    func testGeolocationJumpRequiresFreshPairedEvidenceAndStoresOnlyJumpFlag() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("history.json").path
        let tracker = try HistoryTracker(persistentPath: path, keyData: Data(repeating: 9, count: 32))
        let start = Date()
        func inputs(_ ip: String, latitude: Double, longitude: Double) -> (TraceObservation, IPReputation) {
            let trace = TraceObservation(targetHost: "api.anthropic.com", ip: ip, countryCode: "US")
            let reputation = IPReputation(ip: ip, countryCode: "US", timeZone: "UTC",
                latitude: latitude, longitude: longitude, autonomousSystem: 64500,
                isDatacenter: nil, isVPN: nil, isProxy: nil, isTor: nil, isAbuser: nil)
            return (trace, reputation)
        }
        let (firstTrace, firstReputation) = inputs("192.0.2.1", latitude: 0, longitude: 0)
        let firstValue = await tracker.observe(environment: [:], trace: firstTrace,
            reputation: firstReputation, at: start)
        let first = try XCTUnwrap(firstValue)
        XCTAssertEqual(first.observations.first { $0.id == "C05" }?.status,
                       .unknown(source: "history-geolocation-window", critical: true))

        let (nextTrace, nextReputation) = inputs("192.0.2.2", latitude: 20, longitude: 0)
        let nextValue = await tracker.observe(environment: [:], trace: nextTrace,
            reputation: nextReputation, at: start.addingTimeInterval(60))
        let next = try XCTUnwrap(nextValue)
        XCTAssertTrue(next.triggered.contains { $0.id == "C05" })
        let local = LocalEnvironmentSnapshot.collect(environment: [:],
            systemTimeZone: TimeZone(identifier: "UTC")!, systemLocale: Locale(identifier: "en_US"),
            preferredLanguages: ["en"], collectedAt: start.addingTimeInterval(60))
        let observations = EnvironmentAssessment.observations(snapshot: local, apiTrace: nil,
            reputation: nil, countryLanguages: nil, firstRun: false,
            historicalTriggers: next.observations, at: start.addingTimeInterval(60))
        let evaluation = SafetyEvaluator.evaluate(observations)
        XCTAssertTrue(evaluation.deductions.contains { $0.ruleID == "C05" && $0.points == 10 },
                      "\(evaluation.deductions); history=\(next.observations)")
        XCTAssertTrue(evaluation.unknownRuleIDs.contains("C05"))
        XCTAssertEqual(evaluation.decision, .hold)
        XCTAssertEqual(evaluation.ruleStatuses.first { $0.rule == "C05" }?.observedAt,
                       start.addingTimeInterval(60))
        let persisted = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertTrue(persisted.contains("geoJump"))
        XCTAssertFalse(persisted.contains("latitude"))
        XCTAssertFalse(persisted.contains("longitude"))

        let mismatched = TraceObservation(targetHost: "api.anthropic.com",
                                          ip: "192.0.2.3", countryCode: "JP")
        let mismatchedReputation = IPReputation(ip: "192.0.2.3", countryCode: "US", timeZone: "UTC",
            latitude: -20, longitude: 0, autonomousSystem: 64500,
            isDatacenter: nil, isVPN: nil, isProxy: nil, isTor: nil, isAbuser: nil)
        let unknownValue = await tracker.observe(environment: [:], trace: mismatched,
            reputation: mismatchedReputation, at: start.addingTimeInterval(120))
        let unknown = try XCTUnwrap(unknownValue)
        XCTAssertTrue(unknown.triggered.contains { $0.id == "C05" })
    }
    func testPersistentHistorySurvivesRestartWithoutRawAddressesOrProxyCredentials() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("history.json").path
        let key = Data(repeating: 7, count: 32)
        let start = Date()
        let first = try HistoryTracker(persistentPath: path, keyData: key)
        let env = ["HTTPS_PROXY": "http://private-user:private-password@127.0.0.1:8000"]
        for i in 1...4 {
            _ = await first.observe(environment: env,
                trace: TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.\(i)", countryCode: "US"),
                reputation: nil, at: start.addingTimeInterval(Double(i)))
        }
        let content = try String(contentsOfFile: path, encoding: .utf8)
        XCTAssertFalse(content.contains("private-password"))
        XCTAssertFalse(content.contains("192.0.2."))
        let second = try HistoryTracker(persistentPath: path, keyData: key)
        var result: HistoryTracker.Summary?
        for i in 5...7 {
            result = await second.observe(environment: env,
                trace: TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.\(i)", countryCode: "US"),
                reputation: nil, at: start.addingTimeInterval(Double(i)))
        }
        XCTAssertTrue(try XCTUnwrap(result).triggered.contains { $0.id == "C04" })
        try await second.clear()
        let cleared = try HistoryTracker(persistentPath: path, keyData: key)
        let afterClear = await cleared.observe(environment: env,
            trace: TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.8", countryCode: "US"),
            reputation: nil, at: start.addingTimeInterval(8))
        XCTAssertTrue(try XCTUnwrap(afterClear).triggered.isEmpty)
    }
    func testFirstRunDoesNotRequireWaitingButFullWindowNeedsContinuousSamples() async throws {
        let tracker = HistoryTracker()
        let start = Date()
        let trace = TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "US")
        let reputation = IPReputation(ip: trace.ip, countryCode: "US", timeZone: nil, autonomousSystem: 64500,
                                      isDatacenter: nil, isVPN: nil, isProxy: nil, isTor: nil, isAbuser: nil)
        let first = await tracker.observe(environment: [:], trace: trace, reputation: reputation, at: start)
        let initial = try XCTUnwrap(first)
        XCTAssertTrue(initial.firstRun)
        XCTAssertEqual(initial.observations.first { $0.id == "C02" }?.status, .notApplicable)
        XCTAssertEqual(initial.observations.first { $0.id == "C01" }?.status, .notApplicable)
        var result: HistoryTracker.Summary?
        for i in 1...287 {
            result = await tracker.observe(environment: [:], trace: trace, reputation: reputation,
                                           at: start.addingTimeInterval(Double(i) * 300))
        }
        let completed = try XCTUnwrap(result)
        XCTAssertFalse(completed.firstRun)
        for id in ["C02", "C03", "C04"] {
            XCTAssertEqual(completed.observations.first { $0.id == id }?.status, .passed)
        }
        let changedCountry = await tracker.observe(environment: [:],
            trace: TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.2", countryCode: "JP"),
            reputation: nil, at: start.addingTimeInterval(86_400))
        XCTAssertTrue(try XCTUnwrap(changedCountry).triggered.contains { $0.id == "C01" })
    }
}
