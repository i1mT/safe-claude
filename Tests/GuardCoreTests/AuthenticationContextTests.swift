import Foundation
import XCTest
@testable import GuardCore

final class AuthenticationContextTests: XCTestCase {
    func testContextCombinesOnlyAllowlistedMethodLabels() {
        XCTAssertEqual(AuthenticationContext.combine(processMode: "api-key", settingsModes: ["vertex"]),
                       "api-key+vertex")
        XCTAssertNil(AuthenticationContext.combine(processMode: "api-key-secret-value", settingsModes: []))
        XCTAssertNil(AuthenticationContext.combine(processMode: nil, settingsModes: ["private-token"]))
        XCTAssertEqual(AuthenticationContext.combine(processMode: nil, settingsModes: []), "claude-managed")
    }

    func testThreeMethodSwitchesWithinTenMinutesTriggerAndPersist() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("auth-context.json").path
        let now = Date().addingTimeInterval(-240)
        let first = AuthenticationContextTracker(path: path)
        let initial = await first.observe("claude-managed", at: now)
        let oneSwitch = await first.observe("api-key", at: now.addingTimeInterval(60))
        let twoSwitches = await first.observe("vertex", at: now.addingTimeInterval(120))
        let threeSwitches = await first.observe("auth-token", at: now.addingTimeInterval(180))
        XCTAssertEqual(initial, .passed)
        XCTAssertEqual(oneSwitch, .passed)
        XCTAssertEqual(twoSwitches, .passed)
        XCTAssertEqual(threeSwitches, .triggered(.standard, deduplicationKey: nil))
        let second = AuthenticationContextTracker(path: path)
        let afterRestart = await second.observe("bedrock", at: Date())
        XCTAssertEqual(afterRestart, .triggered(.standard, deduplicationKey: nil))
    }

    func testStaleTransitionsExpireAndCorruptStateStaysUnknown() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("auth-context.json").path
        let now = Date().addingTimeInterval(-700)
        let tracker = AuthenticationContextTracker(path: path)
        _ = await tracker.observe("claude-managed", at: now)
        _ = await tracker.observe("api-key", at: now.addingTimeInterval(20))
        let expired = await tracker.observe("api-key", at: now.addingTimeInterval(700))
        XCTAssertEqual(expired, .passed)

        let corruptPath = root.appendingPathComponent("corrupt.json")
        try Data("not-json".utf8).write(to: corruptPath)
        let unknown = await AuthenticationContextTracker(path: corruptPath.path)
            .observe("claude-managed", at: now)
        XCTAssertEqual(unknown, .unknown(source: "auth-context", critical: true))
    }
}
