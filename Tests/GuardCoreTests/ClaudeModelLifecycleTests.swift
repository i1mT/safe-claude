import Foundation
import XCTest
@testable import GuardCore

final class ClaudeModelLifecycleTests: XCTestCase {
    func testOfficialSnapshotDistinguishesActiveDeprecatedAndRetiredModels() {
        let observed = ISO8601DateFormatter()
        observed.formatOptions = [.withFullDate]
        let date = observed.date(from: "2026-11-13")!

        XCTAssertEqual(ClaudeModelLifecycle.assess(["claude-opus-4-8"], at: date), .active)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["claude-sonnet-4-5-20250929"], at: date), .attention)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["claude-mythos-preview"], at: date), .attention)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["claude-opus-4-1-20250805"], at: date), .attention)
    }

    func testAliasesUnknownModelsStaleSnapshotAndInvalidLabels() {
        let observed = ISO8601DateFormatter()
        observed.formatOptions = [.withFullDate]
        let date = observed.date(from: "2026-11-13")!

        XCTAssertEqual(ClaudeModelLifecycle.assess(["sonnet"], at: date), .active)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["best"], at: date), .active)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["default"], at: date), .unknown)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["custom-model-xyz"], at: date), .unknown)
        XCTAssertEqual(ClaudeModelLifecycle.assess(["claude-opus-4-8"], at: date.addingTimeInterval(46 * 86_400)), .unknown)
        XCTAssertFalse(ClaudeModelLifecycle.isValidIdentifier("claude/secret-token"))
    }

    func testFutureLifecycleDatesDoNotActivateBeforeGlobalCalendarBoundary() {
        let observed = ISO8601DateFormatter()
        observed.formatOptions = [.withFullDate]
        let start = observed.date(from: "2026-11-13")!
        XCTAssertEqual(ClaudeModelLifecycle.assess(status: .deprecated, deprecatedAt: "2026-11-13",
            retiredAt: "2026-11-30", at: start.addingTimeInterval(11 * 60 * 60 + 59 * 60)), .active)
        XCTAssertEqual(ClaudeModelLifecycle.assess(status: .deprecated, deprecatedAt: "2026-11-13",
            retiredAt: "2026-11-30", at: start.addingTimeInterval(12 * 60 * 60)), .attention)
        XCTAssertEqual(ClaudeModelLifecycle.assess(status: .retired, deprecatedAt: nil,
            retiredAt: "2026-11-14", at: start.addingTimeInterval(18 * 60 * 60)), .active)
        XCTAssertEqual(ClaudeModelLifecycle.assess(status: .deprecated, deprecatedAt: nil,
            retiredAt: nil, at: start), .unknown)
    }
}
