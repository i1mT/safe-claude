import Foundation
import XCTest
@testable import GuardCore

final class SessionExitTrackerTests: XCTestCase {
    func testBaselineChangesAndRestoresWithoutStoringRawAddress() async throws {
        let tracker = SessionExitTracker()
        let time = Date(timeIntervalSince1970: 1_000)
        let firstValue = await tracker.observe(ip: "2001:db8:1:2::1", at: time)
        let first = try XCTUnwrap(firstValue)
        XCTAssertFalse(first.changed)
        let difference = await tracker.differsFromBaseline(ip: "2001:db8:1:3::1")
        XCTAssertEqual(difference, true)
        let sameValue = await tracker.observe(ip: "2001:db8:1:2::2", at: time)
        let samePrefix = try XCTUnwrap(sameValue)
        XCTAssertTrue(samePrefix.changed)
        let changedValue = await tracker.observe(ip: "2001:db8:1:3::1", at: time)
        let changed = try XCTUnwrap(changedValue)
        XCTAssertTrue(changed.changed)
        XCTAssertEqual(changed.eventKey, "event:history-1000.0")
        let repeatValue = await tracker.observe(ip: "2001:db8:1:3::1", at: time.addingTimeInterval(5))
        let repeatChange = try XCTUnwrap(repeatValue)
        XCTAssertEqual(repeatChange.eventKey, changed.eventKey)
        let restoredValue = await tracker.observe(ip: "2001:db8:1:2::1", at: time.addingTimeInterval(6))
        let restored = try XCTUnwrap(restoredValue)
        XCTAssertFalse(restored.changed)
        let invalid = await tracker.observe(ip: "invalid", at: time)
        XCTAssertNil(invalid)
    }
}
