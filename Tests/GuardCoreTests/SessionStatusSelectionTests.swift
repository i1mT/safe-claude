import Foundation
import XCTest
@testable import GuardCore

final class SessionStatusSelectionTests: XCTestCase {
    func testSelectsLeastSafeSessionAndRejectsStaleState() throws {
        let now = Date()
        let safe = GuardResponse(decision: "allow", safetyScore: 99, reason: "safe", checkedAt: now)
        let warning = GuardResponse(decision: "warning", safetyScore: 84, reason: "warning", checkedAt: now)
        let held = GuardResponse(decision: "hold", scoreUpperBound: 75, reason: "held", checkedAt: now)
        XCTAssertEqual(SessionStatusSelection.worst([safe, warning, held], at: now)?.reason, "held")
        XCTAssertEqual(SessionStatusSelection.worst([safe, warning], at: now)?.reason, "warning")
        XCTAssertEqual(SessionStatusSelection.worst([safe], at: now.addingTimeInterval(46))?.decision, "hold")
        XCTAssertNil(SessionStatusSelection.worst([], at: now))
    }
}
