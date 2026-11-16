import XCTest
@testable import GuardCore

final class GuardNotificationTransitionTests: XCTestCase {
    func testPersistentRiskNotifiesOnceUntilRecovery() {
        let first = GuardNotificationTransition.next(isActive: false, decision: "hold")
        XCTAssertTrue(first.active)
        XCTAssertEqual(first.event, .risk)

        let continued = GuardNotificationTransition.next(isActive: first.active, decision: "deny")
        XCTAssertTrue(continued.active)
        XCTAssertEqual(continued.event, .none)

        let recovered = GuardNotificationTransition.next(isActive: continued.active, decision: "allow")
        XCTAssertFalse(recovered.active)
        XCTAssertEqual(recovered.event, .recovered)

        let stable = GuardNotificationTransition.next(isActive: recovered.active, decision: "allow")
        XCTAssertFalse(stable.active)
        XCTAssertEqual(stable.event, .none)
    }

    func testWarningStartsAnActiveCondition() {
        let transition = GuardNotificationTransition.next(isActive: false, decision: "warning")
        XCTAssertTrue(transition.active)
        XCTAssertEqual(transition.event, .risk)
    }
}
