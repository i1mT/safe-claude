import XCTest
@testable import GuardCore

final class RuleLabelsTests: XCTestCase {
    func testEveryRuleHasLocalizedTitleAndActionableGuidance() {
        XCTAssertEqual(Set(RuleLabels.chinese.keys), Set(SafetyRuleCatalog.ids))
        XCTAssertEqual(Set(RuleLabels.remediation.keys), Set(SafetyRuleCatalog.ids))
        for rule in SafetyRuleCatalog.ids {
            XCTAssertFalse(RuleLabels.chinese[rule, default: ""].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                           "Missing title for \(rule)")
            XCTAssertFalse(RuleLabels.remediation[rule, default: ""].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                           "Missing remediation for \(rule)")
        }
    }
}
