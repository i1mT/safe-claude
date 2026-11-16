import XCTest
@testable import GuardCore

final class SafetyEvaluationTests: XCTestCase {
    private func observations(_ changes: [String: ObservationStatus]) -> [RuleObservation] {
        SafetyRuleCatalog.ids.map { RuleObservation(id: $0, status: changes[$0] ?? .passed) }
    }

    func testAll64AreRequired() {
        XCTAssertEqual(SafetyRuleCatalog.ids.count, 64)
        let empty = SafetyEvaluator.evaluate([])
        XCTAssertEqual(empty.decision, .hold)
        XCTAssertNil(empty.safetyScore)
        XCTAssertEqual(empty.missingRuleIDs.count, 64)
        XCTAssertEqual(empty.scoreUpperBound, 80)
        XCTAssertEqual(empty.ruleStatuses.count, 64)
        XCTAssertTrue(empty.ruleStatuses.allSatisfy { $0.status == "missing" })
        XCTAssertTrue(empty.ruleStatuses.allSatisfy { $0.remediation?.isEmpty == false })
    }

    func testRuleReportPreservesObservationStatesAndTriggeredPoints() {
        let result = SafetyEvaluator.evaluate(observations([
            "A01": .notApplicable,
            "A02": .triggered(.standard, deduplicationKey: nil),
            "A03": .unknown(source: "target-route", critical: true),
            "A04": .unsupported(source: "adapter", required: false),
        ]))
        let states = Dictionary(uniqueKeysWithValues: result.ruleStatuses.map { ($0.rule, $0) })
        XCTAssertEqual(states["A01"]?.status, "notApplicable")
        XCTAssertEqual(states["A02"]?.status, "triggered")
        XCTAssertEqual(states["A02"]?.points, 40)
        XCTAssertEqual(states["A03"]?.status, "unknown")
        XCTAssertEqual(states["A03"]?.source, "target-route")
        XCTAssertEqual(states["A04"]?.status, "unsupported")
        XCTAssertEqual(states["A05"]?.status, "passed")
        XCTAssertEqual(states["A01"]?.remediation, RuleLabels.remediation["A01"])
        XCTAssertEqual(states["A03"]?.remediation, RuleLabels.remediation["A03"])
    }

    func testObservedRiskCanScoreWhileRemainingEvidenceKeepsTheRuleUnknown() {
        let values = SafetyRuleCatalog.ids.map { id in
            RuleObservation(id: id, status: id == "B07"
                ? .triggeredAndUnknown(.standard, deduplicationKey: "provider:fixture",
                    source: "proxycheck-p2p-unobserved", critical: false)
                : .passed)
        }
        let result = SafetyEvaluator.evaluate(values)
        XCTAssertEqual(result.deductions.first { $0.ruleID == "B07" }?.points, 10)
        XCTAssertTrue(result.unknownRuleIDs.contains("B07"))
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "B07" }?.status, "triggeredUnknown")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "B07" }?.source, "proxycheck-p2p-unobserved")
        XCTAssertEqual(result.decision, .hold)
        XCTAssertNil(result.safetyScore)
    }

    func testReportSourceRejectsArbitraryPaths() {
        let result = SafetyEvaluator.evaluate(observations([
            "A03": .unknown(source: "/Users/private/project", critical: true),
            "A04": .unknown(source: "collector-gap-A04", critical: true),
            "A05": .unknown(source: "collector-gap-/Users/private", critical: true),
        ]))
        XCTAssertNil(result.ruleStatuses.first(where: { $0.rule == "A03" })?.source)
        XCTAssertEqual(result.ruleStatuses.first(where: { $0.rule == "A04" })?.source, "collector-gap-A04")
        XCTAssertNil(result.ruleStatuses.first(where: { $0.rule == "A05" })?.source)
    }

    func testGeolocationJumpCanScoreAndExposeItsUnknownPrecision() {
        let result = SafetyEvaluator.evaluate(observations([
            "C05": .triggeredAndUnknown(.standard, deduplicationKey: "event:geo",
                source: "geolocation-accuracy-unreported", critical: true),
        ]))
        XCTAssertEqual(result.deductions.first { $0.ruleID == "C05" }?.points, 10)
        XCTAssertTrue(result.unknownRuleIDs.contains("C05"))
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "C05" }?.status, "triggeredUnknown")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "C05" }?.source,
                       "geolocation-accuracy-unreported")
        XCTAssertEqual(result.decision, .hold)
    }

    func testModelLifecycleSourceIsReportableButArbitraryModelTextIsNot() {
        let result = SafetyEvaluator.evaluate(observations([
            "G06": .unknown(source: "model-lifecycle", critical: true),
        ]))
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "G06" }?.source, "model-lifecycle")
    }

    func testRuntimeVirtualizationUnknownSourceIsReportable() {
        let result = SafetyEvaluator.evaluate(observations([
            "E09": .unknown(source: "runtime-virtualization", critical: false),
        ]))
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "E09" }?.source, "runtime-virtualization")
    }

    func testIPAPICollectorSourcesAreReportable() {
        let result = SafetyEvaluator.evaluate(observations([
            "B02": .unknown(source: "ipapi-is", critical: false),
            "B03": .unknown(source: "ipapi-is-open-proxy-only", critical: false),
        ]))
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "B02" }?.source, "ipapi-is")
        XCTAssertEqual(result.ruleStatuses.first { $0.rule == "B03" }?.source, "ipapi-is-open-proxy-only")
    }

    func testWeakSignalsAccumulateAndCanDeny() {
        let result = SafetyEvaluator.evaluate(observations([
            "B05": .triggered(.standard, deduplicationKey: nil), // -8
            "B04": .triggered(.standard, deduplicationKey: nil), // -6
            "E01": .triggered(.standard, deduplicationKey: nil), // -6
            "E03": .triggered(.standard, deduplicationKey: nil), // -3
        ]))
        XCTAssertEqual(result.safetyScore, 77)
        XCTAssertEqual(result.decision, .deny)
        XCTAssertEqual(result.deductions.map(\.ruleID), ["B04", "B05", "E01", "E03"])
    }

    func testThresholdBoundaries() {
        let one = observations(["C01": .triggered(.standard, deduplicationKey: nil)])
        XCTAssertEqual(SafetyEvaluator.evaluate(one).safetyScore, 80)
        XCTAssertEqual(SafetyEvaluator.evaluate(one).decision, .warning)
        let low = observations([
            "C01": .triggered(.standard, deduplicationKey: nil),
            "A06": .triggered(.standard, deduplicationKey: nil),
        ])
        XCTAssertEqual(SafetyEvaluator.evaluate(low).safetyScore, 79)
        XCTAssertEqual(SafetyEvaluator.evaluate(low).decision, .deny)
        let at90 = observations(["A05": .triggered(.standard, deduplicationKey: nil)])
        XCTAssertEqual(SafetyEvaluator.evaluate(at90).safetyScore, 90)
        XCTAssertEqual(SafetyEvaluator.evaluate(at90).decision, .allow)
        let at89 = observations([
            "A05": .triggered(.standard, deduplicationKey: nil),
            "A06": .triggered(.standard, deduplicationKey: nil),
        ])
        XCTAssertEqual(SafetyEvaluator.evaluate(at89).safetyScore, 89)
        XCTAssertEqual(SafetyEvaluator.evaluate(at89).decision, .warning)
    }

    func testSharedEventDeduplicatesButDifferentMechanismsAccumulate() {
        let result = SafetyEvaluator.evaluate(observations([
            "C01": .triggered(.standard, deduplicationKey: "event:exit-change-1"),
            "C02": .triggered(.standard, deduplicationKey: "event:exit-change-1"),
            "C06": .triggered(.standard, deduplicationKey: "event:exit-change-1"),
            "E01": .triggered(.standard, deduplicationKey: "timezone-mismatch"),
            "E03": .triggered(.standard, deduplicationKey: "language-mismatch"),
        ]))
        XCTAssertEqual(result.safetyScore, 66)
        XCTAssertEqual(result.deductions.map(\.ruleID), ["C02", "E01", "E03"])
    }

    func testUnknownSourcesHoldAndDeduplicateCompletenessPenalty() {
        let result = SafetyEvaluator.evaluate(observations([
            "B01": .unknown(source: "provider", critical: false),
            "B02": .unknown(source: "provider", critical: false),
            "A03": .unknown(source: "target-route", critical: true),
        ]))
        XCTAssertEqual(result.decision, .hold)
        XCTAssertNil(result.safetyScore)
        XCTAssertEqual(result.scoreUpperBound, 75)
        XCTAssertEqual(result.deductions.map(\.ruleID), ["H01", "H02"])
    }

    func testHardBlockWinsWhenOtherEvidenceIsUnknown() {
        let result = SafetyEvaluator.evaluate(observations([
            "A01": .triggered(.standard, deduplicationKey: nil),
            "B01": .unknown(source: "provider", critical: false),
        ]))
        XCTAssertEqual(result.decision, .deny)
        XCTAssertNil(result.safetyScore)
        XCTAssertEqual(result.scoreUpperBound, 0)
    }

    func testProviderTrustAndTiers() {
        let result = SafetyEvaluator.evaluate(observations([
            "B08": .triggered(.trustScore(40), deduplicationKey: nil),
            "A06": .triggered(.elevated, deduplicationKey: nil),
        ]))
        XCTAssertEqual(result.safetyScore, 53)
        XCTAssertEqual(result.decision, .deny)
    }

    func testRequiredHoldRulesCannotAllow() {
        for id in ["A10", "D06", "F03", "F04", "F06", "F07", "H03"] {
            let result = SafetyEvaluator.evaluate(observations([id: .triggered(.standard, deduplicationKey: nil)]))
            XCTAssertEqual(result.decision, .hold, id)
        }
    }

    func testSharedKeyDoesNotMergeIndependentMechanisms() {
        let changes = Dictionary(uniqueKeysWithValues: ["B04", "B05", "E01", "E03"].map {
            ($0, ObservationStatus.triggered(.standard, deduplicationKey: "same-ip"))
        })
        let result = SafetyEvaluator.evaluate(observations(changes))
        XCTAssertEqual(result.safetyScore, 77)
        XCTAssertEqual(result.decision, .deny)
    }

    func testProviderAggregateReplacesOnlySameProviderEvidence() {
        let result = SafetyEvaluator.evaluate(observations([
            "B04": .triggered(.standard, deduplicationKey: "provider:fixture"),
            "B05": .triggered(.standard, deduplicationKey: "provider:fixture"),
            "B08": .triggered(.trustScore(0), deduplicationKey: "provider:fixture|covers:B04,B05"),
            "E01": .triggered(.standard, deduplicationKey: "provider:fixture")
        ]))
        XCTAssertEqual(result.safetyScore, 74)
        XCTAssertEqual(result.deductions.map(\.ruleID), ["B08", "E01"])
    }

    func testAggregateDoesNotSuppressUndeclaredCoverage() {
        let result = SafetyEvaluator.evaluate(observations([
            "B04": .triggered(.standard, deduplicationKey: "provider:p"),
            "B05": .triggered(.standard, deduplicationKey: "provider:p"),
            "B08": .triggered(.trustScore(0), deduplicationKey: "provider:p|covers:B05")
        ]))
        XCTAssertEqual(result.safetyScore, 74)
        XCTAssertEqual(result.decision, .deny)
    }

    func testProviderKeyDoesNotMergeIndependentProxyFields() {
        let result = SafetyEvaluator.evaluate(observations([
            "B03": .triggered(.standard, deduplicationKey: "provider:fixture"),
            "B06": .triggered(.standard, deduplicationKey: "provider:fixture")
        ]))
        XCTAssertEqual(result.safetyScore, 72)
        XCTAssertEqual(result.decision, .deny)
    }

    func testMalformedInputsFailClosed() {
        let initial = observations(["E01": .triggered(.trustScore(40), deduplicationKey: nil)])
        XCTAssertEqual(SafetyEvaluator.evaluate(initial).decision, .hold)
        XCTAssertEqual(SafetyEvaluator.evaluate(observations([:]) + [RuleObservation(id: "E01", status: .passed)]).decision,
                       .hold)
        XCTAssertEqual(SafetyEvaluator.evaluate(observations([:]), minimumScore: -1).decision, .hold)
        XCTAssertEqual(SafetyEvaluator.evaluate(observations([:]), minimumScore: 95, warningScore: 90).decision, .hold)
        XCTAssertEqual(SafetyEvaluator.evaluate(observations([
            "B08": .triggered(.standard, deduplicationKey: nil),
        ])).decision, .hold)
    }
}
