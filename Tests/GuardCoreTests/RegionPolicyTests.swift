import Foundation
import XCTest
@testable import GuardCore

final class RegionPolicyTests: XCTestCase {
    func testDatesAndIncompleteRegionsAreConservative() {
        let before = Date(timeIntervalSince1970: 1_794_484_799)
        let active = Date(timeIntervalSince1970: 1_794_484_800)
        let expired = Date(timeIntervalSince1970: 1_797_033_600)
        XCTAssertEqual(RegionPolicy.classify(countryCode: "US", at: before), .unknown)
        XCTAssertEqual(RegionPolicy.classify(countryCode: "US", at: active), .supported)
        XCTAssertEqual(RegionPolicy.classify(countryCode: "CN", at: active), .unsupported)
        XCTAssertEqual(RegionPolicy.classify(countryCode: "UA", at: active), .unknown)
        XCTAssertEqual(RegionPolicy.classify(countryCode: "PR", at: active), .supported)
        XCTAssertEqual(RegionPolicy.classify(countryCode: "CN", at: expired), .unknown)
    }

    func testUnsupportedRegionIsHardBlockEvenWithMissingChecks() {
        let snapshot = LocalEnvironmentSnapshot.collect(environment: [:], systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!,
            systemLocale: Locale(identifier: "zh_CN"), preferredLanguages: ["zh-CN"], targetHost: "api.anthropic.com",
            collectedAt: Date(timeIntervalSince1970: 1_794_484_800))
        let reputation = IPReputation(ip: "192.0.2.1", countryCode: "CN", timeZone: "Asia/Shanghai",
            autonomousSystem: 123, isDatacenter: nil, isVPN: nil, isProxy: nil, isTor: nil, isAbuser: nil)
        let trace = TraceProbeResult.observed(TraceObservation(targetHost: "api.anthropic.com", ip: "192.0.2.1", countryCode: "CN"))
        let rules = EnvironmentAssessment.observations(snapshot: snapshot, apiTrace: trace, reputation: reputation,
            countryLanguages: CountryLanguageCatalog.languages(for: "CN"), firstRun: nil,
            traceObservedAt: Date(timeIntervalSince1970: 1_794_484_800),
            reputationObservedAt: Date(timeIntervalSince1970: 1_794_484_800),
            at: Date(timeIntervalSince1970: 1_794_484_800))
        XCTAssertEqual(SafetyEvaluator.evaluate(rules).decision, .deny)
    }
    func testStaleSnapshotCannotProlongPolicyValidity() {
        let active = Date(timeIntervalSince1970: 1_794_484_800)
        let snapshot = LocalEnvironmentSnapshot.collect(environment: [:], systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!,
            systemLocale: Locale(identifier: "zh_CN"), preferredLanguages: ["zh-CN"], collectedAt: active)
        let rules = EnvironmentAssessment.observations(snapshot: snapshot, apiTrace: nil, reputation: nil,
            countryLanguages: nil, firstRun: nil, at: Date(timeIntervalSince1970: 1_797_033_600))
        XCTAssertEqual(rules.first { $0.id == "A01" }?.status, .unknown(source: "stale-snapshot", critical: true))
        XCTAssertEqual(SafetyEvaluator.evaluate(rules).decision, .hold)
    }
}
