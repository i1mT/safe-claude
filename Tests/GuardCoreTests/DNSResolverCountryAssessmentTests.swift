import Foundation
import XCTest
@testable import GuardCore

final class DNSResolverCountryAssessmentTests: XCTestCase {
    func testComparesTargetExitWithObservedResolverAndMarksSingleResolverNotApplicableForD03() {
        let now = Date()
        let result = DNSResolverCountryAssessment.evaluate(
            samples: [DNSResolverCountrySample(resolverDigest: "a", countryCode: "US", observedAt: now)],
            configuredResolverDigests: ["a"], observedResolverDigest: "a",
            targetHTTPCountry: "US", targetHTTPObservedAt: now, at: now)
        XCTAssertEqual(result.httpConsistency, .matching)
        XCTAssertEqual(result.resolverConsistency, .notApplicable)
        XCTAssertEqual(result.httpObservedAt, now)
    }

    func testFlagsTargetResolverCountryMismatchAndConflictingResolverCountries() {
        let now = Date()
        let result = DNSResolverCountryAssessment.evaluate(
            samples: [
                DNSResolverCountrySample(resolverDigest: "a", countryCode: "US", observedAt: now),
                DNSResolverCountrySample(resolverDigest: "b", countryCode: "JP", observedAt: now),
            ],
            configuredResolverDigests: ["a", "b"], observedResolverDigest: "b",
            targetHTTPCountry: "US", targetHTTPObservedAt: now, at: now)
        XCTAssertEqual(result.httpConsistency, .different)
        XCTAssertEqual(result.resolverConsistency, .different)
        XCTAssertEqual(result.resolverObservedAt, now)
    }

    func testUsesAllResolversBeforeFirstClaudeQueryAndKeepsPartialPositiveAsTriggeredAndUnknown() {
        let now = Date()
        let partial = DNSResolverCountryAssessment.evaluate(
            samples: [DNSResolverCountrySample(resolverDigest: "a", countryCode: "JP", observedAt: now)],
            configuredResolverDigests: ["a", "b"], observedResolverDigest: nil,
            targetHTTPCountry: "US", targetHTTPObservedAt: now, at: now)
        XCTAssertEqual(partial.httpConsistency, .differentWithUnknown)
        XCTAssertEqual(partial.resolverConsistency, .unknown)
    }

    func testMissingStaleOrMalformedFactsCannotPass() {
        let now = Date()
        let stale = DNSResolverCountrySample(resolverDigest: "a", countryCode: "US",
                                              observedAt: now.addingTimeInterval(-901))
        let result = DNSResolverCountryAssessment.evaluate(samples: [stale],
            configuredResolverDigests: ["a", "b"], observedResolverDigest: nil,
            targetHTTPCountry: "US", targetHTTPObservedAt: now, at: now)
        XCTAssertEqual(result.httpConsistency, .unknown)
        XCTAssertEqual(result.resolverConsistency, .unknown)

        let noHTTP = DNSResolverCountryAssessment.evaluate(samples: [
            DNSResolverCountrySample(resolverDigest: "a", countryCode: "US", observedAt: now),
            DNSResolverCountrySample(resolverDigest: "b", countryCode: "US", observedAt: now),
        ], configuredResolverDigests: ["a", "b"], observedResolverDigest: nil,
           targetHTTPCountry: nil, targetHTTPObservedAt: nil, at: now)
        XCTAssertEqual(noHTTP.httpConsistency, .unknown)
        XCTAssertEqual(noHTTP.resolverConsistency, .matching)
    }
}
