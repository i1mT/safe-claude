import XCTest
@testable import GuardCore

final class DNSResolverPolicyTests: XCTestCase {
    func testMatchesExactAndLabelBoundaryScopedDomains() {
        let settings = [DNSResolverPolicySetting(security: .dnsOverHTTPS,
            matchDomains: ["anthropic.com"])]
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"], settings: settings), .dnsOverHTTPS)
        XCTAssertEqual(DNSResolverPolicy.security(for: ["anthropic.com"], settings: settings), .dnsOverHTTPS)
        XCTAssertEqual(DNSResolverPolicy.security(for: ["notanthropic.com"], settings: settings), .unknown)
    }

    func testDefaultAndNonmatchingScopedSettings() {
        let defaultRoute = [DNSResolverPolicySetting(security: .dnsOverTLS, matchDomains: nil)]
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"], settings: defaultRoute), .dnsOverTLS)

        let otherDomain = [DNSResolverPolicySetting(security: .dnsOverHTTPS, matchDomains: ["example.net"])]
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"], settings: otherDomain), .unknown)
    }

    func testConflictingOrUnresolvedPoliciesRemainUnknown() {
        let conflicting = [
            DNSResolverPolicySetting(security: .dnsOverHTTPS, matchDomains: nil),
            DNSResolverPolicySetting(security: .cleartext, matchDomains: ["anthropic.com"]),
        ]
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"], settings: conflicting), .unknown)

        let mixedDomains = [
            DNSResolverPolicySetting(security: .dnsOverHTTPS, matchDomains: ["api.anthropic.com"]),
            DNSResolverPolicySetting(security: .cleartext, matchDomains: ["claude.ai"]),
        ]
        XCTAssertEqual(DNSResolverPolicy.security(
            for: ["api.anthropic.com", "claude.ai"], settings: mixedDomains), .unknown)
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"],
            settings: [DNSResolverPolicySetting(security: .unknown, matchDomains: nil)]), .unknown)
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"],
            settings: [DNSResolverPolicySetting(security: .dnsOverHTTPS, matchDomains: [])]), .unknown)
        XCTAssertEqual(DNSResolverPolicy.security(for: [], settings: mixedDomains), .unknown)
        XCTAssertEqual(DNSResolverPolicy.security(for: ["api.anthropic.com"], settings: nil), .unknown)
    }

    func testUniqueSettingSelectionRequiresOneSharedConfigurationForAllQueries() {
        let settings = [
            DNSResolverPolicySetting(security: .dnsOverHTTPS, matchDomains: ["anthropic.com"]),
            DNSResolverPolicySetting(security: .dnsOverTLS, matchDomains: ["example.net"]),
        ]
        XCTAssertEqual(DNSResolverPolicy.uniqueApplicableSettingIndex(
            for: ["api.anthropic.com", "claude.ai"], settings: [
                settings[0], DNSResolverPolicySetting(security: .dnsOverTLS, matchDomains: ["claude.ai"])
            ]), nil)
        XCTAssertEqual(DNSResolverPolicy.uniqueApplicableSettingIndex(
            for: ["api.anthropic.com", "claude.ai"], settings: [
                DNSResolverPolicySetting(security: .dnsOverHTTPS,
                    matchDomains: ["anthropic.com", "claude.ai"])
            ]), 0)
        XCTAssertNil(DNSResolverPolicy.uniqueApplicableSettingIndex(
            for: ["api.anthropic.com"], settings: [
                DNSResolverPolicySetting(security: .dnsOverHTTPS, matchDomains: nil),
                DNSResolverPolicySetting(security: .cleartext, matchDomains: ["anthropic.com"])
            ]))
    }
}
