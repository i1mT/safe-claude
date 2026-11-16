import XCTest
@testable import GuardCore

final class ProxyConfigurationTests: XCTestCase {
    func testDocumentedPrecedenceAndRedaction() throws {
        let decision = ProxyConfiguration.resolve(targetHost: "api.anthropic.com", environment: [
            "https_proxy": "http://user:secret@127.0.0.1:8123",
            "HTTPS_PROXY": "http://127.0.0.1:9000",
        ])
        guard case .proxy(let proxy) = decision else { return XCTFail("Expected proxy") }
        XCTAssertEqual(proxy.port, 8123)
        XCTAssertEqual(proxy.sourceKey, "https_proxy")
        XCTAssertTrue(proxy.hasCredentials)
        XCTAssertEqual(ProxyConfiguration.conflictingKeys(environment: [
            "https_proxy": "http://user:secret@127.0.0.1:8123",
            "HTTPS_PROXY": "http://127.0.0.1:9000",
        ]), ["https_proxy", "HTTPS_PROXY"])
        let encoded = try String(decoding: JSONEncoder().encode(proxy), as: UTF8.self)
        XCTAssertFalse(encoded.contains("secret"))
        XCTAssertFalse(encoded.contains("user"))
    }

    func testDistinctSettingsKeysStillFollowProxyPriority() {
        let decision = ProxyConfiguration.resolve(targetHost: "api.anthropic.com",
            environment: ["HTTPS_PROXY": "http://127.0.0.1:9000"],
            settingsEnvironment: ["https_proxy": "http://127.0.0.1:8000"])
        guard case .proxy(let proxy) = decision else { return XCTFail("Expected proxy") }
        XCTAssertEqual(proxy.port, 8000)
        XCTAssertEqual(proxy.source, "settings")
    }

    func testConflictingSameKeyAcrossSourcesRemainsUnknown() {
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "api.anthropic.com",
            environment: ["http_proxy": "http://127.0.0.1:9000"],
            settingsEnvironment: ["http_proxy": "http://127.0.0.1:8000"]),
            .unknown(reason: "SETTINGS_ENV_CONFLICT"))
    }

    func testNoProxySupportsDomainsAndPorts() {
        let env = ["HTTPS_PROXY": "http://127.0.0.1:9000", "NO_PROXY": ".anthropic.com:443"]
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "api.anthropic.com", environment: env),
                       .direct(reason: "NO_PROXY"))
        guard case .proxy = ProxyConfiguration.resolve(targetHost: "notanthropic.com", environment: env)
        else { return XCTFail("Domain suffix matched unrelated host") }
        guard case .proxy = ProxyConfiguration.resolve(targetHost: "api.anthropic.com", targetPort: 8443, environment: env)
        else { return XCTFail("Port-specific bypass matched wrong port") }
    }

    func testConflictingBypassSettingsFailClosed() {
        let decision = ProxyConfiguration.resolve(targetHost: "api.anthropic.com", environment: [
            "no_proxy": "example.com", "NO_PROXY": "other.example",
        ])
        XCTAssertEqual(decision, .unknown(reason: "NO_PROXY_CONFLICT"))
    }

    func testCIDRForHostnameRemainsUnknownWithoutResolvedTargetAddress() {
        let decision = ProxyConfiguration.resolve(targetHost: "api.anthropic.com", environment: [
            "NO_PROXY": "10.0.0.0/8", "HTTPS_PROXY": "http://127.0.0.1:9000",
        ])
        XCTAssertEqual(decision, .unknown(reason: "NO_PROXY_UNSUPPORTED"))
    }

    func testNoProxyMatchesIPv4AndIPv6LiteralsAndCIDRs() {
        let proxy = "http://127.0.0.1:9000"
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "10.4.5.6",
            environment: ["NO_PROXY": "10.0.0.0/8", "HTTPS_PROXY": proxy]),
            .direct(reason: "NO_PROXY"))
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "2001:db8::1234",
            environment: ["NO_PROXY": "2001:db8::/32", "HTTPS_PROXY": proxy]),
            .direct(reason: "NO_PROXY"))
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "2001:db8::1",
            environment: ["NO_PROXY": "[2001:db8::1]:443", "HTTPS_PROXY": proxy]),
            .direct(reason: "NO_PROXY"))
        guard case .proxy = ProxyConfiguration.resolve(targetHost: "192.0.2.1",
            environment: ["NO_PROXY": "10.0.0.0/8", "HTTPS_PROXY": proxy]) else {
            return XCTFail("Nonmatching IPv4 CIDR bypassed the proxy")
        }
        guard case .proxy = ProxyConfiguration.resolve(targetHost: "2001:db9::1",
            environment: ["NO_PROXY": "2001:db8::/32", "HTTPS_PROXY": proxy]) else {
            return XCTFail("Nonmatching IPv6 CIDR bypassed the proxy")
        }
    }

    func testNoProxyRejectsMalformedCIDRConservatively() {
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "192.0.2.1",
            environment: ["NO_PROXY": "192.0.2.0/33", "HTTPS_PROXY": "http://127.0.0.1:9000"]),
            .unknown(reason: "NO_PROXY_UNSUPPORTED"))
    }

    func testUnsupportedProxyAndEmptyConfigurationFailClosed() {
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "api.anthropic.com",
            environment: ["HTTPS_PROXY": "socks5://127.0.0.1:1080"]),
            .unknown(reason: "UNSUPPORTED_PROXY_SCHEME"))
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "api.anthropic.com",
            environment: ["https_proxy": "", "HTTPS_PROXY": "http://127.0.0.1:9000"]),
            .unknown(reason: "EMPTY_PROXY_VALUE"))
    }

    func testDirectWhenNoProxyConfigured() {
        XCTAssertEqual(ProxyConfiguration.resolve(targetHost: "api.anthropic.com", environment: [:]),
                       .direct(reason: "NO_PROXY_CONFIGURED"))
    }

    func testUnverifiedAllProxyNeverBecomesDirect() {
        for key in ["ALL_PROXY", "all_proxy"] {
            XCTAssertEqual(ProxyConfiguration.resolve(
                targetHost: "api.anthropic.com",
                environment: [key: "socks5://127.0.0.1:1080"]),
                .unknown(reason: "ALL_PROXY_UNVERIFIED"))
            XCTAssertEqual(ProxyConfiguration.resolve(
                targetHost: "api.anthropic.com",
                environment: [key: "socks5://127.0.0.1:1080", "NO_PROXY": "api.anthropic.com"]),
                .unknown(reason: "ALL_PROXY_UNVERIFIED"))
        }
    }

    func testEqualProxyValuesDoNotCreateConflict() {
        let proxy = "http://127.0.0.1:9000"
        XCTAssertTrue(ProxyConfiguration.conflictingKeys(
            environment: ["https_proxy": proxy, "HTTPS_PROXY": proxy]).isEmpty)
    }

    func testEveryCaseVariantProxyPairReportsOnlyConflictingVariableNames() {
        let cases: [(String, String)] = [
            ("http_proxy", "HTTP_PROXY"),
            ("https_proxy", "HTTPS_PROXY"),
            ("all_proxy", "ALL_PROXY"),
            ("no_proxy", "NO_PROXY"),
        ]
        for (lower, upper) in cases {
            let conflicts = ProxyConfiguration.conflictingKeys(environment: [
                lower: "http://lower-user:lower-secret@lower.example:8080",
                upper: "http://upper-user:upper-secret@upper.example:9090",
            ])
            XCTAssertEqual(conflicts, [lower, upper], "\(lower) / \(upper)")
            XCTAssertFalse(conflicts.contains { $0.contains("secret") })
        }
    }

    func testEqualAllAndNoProxyCaseVariantsDoNotReportConflict() {
        let values = [
            "all_proxy": "socks5://127.0.0.1:1080",
            "ALL_PROXY": "socks5://127.0.0.1:1080",
            "no_proxy": ".anthropic.com,localhost",
            "NO_PROXY": ".anthropic.com,localhost",
        ]
        XCTAssertTrue(ProxyConfiguration.conflictingKeys(environment: values).isEmpty)
    }
}
