import Foundation
import XCTest
@testable import GuardCore

final class LocalEnvironmentSnapshotTests: XCTestCase {
    private func snapshot(_ environment: [String: String], target: String? = "api.anthropic.com") -> LocalEnvironmentSnapshot {
        LocalEnvironmentSnapshot.collect(environment: environment,
            systemTimeZone: TimeZone(identifier: "Asia/Shanghai")!,
            systemLocale: Locale(identifier: "zh_CN"), preferredLanguages: ["zh-Hans-CN", "en-US"],
            targetHost: target, collectedAt: Date(timeIntervalSince1970: 1_800_000_000))
    }

    func testCapturesSystemAndProcessFacts() {
        let value = snapshot(["TZ": "America/New_York", "LANG": "en_US.UTF-8"])
        XCTAssertEqual(value.systemTimeZoneIdentifier, "Asia/Shanghai")
        XCTAssertEqual(value.systemRegionCode, "CN")
        XCTAssertEqual(value.preferredLanguages, ["zh-Hans-CN", "en-US"])
        XCTAssertEqual(value.processLocale["LANG"], "en_US.UTF-8")
        XCTAssertEqual(value.processTimeZoneConsistency, .different)
        XCTAssertEqual(value.processLanguageConsistency, .different)
        XCTAssertEqual(value.proxyRoute, .direct(reason: "NO_PROXY_CONFIGURED"))
    }

    func testInvalidInputsStayUnknownAndDoNotFallBack() {
        let value = snapshot(["TZ": "secret-invalid-zone", "LC_ALL": "secret value!", "LANG": "zh_CN.UTF-8"])
        XCTAssertTrue(value.processTimeZoneIsInvalid)
        XCTAssertNil(value.processTimeZoneIdentifier)
        XCTAssertEqual(value.processTimeZoneConsistency, .unknown)
        XCTAssertEqual(value.processLanguageConsistency, .unknown)
        XCTAssertEqual(value.invalidProcessLocaleKeys, ["LC_ALL"])
        XCTAssertNil(value.processLocale["LC_ALL"])
    }

    func testProxyValuesAndUnrelatedEnvironmentNeverAppearInSnapshot() {
        let value = snapshot(["https_proxy": "http://fixture-user:fixture-password@proxy.example:8080",
                              "HTTPS_PROXY": "http://other.example:9999",
                              "NO_PROXY": "private.example", "CLAUDE_TOKEN": "fixture-token"])
        XCTAssertEqual(value.presentProxyKeys, ["https_proxy", "HTTPS_PROXY", "NO_PROXY"])
        XCTAssertEqual(value.conflictingProxyKeys, ["https_proxy", "HTTPS_PROXY"])
        XCTAssertEqual(value.proxyRoute, .configured(scheme: "http", sourceKey: "https_proxy",
                                                    source: "environment", hasCredentials: true))
        let description = String(reflecting: value)
        for secret in ["fixture-user", "fixture-password", "proxy.example", "private.example", "fixture-token"] {
            XCTAssertFalse(description.contains(secret))
        }
    }

    func testNoTargetAndUnsupportedProxyRemainDistinct() {
        XCTAssertEqual(snapshot([:], target: nil).proxyRoute, .notEvaluated)
        XCTAssertEqual(snapshot(["ALL_PROXY": "socks5://localhost:1080"]).proxyRoute,
                       .unknown(reason: "ALL_PROXY_UNVERIFIED"))
        XCTAssertEqual(snapshot(["NO_PROXY": "api.anthropic.com"]).proxyRoute, .direct(reason: "NO_PROXY"))
    }

    func testUnavailableSystemZoneStaysUnknown() {
        let result = LocalEnvironmentSnapshot.collect(environment: ["TZ": "Asia/Shanghai"], systemTimeZone: nil,
            systemLocale: Locale(identifier: "zh_CN"), preferredLanguages: ["zh-CN"], collectedAt: Date())
        XCTAssertNil(result.systemTimeZoneIdentifier)
        XCTAssertEqual(result.processTimeZoneConsistency, .unknown)
    }

    func testLiveCaptureIsUsableWithoutScoring() {
        let result = LocalEnvironmentSnapshot.capture()
        XCTAssertNotNil(result.systemTimeZoneIdentifier)
        XCTAssertEqual(result.proxyRoute, .notEvaluated)
    }

    func testVirtualizationSysctlParserFailsClosedOnMalformedResults() {
        let size = MemoryLayout<Int32>.size
        XCTAssertEqual(LocalEnvironmentSnapshot.parseVirtualizationStatus(
            value: 0, size: size, result: 0), false)
        XCTAssertEqual(LocalEnvironmentSnapshot.parseVirtualizationStatus(
            value: 1, size: size, result: 0), true)
        XCTAssertNil(LocalEnvironmentSnapshot.parseVirtualizationStatus(
            value: 0, size: size, result: -1))
        XCTAssertNil(LocalEnvironmentSnapshot.parseVirtualizationStatus(
            value: 1, size: size - 1, result: 0))
        XCTAssertNil(LocalEnvironmentSnapshot.parseVirtualizationStatus(
            value: 2, size: size, result: 0))
    }

    func testRemoteShellMarkersAreValidatedAndTheirValuesAreNotRetained() {
        let connection = "192.0.2.18 54821 198.51.100.4 22"
        let remote = snapshot(["SSH_CONNECTION": connection])
        XCTAssertTrue(remote.hasRemoteShellContext)
        XCTAssertFalse(String(reflecting: remote).contains("192.0.2.18"))
        XCTAssertFalse(String(reflecting: remote).contains("198.51.100.4"))

        XCTAssertTrue(snapshot(["SSH_CLIENT": "2001:db8::4 54219 22"]).hasRemoteShellContext)
        XCTAssertTrue(snapshot(["SSH_TTY": "/dev/ttys007"]).hasRemoteShellContext)
        XCTAssertFalse(snapshot(["SSH_CONNECTION": "not-an-ip 22 host 22"]).hasRemoteShellContext)
        XCTAssertFalse(snapshot(["SSH_CLIENT": "192.0.2.1 0 22"]).hasRemoteShellContext)
        XCTAssertFalse(snapshot(["SSH_TTY": "fixture-private-path"]).hasRemoteShellContext)
    }
}
